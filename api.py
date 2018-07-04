#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import datetime
import logging
import hashlib
import uuid

from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict, Sequence, Sized

from scoring import get_score, get_interests

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
ADMIN_SCORE = 42
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}
LIMIT_YEARS = 70
PHONE_LENGTH = 11


class ValidationError(Exception):
    pass


class BaseField(object):
    """
    Base class for all fields
    The attr `required` assumes the should be in request.
    If `nullable` attr is set to `True` the field
    can have `None` value.
    """
    allowed_types = (type(None),)

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.field_name = None

    def __set__(self, instance, value):
        if not isinstance(value, self.allowed_types):
            error_str = ' or '.join(
                str(type_) for type_ in self.allowed_types
            )
            raise ValidationError("The field must be %s" % error_str)
        if not self.nullable and value is None:
            raise ValidationError("The field cannot be "
                                  "None with nullable=False option")
        instance.__dict__[self.field_name] = value

    def __get__(self, instance, owner):
        return instance.__dict__[self.field_name]


class CharField(BaseField):
    allowed_types = (type(None), basestring)

    def __set__(self, instance, value):
        super(CharField, self).__set__(instance, value)


class ArgumentsField(BaseField):
    allowed_types = (type(None), dict)

    def __set__(self, instance, value):
        super(ArgumentsField, self).__set__(instance, value)


class EmailField(CharField):
    def __set__(self, instance, value):
        super(EmailField, self).__set__(instance, value)
        if isinstance(instance.__dict__[self.field_name], basestring) \
                and "@" not in value and len(value):
            raise ValidationError("@ character should be in EmailField")


class PhoneField(BaseField):
    allowed_types = (type(None), basestring, int)

    def __set__(self, instance, value):
        super(PhoneField, self).__set__(instance, value)
        if value is not None:
            converted_value = str(value)
            if not (len(converted_value) == PHONE_LENGTH
                    and converted_value.startswith("7")):
                raise ValidationError("The field should has length=11 "
                                      "and starts from 7")


class DateField(BaseField):
    allowed_types = (type(None), basestring, datetime.datetime)

    def __set__(self, instance, value):
        if isinstance(value, basestring):
            try:
                value = datetime.datetime.strptime(value, "%d.%m.%Y")
            except ValueError:
                raise ValidationError("Invalid field datetime format")
        super(DateField, self).__set__(instance, value)


class BirthDayField(DateField):
    def __set__(self, instance, value):
        super(BirthDayField, self).__set__(instance, value)
        if isinstance(instance.__dict__[self.field_name], datetime.datetime):
            if instance.__dict__[self.field_name] < (datetime.datetime.today() -
                             datetime.timedelta(days=365 * LIMIT_YEARS)):
                raise ValidationError("The field cannot be "
                                      "older than %d years" % LIMIT_YEARS)


class GenderField(BaseField):
    allowed_types = (type(None), int)

    def __set__(self, instance, value):
        super(GenderField, self).__set__(instance, value)
        variants = GENDERS.keys() + [None]
        if value not in variants:
            raise ValidationError("The field should have "
                                  "values: %s" % " ,".join(list(map(str, variants))))


class ClientIDsField(BaseField):
    allowed_types = (type(None), Sequence)

    def __set__(self, instance, value):
        super(ClientIDsField, self).__set__(instance, value)
        if isinstance(value, Sized) and len(value) <= 0:
            raise ValidationError("The field must contain more than one id")
        if isinstance(value, Sequence) and\
                not all(map(lambda i: isinstance(i, int), value)):
            raise ValidationError("All members should have type int")


class BaseRequest(object):
    def __init__(self, **kwargs):
        self.errors = []
        self.kwargs = kwargs
        self.is_validated = False
        self.fields = {}

    def _get_fields(self):
        for name, value in vars(self.__class__).items():
            if isinstance(value, BaseField):
                self.fields[name] = value
                value.field_name = name

    def validate_fields(self):
        self._get_fields()
        for field_name, field_value in self.fields.items():
            if field_value.required and self.kwargs.get(field_name, False) is False:
                self.errors.append("The %s is required" % field_name)
            try:
                setattr(self, field_name, self.kwargs.get(field_name))
            except ValidationError as e:
                self.errors.append("The %s error: %s" % (field_name, str(e)))
        self.is_validated = True

    def is_valid(self):
        if not self.is_validated:
            self.validate_fields()
        return not self.errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate_fields(self):
        super(OnlineScoreRequest, self).validate_fields()
        is_phone_and_email_exists = self.kwargs.get("phone") and self.kwargs.get("email")
        is_first_and_last_name_exists = (self.kwargs.get("first_name")
                                         and self.kwargs.get("last_name"))
        is_gender_and_birthday_exists = ((self.kwargs.get("gender") in GENDERS.keys())
                                         and self.kwargs.get("birthday"))

        if not any([is_phone_and_email_exists, is_first_and_last_name_exists,
                    is_gender_and_birthday_exists]):
            self.errors.append("missing one of non-empty pairs: "
                               "phone & email or first & "
                               "last name or gender & birthday")


class RequestHandler(object):
    request_cls = None

    def handle(self, request, ctx, store):
        if not self.request_cls:
            logging.error("You must specify request_cls in the handler")
            return "Invalid handler", INVALID_REQUEST
        arguments = self.request_cls(**request.arguments)
        if not arguments.is_valid():
            logging.error("%s: %s" % (ERRORS[INVALID_REQUEST], arguments.errors))
            return arguments.errors, INVALID_REQUEST
        return self.get_result(request, arguments, ctx, store)

    def get_result(self, request, arguments, ctx, store):
        return {}, OK


class OnlineScoreHandler(RequestHandler):
    request_cls = OnlineScoreRequest

    def get_result(self, request, arguments, ctx, store):
        if request.is_admin:
            logging.info("Returned response for admin with score=42")
            return {"score": ADMIN_SCORE}, OK
        else:
            score = get_score(
                store,
                phone=arguments.phone,
                email=arguments.email,
                birthday=arguments.birthday,
                gender=arguments.gender,
                first_name=arguments.first_name,
                last_name=arguments.last_name
            )
        ctx["has"] = [field_name for field_name, field_value in arguments.fields.items()
                      if getattr(arguments, field_name) is not None]
        return {"score": score}, OK


class ClientsInterestsHandler(RequestHandler):
    request_cls = ClientsInterestsRequest

    def get_result(self, request, arguments, ctx, store):
        ctx["nclients"] = len(arguments.client_ids)
        return {client_id: get_interests(store, client_id)
                for client_id in arguments.client_ids}, OK


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    methods = {
        "online_score": OnlineScoreHandler,
        "clients_interests": ClientsInterestsHandler
    }

    request_obj = MethodRequest(**request["body"])
    if not request_obj.is_valid():
        logging.error("%s: %s" % (ERRORS[INVALID_REQUEST], request_obj.errors))
        return request_obj.errors, INVALID_REQUEST

    if not check_auth(request_obj):
        logging.error("%s user %s: %d" % (ERRORS[FORBIDDEN],
                                          request_obj.login, FORBIDDEN))
        return request_obj.errors, FORBIDDEN

    method = request["body"].get("method")

    if method in methods:
        method_obj = methods[method]
    else:
        logging.info("Unknown method: %s" % method)
        return {"method": "Unknown method"}, INVALID_REQUEST
    response, code = method_obj().handle(request_obj, ctx, store)

    logging.info("Returned context: %s, "
                 "response: %s, code: %s" % (ctx, response, code))
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
