#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

from collections import defaultdict, Sequence, Sized

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
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


class BaseField(object):
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.value = None

    def __set__(self, instance, value):
        if not self.nullable and value is None:
            raise ValueError("The field cannot be "
                             "None with nullable=False option")

    def __get__(self, instance, owner):
        return self.value


class TypeFieldMixin(BaseField):
    allowed_types = [type(None)]

    def __set__(self, instance, value):
        super(TypeFieldMixin, self).__set__(instance, value)
        if not any(isinstance(value, type_) for type_ in self.allowed_types):
            error_str = ' or '.join(
                str(type_) for type_ in self.allowed_types
            )
            raise TypeError("The field must be %s" % error_str)


class CharField(TypeFieldMixin, BaseField):
    allowed_types = [type(None), str, unicode]

    def __set__(self, instance, value):
        super(CharField, self).__set__(instance, value)
        self.value = value


class ArgumentsField(TypeFieldMixin, BaseField):
    allowed_types = [type(None), dict]

    def __set__(self, instance, value):
        super(ArgumentsField, self).__set__(instance, value)
        self.value = value


class EmailField(CharField):
    def __set__(self, instance, value):
        super(EmailField, self).__set__(instance, value)
        if (isinstance(self.value, str) or isinstance(self.value, unicode)) \
                and "@" not in value:
            raise ValueError("@ character should be in EmailField")


class PhoneField(TypeFieldMixin, BaseField):
    allowed_types = [type(None), str, unicode, int]

    def __set__(self, instance, value):
        super(PhoneField, self).__set__(instance, value)
        if (isinstance(value, str) or isinstance(value, unicode) or
                isinstance(value, int)):
            converted_value = str(value)
            if not (len(converted_value) == PHONE_LENGTH
                    and converted_value.startswith("7")):
                raise ValueError("The field should has length=11 "
                                 "and starts from 7")
        self.value = value


class DateField(TypeFieldMixin, BaseField):
    allowed_types = [type(None), str, unicode, datetime.datetime]

    def __set__(self, instance, value):
        super(DateField, self).__set__(instance, value)
        if isinstance(value, str) or isinstance(value, unicode):
            try:
                value = datetime.datetime.strptime(value, "%d.%m.%Y")
            except ValueError:
                raise ValueError("Invalid field datetime format")
        self.value = value


class BirthDayField(DateField):
    def __set__(self, instance, value):
        super(BirthDayField, self).__set__(instance, value)
        if isinstance(self.value, datetime.datetime):
            if self.value < (datetime.datetime.today() -
                            datetime.timedelta(days=365 * LIMIT_YEARS)):
                raise ValueError("The field cannot be "
                                 "older than %d years" % LIMIT_YEARS)


class GenderField(TypeFieldMixin, BaseField):
    allowed_types = [type(None), int]

    def __set__(self, instance, value):
        super(GenderField, self).__set__(instance, value)
        if value not in [None, 0, 1, 2]:
            raise ValueError("The field should have value: 0, 1 or 2")
        self.value = value


class ClientIDsField(TypeFieldMixin, BaseField):
    allowed_types = [type(None), Sequence]

    def __set__(self, instance, value):
        super(ClientIDsField, self).__set__(instance, value)
        if isinstance(value, Sized) and len(value) <= 0:
            raise ValueError("The field must contain more than one id")
        self.value = value


class BaseRequest(object):

    def __init__(self, **kwargs):
        self._errors = defaultdict(list)
        self._fields = self._get_fields()

        for field_name, field_value in self._fields:
            if field_value.required and kwargs.get(field_name, False) is False:
                self._errors[field_name].append("The field is required")
            try:
                setattr(self, field_name, kwargs.get(field_name))
            except (ValueError, TypeError) as e:
                self._errors[field_name].append(str(e))

    def _get_fields(self):
        fields = []
        for name, value in vars(self.__class__).items():
            if hasattr(value, 'required'):
                fields.append((name, value))
        return fields

    def get_result(self):
        raise NotImplemented

    def is_valid(self):
        return not bool(self._errors)

    @property
    def errors(self):
        return self._errors


class BaseOnlineScoreRequest(BaseRequest):
    def __init__(self, **kwargs):
        super(BaseOnlineScoreRequest, self).__init__(**kwargs)
        # check if any of this pairs: phone & email or
        # first & last name or gender & birthday exist in passed arguments
        is_phone_and_email_exists = kwargs.get("phone") and kwargs.get("email")
        is_first_and_last_name_exists = (kwargs.get("first_name")
                                         and kwargs.get("last_name"))
        is_gender_and_birthday_exists = (kwargs.get("gender")
                                         and kwargs.get("birthday"))

        if not any([is_phone_and_email_exists, is_first_and_last_name_exists,
                    is_gender_and_birthday_exists]):
            self._errors["params"] = "missing one of non-empty pairs: " \
                                     "phone & email or first & last name or " \
                                     "gender & birthday"

    def get_result(self):
        pass


class ClientsInterestsMixin(BaseRequest):
    def get_result(self):
        pass


class ClientsInterestsRequest(ClientsInterestsMixin, BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseOnlineScoreRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=False)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=False)
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
    response, code = {}, None
    request_obj = MethodRequest(**request["body"])

    if not request_obj.is_valid():
        logging.info("%s: %s" % (ERRORS[INVALID_REQUEST], request_obj.errors))
        return request_obj.errors, BAD_REQUEST

    method = request["body"].get("method")
    if method == "online_score":
        method_obj = OnlineScoreRequest(**request["body"].get("arguments"))
    elif method == "clients_interests":
        method_obj = ClientsInterestsRequest(**request["body"].get("arguments"))
    else:
        logging.info("Unknown method: %s" % method)
        return {"method": "Unknown method"}, INVALID_REQUEST

    if method_obj.is_valid():
        response = method_obj.get_result()
        code = OK
    else:
        logging.info("%s: %s" % (ERRORS[INVALID_REQUEST], request_obj.errors))
        return method_obj.errors, BAD_REQUEST
    ctx.update({"new": 1})
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
