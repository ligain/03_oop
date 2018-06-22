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

from collections import defaultdict

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


class CharField(object):

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __set__(self, instance, value):
        if not isinstance(value, str):
            raise ValueError("The field must be a string")
        if self.nullable is not True and value is None:
            raise ValueError("The field cannot be "
                             "None with nullable=False option")
        self.value = value

    def __get__(self, instance, owner):
        return self.value


class ArgumentsField(object):
    pass


class EmailField(CharField):
    def __set__(self, instance, value):
        super(EmailField, self).__set__(instance, value)
        if "@" not in value:
            raise ValueError("@ character should be in EmailField")
        self.value = value


class PhoneField(object):
    pass


class DateField(object):
    pass


class BirthDayField(object):
    pass


class GenderField(object):
    pass


class ClientIDsField(object):
    pass


class ClientsInterestsRequest(object):
    pass
    # client_ids = ClientIDsField(required=True)
    # date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    pass
    # first_name = CharField(required=False, nullable=True)
    # last_name = CharField(required=False, nullable=True)
    # email = EmailField(required=False, nullable=True)
    # phone = PhoneField(required=False, nullable=True)
    # birthday = BirthDayField(required=False, nullable=True)
    # gender = GenderField(required=False, nullable=True)


class BaseRequest(object):

    def __init__(self, **kwargs):
        self._errors = defaultdict(list)
        self._fields = self._get_fields()

        for field_name, field_value in self._fields:
            if kwargs.get(field_name) is not None:
                try:
                    setattr(self, field_name, kwargs.get(field_name))
                except ValueError as e:
                    self._errors[field_name].append(str(e))
            else:
                if field_value.required:
                    self._errors[field_name].append("The field is required")

    def _get_fields(self):
        fields = []
        for name, value in vars(self.__class__).items():
            if hasattr(value, 'required'):
                fields.append((name, value))
        return fields

    def is_valid(self):
        return False if self._errors else True


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=False)

    # TODO: delete after testing
    email = EmailField(required=False, nullable=True)

    # token = CharField(required=True, nullable=True)
    # arguments = ArgumentsField(required=True, nullable=True)
    # method = CharField(required=True, nullable=False)

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
    response, code = None, None
    r = MethodRequest(account=12, login="", email=12)
    r.is_valid()
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
