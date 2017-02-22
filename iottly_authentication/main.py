import json
import logging

import tornado.ioloop

from inspect import ismodule

from cerberus import Validator
from tornado import gen, web

from . import db, validation
from .settings import settings


class ApiHandler(web.RequestHandler):
    def prepare(self):
        content_type = self.request.headers.get('Content-Type')
        if content_type and content_type == 'application/json':
            try:
                self.json_args = json.loads(self.request.body.decode())
            except ValueError:
                msg = {
                    'error': 'Invalid JSON'
                }
                logging.debug('{}: {}'.format('Invalid JSON', self.request.body))
                raise web.HTTPError(400, json.dumps(msg))
        else:
            self.json_args = None

        self.set_header("Content-Type", "application/json")


class RegistrationHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.USER_REGISTRATION)
        if not v.validate(self.json_args):
            raise web.HTTPError(400, json.dumps(v.errors))

        data = self.json_args.copy()
        # TODO: HASHPASSWORD
        try:
            self.application.db.insert('users', data)
        except db.errors.DuplicateKeyError:
            raise web.HTTPError(409, json.dumps({'error': 'Invalid username / email'}))

        self.set_status(201)
        self.write(json.dumps({}))


class UserHandler(ApiHandler):
    @gen.coroutine
    def post(self, username):
        print("hi")

    @gen.coroutine
    def put(self):
        print("hi")

    @gen.coroutine
    def delete(self):
        print("hi")


class IottlyApplication(web.Application):
    def __init__(self, handlers=None, default_host=None, transforms=None, **settings):
        super(IottlyApplication, self).__init__(handlers, default_host, transforms, **settings)
        self.db = db.Database(settings)


def make_app(override_settings=None):
    # app_settings = settings.to_dict()
    app_settings = {k: v for k, v in settings.__dict__.items() if k[0] != '_' and not ismodule(v)}
    if override_settings:
        app_settings.update(override_settings)
    return IottlyApplication([
        (r'/auth/register', RegistrationHandler),
        (r'/users/$(\w+)', UserHandler),
    ], **app_settings)


if __name__ == "__main__":
    app = make_app()
    app.listen(8523)
    logging.info(" [*] Listening on 0.0.0.0:8523")

    tornado.ioloop.IOLoop.current().start()
