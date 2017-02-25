import json
import logging
import re

import tornado.ioloop

from inspect import ismodule

from cerberus import Validator
from tornado import gen, web

from . import db, sessions, validation
from .hashers import make_password
from .settings import settings


TOKEN_RE = re.compile(r'bearer (.{32})$', re.IGNORECASE)

# TODO:
# move username check to a decorator
# add active user decorator

class ApiHandler(web.RequestHandler):
    COOKIE_NAME = 'iottly-session-id'

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

    def get_user_from_cookie(self):
        session_id = self.get_secure_cookie(self.COOKIE_NAME)
        if not session_id:
            return None
        user = yield self.application.redis.get_session(session_id)
        if not user:
            return None
        return user

    def set_session_cookie(self, session_id):
        self.set_secure_cookie(self.COOKIE_NAME, session_id)

    def get_token(self):
        token = self.request.headers.get('Authentication')
        if not token:
            return None
        match = TOKEN_RE.match(token)
        if not match:
            return None
        token_id = match.group(0)
        user = yield self.application.redis.get_token(token_id)
        if not user:
            return None
        return user

    def get_current_user(self):
        return self.get_user_from_cookie()


class RegistrationHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.USER_REGISTRATION)
        if not v.validate(self.json_args):
            raise web.HTTPError(400, json.dumps(v.errors))

        data = self.json_args.copy()
        data['password'] = make_password(data['password'])
        data['active'] = False
        try:
            yield self.application.db.insert('users', data)
        except db.errors.DuplicateKeyError:
            raise web.HTTPError(409, json.dumps({'error': 'Invalid username / email'}))

        # FIXME: send email with token and confirmation

        self.set_status(201)
        self.write(json.dumps({}))

    @gen.coroutine
    def get(self):
        v = Validator(validation.USER_REGISTRATION_CONFIRM)
        if not v.validate(self.json_args):
            raise web.HTTPError(400, json.dumps(v.errors))

        data = self.json_args
        user = yield self.application.db.get('users', {'email': data['email']})
        if not user:
            self.application.redis.clear_registration_token(data['registration_token'])
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        email = self.application.redis.get_registration_token_email(data['registration_token'])
        if not email or email != data['email']:
            self.application.redis.clear_registration_token(data['registration_token'])
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.update('users', {'email': data['email']}, {'active': True})

        self.application.redis.clear_registration_token(data['registration_token'])

        self.set_status(200)
        self.write(json.dumps({}))


class LoginHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.USER_LOGIN)
        if not v.validate(self.json_args):
            raise web.HTTPError(400, json.dumps(v.errors))

        # we already have a session for the user
        if self.get_user_from_cookie():
            self.set_status(200)
            self.write(json.dumps({}))
            return

        data = self.json_args
        user = yield self.application.db.get('users', {'username': data['username']})
        if not user:
            raise web.HTTPError(403, json.dumps({'error': 'Invalid username / password'}))

        login_valid = check_password(user['password'], data['password'])
        if not login_valid:
            raise web.HTTPError(403, json.dumps({'error': 'Invalid username / password'}))

        try:
            session_id = self.application.redis.create_session()
        except sessions.SessionCreationError:
            self.set_status(500)
            self.write(json.dumps({'error': 'Internal Server Error'}))
            return

        self.set_session_cookie(session_id)

        self.set_status(200)
        self.write(json.dumps({}))


class LogoutHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        session_id = self.get_secure_cookie(self.COOKIE_NAME)
        if not session_id:
            return None
        user = yield self.application.redis.get_session(session_id)
        yield self.application.redis.clear_session(session_id)


class UserHandler(ApiHandler):
    @web.authenticated
    @gen.coroutine
    def get(self, username):
        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))
        data = {
           'username': user['username'],
           'full_name': user['full_name'],
        }
        self.set_status(200)
        self.write(json.dumps(data))

    @web.authenticated
    @gen.coroutine
    def put(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        v = Validator(validation.USER_UPDATE)
        if not v.validate(self.json_args):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        user = yield self.application.db.update('users', {'username': username}, self.json_args)
        data = {
           'full_name': user['full_name'],
        }
        self.set_status(200)
        self.write(json.dumps(data))

    @web.authenticated
    @gen.coroutine
    def delete(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        v = Validator(validation.USER_DELETE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'username': username, 'email': data['email']})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        login_valid = check_password(user['password'], data['password'])
        if not login_valid:
            raise web.HTTPError(403, json.dumps({'error': 'Invalid username / password'}))

        # FIXME: do actual deletion

        self.set_status(204)


class PasswordResetRequestHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.PASSWORD_RESET_REQUEST)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'email': data['email']})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        try:
            token_id = self.application.redis.create_reset_token()
        except sessions.ResetTokenCreationError:
            self.set_status(500)
            self.write(json.dumps({'error': 'Internal Server Error'}))
            return

        # FIXME: send email confirmation with the token

        self.set_status(200)
        self.write(json.dumps({}))


class PasswordUpdateHandler(ApiHandler):
    @web.authenticated
    @gen.coroutine
    def put(self, username):
        v = Validator(validation.PASSWORD_UPDATE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'username': data['username']})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        password = make_password(data['password'])
        user = yield self.application.db.update('users', {'email': email}, {'password': password})

        self.set_status(200)


class PasswordResetHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.PASSWORD_RESET)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'email': data['email']})
        if user is None:
            self.application.redis.clear_reset_token(data['reset_token'])
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        email = self.application.redis.get_reset_token_email(data['reset_token'])
        if not email or email != data['email']:
            self.application.redis.clear_reset_token(data['reset_token'])
            raise web.HTTPError(400, json.dumps(v.errors))

        password = make_password(data['password'])
        user = yield self.application.db.update('users', {'email': email}, {'password': password})

        self.application.redis.clear_reset_token(data['reset_token'])

        self.set_status(200)


class TokenHandler(ApiHandler):
    @web.authenticated
    @gen.coroutine
    def get(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))
        self.set_status(200)
        self.write(json.dumps(user['tokens']))

    @web.authenticated
    @gen.coroutine
    def post(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        v = Validator(validation.TOKEN_CREATE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        try:
            token_id = self.application.redis.create_token()
        except sessions.TokenCreationError:
            self.set_status(500)
            self.write(json.dumps({'error': 'Internal Server Error'}))
            return

        token = {
             'description': data['description'],
             'token_id': token_id
        }

        tokens = user['tokens'] + [token]
        user = yield self.application.db.update('users', {'username': username}, {'tokens': tokens})
        self.set_status(200)
        self.write(json.dumps(token))

    @web.authenticated
    @gen.coroutine
    def delete(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        v = Validator(validation.TOKEN_DELETE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        tokens = [token for token in user['tokens'] if token['token_id'] != token_id]
        user = yield self.application.db.update('users', {'username': username}, {'tokens': tokens})

        yield self.application.redis.clear_token(token_id)

        self.set_status(204)


class IottlyApplication(web.Application):
    def __init__(self, handlers=None, default_host=None, transforms=None, **settings):
        super(IottlyApplication, self).__init__(handlers, default_host, transforms, **settings)
        self.db = db.Database(settings)
        self.redis = sessions.RedisStore(
            host=settings['REDIS_HOST'],
            port=settings['REDIS_PORT'],
            autoconnect=True,
            session_ttl=settings['SESSION_TTL']
        )


def make_app(override_settings=None):
    # app_settings = settings.to_dict()
    app_settings = {k: v for k, v in settings.__dict__.items() if k[0] != '_' and not ismodule(v)}
    if override_settings:
        app_settings.update(override_settings)
    return IottlyApplication([
        (r'/auth/register$', RegistrationHandler),
        (r'/auth/password/reset$', PasswordResetHandler),
        (r'/auth/password/reset/request$', PasswordResetRequestHandler),
        (r'/users/([\w_+\.\-])/token$', TokenHandler),
        (r'/users/([\w_+\.\-])$', UserHandler),
        (r'/users/([\w_+\.\-])/password/update$', PasswordUpdateHandler),
    ], **app_settings)


if __name__ == "__main__":
    app = make_app()
    app.listen(8523)
    logging.info(" [*] Listening on 0.0.0.0:8523")

    tornado.ioloop.IOLoop.current().start()
