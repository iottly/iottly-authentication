import json
import logging
import re

import tornado.ioloop

from cerberus import Validator
from tornado import gen, web, autoreload
from tornadomail.backends.smtp import EmailBackend

from iottly_authentication import db, sessions, validation
from iottly_authentication.decorators import user_authenticated
from iottly_authentication.hashers import make_password, check_password
from iottly_authentication.settings import settings

logging.getLogger().setLevel(logging.INFO)

TOKEN_RE = re.compile(r'bearer (.{32})$', re.IGNORECASE)

# TODO:
# le coroutine non devono alzare eccezioni

class ApiHandler(web.RequestHandler):
    COOKIE_NAME = 'iottly-session-id'

    def prepare(self):
        if self.request.method not in ('GET', 'DELETE'):
            content_type = self.request.headers.get('Content-Type')
            if content_type and content_type == 'application/json':
                try:
                    self.json_args = json.loads(self.request.body.decode())
                except ValueError:
                    msg = {
                        'error': 'Invalid JSON'
                    }
                    logging.debug('{}: {}'.format('Invalid JSON', self.request.body))
                    self.json_error(400, msg)
                    return
            else:
                self.json_args = None

        self.set_header('Content-Type', 'application/json')

    def json_error(self, status_code, body):
        self.set_header('Content-Type', 'application/json')
        self.set_status(status_code)
        self.write(json.dumps(body))
        self.finish()

    @gen.coroutine
    def get_user_from_cookie(self):
        session_id = self.get_secure_cookie(self.COOKIE_NAME)
        if not session_id:
            return None
        session_id = session_id.decode('utf-8')
        user = yield self.application.redis.get_session(session_id)
        if not user:
            return None
        return user

    def set_session_cookie(self, session_id):
        self.set_secure_cookie(self.COOKIE_NAME, session_id)

    @gen.coroutine
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
        result = self.get_user_from_cookie()
        return result.result()


class RegistrationHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.USER_REGISTRATION)
        if not v.validate(self.json_args):
            self.json_error(400, v.errors)
            return

        data = self.json_args.copy()
        data['password'] = make_password(data['password'])
        data['active'] = False
        try:
            yield self.application.db.insert('users', data)
        except db.errors.DuplicateKeyError:
            self.json_error(409, {'error': 'Invalid username / email'})
            return

        try:
            token = yield self.application.redis.create_registration_token(data['email'])
        except sessions.RegistrationTokenCreationError:
            self.json_error(500, {'error': 'Internal Server Error'})
            return

        # FIXME: send email confirmation url

        self.set_status(201)
        self.write(json.dumps({}))

    @gen.coroutine
    def get(self):
        try:
            data = {
                'email': self.get_query_argument('email'),
                'registration_token': self.get_query_argument('registration_token'),
            }
        except web.MissingArgumentError:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        v = Validator(validation.USER_REGISTRATION_CONFIRM)
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        user = yield self.application.db.get('users', {'email': data['email']})
        if not user:
            yield self.application.redis.clear_registration_token(data['registration_token'])
            self.json_error(400, {'error': 'Invalid Request'})
            return

        email = yield self.application.redis.get_registration_token(data['registration_token'])
        if not email or email != data['email']:
            yield self.application.redis.clear_registration_token(data['registration_token'])
            self.json_error(400, {'error': 'Invalid Request'})
            return

        user = yield self.application.db.update('users', {'email': data['email']}, {'active': True})

        yield self.application.redis.clear_registration_token(data['registration_token'])

        self.set_status(200)
        self.write(json.dumps({}))


class LoginHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.USER_LOGIN)
        if not v.validate(self.json_args):
            self.json_error(400, v.errors)
            return

        # we already have a session for the user
        user = yield self.get_user_from_cookie()
        if user:
            self.set_status(200)
            self.write(json.dumps({}))
            return

        data = self.json_args
        user = yield self.application.db.get('users', {'username': data['username']})
        if not user:
            self.json_error(403, {'error': 'Invalid username / password'})
            return

        if not user['active']:
            self.json_error(403, {'error': 'Invalid username / password'})
            return

        login_valid = check_password(user['password'], data['password'])
        if not login_valid:
            self.json_error(403, {'error': 'Invalid username / password'})
            return

        try:
            session_id = yield self.application.redis.create_session(user['username'])
        except sessions.SessionCreationError:
            self.json_error(500, {'error': 'Internal Server Error'})
            return

        self.set_session_cookie(session_id)

        self.set_status(200)
        self.write(json.dumps({}))


class LogoutHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        session_id = self.get_secure_cookie(self.COOKIE_NAME)
        if not session_id:
            self.json_error(404, {'error': 'No session found'})
            return
        session_id = session_id.decode('utf-8')
        yield self.application.redis.clear_session(session_id)

        self.set_status(200)
        self.finish()


class SessionUserHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        data = self.json_args
        v = Validator(validation.USER_FROM_SESSION)
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        user = yield self.application.redis.get_session(data['session_id'])
        if not user:
            self.json_error(404, {'error': 'No session found'})
            return

        self.set_status(200)
        self.write(json.dumps({'user': user}))


class UserHandler(ApiHandler):
    @user_authenticated
    @gen.coroutine
    def put(self, username):
        if self.current_user != username:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        v = Validator(validation.USER_UPDATE)
        if not v.validate(self.json_args):
            self.json_error(400, v.errors)
            return

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        yield self.application.db.update('users', {'username': username}, self.json_args)
        self.set_status(200)
        self.write(json.dumps({}))

    @user_authenticated
    @gen.coroutine
    def delete(self, username):
        if self.current_user != username:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        # FIXME: do actual deletion

        self.set_status(204)
        self.finish()


class PasswordResetRequestHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.PASSWORD_RESET_REQUEST)
        data = self.json_args
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        user = yield self.application.db.get('users', {'email': data['email']})
        if user is None:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        try:
            token_id = yield self.application.redis.create_reset_token(data['email'])
        except sessions.ResetTokenCreationError:
            self.json_error(500, {'error': 'Internal Server Error'})
            return

        # FIXME: send email confirmation with the token

        self.set_status(200)
        self.write(json.dumps({}))


class PasswordUpdateHandler(ApiHandler):
    @user_authenticated
    @gen.coroutine
    def put(self, username):
        if self.current_user != username:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        v = Validator(validation.PASSWORD_UPDATE)
        data = self.json_args
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            self.json_error(400, {'error': 'Invalid Request'})
            return

        password = make_password(data['password'])
        yield self.application.db.update('users', {'username': username}, {'password': password})

        self.set_status(200)
        self.write(json.dumps({}))


class PasswordResetHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.PASSWORD_RESET)
        data = self.json_args
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        user = yield self.application.db.get('users', {'email': data['email']})
        if user is None:
            yield self.application.redis.clear_reset_token(data['reset_token'])
            self.json_error(400, {'error': 'Invalid Request'})
            return

        email = yield self.application.redis.get_reset_token(data['reset_token'])
        if not email or email != data['email']:
            yield self.application.redis.clear_reset_token(data['reset_token'])
            self.json_error(400, {'error': 'Invalid Request'})
            return

        password = make_password(data['password'])
        user = yield self.application.db.update('users', {'email': email}, {'password': password})

        yield self.application.redis.clear_reset_token(data['reset_token'])

        self.set_status(200)
        self.write(json.dumps({}))


class TokenCreateHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.TOKEN_CREATE)
        data = self.json_args
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        try:
            token_id = yield self.application.redis.create_token(data['project'])
        except sessions.TokenCreationError:
            self.json_error(500, {'error': 'Internal Server Error'})
            return

        token = {
             'project': data['project'],
             'token_id': token_id
        }

        self.set_status(201)
        self.write(json.dumps(token))


class TokenDeleteHandler(ApiHandler):
    @gen.coroutine
    def delete(self, project, token_id):
        v = Validator(validation.TOKEN_DELETE)
        data = {
            'token_id': token_id,
            'project': project
        }
        if not v.validate(data):
            self.json_error(400, v.errors)
            return

        token_value = yield self.application.redis.get_token(token_id)
        if not token_value or token_value != project:
            self.json_error(400, {'error': 'Invalid Request'})
            return
        yield self.application.redis.clear_token(token_id)

        self.set_status(204)
        self.finish()


class SessionTestHandler(web.RequestHandler):
    @gen.coroutine
    def get(self):
        token_id = yield self.application.redis.create_token('foo')
        token_value = yield self.application.redis.get_token(token_id)
        yield self.application.redis.clear_token(token_id.result())

        token_id = yield self.application.redis.create_reset_token('foo')
        token_value = yield self.application.redis.get_reset_token(token_id)
        yield self.application.redis.clear_reset_token(token_id.result())

        session_id = yield self.application.redis.create_session('foo')
        token_value = yield self.application.redis.get_session(session_id)
        yield self.application.redis.clear_session(session_id.result())

        token = yield self.application.redis.create_registration_token('foo')
        token_value = yield self.application.redis.get_registration_token(token)
        yield self.application.redis.clear_registration_token(token.result())

        self.set_status(200)
        self.finish()


class IottlyApplication(web.Application):
    def __init__(self, handlers=None, default_host=None, transforms=None, **settings):
        tornado_settings = {
            'cookie_secret': settings['COOKIE_SECRET'],
            'debug': settings['debug']
        }
        super(IottlyApplication, self).__init__(handlers, default_host, transforms, **tornado_settings)
        self.db = db.Database(settings)
        self.redis = sessions.RedisStore(
            host=settings['REDIS_HOST'],
            port=settings['REDIS_PORT'],
            autoconnect=True,
            session_ttl=settings['SESSION_TTL']
        )
        self.mail = EmailBackend(
            settings['SMTP_HOST'],
            settings['SMTP_PORT'],
            settings['SMTP_USER'],
            settings['SMTP_PASSWORD'],
            True
        )

def shutdown():
    pass

def make_app():
    autoreload.add_reload_hook(shutdown)
    app_settings = settings.to_dict()

    return IottlyApplication([
        (r'/auth/login$', LoginHandler),
        (r'/auth/logout$', LogoutHandler),
        (r'/auth/password/reset$', PasswordResetHandler),
        (r'/auth/password/reset/request$', PasswordResetRequestHandler),
        (r'/auth/register$', RegistrationHandler),
        (r'/auth/users/([\w_\+\.\-]+)$', UserHandler),
        (r'/auth/users/([\w_\+\.\-]+)/password/update$', PasswordUpdateHandler),
        (r'/user$', SessionUserHandler),
        (r'/projects/token$', TokenCreateHandler),
        (r'/projects/([\w_\+\.\-]+)/token/(\w+)$', TokenDeleteHandler),
    ], **app_settings)


if __name__ == "__main__":
    app = make_app()
    app.listen(8523)
    logging.info(" [*] Listening on 0.0.0.0:8523")

    tornado.ioloop.IOLoop.current().start()
