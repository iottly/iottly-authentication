import json
import logging
import re

import tornado.ioloop

from inspect import ismodule

from cerberus import Validator
from tornado import gen, web

from . import db, sessions, validation
from .decorators import user_authenticated
from .hashers import make_password, check_password
from .settings import settings


TOKEN_RE = re.compile(r'bearer (.{32})$', re.IGNORECASE)

# TODO:
# per scrivere su mongo forse passiamo per api
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
                    raise web.HTTPError(400, json.dumps(msg))
            else:
                self.json_args = None

        self.set_header("Content-Type", "application/json")

    @gen.coroutine
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
            raise web.HTTPError(400, json.dumps(v.errors))

        data = self.json_args.copy()
        data['password'] = make_password(data['password'])
        data['active'] = False
        try:
            yield self.application.db.insert('users', data)
        except db.errors.DuplicateKeyError:
            raise web.HTTPError(409, json.dumps({'error': 'Invalid username / email'}))

        try:
            token = yield self.application.redis.create_registration_token(data['email'])
        except sessions.RegistrationTokenCreationError:
            raise web.HTTPError(500, json.dumps({'error': 'Internal Server Error'}))

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
            raise web.HTTPError(400, json.dumps({'error': 'Invalid Request'}))

        v = Validator(validation.USER_REGISTRATION_CONFIRM)
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'email': data['email']})
        if not user:
            yield self.application.redis.clear_registration_token(data['registration_token'])
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        email = yield self.application.redis.get_registration_token(data['registration_token'])
        if not email or email != data['email']:
            yield self.application.redis.clear_registration_token(data['registration_token'])
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.update('users', {'email': data['email']}, {'active': True})

        yield self.application.redis.clear_registration_token(data['registration_token'])

        self.set_status(200)
        self.write(json.dumps({}))


class LoginHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        v = Validator(validation.USER_LOGIN)
        if not v.validate(self.json_args):
            raise web.HTTPError(400, json.dumps(v.errors))

        # we already have a session for the user
        user = yield self.get_user_from_cookie()
        if user:
            self.set_status(200)
            self.write(json.dumps({}))
            return

        data = self.json_args
        user = yield self.application.db.get('users', {'username': data['username']})
        if not user:
            raise web.HTTPError(403, json.dumps({'error': 'Invalid username / password'}))

        if not user['active']:
            raise web.HTTPError(403, json.dumps({'error': 'User is not active'}))

        login_valid = check_password(user['password'], data['password'])
        if not login_valid:
            raise web.HTTPError(403, json.dumps({'error': 'Invalid username / password'}))

        try:
            session_id = yield self.application.redis.create_session(user['username'])
        except sessions.SessionCreationError:
            raise web.HTTPError(500, json.dumps({'error': 'Internal Server Error'}))

        self.set_session_cookie(session_id)

        self.set_status(200)
        self.write(json.dumps({}))


class LogoutHandler(ApiHandler):
    @gen.coroutine
    def post(self):
        session_id = self.get_secure_cookie(self.COOKIE_NAME)
        if not session_id:
            return None
        yield self.application.redis.clear_session(session_id)

        self.set_status(200)
        self.finish()


class UserHandler(ApiHandler):
    @user_authenticated
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

    @user_authenticated
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

        yield self.application.db.update('users', {'username': username}, self.json_args)
        self.set_status(200)
        self.write(json.dumps({}))

    @user_authenticated
    @gen.coroutine
    def delete(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        # FIXME: do actual deletion

        self.set_status(204)
        self.finish()


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
            token_id = yield self.application.redis.create_reset_token(data['email'])
        except sessions.ResetTokenCreationError:
            raise web.HTTPError(500, json.dumps({'error': 'Internal Server Error'}))

        # FIXME: send email confirmation with the token

        self.set_status(200)
        self.write(json.dumps({}))


class PasswordUpdateHandler(ApiHandler):
    @user_authenticated
    @gen.coroutine
    def put(self, username):
        if self.current_user != username:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        v = Validator(validation.PASSWORD_UPDATE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'username': username})
        if user is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

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
            raise web.HTTPError(400, json.dumps(v.errors))

        user = yield self.application.db.get('users', {'email': data['email']})
        if user is None:
            yield self.application.redis.clear_reset_token(data['reset_token'])
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        email = yield self.application.redis.get_reset_token(data['reset_token'])
        if not email or email != data['email']:
            yield self.application.redis.clear_reset_token(data['reset_token'])
            raise web.HTTPError(400, json.dumps(v.errors))

        password = make_password(data['password'])
        user = yield self.application.db.update('users', {'email': email}, {'password': password})

        yield self.application.redis.clear_reset_token(data['reset_token'])

        self.set_status(200)
        self.write(json.dumps({}))


class TokenHandler(ApiHandler):
    @gen.coroutine
    def _get_project(self, project_name):
        project = yield self.application.db.get('projects', {'name': project_name})
        return project

    @gen.coroutine
    def _update_project_tokens(self, project_name, token):
        yield self.application.db.update('projects', {'name': project_name}, {'tokens': tokens})

    @user_authenticated
    @gen.coroutine
    def get(self, project_name):
        # TODO: check that the user has proper rights for the project
        project = self._get_project(project_name)
        if project is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        self.set_status(200)
        self.write(json.dumps(project['tokens']))

    @user_authenticated
    @gen.coroutine
    def post(self, project_name):
        # TODO: check that the user has proper rights for the project
        v = Validator(validation.TOKEN_CREATE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        project = self._get_project(project_name)
        if project is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        try:
            token_id = yield self.application.redis.create_token()
        except sessions.TokenCreationError:
            raise web.HTTPError(500, json.dumps({'error': 'Internal Server Error'}))

        token = {
             'description': data['description'],
             'token_id': token_id
        }

        tokens = user['tokens'] + [token]
        yield self._update_project_tokens(project_name, tokens)
        self.set_status(200)
        self.write(json.dumps(token))

    @user_authenticated
    @gen.coroutine
    def delete(self, username):
        # TODO: check that the user has proper rights for the project
        v = Validator(validation.TOKEN_DELETE)
        data = self.json_args
        if not v.validate(data):
            raise web.HTTPError(400, json.dumps(v.errors))

        project = self._get_project(project_name)
        if project is None:
            raise web.HTTPError(400, json.dumps({'error': 'Invalid request'}))

        tokens = [token for token in project['tokens'] if token['token_id'] != token_id]
        yield self._update_project_tokens(project_name, tokens)

        yield self.application.redis.clear_token(token_id)

        self.set_status(204)
        self.finish()

class IottlyApplication(web.Application):
    def __init__(self, handlers=None, default_host=None, transforms=None, **settings):
        tornado_settings = {
            'cookie_secret': settings['COOKIE_SECRET']
        }
        super(IottlyApplication, self).__init__(handlers, default_host, transforms, **tornado_settings)
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
        (r'/auth/login$', LoginHandler),
        (r'/auth/logout$', LogoutHandler),
        (r'/auth/password/reset$', PasswordResetHandler),
        (r'/auth/password/reset/request$', PasswordResetRequestHandler),
        (r'/auth/projects/([\w_\+\.\-]+)/token$', TokenHandler),
        (r'/auth/register$', RegistrationHandler),
        (r'/auth/users/([\w_\+\.\-]+)$', UserHandler),
        (r'/auth/users/([\w_\+\.\-]+)/password/update$', PasswordUpdateHandler),
    ], **app_settings)


if __name__ == "__main__":
    app = make_app()
    app.listen(8523)
    logging.info(" [*] Listening on 0.0.0.0:8523")

    tornado.ioloop.IOLoop.current().start()
