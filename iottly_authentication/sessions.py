import tornadis

from concurrent.futures import Future
from tornado import gen

from iottly_authentication import secrets


class RegistrationTokenCreationError(Exception):
    pass


class SessionCreationError(Exception):
    pass


class ResetTokenCreationError(Exception):
    pass


class TokenCreationError(Exception):
    pass


class RedisStore:
    TOKEN_BUCKET_KEY = 'iottly_auth_token_bucket'
    SESSION_BUCKET_KEY = 'iottly_auth_session_bucket'
    RESET_PASSWORD_BUCKET_KEY = 'iottly_auth_reset_password_bucket'
    REGISTRATION_BUCKET_KEY = 'iottly_auth_registration_bucket'

    RESET_PASSWORD_TTL = 60 * 60
    REGISTRATION_TOKEN_TTL = 24 * 60 * 60

    def __init__(self, **kwargs):
        try:
            ttl = kwargs.pop('session_ttl')
        except KeyError:
            ttl = 30 * 24 * 60 * 60
        self.client = tornadis.Client(**kwargs)
        self.session_ttl = ttl

    @gen.coroutine
    def set(self, key, value, ttl):
        args = ['SET', key, value]
        if ttl > 0:
            args += ['EX', ttl]
        result = yield self.client.call(*args)
        return result

    @gen.coroutine
    def get(self, key):
        result = yield self.client.call('GET', key)
        return result

    @gen.coroutine
    def delete(self, key):
        result = yield self.client.call('DEL', key)
        return result

    # WEB CLIENTS SESSIONS

    def get_session_key(self, session_id):
        return 'iottly_auth_session_'.format(session_id)

    @gen.coroutine
    def create_session(self, session_value):
        for i in range(3):
            session_id = secrets.token_hex(16)
            result = yield self.client.call('SADD', self.SESSION_BUCKET_KEY, session_id)
            if result:
                break
        if not result:
            raise SessionCreationError
        key = self.get_session_key(session_id)
        yield self.set(key, session_value, self.session_ttl)
        return session_id

    @gen.coroutine
    def get_session(self, session_id):
        key = self.get_session_key(session_id)
        result = yield self.get(key)
        return result

    @gen.coroutine
    def clear_session(self, session_id):
        key = self.get_session_key(session_id)
        yield self.delete(key)
        yield self.client.call('SREM', self.SESSION_BUCKET_KEY, session_id)
        return True

    # REGISTRATION TOKEN

    def get_registration_key(self, token_id):
        return 'iottly_auth_registration_token_'.format(token_id)

    @gen.coroutine
    def create_registration_token(self, email):
        for i in range(3):
            token_id = secrets.token_urlsafe(16)
            result = yield self.client.call('SADD', self.REGISTRATION_BUCKET_KEY, token_id)
            if result:
                break
        if not result:
            raise RegistrationTokenCreationError
        key = self.get_registration_key(token_id)
        yield self.set(key, email, self.REGISTRATION_TOKEN_TTL)
        return token_id

    @gen.coroutine
    def get_registration_token(self, token_id):
        key = self.get_registration_key(token_id)
        result = yield self.get(key)
        return result

    @gen.coroutine
    def clear_registration_token(self, token_id):
        key = self.get_registration_key(token_id)
        yield self.delete(key)
        yield self.client.call('SREM', self.REGISTRATION_BUCKET_KEY, token_id)
        return True

    # RESET PASSWORD

    def get_reset_password_key(self, token_id):
        return 'iottly_auth_reset_token_'.format(token_id)

    @gen.coroutine
    def create_reset_token(self, email):
        for i in range(3):
            token_id = secrets.token_hex(16)
            result = yield self.client.call('SADD', self.RESET_PASSWORD_BUCKET_KEY, token_id)
            if result:
                break
        if not result:
            raise ResetTokenCreationError
        key = self.get_reset_password_key(token_id)
        yield self.set(key, email, self.RESET_PASSWORD_TTL)
        return token_id

    @gen.coroutine
    def get_reset_token(self, token_id):
        key = self.get_reset_password_key(token_id)
        result = yield self.get(key)
        return result

    @gen.coroutine
    def clear_reset_token(self, token_id):
        key = self.get_reset_password_key(token_id)
        yield self.delete(key)
        yield self.client.call('SREM', self.RESET_PASSWORD_BUCKET_KEY, token_id)
        return True

    # APPLICATIONS TOKENS

    def get_token_key(self, token_id):
        return 'iottly_auth_token_'.format(token_id)

    @gen.coroutine
    def create_token(self, token_value):
        for i in range(3):
            token_id = secrets.token_hex(16)
            result = yield self.client.call('SADD', self.TOKEN_BUCKET_KEY, token_id)
            if result:
                break
        if not result:
            raise TokenCreationError
        key = self.get_token_key(token_id)
        yield self.set(key, token_value, -1)
        return token_id

    @gen.coroutine
    def get_token(self, token_id):
        key = self.get_token_key(token_id)
        result = yield self.get(key)
        return result

    @gen.coroutine
    def clear_token(self, token_id):
        key = self.get_token_key(token_id)
        yield self.delete(key)
        yield self.client.call('SREM', self.TOKEN_BUCKET_KEY, token_id)
        return True
