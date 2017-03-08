import json

from concurrent.futures import Future
from unittest import TestCase, mock

from iottly_authentication import db, main
from iottly_authentication.hashers import make_password, check_password

from tornado.httputil import url_concat
from tornado.testing import AsyncHTTPTestCase


class TestIottlyAuthentication(AsyncHTTPTestCase):
    HASHED_PASSWORD = '$argon2i$v=19$m=512,t=2,p=2$x5nO2dG9+gqmVFy8k5ICiA$pArlNSVHW3Hr+Gy9IqIyyg'
    SESSION_TOKEN = 'f9bf78b9a18ce6d46a0cd2b0b86df9da'

    def get_app(self):
        settings = {
            'MONGO_DB_MOCK': True,
            'MONGO_DB_NAME': 'testdb',
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': 12345,
            'SESSION_TTL': '10',
            'COOKIE_SECRET': 'secret',
            'SMTP_MOCK': True,
            'SMTP_HOST': 'localhost',
            'SMTP_PORT': 587,
            'SMTP_USER': None,
            'SMTP_PASSWORD': None,
            'FROM_EMAIL': 'foo@bar.it',
            'AUTH_COOKIE_NAME': 'testcookie',
            'debug': False,
            'PUBLIC_HOST': '127.0.0.1',
            'PUBLIC_URL_PATTERN': 'http://{}',
            'REGISTRATION_CONFIRM_PATH': '/auth/register',
            'RESET_PASSWORD_PATH': '/auth/password/reset',
        }
        return main.IottlyApplication([
            (r'/auth/login$', main.LoginHandler),
            (r'/auth/logout$', main.LogoutHandler),
            (r'/auth/password/reset$', main.PasswordResetHandler),
            (r'/auth/password/reset/request$', main.PasswordResetRequestHandler),
            (r'/auth/register$', main.RegistrationHandler),
            (r'/auth/register2$', main.Registration2StepsHandler),
            (r'/auth/users/([\w_\+\.\-]+)$', main.UserHandler),
            (r'/auth/users/([\w_\+\.\-]+)/password/update$', main.PasswordUpdateHandler),
            (r'/auth/users/([\w_\+\.\-]+)/password/set$', main.Password2StepsHandler),
            (r'/projects/token$', main.TokenCreateHandler),
            (r'/projects/([\w_\+\.\-]+)/token/(\w+)$', main.TokenDeleteHandler),
        ], **settings)

    def get_db(self):
        return self._app.db

    def fetch(self, *args, **kwargs):
        try:
            headers = kwargs.pop('headers')
            try:
                headers['Content-Type']
            except KeyError:
                headers['Content-Type'] = 'application/json'
        except KeyError:
            headers = {'Content-Type': 'application/json'}
        kwargs.update({'headers': headers})
        return super(TestIottlyAuthentication, self).fetch(*args, **kwargs)

    def insert_valid_user(self, db):
        db.insert('users', {
            'email': 'ciccio@pasticcio.it',
            'full_name': 'Ciccio Pasticcio',
            'username': 'cicciopasticcio',
            'password': self.HASHED_PASSWORD,
            'active': True
        })

    def test_user_registration(self):
        data = {
            'email': 'ciccio@pasticcio.it',
            'full_name': 'Ciccio Pasticcio',
            'username': 'cicciopasticcio',
            'password': 'password'
        }

        session_id, send = Future(), Future()
        session_id.set_result(self.SESSION_TOKEN)
        send.set_result(None)
        with mock.patch.object(self._app.redis, 'create_registration_token', return_value=session_id) as create_token:
            response = self.fetch('/auth/register', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 201)
        create_token.assert_called_once_with(data['email'])

        # duplicated username
        dup_data = data.copy()
        dup_data.update({
            'email': 'ciccio2@pasticcio.it',
        })
        with mock.patch.object(self._app.db, 'insert', side_effect=db.errors.DuplicateKeyError('')):
            response = self.fetch('/auth/register', method='POST', body=json.dumps(dup_data))
        self.assertEqual(response.code, 409)
        self.assertEqual(response.headers['Content-Type'], 'application/json')

        # duplicated email
        dup_data = data.copy()
        dup_data.update({
            'username': 'cicciopasticcio2',
        })
        with mock.patch.object(self._app.db, 'insert', side_effect=db.errors.DuplicateKeyError('')):
            response = self.fetch('/auth/register', method='POST', body=json.dumps(dup_data))
        self.assertEqual(response.code, 409)

    def test_user_registration2(self):
        data = {
            'email': 'ciccio@pasticcio.it',
            'full_name': 'Ciccio Pasticcio',
            'username': 'cicciopasticcio',
        }

        session_id, send = Future(), Future()
        session_id.set_result(self.SESSION_TOKEN)
        send.set_result(None)
        with mock.patch.object(self._app.redis, 'create_registration_token', return_value=session_id) as create_token:
            response = self.fetch('/auth/register2', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 201)
        create_token.assert_called_once_with(data['email'])

        # duplicated username
        dup_data = data.copy()
        dup_data.update({
            'email': 'ciccio2@pasticcio.it',
        })
        with mock.patch.object(self._app.db, 'insert', side_effect=db.errors.DuplicateKeyError('')):
            response = self.fetch('/auth/register2', method='POST', body=json.dumps(dup_data))
        self.assertEqual(response.code, 409)
        self.assertEqual(response.headers['Content-Type'], 'application/json')

        # duplicated email
        dup_data = data.copy()
        dup_data.update({
            'username': 'cicciopasticcio2',
        })
        with mock.patch.object(self._app.db, 'insert', side_effect=db.errors.DuplicateKeyError('')):
            response = self.fetch('/auth/register2', method='POST', body=json.dumps(dup_data))
        self.assertEqual(response.code, 409)

    def test_user_registration_confirm(self):
        base_url = '/auth/register'
        params = {'email': 'ciccio@pasticcio.it', 'registration_token': self.SESSION_TOKEN}
        url = url_concat(base_url, params)

        user, email, clear = Future(), Future(), Future()
        user.set_result({'email': 'ciccio@pasticcio.it'})
        email.set_result('ciccio@pasticcio.it')
        clear.set_result(True)
        with mock.patch.object(self._app.db, 'get', return_value=user):
            with mock.patch.object(self._app.redis, 'get_registration_token', return_value=email):
                with mock.patch.object(self._app.redis, 'clear_registration_token', return_value=clear) as clear_token:
                    response = self.fetch(url, method='GET')
        self.assertEqual(response.code, 200)
        clear_token.assert_called_once_with(self.SESSION_TOKEN)

    def test_user_login(self):
        db = self.get_db()
        self.insert_valid_user(db)
        data = {
            'username': 'cicciopasticcio',
            'password': 'password',
        }
        session_id = Future()
        session_id.set_result(self.SESSION_TOKEN)
        with mock.patch.object(self._app.redis, 'create_session', return_value=session_id):
            response = self.fetch('/auth/login', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 201)

    def test_user_login_already_logged(self):
        db = self.get_db()
        self.insert_valid_user(db)
        data = {
            'username': 'cicciopasticcio',
            'password': 'password',
        }
        user = Future()
        user.set_result('cicciopasticcio')
        with mock.patch.object(main.LoginHandler, 'get_user_from_cookie', return_value=user):
            response = self.fetch('/auth/login', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 200)

    def test_user_login_invalid_user(self):
        data = {
            'username': 'anotherusername',
            'password': 'password',
        }
        response = self.fetch('/auth/login', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 403)

    def test_user_login_inactive_user(self):
        db = self.get_db()
        db.insert('users', {
            'email': 'inactive@pasticcio.it',
            'full_name': 'Inactive Pasticcio',
            'username': 'inactivepasticcio',
            'password': self.HASHED_PASSWORD,
            'active': False
        })
        data = {
            'username': 'inactivepasticcio',
            'password': 'password',
        }
        response = self.fetch('/auth/login', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 403)

    def test_user_logout_unauthenticated(self):
        response = self.fetch('/auth/logout', method='POST', body=json.dumps({}))
        self.assertEqual(response.code, 404)

    def test_user_logout(self):
        clear = Future()
        clear.set_result(True)
        cookie = self.SESSION_TOKEN.encode('utf-8')
        with mock.patch.object(main.LogoutHandler, 'get_secure_cookie', return_value=cookie):
            with mock.patch.object(self._app.redis, 'clear_session', return_value=clear) as clear_session:
                response = self.fetch('/auth/logout', method='POST', body=json.dumps({}))
        self.assertEqual(response.code, 200)
        clear_session.assert_called_once_with(self.SESSION_TOKEN)

    def test_update_user_data(self):
        db = self.get_db()
        self.insert_valid_user(db)

        data = {
            'full_name': 'my new full name'
        }
        with mock.patch.object(main.UserHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/cicciopasticcio', method='PUT', body=json.dumps(data))
        self.assertEqual(response.code, 200)

        with mock.patch.object(main.UserHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/myusername', method='PUT', body=json.dumps(data))
        self.assertEqual(response.code, 400)

    def test_delete_user(self):
        db = self.get_db()
        self.insert_valid_user(db)

        with mock.patch.object(main.UserHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/cicciopasticcio', method='DELETE')
        self.assertEqual(response.code, 204)

    def test_delete_user_twice(self):
        db = self.get_db()
        self.insert_valid_user(db)

        with mock.patch.object(main.UserHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/cicciopasticcio', method='DELETE')
        self.assertEqual(response.code, 204)

        # already deleted
        empty_user = Future()
        empty_user.set_result(None)
        with mock.patch.object(main.UserHandler, 'get_current_user', return_value='cicciopasticcio'):
            with mock.patch.object(self._app.db, 'get', return_value=empty_user):
                response = self.fetch('/auth/users/cicciopasticcio', method='DELETE')
        self.assertEqual(response.code, 400)

    def test_delete_another_user(self):
        with mock.patch.object(main.UserHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/anotheruser', method='DELETE')
        self.assertEqual(response.code, 400)

    def test_password_reset_request_no_user(self):
        data = {
            'email': 'ciccio@pasticcio.it'
        }
        response = self.fetch('/auth/password/reset/request', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 400)

    def test_password_reset_request(self):
        db = self.get_db()
        self.insert_valid_user(db)

        data = {
            'email': 'ciccio@pasticcio.it'
        }
        session_id = Future()
        session_id.set_result(self.SESSION_TOKEN)
        with mock.patch.object(self._app.redis, 'create_reset_token', return_value=session_id) as create_reset:
            response = self.fetch('/auth/password/reset/request', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 200)
        create_reset.assert_called_once_with(data['email'])

    def test_password_reset_no_user(self):
        data = {
            'email': 'ciccio@pasticcio.it',
            'password': 'newpassword',
            'reset_token': self.SESSION_TOKEN,
        }
        clear = Future()
        clear.set_result(True)
        with mock.patch.object(self._app.redis, 'clear_reset_token', return_value=clear) as clear_token:
            response = self.fetch('/auth/password/reset', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 400)
        clear_token.assert_called_once_with(self.SESSION_TOKEN)

    def test_password_reset(self):
        data = {
            'email': 'ciccio@pasticcio.it',
            'password': 'newpassword',
            'reset_token': self.SESSION_TOKEN,
        }
        user, email, clear = Future(), Future(), Future()

        user.set_result({'email': 'ciccio@pasticcio.it'})
        email.set_result('ciccio@pasticcio.it')
        clear.set_result(True)
        with mock.patch.object(self._app.db, 'get', return_value=user):
            with mock.patch.object(self._app.redis, 'get_reset_token', return_value=email):
                with mock.patch.object(self._app.redis, 'clear_reset_token', return_value=clear) as clear_token:
                    response = self.fetch('/auth/password/reset', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 200)
        clear_token.assert_called_once_with(self.SESSION_TOKEN)

    def test_password_update(self):
        db = self.get_db()
        self.insert_valid_user(db)

        data = {
            'password': 'newpassword'
        }
        with mock.patch.object(main.PasswordUpdateHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/cicciopasticcio/password/update', method='PUT', body=json.dumps(data))
        self.assertEqual(response.code, 200)

    def test_password_update_different_user(self):
        data = {
            'password': 'newpassword'
        }
        with mock.patch.object(main.PasswordUpdateHandler, 'get_current_user', return_value='cicciopasticcio'):
            response = self.fetch('/auth/users/anotheruser/password/update', method='PUT', body=json.dumps(data))
        self.assertEqual(response.code, 400)

    def test_password_update_no_user(self):
        data = {
            'password': 'newpassword'
        }
        with mock.patch.object(main.PasswordUpdateHandler, 'get_current_user', return_value='anotheruser'):
            response = self.fetch('/auth/users/anotheruser/password/update', method='PUT', body=json.dumps(data))
        self.assertEqual(response.code, 400)

    def test_password_two_steps_set(self):
        db = self.get_db()
        self.insert_valid_user(db)

        data = {
            'password': 'newpassword',
            'registration_token': self.SESSION_TOKEN
        }
        email, clear = Future(), Future()
        email.set_result('ciccio@pasticcio.it')
        clear.set_result(None)
        with mock.patch.object(self._app.redis, 'get_registration_token', return_value=email):
            with mock.patch.object(self._app.redis, 'clear_registration_token', return_value=clear) as clear_token:
                response = self.fetch('/auth/users/cicciopasticcio/password/set', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 200)
        clear_token.assert_called_once_with(data['registration_token'])

    def test_password_two_steps_set_no_user(self):
        data = {
            'password': 'newpassword',
            'registration_token': self.SESSION_TOKEN
        }
        response = self.fetch('/auth/users/anotheruser/password/set', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 400)

    def test_password_two_steps_invalid_token(self):
        db = self.get_db()
        self.insert_valid_user(db)

        data = {
            'password': 'newpassword',
            'registration_token': self.SESSION_TOKEN
        }
        email, clear = Future(), Future()
        email.set_result(None)
        clear.set_result(None)
        with mock.patch.object(self._app.redis, 'get_registration_token', return_value=email):
            with mock.patch.object(self._app.redis, 'clear_registration_token', return_value=clear) as clear_token:
                response = self.fetch('/auth/users/cicciopasticcio/password/set', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 400)

    def test_token_handler_create(self):
        data = {
            'project': 'myprojecthashsupposedly',
        }
        token = Future()
        token.set_result('myprojecthashsupposedly')
        with mock.patch.object(self._app.redis, 'create_token', return_value=token):
            response = self.fetch('/projects/token', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 201)

        response = self.fetch('/projects/token', method='POST', body=json.dumps({}))
        self.assertEqual(response.code, 400)

    def test_token_handler_delete(self):
        clear, token, invalid_token = Future(), Future(), Future()
        clear.set_result(True)
        token.set_result('myprojecthashsupposedly')
        invalid_token.set_result('anotherprojecthash')
        url = '/projects/myprojecthashsupposedly/token/f9bf78b9a18ce6d46a0cd2b0b86df9da'
        with mock.patch.object(self._app.redis, 'get_token', return_value=token):
            with mock.patch.object(self._app.redis, 'clear_token', return_value=clear) as clear_token:
                response = self.fetch(url, method='DELETE')
        self.assertEqual(response.code, 204)
        clear_token.assert_called_once_with('f9bf78b9a18ce6d46a0cd2b0b86df9da')

        with mock.patch.object(self._app.redis, 'get_token', return_value=invalid_token):
            response = self.fetch(url, method='DELETE')
        self.assertEqual(response.code, 400)


class HashersTestCase(TestCase):
    def test_password_hashing(self):
        hashed = make_password('mypassword')
        self.assertTrue(hashed)
        self.assertTrue(check_password(hashed, 'mypassword'))
        self.assertFalse(check_password(hashed, 'anotherpassword'))

        another_hashed = make_password('anotherpassword')
        self.assertNotEqual(hashed, another_hashed)
