import json

from iottly_authentication.main import make_app

from tornado.testing import AsyncHTTPTestCase


class TestIottlyAuthentication(AsyncHTTPTestCase):

    def get_app(self):
        settings = {
            'MONGO_DB_MOCK': True
        }
        return make_app(override_settings=settings)

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

    def test_user_registration(self):
        data = {
            'email': 'ciccio@pasticcio.it',
            'full_name': 'Ciccio Pasticcio',
            'username': 'cicciopasticcio',
            'password': 'password'
        }
        response = self.fetch('/auth/register', method='POST', body=json.dumps(data))
        self.assertEqual(response.code, 201)

        # duplicated username
        dup_data = data.copy()
        dup_data.update({
            'email': 'ciccio2@pasticcio.it',
        })
        response = self.fetch('/auth/register', method='POST', body=json.dumps(dup_data))
        self.assertEqual(response.code, 409)

        # duplicated email
        dup_data = data.copy()
        dup_data.update({
            'username': 'cicciopasticcio2',
        })
        response = self.fetch('/auth/register', method='POST', body=json.dumps(dup_data))
        self.assertEqual(response.code, 409)

    def test_get_user_data(self):
        data = {
        }
        response = self.fetch('/users/myusername', method='GET', body=json.dumps(data))
        self.assertEqual(response.code, 200)

    def test_update_user_data(self):
        data = {
        }
        response = self.fetch('/users/myusername', method='PUT', body=json.dumps(data))
        self.assertEqual(response.code, 200)

    def test_unregister_user(self):
        data = {
        }
        response = self.fetch('/users/myusername', method='DELETE', body=json.dumps(data))
        self.assertEqual(response.code, 204)

        # invalid username
        data = {
        }
        response = self.fetch('/users/myusername', method='DELETE', body=json.dumps(data))
        self.assertEqual(response.code, 400)
