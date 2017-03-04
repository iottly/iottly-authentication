from iottly_authentication import main
from iottly_authentication.settings import settings
from iottly_authentication.tests import testhandlers

from tornado.testing import AsyncHTTPTestCase


class TestIottlyAuthenticationSession(AsyncHTTPTestCase): 
    def get_app(self): 
        app_settings = settings.to_dict()
        app_settings['MONGO_DB_MOCK'] = True
        app_settings['MONGO_DB_NAME'] = 'testdb'
        return main.IottlyApplication([ 
            (r'/$', testhandlers.SessionTestHandler), 
        ], **app_settings)

    def test_session_handler(self):
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 200)
