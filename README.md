# iottly-authentication
Authentication module for Iottly

## Handle authentication on other modules

For API called by user clients you have to implement something like this *get_current_user* for
your RequestHandler:

```
import tornadis

from tornado import gen, web

class MyHandler(web.requestHandler):
    @gen.coroutine
    def get_user_from_cookie(self):
        """
        Unpack the cookie to read the session_id then query redis to get the username
        associated with the session_id
        """
        settings = self.application.settings

        cookie_name = settings['AUTH_COOKIE_NAME']
        session_id = self.get_secure_cookie(cookie_name)
        if not session_id:
            return None
        session_id = session_id.decode('utf-8')
        session_key = 'iottly_auth_session_{}'.format(session_id)

        # you may want to cache this at application startup
        client = tornadis.Client(
            host=settings['REDIS_HOST'],
            port=settings['REDIS_PORT'],
            autoconnect=True,
            session_ttl=settings['SESSION_TTL'],
        )
        result = yield client.call('GET', session_key)
        if not result:
            return None
        username = result.decode('utf-8')
        if not username:
            return None
        return username

    def get_current_user(self):
        result = self.get_user_from_cookie()
        return result.result()
```

You can then use this decorator to check if the user is logged:

```
import functools
import json

from tornado import web


def user_authenticated(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            self.set_header('Content-Type', 'application/json')
            self.set_status(403)
            self.write(json.dumps({}))
            self.finish()
            return
        return method(self, *args, **kwargs)
    return wrapper
```
