import functools

from tornado import web


def user_authenticated(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            raise web.HTTPError(403)
        return method(self, *args, **kwargs)
    return wrapper
