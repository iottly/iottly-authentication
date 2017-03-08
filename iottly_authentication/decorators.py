import functools

from tornado import web


def user_authenticated(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            self.json_error(403, {})
            return
        return method(self, *args, **kwargs)
    return wrapper
