from tornado import gen, web


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
