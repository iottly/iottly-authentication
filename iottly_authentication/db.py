import mongomock
import motor

from pymongo import errors
from tornado import gen
from bson.objectid import ObjectId


class Database(object):
    def __init__(self, settings):
        if settings['MONGO_DB_MOCK']:
            self.db = mongomock.MongoClient()
        else:
            self.db = motor.MotorClient(settings['MONGO_DB_URL'])[settings['MONGO_DB_NAME']]

    @gen.coroutine
    def insert(self, collection_name, data):
        # FIXME: TypeError: 'Collection' object is not callable
        new_id = yield self.db[collection_name].insert_one(data)
        raise gen.Return(new_id)

    @gen.coroutine
    def get(self, collection_name, condition):
        # FIXME: TypeError: 'Collection' object is not callable
        result = yield self.db[collection_name].find_one(condition)
        raise gen.Return(result)
