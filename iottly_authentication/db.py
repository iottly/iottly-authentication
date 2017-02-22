import mongomock
import motor

from pymongo import errors
from tornado import gen
from bson.objectid import ObjectId


class Database(object):
    def __init__(self, settings):
        if settings['MONGO_DB_MOCK']:
            db = mongomock.MongoClient().db
        else:
            db = motor.MotorClient(settings['MONGO_DB_URL'])[settings['MONGO_DB_NAME']]

    def insert(self, collection_name, data):
        new_id = yield self.db[collection_name].insert_one(data)
        raise gen.Return(new_id)
