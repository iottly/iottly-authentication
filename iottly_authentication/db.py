import mongomock
import motor

from concurrent.futures import Future
from pymongo import errors
from tornado import gen
from bson.objectid import ObjectId


class AsyncMongoMockDatabase(mongomock.database.Database):
    def get_collection(self, name, codec_options=None, read_preference=None,
                       write_concern=None):
        collection = self._collections.get(name)
        if collection is None:
            collection = self._collections[name] = AsyncMongoMockCollection(self, name)
        return collection


class AsyncMongoMockCollection(mongomock.collection.Collection):
    def futurize(self, result):
        future = Future()
        future.set_result(result)
        return future

    def insert_one(self, document):
        result = super(AsyncMongoMockCollection, self).insert_one(document)
        return self.futurize(result)

    def update_one(self, filter, update, upsert=False):
        result = super(AsyncMongoMockCollection, self).update_one(filter, update, upsert)
        return self.futurize(result)

    def find_one(self, filter=None, *args, **kwargs):
        result = super(AsyncMongoMockCollection, self).find_one(filter, *args, **kwargs)
        return self.futurize(result)


class Database(object):
    def __init__(self, settings):
        if settings['MONGO_DB_MOCK']:
            client = mongomock.MongoClient()
            self.db = AsyncMongoMockDatabase(client, settings['MONGO_DB_NAME'])
        else:
            client = motor.MotorClient(settings['MONGO_DB_URL'])
            self.db = client[settings['MONGO_DB_NAME']]

    @gen.coroutine
    def insert(self, collection_name, data):
        result = yield self.db[collection_name].insert_one(data)
        return result.inserted_id

    @gen.coroutine
    def get(self, collection_name, condition):
        result = yield self.db[collection_name].find_one(condition)
        return result

    @gen.coroutine
    def update(self, collection_name, condition, data):
        result = yield self.db[collection_name].update_one(condition, {'$set': data})
        return result
