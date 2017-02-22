import prettysettings


defaults = dict(
    # MongoDB settings
    MONGO_DB_URL = 'mongodb://db:27017/',
    MONGO_DB_NAME = 'iottly',
    MONGO_DB_MOCK = False,
)

settings = prettysettings.Settings(defaults)
