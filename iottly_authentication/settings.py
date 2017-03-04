import prettysettings


defaults = dict(
    # MongoDB settings
    MONGO_DB_URL = 'mongodb://db:27017/',
    MONGO_DB_NAME = 'iottly',
    MONGO_DB_MOCK = False,

    REDIS_HOST = 'localhost',
    REDIS_PORT = 6379,

    SMTP_HOST = 'localhost',
    SMTP_PORT = 587,
    SMTP_USER = None,
    SMTP_PASSWORD = None,

    SESSION_TTL = 30 * 24 * 60 * 60,

    COOKIE_SECRET = 'iottlycookiesecret',
)

settings = prettysettings.Settings(defaults)
