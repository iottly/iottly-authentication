import prettysettings


defaults = dict(
    # MongoDB settings
    MONGO_DB_URL = 'mongodb://db:27017/',
    MONGO_DB_NAME = 'iottly',
    MONGO_DB_MOCK = False,

    REDIS_HOST = 'localhost',
    REDIS_PORT = 6379,

    SMTP_HOST = 'smtp.gmail.com',
    SMTP_PORT = 587,
    SMTP_USER = None,
    SMTP_PASSWORD = None,
    SMTP_MOCK = False,

    FROM_EMAIL = 'foo@example.com',

    SESSION_TTL = 30 * 24 * 60 * 60,

    AUTH_COOKIE_NAME = 'iottly-session-id',

    COOKIE_SECRET = 'iottlycookiesecret',

    debug = True,

    PUBLIC_HOST = '127.0.0.1:8523',
    PUBLIC_URL_PATTERN = 'http://{}',

    REGISTRATION_CONFIRM_PATH = '/auth/register',
    RESET_PASSWORD_PATH = '/auth/password/reset',
)

settings = prettysettings.Settings(defaults)
