
EMAIL_REGEX = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
USERNAME_REGEX = '^[a-zA-Z0-9_.+-]+$'

USER_REGISTRATION = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255},
    'full_name': {'type': 'string', 'maxlength': 100},
    'username': {'type': 'string', 'regex': USERNAME_REGEX, 'maxlength': 24},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50}
}

USER_REGISTRATION_CONFIRM = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255},
    'registration_token': {'type': 'string'}
}

USER_LOGIN = {
    'username': {'type': 'string', 'regex': USERNAME_REGEX, 'maxlength': 24},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50}
}

USER_UPDATE = {
    'full_name': {'type': 'string', 'maxlength': 100},
}

USER_FROM_SESSION = {
    'session_id': {'type': 'string', 'minlength': 32, 'maxlength': 32}
}

TOKEN_CREATE = {
    'project': {'type': 'string'},
}

TOKEN_DELETE = {
    'project': {'type': 'string'},
    'token_id': {'type': 'string', 'minlength': 32, 'maxlength': 32}
}

PASSWORD_RESET_REQUEST = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255},
}

PASSWORD_RESET = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50},
    'reset_token': {'type': 'string', 'minlength': 32, 'maxlength': 32}
}

PASSWORD_UPDATE = {
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50}
}
