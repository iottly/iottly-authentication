
EMAIL_REGEX = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
USERNAME_REGEX = '^[a-zA-Z0-9_.+-]+$'

USER_REGISTRATION = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255, 'required': True},
    'full_name': {'type': 'string', 'maxlength': 100, 'required': True, 'empty': False},
    'username': {'type': 'string', 'regex': USERNAME_REGEX, 'maxlength': 24, 'required': True},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50, 'required': True}
}

USER_REGISTRATION_TWO_STEPS = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255, 'required': True},
    'full_name': {'type': 'string', 'maxlength': 100, 'required': True, 'empty': False},
    'username': {'type': 'string', 'regex': USERNAME_REGEX, 'maxlength': 24, 'required': True},
}

USER_REGISTRATION_CONFIRM = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255, 'required': True},
    'registration_token': {'type': 'string', 'required': True, 'empty': False}
}

USER_LOGIN = {
    'username': {'type': 'string', 'regex': USERNAME_REGEX, 'maxlength': 24, 'required': True},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50, 'required': True, 'empty': False}
}

USER_UPDATE = {
    'full_name': {'type': 'string', 'maxlength': 100, 'required': True, 'empty': False},
}

USER_FROM_SESSION = {
    'session_id': {'type': 'string', 'minlength': 32, 'maxlength': 32, 'required': True, 'empty': False}
}

TOKEN_CREATE = {
    'project': {'type': 'string', 'required': True, 'empty': False},
}

TOKEN_DELETE = {
    'project': {'type': 'string', 'required': True, 'empty': False},
    'token_id': {'type': 'string', 'minlength': 32, 'maxlength': 32, 'required': True, 'empty': False}
}

PASSWORD_RESET_REQUEST = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255, 'required': True, 'empty': False},
}

PASSWORD_RESET = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255, 'required': True, 'empty': False},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50, 'required': True, 'empty': False},
    'reset_token': {'type': 'string', 'minlength': 32, 'maxlength': 32, 'required': True, 'empty': False}
}

PASSWORD_UPDATE = {
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50, 'required': True, 'empty': False}
}

PASSWORD_TWO_STEPS_SET = {
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50, 'required': True, 'empty': False},
    'registration_token': {'type': 'string', 'required': True, 'empty': False}
}
