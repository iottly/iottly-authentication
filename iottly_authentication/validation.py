
EMAIL_REGEX = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

USER_REGISTRATION = {
    'email': {'type': 'string', 'regex': EMAIL_REGEX, 'maxlength': 255},
    'full_name': {'type': 'string', 'maxlength': 100},
    'username': {'type': 'string', 'maxlength': 24},
    'password': {'type': 'string', 'minlength': 8, 'maxlength': 50}
}

USER_UPDATE = {
}
