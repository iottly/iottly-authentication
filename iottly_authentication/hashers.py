from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


def make_password(password):
    hasher = PasswordHasher()
    return hasher.hash(password)

def check_password(hashed, password):
    hasher = PasswordHasher()
    try:
        return hasher.verify(hashed, password)
    except VerifyMismatchError:
        return False
