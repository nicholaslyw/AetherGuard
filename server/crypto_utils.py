import hashlib
import os
import base64


def hash_password(password: str) -> str:
    """Hash a password with a random salt using SHA-256."""
    salt = os.urandom(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 100000
    )
    return base64.b64encode(salt + pw_hash).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    decoded = base64.b64decode(stored_hash.encode())
    salt = decoded[:16]
    stored_pw_hash = decoded[16:]
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 100000
    )
    return pw_hash == stored_pw_hash