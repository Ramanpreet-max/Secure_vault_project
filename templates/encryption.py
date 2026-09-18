import base64
import json

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def encrypt_entry(data, key):
    return Fernet(key).encrypt(json.dumps(data).encode()).decode()


def decrypt_entry(encrypted_data, key):
    return json.loads(Fernet(key).decrypt(encrypted_data).decode())