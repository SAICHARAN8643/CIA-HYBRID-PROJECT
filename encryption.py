import hashlib
from cryptography.fernet import Fernet

# 🔐 FIXED KEY (DO NOT CHANGE AFTER THIS)
key = b'5hFv5l8G0X1kR9Yw8Q2Z3mN7cA4pT6sUeVxWbYz1234='

cipher = Fernet(key)

def encrypt_data(data):
    encrypted = cipher.encrypt(data.encode())
    hash_value = hashlib.sha256(encrypted).hexdigest()
    return encrypted, hash_value

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data).decode()