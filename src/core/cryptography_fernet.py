from cryptography.fernet import Fernet


class StringEncryptDecrypt:
    def __init__(self, key):
        self._fernet = Fernet(key)

    def encrypt_str(self, message: str) -> str:
        return self._fernet.encrypt(message.encode()).decode('utf-8')

    def decrypt_str(self, enc_message: str) -> str:
        return self._fernet.decrypt(enc_message).decode()

