from cryptography.fernet import Fernet
import hashlib
import os

class FileRegister:
    def __init__(self, register_path="data/file_register.json"):
        self.register_path = register_path
        self._load()

    def _load(self):
        if os.path.exists(self.register_path):
            import json
            with open(self.register_path, "r") as f:
                self.register = json.load(f)
        else:
            self.register = {}

    def _save(self):
        import json
        with open(self.register_path, "w") as f:
            json.dump(self.register, f)

    def register_file(self, path: str, key: Fernet) -> str:
        with open(path, "rb") as f:
            data = f.read()
        filehash = hashlib.sha256(data).hexdigest()
        filekey = key.encrypt(filehash.encode())
        self.register[path] = filekey.decode()
        self._save()
        return filekey.decode()

    def get_filekey(self, path: str) -> str:
        return self.register.get(path, None)
