import pytest
import numpy as np
from modules.media_processor import MediaProcessor
from data.file_register import FileRegister
from cryptography.fernet import Fernet
import tempfile
import os

def test_process_mp3_entropy_symmetry():
    mp = MediaProcessor()
    data = b"\x00\x01\x02\x03" * 100
    features = mp.process_mp3(data)
    assert features["entropy"] > 0
    assert 0 <= features["symmetry"] <= 1

def test_process_image_entropy_symmetry():
    mp = MediaProcessor()
    arr = np.random.randint(0, 255, (10, 10), dtype=np.uint8)
    features = mp.process_image(arr)
    assert features["entropy"] > 0
    assert 0 <= features["symmetry"] <= 1

def test_filekey_encryption_decryption():
    key = Fernet.generate_key()
    f = Fernet(key)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"testdata")
        tmp_path = tmp.name
    fr = FileRegister()
    filekey = fr.register_file(tmp_path, f)
    filehash = f.decrypt(filekey.encode()).decode()
    assert len(filehash) == 64  # SHA256
    os.remove(tmp_path)
