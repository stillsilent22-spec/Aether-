import sys, secrets, stat, hashlib
from pathlib import Path

key_path = Path("keys/node_secret.key")
if key_path.exists():
    print("node_secret.key already exists")
else:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(secrets.token_bytes(32))
    key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    print("node_secret.key created")

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PublicFormat
)
priv = load_pem_private_key(Path("keys/node_private.key").read_bytes(), password=None)
pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
node_id = hashlib.sha256(pub_pem.encode()).hexdigest()[:16]
print(f"pub_pem = {repr(pub_pem)}")
if node_id == "413616ab27cc02f3":
    print("GENESIS KEY CONFIRMED")
else:
    print(f"node_id = {node_id} (neue Genesis-Identität)")
