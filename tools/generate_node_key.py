from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib, os, json, time

priv = ed25519.Ed25519PrivateKey.generate()
priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
pub = priv.public_key()
pub_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
node_id = hashlib.sha256(raw).hexdigest()[:16]

os.makedirs("keys", exist_ok=True)
open("keys/node_private.key","wb").write(priv_pem)
open("keys/node_public.pem","wb").write(pub_pem)
print(node_id)
