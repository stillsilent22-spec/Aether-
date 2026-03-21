#!/usr/bin/env python3
import hashlib
import json
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


NODE_SECRET_PATH = Path("keys/node_secret.key")
NODE_KEY_DIR = Path("keys")
SWARM_DIR = Path("data/swarm/nodes")
ANCHOR_DIR = Path("data/anchors")
VERSION = "master-v13"


def main() -> None:
    if NODE_SECRET_PATH.exists():
        print("Node bereits initialisiert. Abbruch.")
        sys.exit(0)
    NODE_KEY_DIR.mkdir(parents=True, exist_ok=True)
    SWARM_DIR.mkdir(parents=True, exist_ok=True)
    ANCHOR_DIR.mkdir(parents=True, exist_ok=True)
    node_secret = secrets.token_bytes(32)
    NODE_SECRET_PATH.write_bytes(node_secret)
    NODE_SECRET_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        priv = Ed25519PrivateKey.generate()
        pub_pem = priv.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        priv_path = NODE_KEY_DIR / "node_private.key"
        priv_path.write_bytes(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        priv_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except ImportError:
        print("WARN: cryptography fehlt - pip install cryptography")
        pub_pem = ""
    node_id = hashlib.sha256((pub_pem or secrets.token_hex(32)).encode()).hexdigest()[:16]
    record = {
        "node_id": node_id,
        "public_key_pem": pub_pem,
        "role": "genesis",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "aether_version": VERSION,
    }
    node_path = SWARM_DIR / f"{node_id}.json"
    node_path.write_text(json.dumps(record, indent=2, ensure_ascii=True), encoding="utf-8")
    pack_id = hashlib.sha256(f"genesis:{node_id}".encode()).hexdigest()
    genesis = {
        "pack_id": pack_id,
        "node_id": node_id,
        "type": "genesis",
        "anchors": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    pack_path = ANCHOR_DIR / f"genesis_{node_id}.pack"
    pack_path.write_text(json.dumps(genesis, indent=2, ensure_ascii=True), encoding="utf-8")
    try:
        subprocess.run(["git", "add", str(node_path), str(pack_path)], check=True)
        subprocess.run(["git", "commit", "-m", f"swarm: node1 genesis {node_id[:8]}"], check=True)
        subprocess.run(["git", "push", "origin", "main"], check=True)
    except subprocess.CalledProcessError as err:
        print(f"WARN: Git fehlgeschlagen (lokal gueltig): {err}")
    print(f"\n[NODE INIT DONE] {node_id}")


if __name__ == "__main__":
    main()