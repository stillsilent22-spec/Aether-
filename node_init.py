#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple


NODE_SECRET_PATH = Path("keys/node_secret.key")
NODE_KEY_DIR = Path("keys")
SWARM_DIR = Path("data/swarm/nodes")
ANCHOR_DIR = Path("data/anchors")
VERSION = "master-v13"


def _load_or_create_ed25519_keypair() -> Tuple[Optional[bytes], str]:
    """Laedt oder erzeugt das lokale Ed25519-Keypair und gibt PEM-Daten zurueck."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
            load_pem_private_key,
        )
    except ImportError:
        print("WARN: cryptography fehlt - pip install cryptography")
        return None, ""

    NODE_KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = NODE_KEY_DIR / "node_private.key"
    pub_path = NODE_KEY_DIR / "node_public.key"

    try:
        if priv_path.exists():
            private_key = load_pem_private_key(priv_path.read_bytes(), password=None)
        else:
            private_key = Ed25519PrivateKey.generate()
            priv_path.write_bytes(
                private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            priv_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

        public_pem_bytes = private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
        pub_path.write_bytes(public_pem_bytes)
        pub_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return priv_path.read_bytes(), public_pem_bytes.decode("utf-8")
    except Exception as err:
        print(f"WARN: Keypair konnte nicht geladen/erstellt werden: {err}")
        return None, ""


def repair_genesis_key(node_id: str) -> None:
    """Schreibt fehlenden public_key_pem in bestehenden Node-JSON-Eintrag."""
    try:
        _, public_pem = _load_or_create_ed25519_keypair()
        if not public_pem:
            print(f"[AETHERNET] repair fehlgeschlagen: public_key_pem leer fuer {node_id}")
            return

        node_path = SWARM_DIR / f"{node_id}.json"
        if not node_path.exists():
            print(f"[AETHERNET] repair fehlgeschlagen: Node-Datei fehlt {node_path}")
            return

        record = json.loads(node_path.read_text(encoding="utf-8"))
        record["public_key_pem"] = public_pem
        node_path.write_text(
            json.dumps(record, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        print(f"[REPAIR DONE] {node_id}")
    except Exception as err:
        print(f"[AETHERNET] repair fehlgeschlagen fuer {node_id}: {err}")


def main() -> None:
    if "--repair" in sys.argv:
        repair_genesis_key("6c9e2fcad95e2bd0")
        return
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
        _, pub_pem = _load_or_create_ed25519_keypair()
    except Exception:
        pub_pem = ""
    node_id = hashlib.sha256((pub_pem or secrets.token_hex(32)).encode()).hexdigest()[:16]

    # Detect local IP for lan_url so other nodes can reach us
    import socket as _socket
    try:
        _s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        _local_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        _local_ip = "127.0.0.1"
    _lan_url = f"http://{_local_ip}:7385"

    record = {
        "node_id": node_id,
        "public_key_pem": pub_pem,
        "role": "genesis",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "aether_version": VERSION,
        "lan_url": _lan_url,
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