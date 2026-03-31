from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict


def _utc_now() -> datetime:
    """Liefert den aktuellen UTC-Zeitpunkt."""
    return datetime.now(timezone.utc)


def _canonical_payload(pack: Dict[str, Any]) -> bytes:
    """Serialisiert einen Invite deterministisch ohne Signaturfeld."""
    payload = dict(pack)
    payload.pop("signature_b64", None)
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_invite_pack(
    inviter_node_id: str,
    inviter_private_key_path: str,
) -> Dict[str, Any]:
    """Erzeugt ein signiertes Invite-Paket fuer einen neuen Schwarm-Teilnehmer."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key = load_pem_private_key(Path(inviter_private_key_path).read_bytes(), password=None)
        created_at = _utc_now()
        pack: Dict[str, Any] = {
            "schema": "aether.swarm.invite.v1",
            "inviter_node_id": str(inviter_node_id),
            "invite_id": uuid.uuid4().hex,
            "created_at": created_at.isoformat(),
            "expires_at": (created_at + timedelta(hours=72)).isoformat(),
        }
        signature = private_key.sign(_canonical_payload(pack))
        pack["signature_b64"] = base64.b64encode(signature).decode("ascii")
        return pack
    except Exception as err:
        print(f"[AETHERNET] generate_invite_pack failed: {err}")
        return {}


def validate_invite_pack(
    pack: Dict[str, Any],
    known_nodes_dir: str = "data/swarm/nodes",
) -> bool:
    """Prueft Schema, Ablaufzeit und Ed25519-Signatur eines Invite-Pakets."""
    try:
        if not isinstance(pack, dict):
            return False
        if str(pack.get("schema", "")) != "aether.swarm.invite.v1":
            return False
        inviter_node_id = str(pack.get("inviter_node_id", "")).strip()
        if not inviter_node_id:
            return False
        expires_at = datetime.fromisoformat(str(pack.get("expires_at", "")))
        if expires_at <= _utc_now():
            return False

        node_file = Path(known_nodes_dir) / f"{inviter_node_id}.json"
        if not node_file.exists():
            return False
        node_payload = json.loads(node_file.read_text(encoding="utf-8"))
        public_pem = str(node_payload.get("public_key_pem", "")).strip()
        signature_b64 = str(pack.get("signature_b64", "")).strip()
        if not public_pem or not signature_b64:
            return False

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        public_key = load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(base64.b64decode(signature_b64), _canonical_payload(pack))
        return True
    except Exception as e:
        return False


def accept_invite(
    pack: Dict[str, Any],
    my_node_id: str,
    my_public_key_pem: str,
    known_nodes_dir: str = "data/swarm/nodes",
) -> bool:
    """Akzeptiert ein Invite und registriert den lokalen Peer im bekannten Node-Verzeichnis."""
    try:
        if not validate_invite_pack(pack, known_nodes_dir=known_nodes_dir):
            return False
        node_dir = Path(known_nodes_dir)
        node_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "node_id": str(my_node_id),
            "public_key_pem": str(my_public_key_pem),
            "role": "peer",
            "invited_by": str(pack.get("inviter_node_id", "")),
            "invite_id": str(pack.get("invite_id", "")),
            "registered_at": _utc_now().isoformat(),
        }
        (node_dir / f"{my_node_id}.json").write_text(
            json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return True
    except Exception as err:
        print(f"[AETHERNET] accept_invite failed: {err}")
        return False