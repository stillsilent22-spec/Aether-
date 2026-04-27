from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
"""modules/session_guard.py — Entry-point enforcement for Aether.

Every runnable script that is NOT the main registration window must call
`require_session()` as the first action inside its `if __name__ == "__main__"`
block.  The function exits with a clear error message when no valid registered
session exists, preventing modules from being used in isolation without first
going through the bootstrap/registration window (python start.py).

Device-lock enforcement:
  - Exactly ONE account per device is allowed.
  - The same account cannot run on two different devices.
  - Violation aborts with a clear message and exit code 1.

Identity-lock enforcement:
    - Native Ygg-capable nodes must match hardware fingerprint + Yggdrasil address
        + username-derived account lock.
    - Genesis is the creator-bound exception and must match the trusted publisher
        manifest for the admin username.
"""

import base64
import hmac
import json
import sys
from pathlib import Path

from modules.identity_claim import (
        admin_publisher_id,
        compute_identity_lock,
        infer_native_ygg_capable,
        is_verified_genesis_claim,
        load_sole_user_record,
        load_trusted_publishers,
        public_key_b64_from_pem,
)

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS_FILE = _ROOT / "data" / "settings.json"
_KEY_FILE = _ROOT / "data" / "keys" / "node_private.key"
_ENTRY_HINT = "Start Aether via the registration window:  python start.py"


class SessionGuardError(RuntimeError):
        """Raised when the local runtime is not cryptographically self-consistent."""


def _normalize_pubkey_b64(b64_str: str) -> str:
    """Normalize a public key b64 string to raw 32-byte Ed25519 format.

    Older code stored the SubjectPublicKeyInfo DER (44 bytes) base64-encoded.
    Current code uses raw 32-byte base64. Accept both so stored records created
    by either code version compare equal to the live-derived value.
    """
    try:
        decoded = base64.b64decode(b64_str)
        if len(decoded) == 32:
            return b64_str
        from cryptography.hazmat.primitives.serialization import (
            load_der_public_key,
            Encoding,
            PublicFormat,
        )
        pub = load_der_public_key(decoded)
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        return b64_str


def _derive_node_id_from_key(key_path: Path) -> str:
    """Leitet die node_id aus dem oeffentlichen Schluessel ab.

    Formel: SHA-256(raw_pub_bytes).hexdigest()[:16] — identisch mit solo_bootstrap.py.
    """
    import hashlib
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pem = key_path.read_bytes()
        private_key = load_pem_private_key(pem, password=None)
        pub = private_key.public_key()
        pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return hashlib.sha256(pub_bytes).hexdigest()[:16]
    except Exception:
        return ""


def _load_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _device_lock_path(root: Path) -> Path:
    return root / "data" / "device_lock.json"


def _node_path(root: Path) -> Path:
    return root / "data" / "swarm" / "node.json"


def _users_path(root: Path) -> Path:
    return root / "data" / "rust_shell" / "users.json"


def _node_public_key_path(root: Path) -> Path:
    return root / "data" / "keys" / "node_public.key"


def _startup_route_path(root: Path) -> Path:
    return root / "data" / "interbus" / "startup_route.json"


def _hw_capability_path(root: Path) -> Path:
    return root / "data" / "interbus" / "hw_capability.json"


def _load_local_device_fingerprint(root: Path, node_id: str) -> str:
    from modules.device_lock import compute_device_fingerprint

    current_fingerprint = compute_device_fingerprint()
    lock_path = _device_lock_path(root)
    if not lock_path.is_file():
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(
            json.dumps(
                {
                    "schema": "aether.device_lock.v1",
                    "node_id": str(node_id).strip(),
                    "device_fingerprint": current_fingerprint,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return current_fingerprint

    payload = _load_json(lock_path)
    stored_node_id = str(payload.get("node_id", "") or "").strip()
    stored_fingerprint = str(payload.get("device_fingerprint", "") or "").strip()
    if stored_node_id and not hmac.compare_digest(stored_node_id, str(node_id).strip()):
        raise SessionGuardError(
            f"Dieses Geraet ist bereits an Node '{stored_node_id[:16]}...' gebunden."
        )
    if stored_fingerprint and not hmac.compare_digest(stored_fingerprint, current_fingerprint):
        raise SessionGuardError(
            "Hardware-Fingerprint stimmt nicht mit der lokalen Device-Bindung ueberein."
        )
    return stored_fingerprint or current_fingerprint


def _load_public_key_pem(root: Path, node_payload: dict) -> str:
    public_key_pem = str(node_payload.get("public_key_pem", "") or "").strip()
    if public_key_pem:
        return public_key_pem
    public_key_path = _node_public_key_path(root)
    if not public_key_path.is_file():
        return ""
    try:
        return public_key_path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def validate_registered_runtime(root: Path | None = None) -> None:
    runtime_root = root or _ROOT
    settings_path = runtime_root / "data" / "settings.json"
    key_path = runtime_root / "data" / "keys" / "node_private.key"
    node_path = _node_path(runtime_root)
    users_path = _users_path(runtime_root)

    if not settings_path.is_file():
        raise SessionGuardError("Keine lokale Session gefunden.")
    if not key_path.is_file():
        raise SessionGuardError("Node-Private-Key fehlt.")
    if not node_path.is_file():
        raise SessionGuardError("Node-Claim fehlt in data/swarm/node.json.")
    if not users_path.is_file():
        raise SessionGuardError("Lokaler Account fehlt in data/rust_shell/users.json.")

    settings = _load_json(settings_path)
    node_payload = _load_json(node_path)
    user_record = load_sole_user_record(runtime_root)
    if user_record is None:
        raise SessionGuardError("Es muss genau ein lokaler Account pro Geraet existieren.")

    node_id = _derive_node_id_from_key(key_path)
    if not node_id:
        raise SessionGuardError("Node-ID konnte nicht aus dem lokalen Schluessel abgeleitet werden.")

    settings_node_id = str(settings.get("node_id", "") or "").strip()
    node_claim_id = str(node_payload.get("node_id", "") or "").strip()
    if settings_node_id and settings_node_id.lower() != node_id.lower():
        raise SessionGuardError("settings.json ist an eine andere Node-ID gebunden.")
    if node_claim_id and node_claim_id.lower() != node_id.lower():
        raise SessionGuardError("node.json ist an eine andere Node-ID gebunden.")

    device_fingerprint = _load_local_device_fingerprint(runtime_root, node_id)
    username = str(user_record.get("username", "") or "").strip()
    if not username:
        raise SessionGuardError("Lokaler Account hat keinen Usernamen.")

    settings_username = str(settings.get("account_username", "") or "").strip()
    node_username = str(node_payload.get("account_username", "") or "").strip()
    if settings_username and settings_username.lower() != username.lower():
        raise SessionGuardError("settings.json referenziert einen anderen Account-Namen.")
    if node_username and node_username.lower() != username.lower():
        raise SessionGuardError("node.json referenziert einen anderen Account-Namen.")

    public_key_pem = _load_public_key_pem(runtime_root, node_payload)
    if not public_key_pem:
        raise SessionGuardError("Lokaler Public-Key fehlt im Node-Claim.")
    public_key_b64 = public_key_b64_from_pem(public_key_pem)
    yggdrasil_addr = str(node_payload.get("yggdrasil_addr", "") or "").strip()
    # AetherNet DHT peer-id as the alternative network entry identity.
    # Derived deterministically from the public key — same logic as derive_peer_id().
    import base64 as _b64
    _pub_raw = _b64.b64decode(public_key_b64)
    network_entry_id = "peer-" + _b64.urlsafe_b64encode(_pub_raw).decode("ascii").rstrip("=")[:32]
    role = str(node_payload.get("role", settings.get("node_role", "peer")) or "peer").strip().lower() or "peer"
    route = _load_json(_startup_route_path(runtime_root))
    hw_capability = _load_json(_hw_capability_path(runtime_root))
    lock_declared = any(
        [
            bool(user_record.get("native_ygg_bound", False)),
            bool(node_payload.get("native_ygg_bound", False)),
            bool(settings.get("native_ygg_bound", False)),
            bool(str(user_record.get("identity_lock", "") or "").strip()),
            bool(str(node_payload.get("account_identity_lock", "") or "").strip()),
            bool(str(settings.get("account_identity_lock", "") or "").strip()),
        ]
    )
    native_ygg_bound = lock_declared or infer_native_ygg_capable(route, hw_capability, role, yggdrasil_addr, network_entry_id)
    expected_identity_lock = compute_identity_lock(
        username,
        node_id,
        public_key_b64,
        device_fingerprint,
        yggdrasil_addr,
        native_ygg_bound,
        network_entry_id,
    )

    if str(user_record.get("node_id", "") or "").strip() and str(user_record.get("node_id", "") or "").strip().lower() != node_id.lower():
        raise SessionGuardError("Lokaler Account ist an eine andere Node-ID gebunden.")
    _stored_key = _normalize_pubkey_b64(str(user_record.get("public_key_b64", "") or "").strip())
    if _stored_key and not hmac.compare_digest(_stored_key, public_key_b64):
        raise SessionGuardError("Lokaler Account passt nicht zum aktuellen Public-Key.")
    _stored_fp = str(user_record.get("device_fingerprint", "") or "").strip()
    if _stored_fp and not hmac.compare_digest(_stored_fp, device_fingerprint):
        raise SessionGuardError("Lokaler Account ist an eine andere Hardware-Bindung gekoppelt.")
    _stored_ygg = str(user_record.get("yggdrasil_addr", "") or "").strip().lower()
    if _stored_ygg and not hmac.compare_digest(_stored_ygg, yggdrasil_addr.lower()):
        raise SessionGuardError("Lokaler Account ist an eine andere Yggdrasil-Adresse gekoppelt.")

    if native_ygg_bound:
        if not expected_identity_lock:
            raise SessionGuardError(
                "Netzwerk-Bindung ist unvollstaendig: Hardware, Username oder "
                "Netzwerk-Einstiegs-ID (Yggdrasil-Adresse oder AetherNet-DHT-Peer-ID) fehlen."
            )
        for source_name, value in (
            ("users.json", user_record.get("identity_lock", "")),
            ("node.json", node_payload.get("account_identity_lock", "")),
            ("settings.json", settings.get("account_identity_lock", "")),
        ):
            normalized_value = str(value or "").strip()
            if normalized_value and normalized_value != expected_identity_lock:
                raise SessionGuardError(
                    f"Identity-Lock in {source_name} passt nicht zur lokalen Hardware-/Ygg-/Username-Bindung."
                )

    manifest = load_trusted_publishers(runtime_root)
    creator_locked_username = str(
        node_payload.get(
            "creator_locked_username",
            settings.get("creator_locked_username", ""),
        )
        or ""
    ).strip()
    genesis_bound = bool(user_record.get("genesis_bound", False)) or role == "genesis" or bool(settings.get("solo_genesis_mode", False))
    if genesis_bound:
        expected_creator = admin_publisher_id(manifest)
        if creator_locked_username and creator_locked_username.lower() != expected_creator.lower():
            raise SessionGuardError("Genesis-Claim ist an den falschen Creator-Usernamen gebunden.")
        if not yggdrasil_addr:
            raise SessionGuardError("Genesis-Claim braucht eine lokale Yggdrasil-Adresse.")
        if not expected_identity_lock:
            raise SessionGuardError(
                "Genesis-Claim braucht einen vollstaendigen Yggdrasil-/Hardware-/Username-Lock."
            )
        if not is_verified_genesis_claim(
            username,
            node_id,
            public_key_b64,
            manifest,
            expected_identity_lock,
        ):
            raise SessionGuardError("Genesis-Claim passt nicht zum Trusted-Publisher-Manifest.")


def require_session() -> None:
    """Abort with an informative message if no valid registered session exists."""
    try:
        validate_registered_runtime()
    except SessionGuardError as exc:
        print(f"[AETHER] Session invalid or incomplete — {exc}\n  {_ENTRY_HINT}")
        sys.exit(1)
