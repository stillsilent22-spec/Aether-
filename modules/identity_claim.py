from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Optional

DEFAULT_ADMIN_PUBLISHER_ID = "tryharder997"
IDENTITY_LOCK_MODE = "ygg-hw-username-v1"
IDENTITY_LOCK_MODE_DHT = "dht-hw-username-v1"  # for nodes entering via AetherNet DHT (no Yggdrasil)
_LEGACY_WINDOWS_RELEASES = {
    "95",
    "98",
    "me",
    "2000",
    "xp",
    "2003",
    "2003server",
    "vista",
    "7",
}


def load_json_dict(path: Path, default: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    payload_default = dict(default or {})
    try:
        if not path.is_file():
            return payload_default
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else payload_default
    except Exception:
        return payload_default


def load_sole_user_record(root: Path) -> Optional[dict[str, Any]]:
    users_path = root / "data" / "rust_shell" / "users.json"
    payload = load_json_dict(users_path, {"users": []})
    users = payload.get("users", [])
    if not isinstance(users, list) or len(users) != 1:
        return None
    user = users[0]
    if not isinstance(user, dict):
        return None
    return dict(user)


def public_key_b64_from_pem(public_key_pem: str) -> str:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def compute_identity_lock(
    username: str,
    node_id: str,
    public_key_b64: str,
    device_fingerprint: str,
    yggdrasil_addr: str,
    native_ygg_capable: bool,
    network_entry_id: str = "",
) -> str:
    """Compute the identity lock hash.

    Two equivalent entry paths are supported:
      - Yggdrasil: yggdrasil_addr is the network identity (schema ygg-hw-user-lock.v1)
      - AetherNet DHT: network_entry_id (DHT peer-id) is the network identity
        (schema dht-hw-user-lock.v1) — used by legacy/non-Ygg hardware.
    Both produce an equally strong cryptographic lock; the schema tag in the
    payload ensures locks from different entry paths cannot collide.
    """
    normalized_username = str(username or "").strip().lower()
    normalized_node_id = str(node_id or "").strip().lower()
    normalized_public_key = str(public_key_b64 or "").strip()
    normalized_device_fingerprint = str(device_fingerprint or "").strip()
    normalized_yggdrasil_addr = str(yggdrasil_addr or "").strip().lower()
    normalized_network_entry_id = str(network_entry_id or "").strip().lower()
    # Prefer Yggdrasil address; fall back to DHT peer-id for legacy/non-Ygg nodes.
    effective_network_id = normalized_yggdrasil_addr or normalized_network_entry_id
    if not native_ygg_capable:
        return ""
    if not all(
        [
            normalized_username,
            normalized_node_id,
            normalized_public_key,
            normalized_device_fingerprint,
            effective_network_id,
        ]
    ):
        return ""
    schema = (
        "aether.ygg-hw-user-lock.v1"
        if normalized_yggdrasil_addr
        else "aether.dht-hw-user-lock.v1"
    )
    payload = "|".join(
        [
            schema,
            normalized_username,
            normalized_node_id,
            normalized_public_key,
            normalized_device_fingerprint,
            effective_network_id,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def infer_native_ygg_capable(
    route: dict[str, Any],
    hw_capability: dict[str, Any],
    role: str,
    yggdrasil_addr: str,
    network_entry_id: str = "",
) -> bool:
    """Return True when this node has a stable, verified network identity.

    Two entry paths are accepted as equivalent:
      - Yggdrasil: yggdrasil_addr is non-empty on qualifying hardware.
      - AetherNet DHT: hw_capability.dht == True OR network_entry_id is provided.
        Legacy hardware (e.g. Windows XP/7) that enters via a relay-bridge into
        the DHT AetherNet is treated as a full equal node.
    """
    normalized_role = str(role or "peer").strip().lower()
    normalized_yggdrasil_addr = str(yggdrasil_addr or "").strip()
    normalized_network_entry_id = str(network_entry_id or "").strip()

    if normalized_role == "genesis" and normalized_yggdrasil_addr:
        return True

    native_rank = int(hw_capability.get("native_tier_rank", hw_capability.get("tier_rank", 0)) or 0)
    if native_rank >= 3:
        return True
    if bool(hw_capability.get("yggdrasil", False)):
        return True
    # DHT-capable hardware (tier 4 or dht flag) or relay-bridge with confirmed DHT peer-id:
    # these nodes enter via AetherNet DHT and receive equal identity treatment.
    if bool(hw_capability.get("dht", False)):
        return True
    if native_rank >= 2 and normalized_network_entry_id:
        return True

    mode = str(route.get("mode", "") or "").strip().lower()
    platform_name = str(route.get("platform", "") or "").strip().lower()
    release = str(route.get("release", "") or "").strip().lower()
    if mode != "full":
        return False
    # Nodes with no Ygg address but a confirmed DHT peer-id are still eligible.
    if not normalized_yggdrasil_addr and not normalized_network_entry_id:
        return False
    if platform_name.startswith("win"):
        # Legacy Windows can use DHT entry path if a network_entry_id is provided.
        if release in _LEGACY_WINDOWS_RELEASES:
            return bool(normalized_network_entry_id)
        return True
    if platform_name in {"linux", "darwin", "mac", "android"}:
        return True
    return bool(normalized_yggdrasil_addr or normalized_network_entry_id)


def load_trusted_publishers(root: Path) -> dict[str, Any]:
    return load_json_dict(
        root / "data" / "trusted_publishers.json",
        {"schema": "aether.trusted_publishers.v1", "publishers": {}},
    )


def admin_publisher_id(manifest: dict[str, Any]) -> str:
    return str(manifest.get("admin_publisher_id", "") or DEFAULT_ADMIN_PUBLISHER_ID).strip() or DEFAULT_ADMIN_PUBLISHER_ID


def trusted_publisher_entry(manifest: dict[str, Any], publisher_id: Optional[str] = None) -> dict[str, Any]:
    publishers = manifest.get("publishers", {})
    if not isinstance(publishers, dict):
        return {}
    target_publisher_id = str(publisher_id or admin_publisher_id(manifest) or DEFAULT_ADMIN_PUBLISHER_ID).strip()
    entry = publishers.get(target_publisher_id, {})
    return dict(entry) if isinstance(entry, dict) else {}


def matches_manifest_genesis_identity(
    manifest: dict[str, Any],
    *,
    username: str,
    node_id: str,
    public_key_b64: str = "",
    device_fingerprint: str,
    yggdrasil_addr: str,
    identity_lock: str,
) -> bool:
    normalized_username = str(username or "").strip().lower()
    normalized_node_id = str(node_id or "").strip().lower()
    normalized_public_key = str(public_key_b64 or "").strip()
    normalized_identity_lock = str(identity_lock or "").strip()
    expected_publisher_id = admin_publisher_id(manifest)
    entry = trusted_publisher_entry(manifest, expected_publisher_id)
    if normalized_username != expected_publisher_id.lower():
        return False
    if not bool(entry.get("enabled", False)):
        return False
    if str(entry.get("role", "") or "").strip().lower() != "genesis":
        return False
    stored_node_id = str(entry.get("node_id", "") or "").strip().lower()
    stored_public_key = str(entry.get("public_key", "") or "").strip()
    stored_identity_lock = str(entry.get("identity_lock", "") or "").strip()
    stored_identity_lock_mode = str(entry.get("identity_lock_mode", "") or "").strip()
    if not stored_node_id or not stored_public_key or not stored_identity_lock:
        return False
    if stored_identity_lock_mode and stored_identity_lock_mode != IDENTITY_LOCK_MODE:
        return False
    if not hmac.compare_digest(stored_node_id, normalized_node_id):
        return False
    if normalized_public_key and not hmac.compare_digest(stored_public_key, normalized_public_key):
        return False
    expected_lock = compute_identity_lock(
        expected_publisher_id,
        stored_node_id,
        stored_public_key,
        str(device_fingerprint or "").strip(),
        str(yggdrasil_addr or "").strip(),
        True,
    )
    if not expected_lock:
        return False
    if not hmac.compare_digest(stored_identity_lock, expected_lock):
        return False
    return bool(normalized_identity_lock and hmac.compare_digest(normalized_identity_lock, expected_lock))


def is_verified_genesis_claim(
    username: str,
    node_id: str,
    public_key_b64: str,
    manifest: dict[str, Any],
    identity_lock: str = "",
) -> bool:
    normalized_username = str(username or "").strip()
    normalized_node_id = str(node_id or "").strip()
    normalized_public_key = str(public_key_b64 or "").strip()
    normalized_identity_lock = str(identity_lock or "").strip()
    expected_publisher_id = admin_publisher_id(manifest)
    entry = trusted_publisher_entry(manifest, expected_publisher_id)
    if not normalized_username or not normalized_node_id or not normalized_public_key:
        return False
    if normalized_username.lower() != expected_publisher_id.lower():
        return False
    if not bool(entry.get("enabled", False)):
        return False
    if str(entry.get("role", "") or "").strip().lower() != "genesis":
        return False
    stored_node_id = str(entry.get("node_id", "") or "").strip()
    stored_public_key = str(entry.get("public_key", "") or "").strip()
    stored_identity_lock = str(entry.get("identity_lock", "") or "").strip()
    stored_identity_lock_mode = str(entry.get("identity_lock_mode", "") or "").strip()
    if stored_node_id and not hmac.compare_digest(stored_node_id, normalized_node_id):
        return False
    if stored_public_key and not hmac.compare_digest(stored_public_key, normalized_public_key):
        return False
    if stored_identity_lock:
        if not normalized_identity_lock:
            return False
        if stored_identity_lock_mode and stored_identity_lock_mode != IDENTITY_LOCK_MODE:
            return False
        if not hmac.compare_digest(stored_identity_lock, normalized_identity_lock):
            return False
    return True