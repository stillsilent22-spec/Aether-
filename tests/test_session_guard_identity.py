from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.device_lock import compute_device_fingerprint
from modules.identity_claim import (
    IDENTITY_LOCK_MODE,
    compute_identity_lock,
    matches_manifest_genesis_identity,
    public_key_b64_from_pem,
)
from modules.session_guard import SessionGuardError, validate_registered_runtime


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_keypair(root: Path) -> tuple[str, str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    node_id = hashlib.sha256(public_raw).hexdigest()[:16]
    keys_dir = root / "data" / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "node_private.key").write_bytes(private_pem)
    (keys_dir / "node_public.key").write_text(public_pem, encoding="utf-8")
    return node_id, public_pem, public_key_b64_from_pem(public_pem)


def _prepare_runtime(
    tmp_path: Path,
    *,
    username: str,
    role: str,
    genesis_bound: bool = False,
) -> Path:
    root = tmp_path / "aether"
    root.mkdir(parents=True, exist_ok=True)
    node_id, public_key_pem, public_key_b64 = _write_keypair(root)
    device_fingerprint = compute_device_fingerprint()
    yggdrasil_addr = "200:ca77:8d5c:10b2:e3c0:d06c:6af4:1234"
    identity_lock = compute_identity_lock(
        username,
        node_id,
        public_key_b64,
        device_fingerprint,
        yggdrasil_addr,
        True,
    )

    _write_json(
        root / "data" / "device_lock.json",
        {
            "schema": "aether.device_lock.v1",
            "node_id": node_id,
            "device_fingerprint": device_fingerprint,
        },
    )
    _write_json(
        root / "data" / "interbus" / "startup_route.json",
        {
            "platform": "windows",
            "release": "11",
            "mode": "full",
            "requirements_profile": "full",
        },
    )
    _write_json(
        root / "data" / "interbus" / "hw_capability.json",
        {
            "native_tier_rank": 3,
            "tier_rank": 3,
            "yggdrasil": True,
        },
    )
    _write_json(
        root / "data" / "swarm" / "node.json",
        {
            "schema": "aether.swarm.node.v2",
            "node_id": node_id,
            "public_key_pem": public_key_pem,
            "registered_at": "2026-04-09T10:00:00Z",
            "account_username": username,
            "role": role,
            "relay": False,
            "yggdrasil_addr": yggdrasil_addr,
            "native_ygg_bound": True,
            "account_identity_lock": identity_lock,
            "identity_lock_mode": IDENTITY_LOCK_MODE,
            "creator_locked_username": "tryharder997" if role == "genesis" else "",
        },
    )
    _write_json(
        root / "data" / "settings.json",
        {
            "node_id": node_id,
            "account_username": username,
            "node_role": role,
            "native_ygg_bound": True,
            "account_identity_lock": identity_lock,
            "identity_lock_mode": IDENTITY_LOCK_MODE,
            "solo_genesis_mode": role == "genesis",
            "creator_locked_username": "tryharder997" if role == "genesis" else "",
        },
    )
    _write_json(
        root / "data" / "rust_shell" / "users.json",
        {
            "users": [
                {
                    "username": username,
                    "salt_hex": "salt",
                    "password_hash_hex": "hash",
                    "created_at_epoch": 1775728800,
                    "role": "admin" if role == "genesis" else "operator",
                    "user_settings": {
                        "bound_node_id": node_id,
                        "bound_device_fingerprint": device_fingerprint,
                        "bound_yggdrasil_addr": yggdrasil_addr,
                        "bound_identity_lock": identity_lock,
                        "identity_lock_mode": IDENTITY_LOCK_MODE,
                    },
                    "node_id": node_id,
                    "public_key_b64": public_key_b64,
                    "yggdrasil_addr": yggdrasil_addr,
                    "device_fingerprint": device_fingerprint,
                    "genesis_bound": genesis_bound,
                    "native_ygg_bound": True,
                    "identity_lock": identity_lock,
                }
            ]
        },
    )
    _write_json(
        root / "data" / "trusted_publishers.json",
        {
            "schema": "aether.trusted_publishers.v1",
            "admin_publisher_id": "tryharder997",
            "publishers": {
                "tryharder997": {
                    "enabled": True,
                    "signature_scheme": "ed25519",
                    "public_key": public_key_b64,
                    "node_id": node_id,
                    "role": "genesis",
                    "identity_lock": compute_identity_lock(
                        "tryharder997",
                        node_id,
                        public_key_b64,
                        device_fingerprint,
                        yggdrasil_addr,
                        True,
                    ),
                    "identity_lock_mode": IDENTITY_LOCK_MODE,
                }
            },
        },
    )
    return root


def test_validate_registered_runtime_accepts_peer_with_native_ygg_lock(tmp_path: Path) -> None:
    root = _prepare_runtime(tmp_path, username="peer_user", role="peer")

    validate_registered_runtime(root)


def test_validate_registered_runtime_rejects_identity_lock_mismatch(tmp_path: Path) -> None:
    root = _prepare_runtime(tmp_path, username="peer_user", role="peer")
    node_path = root / "data" / "swarm" / "node.json"
    node_payload = json.loads(node_path.read_text(encoding="utf-8"))
    node_payload["account_identity_lock"] = "deadbeef"
    _write_json(node_path, node_payload)

    with pytest.raises(SessionGuardError, match="Identity-Lock"):
        validate_registered_runtime(root)


def test_validate_registered_runtime_rejects_wrong_creator_for_genesis(tmp_path: Path) -> None:
    root = _prepare_runtime(
        tmp_path,
        username="not_the_creator",
        role="genesis",
        genesis_bound=True,
    )

    with pytest.raises(SessionGuardError, match="Trusted-Publisher-Manifest"):
        validate_registered_runtime(root)


def test_validate_registered_runtime_rejects_genesis_manifest_lock_mismatch(tmp_path: Path) -> None:
    root = _prepare_runtime(
        tmp_path,
        username="tryharder997",
        role="genesis",
        genesis_bound=True,
    )
    manifest_path = root / "data" / "trusted_publishers.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["publishers"]["tryharder997"]["identity_lock"] = "deadbeef"
    _write_json(manifest_path, manifest)

    with pytest.raises(SessionGuardError, match="Trusted-Publisher-Manifest"):
        validate_registered_runtime(root)


def test_matches_manifest_genesis_identity_requires_full_lock_chain(tmp_path: Path) -> None:
    root = _prepare_runtime(
        tmp_path,
        username="tryharder997",
        role="genesis",
        genesis_bound=True,
    )
    manifest = json.loads((root / "data" / "trusted_publishers.json").read_text(encoding="utf-8"))
    node = json.loads((root / "data" / "swarm" / "node.json").read_text(encoding="utf-8"))
    users = json.loads((root / "data" / "rust_shell" / "users.json").read_text(encoding="utf-8"))
    user = users["users"][0]

    assert matches_manifest_genesis_identity(
        manifest,
        username="tryharder997",
        node_id=str(node.get("node_id", "") or ""),
        public_key_b64=str(user.get("public_key_b64", "") or ""),
        device_fingerprint=str(user.get("device_fingerprint", "") or ""),
        yggdrasil_addr=str(node.get("yggdrasil_addr", "") or ""),
        identity_lock=str(user.get("identity_lock", "") or ""),
    )
    assert not matches_manifest_genesis_identity(
        manifest,
        username="tryharder997",
        node_id=str(node.get("node_id", "") or ""),
        public_key_b64=str(user.get("public_key_b64", "") or ""),
        device_fingerprint="other-device",
        yggdrasil_addr=str(node.get("yggdrasil_addr", "") or ""),
        identity_lock=str(user.get("identity_lock", "") or ""),
    )