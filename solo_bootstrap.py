from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.key_derivation import AetherKeyTree, master_key_from_private_pem
from modules.yggdrasil_addr import yggdrasil_addr_from_key_tree
from modules.yggdrasil_install import YGGDRASIL_VERSION, install_yggdrasil, is_yggdrasil_available


NODE_SCHEMA = "aether.swarm.node.v2"
AETHER_VERSION = "master-v22"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if path.is_file():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return dict(raw)
    except Exception:
        pass
    return dict(default)


def _dump_json(path: Path, payload: Dict[str, Any], dry_run: bool) -> None:
    if dry_run:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _normalize_public_key(public_key_pem: Any) -> str:
    return str(public_key_pem or "").strip()


def _parse_registered_at(value: Any) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        return datetime.max.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.max.replace(tzinfo=timezone.utc)


def _select_canonical_identity(
    existing_node: Dict[str, Any],
    nodes_dir: Path,
    public_key_pem: str,
) -> Dict[str, Any]:
    normalized_key = _normalize_public_key(public_key_pem)
    if not normalized_key:
        return {}

    candidates = []
    seen_node_ids = set()

    def _add_candidate(payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            return
        if _normalize_public_key(payload.get("public_key_pem", "")) != normalized_key:
            return
        node_id = str(payload.get("node_id", "") or "").strip()
        if not node_id or node_id in seen_node_ids:
            return
        seen_node_ids.add(node_id)
        candidates.append(dict(payload))

    _add_candidate(existing_node)
    if nodes_dir.is_dir():
        for path in sorted(nodes_dir.glob("*.json")):
            payload = _load_json(path, default={})
            _add_candidate(payload)

    if not candidates:
        return {}

    def _rank(payload: Dict[str, Any]) -> tuple:
        role = str(payload.get("role", "") or "").strip().lower()
        return (
            0 if role == "genesis" else 1,
            _parse_registered_at(payload.get("registered_at")),
            str(payload.get("node_id", "") or ""),
        )

    return min(candidates, key=_rank)


def _ensure_keypair(keys_dir: Path, dry_run: bool) -> Dict[str, Any]:
    private_path = keys_dir / "node_private.key"
    public_path = keys_dir / "node_public.key"

    created = False
    if private_path.is_file():
        private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        created = True
        if not dry_run:
            keys_dir.mkdir(parents=True, exist_ok=True)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            private_path.write_bytes(private_pem)

    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    node_id = hashlib.sha256(public_raw).hexdigest()[:16]

    if not dry_run:
        keys_dir.mkdir(parents=True, exist_ok=True)
        if not private_path.is_file():
            private_path.write_bytes(private_pem)
        if not public_path.is_file() or public_path.read_bytes() != public_pem:
            public_path.write_bytes(public_pem)

    return {
        "created": created,
        "node_id": node_id,
        "private_key": str(private_path),
        "public_key": str(public_path),
        "private_pem": private_pem,
        "public_pem": public_pem,
        "public_raw": public_raw,
        "public_key_pem": public_pem.decode("ascii"),
    }


def build_node_record(
    node_id: str,
    public_key_pem: str,
    yggdrasil_addr: Optional[str],
    *,
    relay: bool = False,
    registered_at: Optional[str] = None,
    aether_version: str = AETHER_VERSION,
    role: Optional[str] = None,
) -> Dict[str, Any]:
    payload = {
        "schema": NODE_SCHEMA,
        "node_id": str(node_id),
        "public_key_pem": str(public_key_pem),
        "yggdrasil_addr": yggdrasil_addr,
        "relay": bool(relay),
        "registered_at": str(registered_at or _utc_now()),
        "aether_version": str(aether_version),
    }
    if role:
        payload["role"] = str(role)
    return payload


def _ensure_genesis_pack(anchors_dir: Path, node_id: str, dry_run: bool) -> Dict[str, Any]:
    anchors_dir.mkdir(parents=True, exist_ok=True)
    genesis_path = anchors_dir / f"genesis_{node_id}.pack"

    if genesis_path.is_file():
        return {"created": False, "path": str(genesis_path)}

    payload = {
        "pack_id": hashlib.sha256(f"{node_id}:{_utc_now()}".encode("utf-8")).hexdigest(),
        "node_id": node_id,
        "type": "genesis",
        "anchors": [],
        "created_at": _utc_now(),
    }
    _dump_json(genesis_path, payload, dry_run)
    return {"created": True, "path": str(genesis_path)}


def _ensure_seed_pack(anchors_dir: Path, dry_run: bool) -> Dict[str, Any]:
    seed_path = anchors_dir / "pack-local-001.pack"
    if seed_path.is_file():
        return {"created": False, "path": str(seed_path)}

    payload = {
        "pack_id": "pack-local-001",
        "anchors": [{"k": "v"}],
        "created_at": _utc_now(),
    }
    _dump_json(seed_path, payload, dry_run)
    return {"created": True, "path": str(seed_path)}


def _ensure_settings(settings_path: Path, node_id: str, dry_run: bool) -> Dict[str, Any]:
    settings = _load_json(settings_path, default={})
    settings["solo_genesis_mode"] = True
    settings.setdefault("node_id", node_id)
    settings.setdefault("bootstrap_completed_at", _utc_now())
    _dump_json(settings_path, settings, dry_run)
    return settings


def _ensure_consent(consent_path: Path, dry_run: bool) -> Dict[str, Any]:
    consent = _load_json(consent_path, default={})
    consent["consent_ok"] = True
    consent.setdefault("approved", True)
    consent.setdefault("source", "solo_bootstrap")
    consent.setdefault("updated_at", _utc_now())
    _dump_json(consent_path, consent, dry_run)
    return consent


def run_bootstrap(dry_run: bool = False) -> Dict[str, Any]:
    root = Path(__file__).resolve().parent
    settings_path = root / "data" / "settings.json"
    anchors_dir = root / "data" / "anchors"
    consent_path = root / "data" / "swarm_consent.json"
    node_json_path = root / "data" / "swarm" / "node.json"
    nodes_dir = root / "data" / "swarm" / "nodes"
    keys_dir = root / "keys"

    keypair = _ensure_keypair(keys_dir, dry_run=dry_run)
    existing_node = _load_json(node_json_path, default={})
    if existing_node and not keypair["created"]:
        stored_pubkey = _normalize_public_key(existing_node.get("public_key_pem", ""))
        actual_pubkey = _normalize_public_key(keypair["public_key_pem"])
        if stored_pubkey and stored_pubkey != actual_pubkey:
            print("[BOOTSTRAP] WARNUNG: node.json und keys/ haben verschiedene Public Keys!")
            print("[BOOTSTRAP] Das deutet auf einen manuellen Key-Austausch hin.")
            print("[BOOTSTRAP] Bitte data/swarm/nodes/ manuell pruefen.")

    canonical_node = _select_canonical_identity(existing_node, nodes_dir, keypair["public_key_pem"])
    canonical_node_id = str(canonical_node.get("node_id", "") or "").strip()
    canonical_registered_at = str(
        canonical_node.get("registered_at", "")
        or existing_node.get("registered_at", "")
        or _utc_now()
    )
    canonical_role = str(
        canonical_node.get("role", "")
        or existing_node.get("role", "")
        or ""
    ).strip() or None

    if canonical_node_id:
        node_id = canonical_node_id
        print(f"[BOOTSTRAP] Existierende Node-ID beibehalten: {node_id}")
    else:
        node_id = hashlib.sha256(keypair["public_raw"]).hexdigest()[:16]
        print(f"[BOOTSTRAP] Neue Node-ID: {node_id}")

    key_tree = AetherKeyTree(master_key_from_private_pem(keypair["private_pem"]))
    try:
        yggdrasil_addr = yggdrasil_addr_from_key_tree(key_tree)
        if not is_yggdrasil_available():
            if dry_run:
                print("[BOOTSTRAP] Yggdrasil nicht gefunden. Dry-run ueberspringt Download.")
            else:
                print("[BOOTSTRAP] Yggdrasil nicht gefunden. Lade herunter...")
                print("[BOOTSTRAP] Quelle: github.com/yggdrasil-network/yggdrasil-go")
                print(f"[BOOTSTRAP] Version: {YGGDRASIL_VERSION} (SHA256-verifiziert)")
                binary = install_yggdrasil()
                print(f"[BOOTSTRAP] Yggdrasil installiert: {binary}")
        else:
            print("[BOOTSTRAP] Yggdrasil bereits vorhanden.")

        node_payload = build_node_record(
            node_id,
            str(keypair["public_key_pem"]),
            yggdrasil_addr,
            relay=bool(existing_node.get("relay", False)),
            registered_at=canonical_registered_at,
            role=canonical_role,
        )
        discovery_path = nodes_dir / f"{node_id}.json"
        _dump_json(node_json_path, node_payload, dry_run)
        _dump_json(discovery_path, node_payload, dry_run)

        genesis_pack = _ensure_genesis_pack(anchors_dir, node_id=node_id, dry_run=dry_run)
        seed_pack = _ensure_seed_pack(anchors_dir, dry_run=dry_run)
        settings = _ensure_settings(settings_path, node_id=node_id, dry_run=dry_run)
        consent = _ensure_consent(consent_path, dry_run=dry_run)

        summary = {
            "ok": True,
            "dry_run": bool(dry_run),
            "solo_genesis_mode": bool(settings.get("solo_genesis_mode", False)),
            "keypair_created": bool(keypair["created"]),
            "genesis_pack_created": bool(genesis_pack["created"]),
            "seed_pack_created": bool(seed_pack["created"]),
            "consent_ok": bool(consent.get("consent_ok", False)),
            "node_id": node_id,
            "yggdrasil_addr": yggdrasil_addr,
            "node_json_path": str(node_json_path),
            "discovery_path": str(discovery_path),
        }

        print(f"[BOOTSTRAP] Node ID: {node_id}")
        print(f"[BOOTSTRAP] Yggdrasil: {yggdrasil_addr}")
        print(f"[BOOTSTRAP] node.json -> data/swarm/nodes/{node_id}.json")
        print("[BOOTSTRAP] Naechster Schritt: git add data/swarm/nodes/ && git push")
        return summary
    finally:
        key_tree.zeroize()


def main() -> int:
    parser = argparse.ArgumentParser(description="Aether solo bootstrap")
    parser.add_argument("--dry-run", action="store_true", help="Validate bootstrap flow without writing files")
    args = parser.parse_args()

    result = run_bootstrap(dry_run=bool(args.dry_run))
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
