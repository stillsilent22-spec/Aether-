from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


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


def _ensure_keypair(keys_dir: Path, dry_run: bool) -> Dict[str, Any]:
    private_path = keys_dir / "node_private.key"
    public_path = keys_dir / "node_public.key"

    exists = private_path.is_file() and public_path.is_file()
    if exists:
        private_bytes = private_path.read_bytes()
        node_id = hashlib.sha256(private_bytes).hexdigest()[:16] if private_bytes else secrets.token_hex(8)
        return {
            "created": False,
            "node_id": node_id,
            "private_key": str(private_path),
            "public_key": str(public_path),
        }

    node_id = secrets.token_hex(8)
    if not dry_run:
        keys_dir.mkdir(parents=True, exist_ok=True)
        private_material = f"AETHER-NODE-PRIVATE-{secrets.token_hex(32)}\n"
        public_material = f"AETHER-NODE-PUBLIC-{secrets.token_hex(32)}\n"
        private_path.write_text(private_material, encoding="utf-8")
        public_path.write_text(public_material, encoding="utf-8")

    return {
        "created": True,
        "node_id": node_id,
        "private_key": str(private_path),
        "public_key": str(public_path),
    }


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
    keys_dir = root / "keys"

    keypair = _ensure_keypair(keys_dir, dry_run=dry_run)
    genesis_pack = _ensure_genesis_pack(anchors_dir, node_id=str(keypair["node_id"]), dry_run=dry_run)
    seed_pack = _ensure_seed_pack(anchors_dir, dry_run=dry_run)
    settings = _ensure_settings(settings_path, node_id=str(keypair["node_id"]), dry_run=dry_run)
    consent = _ensure_consent(consent_path, dry_run=dry_run)

    summary = {
        "ok": True,
        "dry_run": bool(dry_run),
        "solo_genesis_mode": bool(settings.get("solo_genesis_mode", False)),
        "keypair_created": bool(keypair["created"]),
        "genesis_pack_created": bool(genesis_pack["created"]),
        "seed_pack_created": bool(seed_pack["created"]),
        "consent_ok": bool(consent.get("consent_ok", False)),
        "node_id": str(keypair["node_id"]),
    }

    if not dry_run:
        print("[solo_bootstrap] completed")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Aether solo bootstrap")
    parser.add_argument("--dry-run", action="store_true", help="Validate bootstrap flow without writing files")
    args = parser.parse_args()

    result = run_bootstrap(dry_run=bool(args.dry_run))
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
