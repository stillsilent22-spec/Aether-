"""Migriert node.json Discovery-Eintraege von Schema v1 nach v2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_NODES_DIR = ROOT / "data" / "swarm" / "nodes"
TARGET_SCHEMA = "aether.swarm.node.v2"
DEFAULTS_V2 = {
    "schema": TARGET_SCHEMA,
    "yggdrasil_addr": None,
    "relay": False,
}


def migrate_node_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    migrated = dict(payload)
    for key, value in DEFAULTS_V2.items():
        migrated.setdefault(key, value)
    return migrated


def migrate_nodes(nodes_dir: Path = DEFAULT_NODES_DIR) -> int:
    updated = 0
    if not nodes_dir.is_dir():
        return updated
    for path in sorted(nodes_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("schema", "")).strip() == TARGET_SCHEMA:
            continue
        migrated = migrate_node_payload(payload)
        path.write_text(json.dumps(migrated, ensure_ascii=True, indent=2), encoding="utf-8")
        updated += 1
    return updated


def main() -> int:
    updated = migrate_nodes()
    print(f"[migrate_node_v1_v2] updated={updated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())