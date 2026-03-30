"""Bereinigt doppelte Node-Eintraege in data/swarm/nodes/.

Zwei Nodes gelten als Duplikat wenn public_key_pem identisch ist.
Beibehaltene ID: genesis bevorzugt, sonst die aeltere registered_at.
Entfernte Datei: wird nach data/swarm/nodes/archive/ verschoben.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_NODES_DIR = ROOT / "data" / "swarm" / "nodes"
DEFAULT_ARCHIVE_DIR = DEFAULT_NODES_DIR / "archive"
DEFAULT_LOCAL_NODE_PATH = ROOT / "data" / "swarm" / "node.json"


def _load_json(path: Path) -> Dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"expected object in {path}")
    return dict(raw)


def _dump_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _normalize_public_key(value: Any) -> str:
    return str(value or "").strip()


def _parse_registered_at(value: Any) -> datetime:
    raw = str(value or "").strip()
    if not raw:
        return datetime.max.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.max.replace(tzinfo=timezone.utc)


def _pubkey_preview(public_key_pem: str) -> str:
    lines = [line.strip() for line in public_key_pem.splitlines() if line and "BEGIN" not in line and "END" not in line]
    if not lines:
        return "<leer>"
    return lines[0][:8]


def _entry_rank(entry: Dict[str, Any]) -> tuple:
    payload = entry["payload"]
    role = str(payload.get("role", "") or "").strip().lower()
    return (
        0 if role == "genesis" else 1,
        _parse_registered_at(payload.get("registered_at")),
        str(payload.get("node_id", "") or ""),
    )


def _merge_local_node_payload(local_payload: Dict[str, Any], winner_payload: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(winner_payload)
    if "relay" in local_payload:
        merged["relay"] = bool(local_payload.get("relay", False))
    if local_payload.get("yggdrasil_addr"):
        merged["yggdrasil_addr"] = local_payload.get("yggdrasil_addr")
    if local_payload.get("aether_version"):
        merged["aether_version"] = local_payload.get("aether_version")
    return merged


def deduplicate_nodes(
    nodes_dir: Path = DEFAULT_NODES_DIR,
    archive_dir: Path = DEFAULT_ARCHIVE_DIR,
    local_node_path: Path = DEFAULT_LOCAL_NODE_PATH,
) -> int:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for path in sorted(nodes_dir.glob("*.json")):
        payload = _load_json(path)
        public_key_pem = _normalize_public_key(payload.get("public_key_pem", ""))
        if not public_key_pem:
            continue
        groups.setdefault(public_key_pem, []).append({"path": path, "payload": payload})

    local_payload = _load_json(local_node_path) if local_node_path.is_file() else {}
    archived = 0
    for public_key_pem, entries in groups.items():
        if len(entries) <= 1:
            continue
        ordered = sorted(entries, key=_entry_rank)
        winner = ordered[0]
        losers = ordered[1:]

        print(f"[DEDUP] {len(entries)} Eintraege fuer public_key {_pubkey_preview(public_key_pem)}...")
        winner_payload = winner["payload"]
        winner_role = str(winner_payload.get("role", "") or "").strip() or "peer"
        print(
            f"[DEDUP] Behalte: {winner_payload.get('node_id')} "
            f"({winner_payload.get('registered_at', 'unbekannt')}, {winner_role})"
        )

        for loser in losers:
            loser_payload = loser["payload"]
            archive_target = archive_dir / loser["path"].name
            archive_target.parent.mkdir(parents=True, exist_ok=True)
            loser["path"].replace(archive_target)
            archived += 1
            print(
                f"[DEDUP] Archiviere: {loser_payload.get('node_id')} "
                f"({loser_payload.get('registered_at', 'unbekannt')})"
            )

        if local_payload and _normalize_public_key(local_payload.get("public_key_pem", "")) == public_key_pem:
            local_node_id = str(local_payload.get("node_id", "") or "").strip()
            loser_ids = {
                str(loser["payload"].get("node_id", "") or "").strip()
                for loser in losers
            }
            if local_node_id in loser_ids:
                reconciled = _merge_local_node_payload(local_payload, winner_payload)
                _dump_json(local_node_path, reconciled)

    print(f"[DEDUP] Fertig. {archived} Duplikat{'e' if archived != 1 else ''} bereinigt.")
    return archived


def main() -> int:
    deduplicate_nodes()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())