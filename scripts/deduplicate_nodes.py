"""
Duplikate in data/swarm/nodes/ anhand public_key_pem deduplizieren.
Bei gleicher public_key_pem: älteste registered_at behalten, Rest archivieren.
"""
import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Optional


def deduplicate_nodes(
    nodes_dir: Path,
    archive_dir: Path,
    local_node_path: Optional[Path] = None,
) -> int:
    """
    Scannt nodes_dir nach *.json-Dateien.
    Gruppiert nach public_key_pem.
    Behält für jede Gruppe den Knoten mit der ältesten registered_at.
    Verschiebt Duplikate nach archive_dir.

    local_node_path: Falls angegeben, wird geprüft ob der lokale
    node.json zu einem archivierten Eintrag gehört — in diesem Fall
    wird der lokale Eintrag durch den beibehaltenen ersetzt.

    Gibt die Anzahl archivierter Dateien zurück.
    """
    archive_dir.mkdir(parents=True, exist_ok=True)

    # Alle node-JSON-Dateien einlesen
    node_files: dict[Path, dict] = {}
    for path in sorted(nodes_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            node_files[path] = data
        except (json.JSONDecodeError, OSError):
            continue

    # Nach public_key_pem gruppieren
    by_pubkey: dict[str, list] = defaultdict(list)
    for path, data in node_files.items():
        pubkey = data.get("public_key_pem", "")
        registered_at = data.get("registered_at", "")
        by_pubkey[pubkey].append((registered_at, path, data))

    archived_count = 0
    archived_node_ids: set[str] = set()

    for pubkey, entries in by_pubkey.items():
        if len(entries) <= 1:
            continue
        # Älteste registered_at zuerst
        entries.sort(key=lambda e: e[0])
        # Ersten behalten, Rest archivieren
        for _registered_at, path, data in entries[1:]:
            dest = archive_dir / path.name
            shutil.move(str(path), str(dest))
            archived_node_ids.add(data.get("node_id", ""))
            archived_count += 1

    # Lokalen node.json korrigieren falls er archiviert wurde
    if local_node_path is not None and local_node_path.exists() and archived_node_ids:
        try:
            local_data = json.loads(local_node_path.read_text(encoding="utf-8"))
            if local_data.get("node_id") in archived_node_ids:
                local_pubkey = local_data.get("public_key_pem", "")
                # Finde den beibehaltenen Knoten für diesen pubkey
                remaining = by_pubkey.get(local_pubkey, [])
                if remaining:
                    kept_path = remaining[0][1]
                    if kept_path.exists():
                        kept_data = json.loads(kept_path.read_text(encoding="utf-8"))
                        local_node_path.write_text(
                            json.dumps(kept_data, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
        except (json.JSONDecodeError, OSError):
            pass

    return archived_count
