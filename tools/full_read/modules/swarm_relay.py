"""Optionaler Relay-Modus fuer Aether-Nodes.

Wer relay=true setzt, hilft NAT-Nodes sich zu verbinden.
Relay-Nodes erscheinen in node.json mit "relay": true.
Sie leiten nur verschluesselte Pakete weiter, sehen keinen Inhalt.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class RelayConfig:
    """Liest und schreibt Relay-Einstellungen in node.json."""

    def enable(self, node_json_path: str) -> None:
        self._write_flag(node_json_path, True)

    def disable(self, node_json_path: str) -> None:
        self._write_flag(node_json_path, False)

    def is_relay(self, node_json_path: str) -> bool:
        payload = self._load(node_json_path)
        return bool(payload.get("relay", False))

    def _write_flag(self, node_json_path: str, value: bool) -> None:
        payload = self._load(node_json_path)
        payload["relay"] = bool(value)
        path = Path(node_json_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

    @staticmethod
    def _load(node_json_path: str) -> Dict[str, Any]:
        path = Path(node_json_path)
        if not path.is_file():
            raise FileNotFoundError(f"node.json not found: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"node.json must contain an object: {path}")
        return dict(payload)


def get_relay_nodes(nodes_dir: str = "data/swarm/nodes") -> List[Dict[str, Any]]:
    """Gibt alle bekannten Relay-Nodes aus dem Discovery-Verzeichnis zurueck."""
    root = Path(nodes_dir)
    if not root.is_dir():
        return []
    relays: List[Dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict) or not bool(payload.get("relay", False)):
            continue
        relays.append(dict(payload))
    return relays