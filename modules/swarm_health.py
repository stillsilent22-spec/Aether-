from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List
import urllib.request
import urllib.error

from modules.consensus_engine import get_candidate_count, get_consensus_anchors
from modules.invariant_observer import get_last_estimated_saving


def get_swarm_status(
    nodes_dir: str = "data/swarm/nodes",
    anchor_dir: str = "data/anchors",
    consensus_db: str = "data/consensus.db",
) -> Dict[str, Any]:
    """Berechnet einen kompakten Gesundheitsstatus des lokalen Schwarms."""
    try:
        node_path = Path(nodes_dir)
        anchor_path = Path(anchor_dir)
        node_files = list(node_path.glob("*.json")) if node_path.exists() else []
        anchor_files = list(anchor_path.glob("*.pack")) if anchor_path.exists() else []

        genesis_key_ok = False
        for file_path in node_files:
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                if str(payload.get("role", "")).strip().lower() == "genesis":
                    genesis_key_ok = bool(str(payload.get("public_key_pem", "")).strip())
                    break
            except Exception:
                continue

        # Probe each known node's HTTP endpoint to count actually reachable nodes
        reachable_count = 0
        for file_path in node_files:
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                lan_url = str(payload.get("lan_url", "")).strip()
                if not lan_url:
                    continue
                ping_url = lan_url.rstrip("/") + "/ping"
                with urllib.request.urlopen(ping_url, timeout=1.0) as resp:
                    if 200 <= int(resp.status) < 300:
                        reachable_count += 1
            except Exception:
                continue

        candidate_count = get_candidate_count(db_path=consensus_db)
        consensus_count = len(get_consensus_anchors(db_path=consensus_db))
        estimated_saving_percent = round(get_last_estimated_saving() * 100.0, 2)
        quorum_reachable = len(node_files) >= 3
        quorum_reachable = reachable_count >= 3
        summary = (
            f"nodes={len(node_files)} (online={reachable_count}) | packs={len(anchor_files)} | consensus={consensus_count} | "
            f"quorum={'yes' if quorum_reachable else 'no'}"
        )

        return {
            "node_count": int(len(node_files)),
            "reachable_node_count": int(reachable_count),
            "genesis_key_ok": bool(genesis_key_ok),
            "pack_count": int(len(anchor_files)),
            "candidate_count": int(candidate_count),
            "consensus_count": int(consensus_count),
            "quorum_reachable": bool(quorum_reachable),
            "estimated_saving_percent": float(estimated_saving_percent),
            "summary": summary,
        }
    except Exception as err:
        print(f"[AETHERNET] swarm health failed: {err}")
        return {
            "node_count": 0,
            "genesis_key_ok": False,
            "pack_count": 0,
            "candidate_count": 0,
            "consensus_count": 0,
            "quorum_reachable": False,
            "estimated_saving_percent": 0.0,
            "summary": "swarm status unavailable",
        }


def print_swarm_status() -> None:
    """Druckt den aktuellen Schwarmstatus als einfache Zeilenansicht aus."""
    try:
        status = get_swarm_status()
        for key in (
            "node_count",
            "genesis_key_ok",
            "pack_count",
            "candidate_count",
            "consensus_count",
            "quorum_reachable",
            "estimated_saving_percent",
            "summary",
        ):
            print(f"{key}: {status.get(key)}")
    except Exception as err:
        print(f"[AETHERNET] print_swarm_status failed: {err}")