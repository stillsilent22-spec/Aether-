from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List
import urllib.request
import urllib.error

from modules.consensus_engine import get_candidate_count, get_consensus_anchors
from modules.invariant_observer import get_last_estimated_saving

_log = logging.getLogger(__name__)


def _is_solo_genesis_mode() -> bool:
    try:
        import json
        from pathlib import Path
        s = json.loads(Path("data/settings.json").read_text(encoding="utf-8"))
        return bool(s.get("solo_genesis_mode", False))
    except Exception as e:
        return False


def _derive_alerts(*, node_count: int, reachable_count: int, genesis_key_ok: bool, candidate_count: int, consensus_count: int) -> tuple[str, list[dict[str, Any]], float]:
    alerts: list[dict[str, Any]] = []
    score = 1.0

    if not genesis_key_ok:
        alerts.append({"severity": "critical", "code": "GENESIS_KEY_MISSING", "message": "Genesis key missing or invalid."})
        score -= 0.35

    if node_count < 3 and not _is_solo_genesis_mode():
        alerts.append({"severity": "warning", "code": "NODE_COUNT_LOW", "message": "Swarm has fewer than 3 nodes."})
        score -= 0.20

    if node_count > 0:
        reach_ratio = float(reachable_count) / float(max(1, node_count))
        if reach_ratio < 0.5:
            alerts.append({"severity": "critical", "code": "REACHABILITY_LOW", "message": "Less than 50% of nodes are reachable."})
            score -= 0.30
        elif reach_ratio < 0.75:
            alerts.append({"severity": "warning", "code": "REACHABILITY_DEGRADED", "message": "Reachability below 75%."})
            score -= 0.12

    if candidate_count > max(12, int(consensus_count * 2) + 4):
        alerts.append({"severity": "warning", "code": "CANDIDATE_BACKLOG", "message": "Consensus candidate backlog is growing."})
        score -= 0.14

    if not alerts:
        level = "ok"
    elif any(item.get("severity") == "critical" for item in alerts):
        level = "critical"
    elif any(item.get("severity") == "warning" for item in alerts):
        level = "warning"
    else:
        level = "info"

    return level, alerts, max(0.0, min(1.0, score))


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
        local_node = Path("data/swarm/node.json")
        if local_node.exists():
            node_files.append(local_node)
        anchor_files = list(anchor_path.glob("*.pack")) if anchor_path.exists() else []

        genesis_key_ok = False
        for file_path in node_files:
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                if str(payload.get("role", "")).strip().lower() == "genesis":
                    genesis_key_ok = bool(str(payload.get("public_key_pem", "")).strip())
                    break
            except Exception as e:
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
            except Exception as e:
                continue

        candidate_count = get_candidate_count(db_path=consensus_db)
        consensus_count = len(get_consensus_anchors(db_path=consensus_db))
        estimated_saving_percent = round(get_last_estimated_saving() * 100.0, 2)
        quorum_reachable = reachable_count >= 3
        alert_level, alerts, health_score = _derive_alerts(
            node_count=int(len(node_files)),
            reachable_count=int(reachable_count),
            genesis_key_ok=bool(genesis_key_ok),
            candidate_count=int(candidate_count),
            consensus_count=int(consensus_count),
        )

        try:
            from modules.unified_cascade import CASCADE_VERSION

            version_mismatches = 0
            for pack_file in anchor_path.glob("*.pack"):
                try:
                    pack = json.loads(pack_file.read_text(encoding="utf-8"))
                except Exception as e:
                    continue
                if "cascade_version" in pack and pack["cascade_version"] != CASCADE_VERSION:
                    version_mismatches += 1

            if version_mismatches > 0:
                alerts.append(
                    {
                        "severity": "critical",
                        "code": "CASCADE_VERSION_MISMATCH",
                        "message": f"{version_mismatches} pack(s) have wrong cascade_version.",
                    }
                )
                health_score = max(0.0, float(health_score) - 0.30)
                alert_level = "critical"
        except Exception as e:
            logger.warning(f"[swarm_health] Fehler: {e}")
            pass

        summary = (
            f"nodes={len(node_files)} (online={reachable_count}) | packs={len(anchor_files)} | consensus={consensus_count} | "
            f"quorum={'yes' if quorum_reachable else 'no'} | health={alert_level}"
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
            "alert_level": str(alert_level),
            "alerts": list(alerts),
            "health_score": float(health_score),
            "summary": summary,
        }
    except Exception as err:
        _log.warning("swarm health failed: %s", err)
        return {
            "node_count": 0,
            "genesis_key_ok": False,
            "pack_count": 0,
            "candidate_count": 0,
            "consensus_count": 0,
            "quorum_reachable": False,
            "estimated_saving_percent": 0.0,
            "alert_level": "critical",
            "alerts": [{"severity": "critical", "code": "STATUS_UNAVAILABLE", "message": "Swarm status unavailable."}],
            "health_score": 0.0,
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
            "alert_level",
            "health_score",
            "summary",
        ):
            print(f"{key}: {status.get(key)}")
    except Exception as err:
        print(f"[AETHERNET] print_swarm_status failed: {err}")


class SwarmHealthMonitor:
    """Thin wrapper around swarm health functions for object-oriented access."""

    def get_status(self) -> dict:
        return get_swarm_status()

    def print_status(self) -> None:
        print_swarm_status()

    def get_candidate_count(self) -> int:
        return get_candidate_count()

    def get_consensus_anchors(self) -> list:
        return get_consensus_anchors()