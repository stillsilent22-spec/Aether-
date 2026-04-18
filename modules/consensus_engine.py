from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_DB_PATH = "data/consensus.db"


def _utc_now() -> str:
    """Gibt den aktuellen UTC-Zeitstempel als ISO-String zurueck."""
    return datetime.now(timezone.utc).isoformat()


def _ensure_db(db_path: str) -> sqlite3.Connection:
    """Erzeugt bei Bedarf die Consensus-Datenbank samt Tabellen."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS consensus_candidates(
            ttd_hash TEXT PRIMARY KEY,
            anchor_type TEXT,
            software_context TEXT,
            first_seen TEXT,
            last_seen TEXT,
            node_count INTEGER DEFAULT 1,
            node_ids TEXT,
            metrics TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS consensus_anchors(
            ttd_hash TEXT PRIMARY KEY,
            anchor_type TEXT,
            software_context TEXT,
            promoted_at TEXT,
            source_nodes TEXT,
            metrics TEXT,
            invariance_score REAL
        )
        """
    )
    conn.commit()
    return conn


def _normalize_metrics(metrics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalisiert Metriken auf JSON-serielle numerische Werte."""
    normalized: Dict[str, Any] = {}
    source = dict(metrics or {})
    for key, value in source.items():
        try:
            if isinstance(value, bool):
                normalized[str(key)] = int(value)
            elif isinstance(value, int):
                normalized[str(key)] = int(value)
            elif isinstance(value, float):
                normalized[str(key)] = round(float(value), 12)
            else:
                normalized[str(key)] = value
        except Exception as e:
            normalized[str(key)] = 0.0
    return normalized


def _average_metrics(existing: Dict[str, Any], incoming: Dict[str, Any], count_before: int) -> Dict[str, Any]:
    """Mittelt numerische Metriken ueber mehrere Node-Meldungen hinweg."""
    merged: Dict[str, Any] = {}
    left = _normalize_metrics(existing)
    right = _normalize_metrics(incoming)
    keys = sorted(set(left.keys()) | set(right.keys()))
    weight = max(1, int(count_before))
    for key in keys:
        left_value = left.get(key, 0.0)
        right_value = right.get(key, 0.0)
        if isinstance(left_value, (int, float)) and isinstance(right_value, (int, float)):
            merged[key] = round(((float(left_value) * weight) + float(right_value)) / float(weight + 1), 12)
        else:
            merged[key] = right_value if right_value not in (None, "") else left_value
    return merged


def _normalize_artifact_class(artifact_class: str | None) -> str:
    normalized = str(artifact_class or "performance_route").strip().lower()
    if normalized in {"performance_route", "collaborative_discovery", "public_field_observation"}:
        return normalized
    return "performance_route"


def _share_channel_for_artifact(artifact_class: str | None) -> str:
    normalized = _normalize_artifact_class(artifact_class)
    if normalized == "performance_route":
        return "auto_push"
    if normalized == "public_field_observation":
        return "passive_observation"
    return "consent_required"


def _is_genesis_node_id(node_id: str) -> bool:
    """Prueft cryptografisch ob node_id der verifizierte Genesis-Node ist.

    Liest trusted_publishers.json — nur der eingetragene Genesis-Node
    (Hardware-ID + Rolle 'genesis' + enabled=True) besteht diese Pruefung.
    Kein externer Parameter kann diese Logik umgehen.
    """
    try:
        from modules.registry import is_genesis_node as _check
        return _check(str(node_id or "").strip())
    except Exception:
        return False


def _consensus_threshold(artifact_class: str | None, node_id: str) -> int:
    """Entfernte Quorum-Schwelle: Im neuen Modell wird kein Quorum als Gate verwendet.
    Alle Anchor-Kandidaten werden sofort in den Konsens aufgenommen.
    Der Trustscore bleibt weiterhin als Referenzmetrik erhalten.
    """
    return 0


def submit_candidate(
    ttd_hash: str,
    anchor_type: str,
    node_id: str,
    metrics: Dict[str, Any],
    software_context: str = "unknown",
    db_path: str = DEFAULT_DB_PATH,
    artifact_class: str = "performance_route",
) -> str:
    """Registriert einen Ankerkandidaten und promotes ihn sofort in den Konsens."""
    try:
        if not str(ttd_hash).strip() or not str(node_id).strip():
            return "candidate"

        conn = _ensure_db(db_path)
        cur = conn.cursor()
        now = _utc_now()
        normalized_artifact_class = _normalize_artifact_class(artifact_class)
        normalized_metrics = _normalize_metrics(metrics)
        normalized_metrics["artifact_class"] = normalized_artifact_class
        normalized_metrics["share_channel"] = _share_channel_for_artifact(normalized_artifact_class)

        row = cur.execute(
            "SELECT anchor_type, software_context, first_seen, last_seen, node_count, node_ids, metrics FROM consensus_candidates WHERE ttd_hash = ?",
            (ttd_hash,),
        ).fetchone()

        if row is None:
            node_ids = [str(node_id)]
            node_count = len(node_ids)
            cur.execute(
                """
                INSERT OR REPLACE INTO consensus_candidates(
                    ttd_hash, anchor_type, software_context, first_seen, last_seen, node_count, node_ids, metrics
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(ttd_hash),
                    str(anchor_type),
                    str(software_context or "unknown"),
                    now,
                    now,
                    node_count,
                    json.dumps(node_ids, ensure_ascii=True, sort_keys=True),
                    json.dumps(normalized_metrics, ensure_ascii=True, sort_keys=True),
                ),
            )
            invariance_score = float(node_count) / float(node_count + 1)
            cur.execute(
                """
                INSERT OR REPLACE INTO consensus_anchors(
                    ttd_hash, anchor_type, software_context, promoted_at, source_nodes, metrics, invariance_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(ttd_hash),
                    str(anchor_type),
                    str(software_context or "unknown"),
                    now,
                    json.dumps(node_ids, ensure_ascii=True, sort_keys=True),
                    json.dumps(normalized_metrics, ensure_ascii=True, sort_keys=True),
                    round(invariance_score, 12),
                ),
            )
            cur.execute("DELETE FROM consensus_candidates WHERE ttd_hash = ?", (str(ttd_hash),))
            conn.commit()
            conn.close()
            if normalized_artifact_class == "performance_route":
                return "auto_push_ready"
            return "promoted"

        existing_node_ids = json.loads(row[5] or "[]") if row[5] else []
        unique_node_ids = sorted({str(item) for item in list(existing_node_ids) + [str(node_id)] if str(item).strip()})
        node_count = len(unique_node_ids)
        existing_metrics = json.loads(row[6] or "{}") if row[6] else {}
        averaged_metrics = _average_metrics(existing_metrics, normalized_metrics, int(row[4] or 1))

        cur.execute(
            """
            UPDATE consensus_candidates
            SET anchor_type = ?, software_context = ?, last_seen = ?, node_count = ?, node_ids = ?, metrics = ?
            WHERE ttd_hash = ?
            """,
            (
                str(anchor_type or row[0] or "unknown"),
                str(software_context or row[1] or "unknown"),
                now,
                node_count,
                json.dumps(unique_node_ids, ensure_ascii=True, sort_keys=True),
                json.dumps(averaged_metrics, ensure_ascii=True, sort_keys=True),
                str(ttd_hash),
            ),
        )

        invariance_score = float(node_count) / float(node_count + 1)
        cur.execute(
            """
            INSERT OR REPLACE INTO consensus_anchors(
                ttd_hash, anchor_type, software_context, promoted_at, source_nodes, metrics, invariance_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(ttd_hash),
                str(anchor_type or row[0] or "unknown"),
                str(software_context or row[1] or "unknown"),
                now,
                json.dumps(unique_node_ids, ensure_ascii=True, sort_keys=True),
                json.dumps(averaged_metrics, ensure_ascii=True, sort_keys=True),
                round(invariance_score, 12),
            ),
        )
        cur.execute("DELETE FROM consensus_candidates WHERE ttd_hash = ?", (str(ttd_hash),))
        conn.commit()
        conn.close()
        if normalized_artifact_class == "performance_route":
            return "auto_push_ready"
        return "promoted"
    except Exception as err:
        print(f"[AETHERNET] consensus submit failed: {err}")
        return "candidate"


def submit_performance_route_candidate(
    ttd_hash: str,
    anchor_type: str,
    node_id: str,
    metrics: Dict[str, Any],
    software_context: str = "unknown",
    db_path: str = DEFAULT_DB_PATH,
) -> str:
    """Shortcut fuer nichtinvertierbare Leistungsrouten mit Auto-Push-Semantik.

    Ob der Quorum-Bypass greift, entscheidet ausschliesslich die kryptografische
    Verifikation der node_id gegen trusted_publishers.json — kein Parameter.
    """
    return submit_candidate(
        ttd_hash=ttd_hash,
        anchor_type=anchor_type,
        node_id=node_id,
        metrics=metrics,
        software_context=software_context,
        db_path=db_path,
        artifact_class="performance_route",
    )


def get_consensus_anchors(
    software_context: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """Liest alle oder gefilterte globale Konsens-Anker aus der SQLite-Datenbank."""
    try:
        conn = _ensure_db(db_path)
        cur = conn.cursor()
        if software_context is None:
            rows = cur.execute(
                "SELECT ttd_hash, anchor_type, software_context, promoted_at, source_nodes, metrics, invariance_score FROM consensus_anchors ORDER BY promoted_at ASC"
            ).fetchall()
        else:
            rows = cur.execute(
                "SELECT ttd_hash, anchor_type, software_context, promoted_at, source_nodes, metrics, invariance_score FROM consensus_anchors WHERE software_context = ? ORDER BY promoted_at ASC",
                (str(software_context),),
            ).fetchall()
        conn.close()
        return [
            {
                "ttd_hash": row[0],
                "anchor_type": row[1],
                "software_context": row[2],
                "promoted_at": row[3],
                "source_nodes": json.loads(row[4] or "[]"),
                "metrics": json.loads(row[5] or "{}"),
                "invariance_score": float(row[6] or 0.0),
            }
            for row in rows
        ]
    except Exception as err:
        print(f"[AETHERNET] consensus read failed: {err}")
        return []


def get_candidate_count(db_path: str = DEFAULT_DB_PATH) -> int:
    """Zaehlt die aktuell noch nicht promoteten Konsens-Kandidaten."""
    try:
        conn = _ensure_db(db_path)
        row = conn.execute("SELECT COUNT(*) FROM consensus_candidates").fetchone()
        conn.close()
        return int((row or [0])[0] or 0)
    except Exception as err:
        print(f"[AETHERNET] candidate count failed: {err}")
        return 0


def get_invariance_score(
    ttd_hash: str,
    db_path: str = DEFAULT_DB_PATH,
) -> float:
    """Liefert den bekannten Invariance-Score eines Konsens-Ankers oder 0.0."""
    try:
        conn = _ensure_db(db_path)
        row = conn.execute(
            "SELECT invariance_score FROM consensus_anchors WHERE ttd_hash = ?",
            (str(ttd_hash),),
        ).fetchone()
        conn.close()
        if row is None:
            return 0.0
        return float(row[0] or 0.0)
    except Exception as err:
        print(f"[AETHERNET] invariance score failed: {err}")
        return 0.0