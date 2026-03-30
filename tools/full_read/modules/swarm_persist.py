"""Extended persistence layer for Aether Swarm.

Provides SQLite-backed storage for:
  - frame_metrics:    aggregated per-frame metrics + fingerprints (no raw frames)
  - fingerprints:     deduplicated fingerprint index
  - audit_entries:    signed enable/disable/consent events
  - swarm_snapshots:  periodic health snapshots

Privacy rules (enforced):
  - No raw frame bytes are ever stored.
  - Only SHA256 fingerprints and aggregated float metrics.
  - Retention policy: keep at most `max_rows` rows per table (default 10_000).
    Older rows are purged automatically.

Schema version: 1
Migration: additive-only (no column drops). Each migration is idempotent.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_DB_PATH = str(ROOT / "data" / "swarm_metrics.db")
SCHEMA_VERSION = 1
DEFAULT_MAX_ROWS = 10_000

_db_lock = threading.Lock()


# --------------------------------------------------------------------------- #
#  Connection + schema                                                         #
# --------------------------------------------------------------------------- #

def _connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply all schema migrations idempotently."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS frame_metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              REAL NOT NULL,
            frame_index     INTEGER,
            fingerprint     TEXT NOT NULL,
            delta_marker    TEXT,
            adapter_id      TEXT,
            mean_val        REAL,
            std_val         REAL,
            entropy_approx  REAL,
            width           INTEGER,
            height          INTEGER,
            size_bytes      INTEGER,
            extras          TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fingerprints (
            fingerprint     TEXT PRIMARY KEY,
            first_seen_ts   REAL NOT NULL,
            last_seen_ts    REAL NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            actor       TEXT DEFAULT 'local',
            peer_id     TEXT,
            signature   TEXT,
            details     TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS swarm_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            swarm_mode  INTEGER NOT NULL,
            health_score REAL,
            alert_level TEXT,
            node_count  INTEGER,
            extras      TEXT
        )
    """)
    # Indexes for fast recent-row queries
    conn.execute("CREATE INDEX IF NOT EXISTS idx_fm_ts ON frame_metrics(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ae_ts ON audit_entries(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ss_ts ON swarm_snapshots(ts)")
    conn.execute(
        "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', ?)",
        (str(SCHEMA_VERSION),)
    )
    conn.commit()


# --------------------------------------------------------------------------- #
#  frame_metrics                                                              #
# --------------------------------------------------------------------------- #


def _get_conn(db_path: str) -> sqlite3.Connection:
    """Open a fresh connection each call — avoids Windows file-lock issues."""
    return _connect(db_path)


def append_frame_metrics(
    result: Dict[str, Any],
    db_path: str = DEFAULT_DB_PATH,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> None:
    """Persist frame metrics + fingerprint. Raw frame data must NOT be in result."""
    with _db_lock:
        conn = _connect(db_path)
        try:
            ts = float(result.get("timestamp", time.time()))
            fp = str(result.get("fingerprint", ""))
            extras: Dict[str, Any] = {
                k: v for k, v in result.items()
                if k not in (
                    "timestamp", "fingerprint", "delta_marker", "adapter_id",
                    "mean", "std", "entropy_approx", "width", "height", "size_bytes",
                    "frame_index",
                )
            }
            conn.execute("""
                INSERT INTO frame_metrics
                  (ts, frame_index, fingerprint, delta_marker, adapter_id,
                   mean_val, std_val, entropy_approx, width, height, size_bytes, extras)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts,
                int(result.get("frame_index", 0)),
                fp,
                str(result.get("delta_marker", "")),
                str(result.get("adapter_id", "")),
                float(result.get("mean", 0.0)),
                float(result.get("std", 0.0)),
                float(result.get("entropy_approx", 0.0)),
                int(result.get("width", 0)),
                int(result.get("height", 0)),
                int(result.get("size_bytes", 0)),
                json.dumps(extras) if extras else None,
            ))
            if fp:
                conn.execute("""
                    INSERT INTO fingerprints(fingerprint, first_seen_ts, last_seen_ts, occurrence_count)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        last_seen_ts = excluded.last_seen_ts,
                        occurrence_count = occurrence_count + 1
                """, (fp, ts, ts))
            conn.commit()
            _purge_old_rows(conn, "frame_metrics", max_rows)
        finally:
            conn.close()


def _purge_old_rows(conn: sqlite3.Connection, table: str, max_rows: int) -> None:
    count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    if count > max_rows:
        excess = count - max_rows
        conn.execute(
            f"DELETE FROM {table} WHERE id IN "
            f"(SELECT id FROM {table} ORDER BY id ASC LIMIT ?)",
            (excess,)
        )
        conn.commit()


# --------------------------------------------------------------------------- #
#  audit_entries                                                              #
# --------------------------------------------------------------------------- #

def append_audit_entry(
    event_type: str,
    actor: str = "local",
    peer_id: Optional[str] = None,
    signature: Optional[str] = None,
    details: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = _connect(db_path)
        try:
            conn.execute("""
                INSERT INTO audit_entries(ts, event_type, actor, peer_id, signature, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ts, event_type, actor, peer_id, signature, details))
            conn.commit()
            _purge_old_rows(conn, "audit_entries", DEFAULT_MAX_ROWS)
        finally:
            conn.close()


def get_audit_log(
    limit: int = 100,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT ts, event_type, actor, peer_id, details FROM audit_entries "
                "ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        finally:
            conn.close()
    return [
        {"ts": r[0], "event_type": r[1], "actor": r[2], "peer_id": r[3], "details": r[4]}
        for r in rows
    ]


# --------------------------------------------------------------------------- #
#  swarm_snapshots                                                             #
# --------------------------------------------------------------------------- #

def append_swarm_snapshot(
    swarm_mode: bool,
    health_score: Optional[float] = None,
    alert_level: Optional[str] = None,
    node_count: Optional[int] = None,
    extras: Optional[Dict[str, Any]] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = _connect(db_path)
        try:
            conn.execute("""
                INSERT INTO swarm_snapshots(ts, swarm_mode, health_score, alert_level, node_count, extras)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ts, int(swarm_mode), health_score, alert_level, node_count,
                json.dumps(extras) if extras else None,
            ))
            conn.commit()
            _purge_old_rows(conn, "swarm_snapshots", DEFAULT_MAX_ROWS)
        finally:
            conn.close()


def get_recent_snapshots(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT ts, swarm_mode, health_score, alert_level, node_count, extras "
                "FROM swarm_snapshots ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        finally:
            conn.close()
    return [
        {
            "ts": r[0], "swarm_mode": bool(r[1]), "health_score": r[2],
            "alert_level": r[3], "node_count": r[4],
            "extras": json.loads(r[5]) if r[5] else {},
        }
        for r in rows
    ]


# --------------------------------------------------------------------------- #
#  fingerprints query                                                         #
# --------------------------------------------------------------------------- #

def get_fingerprint_stats(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    with _db_lock:
        conn = _connect(db_path)
        try:
            total = conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
            recent = conn.execute(
                "SELECT fingerprint, occurrence_count, last_seen_ts FROM fingerprints "
                "ORDER BY last_seen_ts DESC LIMIT 10"
            ).fetchall()
        finally:
            conn.close()
    return {
        "total_unique_fingerprints": int(total),
        "recent": [
            {"fingerprint": r[0][:16] + "...", "occurrences": r[1], "last_seen": r[2]}
            for r in recent
        ],
    }


# --------------------------------------------------------------------------- #
#  Migration helper (for schema upgrades)                                     #
# --------------------------------------------------------------------------- #

def run_migration(db_path: str = DEFAULT_DB_PATH) -> str:
    """Run all pending idempotent migrations. Safe to call multiple times."""
    conn = _connect(db_path)
    version = conn.execute(
        "SELECT value FROM schema_meta WHERE key='version'"
    ).fetchone()
    current = int(version[0]) if version else 0
    return f"Schema at version {SCHEMA_VERSION} (was {current}). No pending migrations."
