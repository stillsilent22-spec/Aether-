import logging
logger = logging.getLogger(__name__)
"""coord_atlas.py — MetaLayer OS Phase D: Koordinaten-Atlas mit Anomalieerkennung.

Speichert historische Pixel-Pfad-Daten, erkennt Abweichungen vom Baseline
und exportiert den Atlas-Zustand als kryptographischen Anker (SHA-256).
Persistenz via SQLite (90-Tage-Fenster).
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List

from modules.metalayer_os       import MetaLayerStatus
from modules.pixel_coord_optimizer import PixelPath

log = logging.getLogger("coord_atlas")

# ── Konstanten ────────────────────────────────────────────────────────────────

ATLAS_DB_PATH    = os.path.join("data", "coord_atlas.db")
HISTORY_DAYS     = 90
ANOMALY_THRESHOLD = 0.25        # Abweichung >25% vom Baseline = Anomalie
MIN_BASELINE_SAMPLES = 5        # Mindestanzahl Samples für stabilen Baseline


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class CoordAnomaly:
    """Abweichung eines Pfades vom erwarteten strukturellen Baseline."""
    pid: int
    process_name: str
    anomaly_type: str            # "hop_count_spike" | "latency_spike" | "coverage_drop"
    observed: float
    baseline: float
    deviation_pct: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "pid":          self.pid,
            "process_name": self.process_name,
            "anomaly_type": self.anomaly_type,
            "observed":     round(self.observed, 4),
            "baseline":     round(self.baseline, 4),
            "deviation_pct":round(self.deviation_pct, 2),
            "timestamp":    self.timestamp,
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class CoordAtlas:
    """
    Historischer Koordinaten-Atlas.

    - Lernt Baseline-Metriken (hop_count, latency_ms) pro Prozessname.
    - Erkennt strukturelle Anomalien beim Vergleich mit dem Baseline.
    - Speichert optimale Pfad-Map.
    - Exportiert den aktuellen Zustand als SHA-256-Anker.
    """

    def __init__(self, db_path: str = ATLAS_DB_PATH) -> None:
        self._db_path = db_path
        self._baseline: Dict[str, dict] = {}   # process_name → {hop_avg, lat_avg, n}
        self._optimal_map: Dict[str, PixelPath] = {}
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
        self._load_baseline_from_db()

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception as e:
                logger.warning(f"[coord_atlas] Fehler: {e}")
                pass
            self._conn = None

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def update(self, paths: List[PixelPath]) -> None:
        """
        Aktualisiert den Atlas mit neuen Pfad-Daten.
        Trainiert Baseline und speichert in SQLite.
        """
        now = time.time()
        for path in paths:
            self._update_baseline(path)
            self._persist_path(path, now)
            if path.is_optimal or path.process_name not in self._optimal_map:
                self._optimal_map[path.process_name] = path
        self._prune_old_rows()

    def detect_coord_anomaly(self, current_paths: List[PixelPath]) -> list[CoordAnomaly]:
        """Vergleicht aktuelle Pfade mit dem Baseline und gibt Anomalien zurück."""
        anomalies: list[CoordAnomaly] = []
        for path in current_paths:
            name = path.process_name
            base = self._baseline.get(name)
            if base is None or base.get("n", 0) < MIN_BASELINE_SAMPLES:
                continue
            hop_base = base.get("hop_avg", 0.0)
            lat_base = base.get("lat_avg", 0.0)

            # Hop-Anomalie
            if hop_base > 0:
                hop_dev = (path.hop_count - hop_base) / hop_base
                if hop_dev > ANOMALY_THRESHOLD:
                    anomalies.append(CoordAnomaly(
                        pid=path.pid,
                        process_name=name,
                        anomaly_type="hop_count_spike",
                        observed=float(path.hop_count),
                        baseline=hop_base,
                        deviation_pct=round(hop_dev * 100, 2),
                    ))

            # Latenz-Anomalie
            if lat_base > 0:
                lat_dev = (path.estimated_latency_ms - lat_base) / lat_base
                if lat_dev > ANOMALY_THRESHOLD:
                    anomalies.append(CoordAnomaly(
                        pid=path.pid,
                        process_name=name,
                        anomaly_type="latency_spike",
                        observed=path.estimated_latency_ms,
                        baseline=lat_base,
                        deviation_pct=round(lat_dev * 100, 2),
                    ))
        return anomalies

    def get_optimal_coord_map(self) -> Dict[str, PixelPath]:
        """Gibt die Map der bisher optimal beobachteten Pfade zurück."""
        return dict(self._optimal_map)

    def export_anchor(self) -> bytes:
        """
        Exportiert den Atlas-Zustand als SHA-256-Anker (32 Bytes).
        Umfasst: Baseline-Werte + optimale Pfade + Timestamp.
        """
        state = {
            "baseline":     {
                k: {kk: round(vv, 4) for kk, vv in v.items()}
                for k, v in self._baseline.items()
            },
            "optimal_pids": {k: v.pid for k, v in self._optimal_map.items()},
            "timestamp":    time.time(),
        }
        raw = json.dumps(state, sort_keys=True).encode()
        return hashlib.sha256(raw).digest()

    def export_anchor_hex(self) -> str:
        """SHA-256-Anker als Hex-String."""
        return self.export_anchor().hex()

    # ── Baseline-Lernen ───────────────────────────────────────────────────────

    def _update_baseline(self, path: PixelPath) -> None:
        name = path.process_name
        b = self._baseline.setdefault(name, {"hop_avg": 0.0, "lat_avg": 0.0, "n": 0})
        n = b["n"] + 1
        alpha = 1.0 / n   # Einfaches gleitendes Mittel
        b["hop_avg"] = (1 - alpha) * b["hop_avg"] + alpha * path.hop_count
        b["lat_avg"] = (1 - alpha) * b["lat_avg"] + alpha * path.estimated_latency_ms
        b["n"]       = n

    # ── SQLite-Persistenz ─────────────────────────────────────────────────────

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or "data", exist_ok=True)
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS coord_paths (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT    NOT NULL,
                    pid          INTEGER NOT NULL,
                    hop_count    INTEGER NOT NULL,
                    latency_ms   REAL    NOT NULL,
                    is_optimal   INTEGER NOT NULL,
                    timestamp    REAL    NOT NULL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cp_ts ON coord_paths(timestamp)"
            )
            self._conn.commit()
        except Exception as exc:
            log.warning("coord_atlas DB init failed: %s", exc)
            self._conn = None

    def _persist_path(self, path: PixelPath, ts: float) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute(
                "INSERT INTO coord_paths "
                "(process_name, pid, hop_count, latency_ms, is_optimal, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    path.process_name,
                    path.pid,
                    path.hop_count,
                    path.estimated_latency_ms,
                    int(path.is_optimal),
                    ts,
                ),
            )
            self._conn.commit()
        except Exception as exc:
            log.debug("persist_path error: %s", exc)

    def _prune_old_rows(self) -> None:
        """Löscht Einträge älter als HISTORY_DAYS Tage."""
        if self._conn is None:
            return
        cutoff = time.time() - HISTORY_DAYS * 86400
        try:
            self._conn.execute("DELETE FROM coord_paths WHERE timestamp < ?", (cutoff,))
            self._conn.commit()
        except Exception as e:
            logger.warning(f"[coord_atlas] Fehler: {e}")
            pass

    def _load_baseline_from_db(self) -> None:
        """Rekonstruiert den Baseline aus gespeicherten Daten beim Start."""
        if self._conn is None:
            return
        cutoff = time.time() - HISTORY_DAYS * 86400
        try:
            cur = self._conn.execute(
                "SELECT process_name, AVG(hop_count), AVG(latency_ms), COUNT(*) "
                "FROM coord_paths WHERE timestamp >= ? "
                "GROUP BY process_name",
                (cutoff,),
            )
            for row in cur.fetchall():
                name, hop_avg, lat_avg, n = row
                self._baseline[name] = {
                    "hop_avg": float(hop_avg or 0.0),
                    "lat_avg": float(lat_avg or 0.0),
                    "n":       int(n or 0),
                }
        except Exception as exc:
            log.debug("baseline load error: %s", exc)
