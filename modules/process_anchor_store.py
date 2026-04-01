from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""
Aether – Prozess-Anker-Store.

Speichert strukturelle Prozess-Snapshots (Basis-Anker), Konsens-Anker
(Ebene 2) und Meta-Anker (Ebene 3) in einer lokalen SQLite-Datenbank.

Privacy-Garantie:
  - Kein Prozessinhalt, nur Metadaten (CPU, RAM, IO, Threads).
  - Datenbank bleibt lokal, verlässt das Gerät nicht.
  - Alle Daten können jederzeit vollständig gelöscht werden.
"""


import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# Schema-Version (erhöhen bei Breaking Changes)
# ---------------------------------------------------------------------------
_SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS process_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,         -- Unix-Timestamp
    pid             INTEGER NOT NULL,
    name            TEXT    NOT NULL,
    cpu_percent     REAL    NOT NULL DEFAULT 0,
    memory_rss      INTEGER NOT NULL DEFAULT 0,
    memory_vms      INTEGER NOT NULL DEFAULT 0,
    io_read_bytes   INTEGER NOT NULL DEFAULT 0,
    io_write_bytes  INTEGER NOT NULL DEFAULT 0,
    thread_count    INTEGER NOT NULL DEFAULT 1,
    status          TEXT    NOT NULL DEFAULT '',
    ppid            INTEGER NOT NULL DEFAULT 0,
    integrity_level TEXT    NOT NULL DEFAULT 'n/a',
    anchor_hash     TEXT    NOT NULL          -- SHA-256 des Strukturfingerprints
);
CREATE INDEX IF NOT EXISTS idx_ps_name ON process_snapshots (name);
CREATE INDEX IF NOT EXISTS idx_ps_ts   ON process_snapshots (ts);

CREATE TABLE IF NOT EXISTS consensus_anchors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      REAL    NOT NULL,
    window_start    REAL    NOT NULL,
    window_end      REAL    NOT NULL,
    process_name    TEXT    NOT NULL,
    avg_cpu         REAL    NOT NULL DEFAULT 0,
    avg_memory_rss  INTEGER NOT NULL DEFAULT 0,
    avg_threads     REAL    NOT NULL DEFAULT 0,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    pattern_label   TEXT    NOT NULL DEFAULT '',  -- z.B. "monday_morning_spike"
    anchor_hash     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ca_name ON consensus_anchors (process_name);

CREATE TABLE IF NOT EXISTS meta_anchors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      REAL    NOT NULL,
    trigger_name    TEXT    NOT NULL,   -- z.B. "Spiel A"
    effect_name     TEXT    NOT NULL,   -- z.B. "Prozess B"
    correlation     REAL    NOT NULL DEFAULT 0,
    observation     TEXT    NOT NULL DEFAULT '',
    anchor_hash     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS optimization_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    action_type     TEXT    NOT NULL,   -- z.B. "priority_lower", "service_disable"
    target          TEXT    NOT NULL,   -- z.B. Prozessname oder Service-ID
    details         TEXT    NOT NULL DEFAULT '{}',
    rollback_data   TEXT    NOT NULL DEFAULT '{}',  -- JSON für Rollback
    rolled_back     INTEGER NOT NULL DEFAULT 0,     -- 0=nein, 1=ja
    user_consented  INTEGER NOT NULL DEFAULT 1
);
"""


@dataclass
class RawSnapshot:
    """Kompakter Datensatz für einen einzelnen Prozess-Snapshot."""

    ts: float
    pid: int
    name: str
    cpu_percent: float = 0.0
    memory_rss: int = 0
    memory_vms: int = 0
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    thread_count: int = 1
    status: str = ""
    ppid: int = 0
    integrity_level: str = "n/a"
    anchor_hash: str = ""

    def compute_hash(self) -> str:
        """Berechnet einen nicht-invertierbaren SHA-256-Fingerprint."""
        sig = (
            f"{self.name}|{round(self.cpu_percent, 1)}|"
            f"{self.memory_rss // (64 * 1024)}|"  # RAM in 64-KB-Granularität
            f"{self.thread_count}|{self.integrity_level}"
        )
        return hashlib.sha256(sig.encode()).hexdigest()


@dataclass
class ConsensusAnchor:
    """Aggregierter Anker (Ebene 2) aus ähnlichen Basis-Snapshots."""

    process_name: str
    window_start: float
    window_end: float
    avg_cpu: float
    avg_memory_rss: int
    avg_threads: float
    sample_count: int
    pattern_label: str = ""
    anchor_hash: str = ""
    id: int = 0
    created_at: float = field(default_factory=time.time)


@dataclass
class MetaAnchor:
    """Domänenübergreifendes Muster (Ebene 3)."""

    trigger_name: str
    effect_name: str
    correlation: float
    observation: str
    anchor_hash: str = ""
    id: int = 0
    created_at: float = field(default_factory=time.time)


class ProcessAnchorStore:
    """
    Thread-sichere SQLite-Persitenz für Prozess-Anker.

    Alle Schreib-/Lese-Operationen sind atomar. Die Datenbankverbindung
    wird pro Thread neu geöffnet (check_same_thread=False + eigene Locks).
    """

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self._db_path), check_same_thread=False, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception as e:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_db(self) -> None:
        with self._lock, self._conn() as con:
            con.executescript(_DDL)
            cur = con.execute("SELECT value FROM schema_meta WHERE key='version'")
            row = cur.fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO schema_meta(key,value) VALUES('version',?)",
                    (str(_SCHEMA_VERSION),),
                )

    # ------------------------------------------------------------------
    # Basis-Snapshots
    # ------------------------------------------------------------------

    def store_snapshots(self, snapshots: list[RawSnapshot]) -> int:
        """Speichert eine Liste von Prozess-Snapshots. Gibt die Anzahl zurück."""
        if not snapshots:
            return 0
        rows = []
        for s in snapshots:
            h = s.anchor_hash or s.compute_hash()
            rows.append((
                s.ts, s.pid, s.name, s.cpu_percent,
                s.memory_rss, s.memory_vms,
                s.io_read_bytes, s.io_write_bytes,
                s.thread_count, s.status, s.ppid,
                s.integrity_level, h,
            ))
        with self._lock, self._conn() as con:
            con.executemany(
                """INSERT INTO process_snapshots
                   (ts,pid,name,cpu_percent,memory_rss,memory_vms,
                    io_read_bytes,io_write_bytes,thread_count,status,
                    ppid,integrity_level,anchor_hash)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
        return len(rows)

    def get_snapshots_for_process(
        self,
        name: str,
        since: float = 0.0,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Gibt gespeicherte Snapshots für einen bestimmten Prozessnamen zurück."""
        with self._lock, self._conn() as con:
            cur = con.execute(
                """SELECT * FROM process_snapshots
                   WHERE name=? AND ts>=?
                   ORDER BY ts DESC LIMIT ?""",
                (name, since, limit),
            )
            return [dict(row) for row in cur.fetchall()]

    def count_snapshots(self) -> int:
        with self._lock, self._conn() as con:
            cur = con.execute("SELECT COUNT(*) FROM process_snapshots")
            return int(cur.fetchone()[0])

    def purge_old_snapshots(self, older_than_seconds: float = 7 * 86400) -> int:
        """Löscht Snapshots, die älter als *older_than_seconds* sind."""
        cutoff = time.time() - older_than_seconds
        with self._lock, self._conn() as con:
            cur = con.execute(
                "DELETE FROM process_snapshots WHERE ts<?", (cutoff,)
            )
            return cur.rowcount

    # ------------------------------------------------------------------
    # Konsens-Anker (Ebene 2)
    # ------------------------------------------------------------------

    def build_consensus_anchors(self, window_seconds: float = 3600.0) -> int:
        """
        Aggregiert Basis-Snapshots des letzten Fensters zu Konsens-Ankern.
        Gibt die Anzahl neu erstellter Anker zurück.
        """
        now = time.time()
        since = now - window_seconds
        with self._lock, self._conn() as con:
            # Bekannte Prozessnamen im Fenster
            cur = con.execute(
                "SELECT DISTINCT name FROM process_snapshots WHERE ts>=?",
                (since,),
            )
            names = [row[0] for row in cur.fetchall()]

            created = 0
            for name in names:
                cur2 = con.execute(
                    """SELECT cpu_percent, memory_rss, thread_count
                       FROM process_snapshots
                       WHERE name=? AND ts>=?""",
                    (name, since),
                )
                rows = cur2.fetchall()
                if len(rows) < 3:
                    continue
                cpus = [r[0] for r in rows]
                rams = [r[1] for r in rows]
                threads = [r[2] for r in rows]
                avg_cpu = sum(cpus) / len(cpus)
                avg_ram = int(sum(rams) / len(rams))
                avg_thr = sum(threads) / len(threads)

                label = ""
                if avg_cpu > 50:
                    label = "high_cpu"
                elif avg_ram > 500 * 1024 * 1024:
                    label = "high_memory"

                sig = f"{name}|{round(avg_cpu,1)}|{avg_ram//65536}|{round(avg_thr,1)}|{label}"
                anchor_hash = hashlib.sha256(sig.encode()).hexdigest()

                con.execute(
                    """INSERT INTO consensus_anchors
                       (created_at,window_start,window_end,process_name,
                        avg_cpu,avg_memory_rss,avg_threads,sample_count,
                        pattern_label,anchor_hash)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (now, since, now, name, avg_cpu, avg_ram,
                     avg_thr, len(rows), label, anchor_hash),
                )
                created += 1
        return created

    def get_consensus_anchors(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._conn() as con:
            cur = con.execute(
                "SELECT * FROM consensus_anchors ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------
    # Meta-Anker (Ebene 3) — domänenübergreifende Muster
    # ------------------------------------------------------------------

    def detect_meta_anchors(self, min_correlation: float = 0.6) -> int:
        """
        Sucht in Konsens-Ankern nach zeitlichen Korrelationen zwischen
        Prozessen und speichert neue Meta-Anker.
        Gibt die Anzahl neu erkannter Muster zurück.
        """
        with self._lock, self._conn() as con:
            cur = con.execute(
                "SELECT process_name, avg_cpu, window_start FROM consensus_anchors ORDER BY window_start"
            )
            rows = cur.fetchall()

        # Gruppiere nach Zeitfenster (gleicher window_start ≈ gleiche Stunde)
        buckets: dict[int, dict[str, float]] = {}
        for row in rows:
            bucket_key = int(row[2] // 3600)
            if bucket_key not in buckets:
                buckets[bucket_key] = {}
            buckets[bucket_key][row[0]] = float(row[1])

        if len(buckets) < 2:
            return 0

        # Einfache Pearson-Korrelation zwischen CPU-Lasten von Prozesspaaren
        process_names = list({name for b in buckets.values() for name in b})
        created = 0
        checked: set[frozenset] = set()

        for i, a in enumerate(process_names):
            for b in process_names[i + 1:]:
                pair = frozenset({a, b})
                if pair in checked:
                    continue
                checked.add(pair)

                xs = [buckets[t].get(a, 0.0) for t in sorted(buckets)]
                ys = [buckets[t].get(b, 0.0) for t in sorted(buckets)]

                try:
                    n = len(xs)
                    if n < 3:
                        continue
                    mx = sum(xs) / n
                    my = sum(ys) / n
                    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / n
                    stdx = (sum((x - mx) ** 2 for x in xs) / n) ** 0.5
                    stdy = (sum((y - my) ** 2 for y in ys) / n) ** 0.5
                    if stdx < 0.01 or stdy < 0.01:
                        continue
                    corr = cov / (stdx * stdy)
                    corr = max(-1.0, min(1.0, corr))
                except Exception as e:
                    continue

                if abs(corr) >= min_correlation:
                    obs = (
                        f"Wenn '{a}' hohe CPU-Last hat, zeigt '{b}' "
                        f"{'ebenfalls hohe' if corr > 0 else 'niedrige'} CPU-Aktivität "
                        f"(Korrelation: {corr:.2f})"
                    )
                    sig = f"{a}|{b}|{round(corr, 2)}"
                    anch = hashlib.sha256(sig.encode()).hexdigest()
                    now = time.time()
                    with self._lock, self._conn() as con:
                        # Nur einfügen wenn noch nicht vorhanden
                        ex = con.execute(
                            "SELECT id FROM meta_anchors WHERE anchor_hash=?", (anch,)
                        ).fetchone()
                        if ex is None:
                            con.execute(
                                """INSERT INTO meta_anchors
                                   (created_at,trigger_name,effect_name,
                                    correlation,observation,anchor_hash)
                                   VALUES(?,?,?,?,?,?)""",
                                (now, a, b, corr, obs, anch),
                            )
                            created += 1

        return created

    def get_meta_anchors(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._conn() as con:
            cur = con.execute(
                "SELECT * FROM meta_anchors ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------
    # DBSCAN-Clustering von Konsens-Ankern (Ebene 2 → Meta-Ebene)
    # ------------------------------------------------------------------

    @staticmethod
    def _dbscan(points: list[list[float]], eps: float, min_samples: int) -> list[int]:
        """
        Reines Python DBSCAN — O(n²), ausreichend für ≤ 500 Anker.

        Rückgabe: Label-Liste (−1 = Rauschen, ≥ 0 = Cluster-ID).
        """
        n = len(points)
        if n == 0:
            return []
        labels: list[int] = [-1] * n
        visited: list[bool] = [False] * n
        cluster_id = 0
        dim = len(points[0])

        def _dist(i: int, j: int) -> float:
            return sum((points[i][k] - points[j][k]) ** 2 for k in range(dim)) ** 0.5

        def _neighbors(idx: int) -> list[int]:
            return [j for j in range(n) if j != idx and _dist(idx, j) <= eps]

        for i in range(n):
            if visited[i]:
                continue
            visited[i] = True
            nbs = _neighbors(i)
            if len(nbs) < min_samples:
                continue  # Rauschen vorerst
            labels[i] = cluster_id
            seed = list(nbs)
            while seed:
                j = seed.pop(0)
                if not visited[j]:
                    visited[j] = True
                    nbs2 = _neighbors(j)
                    if len(nbs2) >= min_samples:
                        seed.extend(nbs2)
                if labels[j] == -1:
                    labels[j] = cluster_id
            cluster_id += 1
        return labels

    def cluster_consensus_anchors(
        self,
        eps: float = 12.0,
        min_samples: int = 2,
        window_hours: float = 168.0,
    ) -> list[dict[str, Any]]:
        """
        Gruppiert Konsens-Anker mit DBSCAN im Feature-Raum
        (avg_cpu, avg_memory_rss_MB, avg_threads).

        eps        — Max. euklidischer Abstand (in normalisiertem Raum)
        min_samples — Mindestanzahl Punkte für einen Core-Point
        window_hours — Wie weit zurück Anker berücksichtigt werden

        Rückgabe: Liste von Cluster-Deskriptoren
          {
            "cluster_id": int,          # −1 = Rauschen
            "process_names": list[str],
            "centroid_cpu": float,
            "centroid_memory_mb": float,
            "centroid_threads": float,
            "size": int,
            "dominant_label": str,
          }
        """
        since = time.time() - window_hours * 3600.0
        with self._lock, self._conn() as con:
            cur = con.execute(
                """SELECT process_name, avg_cpu, avg_memory_rss, avg_threads, pattern_label
                   FROM consensus_anchors
                   WHERE created_at >= ?
                   ORDER BY created_at DESC""",
                (since,),
            )
            rows = cur.fetchall()

        if not rows:
            return []

        names: list[str] = [r[0] for r in rows]
        labels_raw: list[str] = [r[4] for r in rows]

        # Normalisierung: CPU 0–100, RAM → MB (/1024/1024), Threads 0–100
        def _norm(cpu: float, ram: int, thr: float) -> list[float]:
            return [cpu / 100.0 * 50.0, ram / (1024 * 1024), thr]

        points = [_norm(r[1], r[2], r[3]) for r in rows]
        cluster_labels = self._dbscan(points, eps=eps, min_samples=min_samples)

        # Aggregiere nach Cluster
        clusters: dict[int, dict[str, Any]] = {}
        for idx, cid in enumerate(cluster_labels):
            if cid not in clusters:
                clusters[cid] = {
                    "cluster_id": cid,
                    "process_names": [],
                    "_cpu": [],
                    "_mem": [],
                    "_thr": [],
                    "_labels": [],
                }
            clusters[cid]["process_names"].append(names[idx])
            clusters[cid]["_cpu"].append(rows[idx][1])
            clusters[cid]["_mem"].append(rows[idx][2] / (1024 * 1024))
            clusters[cid]["_thr"].append(rows[idx][3])
            clusters[cid]["_labels"].append(labels_raw[idx])

        result = []
        for cid, data in sorted(clusters.items()):
            n = len(data["_cpu"])
            dominant = max(
                set(l for l in data["_labels"] if l),
                key=data["_labels"].count,
                default="",
            ) if any(data["_labels"]) else ""
            result.append({
                "cluster_id": cid,
                "process_names": list(set(data["process_names"])),
                "centroid_cpu": round(sum(data["_cpu"]) / n, 2),
                "centroid_memory_mb": round(sum(data["_mem"]) / n, 2),
                "centroid_threads": round(sum(data["_thr"]) / n, 2),
                "size": n,
                "dominant_label": dominant,
            })
        return result

    # ------------------------------------------------------------------
    # Optimierungs-Log
    # ------------------------------------------------------------------

    def log_optimization(
        self,
        action_type: str,
        target: str,
        details: dict,
        rollback_data: dict,
        user_consented: bool = True,
    ) -> int:
        """Schreibt eine Optimierungsaktion ins Log. Gibt die neue ID zurück."""
        with self._lock, self._conn() as con:
            cur = con.execute(
                """INSERT INTO optimization_log
                   (ts,action_type,target,details,rollback_data,rolled_back,user_consented)
                   VALUES(?,?,?,?,?,0,?)""",
                (
                    time.time(), action_type, target,
                    json.dumps(details, ensure_ascii=False),
                    json.dumps(rollback_data, ensure_ascii=False),
                    int(user_consented),
                ),
            )
            return int(cur.lastrowid or 0)

    def mark_rolled_back(self, log_id: int) -> None:
        with self._lock, self._conn() as con:
            con.execute(
                "UPDATE optimization_log SET rolled_back=1 WHERE id=?", (log_id,)
            )

    def get_pending_rollbacks(self) -> list[dict[str, Any]]:
        """Gibt alle noch nicht rückgängig gemachten Optimierungsaktionen zurück."""
        with self._lock, self._conn() as con:
            cur = con.execute(
                "SELECT * FROM optimization_log WHERE rolled_back=0 ORDER BY ts DESC"
            )
            rows = []
            for row in cur.fetchall():
                d = dict(row)
                d["details"] = json.loads(d["details"] or "{}")
                d["rollback_data"] = json.loads(d["rollback_data"] or "{}")
                rows.append(d)
            return rows
