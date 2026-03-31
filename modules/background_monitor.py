"""
Aether – Hintergrundüberwachung (Cross-Platform).

Startet einen Hintergrund-Thread, der regelmäßig Prozess-Snapshots
aufnimmt, als Basis-Anker in SQLite speichert und stündlich
Konsens-Anker sowie Meta-Anker ableitet.

Plattform:
  - Windows: Kann als geplante Aufgabe oder normaler Hintergrund-Thread laufen.
  - Linux:   Als systemd-Unit einrichtbar (see docs/service_setup.md).
  - macOS:   Als launchd plist einrichtbar.

Privacy:
  - Nur strukturelle Metadaten (CPU, RAM, IO, Threads).
  - Keine Prozessinhalte, keine Screenshots, keine Netzwerkdaten.
  - Alle Daten bleiben lokal.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Callable

try:
    from .process_monitor import ProcessMonitor, ProcessSnapshot
    from .process_anchor_store import ProcessAnchorStore, RawSnapshot
except ImportError as e:
    from modules.process_monitor import ProcessMonitor, ProcessSnapshot
    from modules.process_anchor_store import ProcessAnchorStore, RawSnapshot

try:
    import psutil
    _PSUTIL_OK = True
except Exception as e:
    psutil = None  # type: ignore
    _PSUTIL_OK = False

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "process_anchors.db"
_DEFAULT_INTERVAL = 30          # Sekunden zwischen Snapshots
_CONSENSUS_INTERVAL = 3600      # Stündlich Konsens-Anker bauen
_META_INTERVAL = 7200           # Alle 2 Stunden Meta-Anker suchen
_MAX_SNAPSHOTS_AGE = 7 * 86400  # 7 Tage Aufbewahrung


class BackgroundMonitor:
    """
    Hintergrundüberwachung für laufende Prozesse.

    Kann in einem eigenen Thread laufen oder als Daemon-Prozess.
    Thread-sicher durch interne Locks.

    Beispiel:
        monitor = BackgroundMonitor(interval=30)
        monitor.start()
        # ... später:
        monitor.stop()
        report = monitor.get_report()
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        interval: float = _DEFAULT_INTERVAL,
        on_snapshot_batch: Callable[[int], None] | None = None,
    ) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._interval = max(5.0, float(interval))
        self._on_snapshot_batch = on_snapshot_batch
        self._store = ProcessAnchorStore(self._db_path)
        self._monitor = ProcessMonitor()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._snapshots_taken = 0
        self._runs = 0
        self._last_consensus = 0.0
        self._last_meta = 0.0
        self._last_purge = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Startet den Hintergrund-Thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                logger.debug("BackgroundMonitor already running.")
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="aether-monitor",
                daemon=True,
            )
            self._thread.start()
            logger.info("BackgroundMonitor started (interval=%.0fs, db=%s)",
                        self._interval, self._db_path)

    def stop(self, timeout: float = 10.0) -> None:
        """Stoppt den Hintergrund-Thread gracefully."""
        self._stop_event.set()
        with self._lock:
            t = self._thread
        if t is not None:
            t.join(timeout=timeout)
        logger.info("BackgroundMonitor stopped.")

    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def get_report(self) -> dict:
        """Gibt einen kompakten Status-Bericht zurück."""
        return {
            "running": self.is_running(),
            "snapshots_taken": self._snapshots_taken,
            "runs": self._runs,
            "interval_seconds": self._interval,
            "db_path": str(self._db_path),
            "stored_count": self._store.count_snapshots(),
            "meta_anchors": self._store.get_meta_anchors(limit=5),
            "consensus_anchors": self._store.get_consensus_anchors(limit=5),
        }

    def set_interval(self, seconds: float) -> None:
        """Ändert das Überwachungsintervall zur Laufzeit."""
        self._interval = max(5.0, float(seconds))
        logger.info("Monitoring interval set to %.0fs", self._interval)

    def force_consensus(self) -> int:
        """Erzwingt sofortige Konsens-Anker-Berechnung."""
        return self._store.build_consensus_anchors()

    def force_meta(self) -> int:
        """Erzwingt sofortige Meta-Anker-Suche."""
        return self._store.detect_meta_anchors()

    # ------------------------------------------------------------------
    # Interne Loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        logger.debug("Monitor loop starting.")
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                logger.warning("Monitor tick error: %s", exc)
            self._stop_event.wait(timeout=self._interval)

        # Letzter Aufräum-Lauf
        try:
            self._store.purge_old_snapshots(_MAX_SNAPSHOTS_AGE)
        except Exception as e:
            logger.warning(f"[background_monitor] Fehler: {e}")
            pass
        logger.debug("Monitor loop ended.")

    def _tick(self) -> None:
        self._runs += 1
        now = time.time()
        snapshots = self._collect_snapshots()
        if snapshots:
            count = self._store.store_snapshots(snapshots)
            self._snapshots_taken += count
            if self._on_snapshot_batch:
                try:
                    self._on_snapshot_batch(count)
                except Exception as e:
                    logger.warning(f"[background_monitor] Fehler: {e}")
                    pass

        # Stündlich: Konsens-Anker
        if now - self._last_consensus >= _CONSENSUS_INTERVAL:
            try:
                n = self._store.build_consensus_anchors()
                if n:
                    logger.info("Built %d consensus anchors.", n)
            except Exception as exc:
                logger.warning("Consensus anchor error: %s", exc)
            self._last_consensus = now

        # 2-stündlich: Meta-Anker
        if now - self._last_meta >= _META_INTERVAL:
            try:
                n = self._store.detect_meta_anchors()
                if n:
                    logger.info("Detected %d meta anchors.", n)
            except Exception as exc:
                logger.warning("Meta anchor error: %s", exc)
            self._last_meta = now

        # Täglich: alte Snapshots aufräumen
        if now - self._last_purge >= 86400:
            try:
                deleted = self._store.purge_old_snapshots(_MAX_SNAPSHOTS_AGE)
                if deleted:
                    logger.info("Purged %d old snapshots.", deleted)
            except Exception as e:
                logger.warning(f"[background_monitor] Fehler: {e}")
                pass
            self._last_purge = now

    def _collect_snapshots(self) -> list[RawSnapshot]:
        """Sammelt Snapshots aller laufenden Prozesse (ohne SYSTEM-Prozesse)."""
        results: list[RawSnapshot] = []
        if not _PSUTIL_OK or psutil is None:
            return results

        now = time.time()
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_info",
                 "io_counters", "num_threads", "status", "ppid"]
            ):
                try:
                    info = proc.info or {}
                    name = str(info.get("name") or "").strip()
                    if not name:
                        continue

                    mem = info.get("memory_info")
                    rss = int(mem.rss) if mem else 0
                    vms = int(mem.vms) if mem else 0

                    io = info.get("io_counters")
                    io_r = int(io.read_bytes) if io else 0
                    io_w = int(io.write_bytes) if io else 0

                    snap = RawSnapshot(
                        ts=now,
                        pid=int(info.get("pid") or 0),
                        name=name,
                        cpu_percent=float(info.get("cpu_percent") or 0.0),
                        memory_rss=rss,
                        memory_vms=vms,
                        io_read_bytes=io_r,
                        io_write_bytes=io_w,
                        thread_count=int(info.get("num_threads") or 1),
                        status=str(info.get("status") or ""),
                        ppid=int(info.get("ppid") or 0),
                        integrity_level="n/a",
                    )
                    snap.anchor_hash = snap.compute_hash()
                    results.append(snap)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.warning(f"[background_monitor] Fehler: {e}")
                    pass
                except Exception as e:
                    logger.warning(f"[background_monitor] Fehler: {e}")
                    pass
        except Exception as exc:
            logger.warning("Error iterating processes: %s", exc)

        return results


# ---------------------------------------------------------------------------
# Standalone-Modus (python -m modules.background_monitor)
# ---------------------------------------------------------------------------

def _run_standalone(interval: float = 30.0, db_path: str | None = None) -> None:
    """Startet den Monitor als Standalone-Prozess (für Dienst-Einrichtung)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info("Aether BackgroundMonitor standalone start (interval=%.0fs)", interval)

    db = Path(db_path) if db_path else _DEFAULT_DB_PATH
    monitor = BackgroundMonitor(db_path=db, interval=interval)
    monitor.start()

    # Graceful shutdown bei SIGTERM/SIGINT
    def _shutdown(signum, frame):  # type: ignore[type-arg]
        logger.info("Shutdown signal received.")
        monitor.stop(timeout=15)
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # Blockieren bis Shutdown
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt as e:
        logger.warning(f"[background_monitor] Fehler: {e}")
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Aether BackgroundMonitor")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="Snapshot-Intervall in Sekunden (Standard: 30)")
    parser.add_argument("--db", type=str, default=None,
                        help="Pfad zur SQLite-Datenbankdatei")
    args = parser.parse_args()
    _run_standalone(interval=args.interval, db_path=args.db)
