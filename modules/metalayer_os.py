"""metalayer_os.py — MetaLayer OS Phase C: Koordinierender Tick-Loop.

Führt alle MetaLayer-Subsysteme in einem adaptiven Tick-Loop zusammen.
Takt-Intervalle (konfiguierbar):
  1s   → Prozess-Snapshot
  5s   → Pixel-Mapping
  30s  → Thinning-Analyse
  300s → Pfad-Optimierung
  3600s → Vault-Commit + Shanway-Report

Alle Aktionen sind nicht-blockierend (asyncio).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from modules.process_pixel_mapper   import ProcessPixelMapper
from modules.process_thinning_engine import ProcessThinningEngine, ThinningProposal
from modules.pixel_coord_optimizer  import PixelCoordOptimizer, CoordMatrix

log = logging.getLogger("metalayer_os")

# ── Tick-Intervalle (Sekunden) ────────────────────────────────────────────────

TICK_PROCESS_SNAPSHOT  = 1
TICK_PIXEL_MAP         = 5
TICK_THINNING          = 30
TICK_PATH_OPTIMIZE     = 300
TICK_VAULT_REPORT      = 3600


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class MetaLayerStatus:
    """Aggregierter Betriebsstatus des MetaLayer OS."""
    tick_count: int = 0
    process_count: int = 0
    active_proposals: int = 0
    last_thinning_run: float = 0.0
    last_optimization_run: float = 0.0
    vault_committed_at: float = 0.0
    last_shanway_report: str = ""

    def to_dict(self) -> dict:
        return {
            "tick_count":            self.tick_count,
            "process_count":         self.process_count,
            "active_proposals":      self.active_proposals,
            "last_thinning_run":     self.last_thinning_run,
            "last_optimization_run": self.last_optimization_run,
            "vault_committed_at":    self.vault_committed_at,
            "last_shanway_report":   self.last_shanway_report,
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class MetaLayerOS:
    """
    Koordinierender Tick-Loop des MetaLayer OS.

    Parameters
    ----------
    consent_callback:
        Wird für Thinning-Proposals aufgerufen; muss True/False zurückgeben.
    shanway:
        Optionale Shanway-Pipeline (aus shanway_pipeline.py).
    vault:
        Optionaler Vault-Orchestrator zum periodischen Commit.
    hardware_profiler:
        Optionaler HardwareProfiler für adaptive Tick-Abstände.
    tick_overrides:
        Überschreibt Standard-Tick-Intervalle für Tests/spezielle Umgebungen.
    """

    def __init__(
        self,
        consent_callback: Optional[Callable[[ThinningProposal], bool]] = None,
        shanway: Optional[Any] = None,
        vault: Optional[Any] = None,
        hardware_profiler: Optional[Any] = None,
        tick_overrides: Optional[dict] = None,
    ) -> None:
        self._consent  = consent_callback or (lambda _: False)
        self._shanway  = shanway
        self._vault    = vault
        self._hw       = hardware_profiler

        overrides = tick_overrides or {}
        self._ticks = {
            "snapshot":   overrides.get("snapshot",   TICK_PROCESS_SNAPSHOT),
            "pixel_map":  overrides.get("pixel_map",  TICK_PIXEL_MAP),
            "thinning":   overrides.get("thinning",   TICK_THINNING),
            "path_opt":   overrides.get("path_opt",   TICK_PATH_OPTIMIZE),
            "vault":      overrides.get("vault",      TICK_VAULT_REPORT),
        }

        self._mapper   = ProcessPixelMapper()
        self._thinner  = ProcessThinningEngine(consent_callback=self._consent)
        self._optimizer = PixelCoordOptimizer()

        self._status   = MetaLayerStatus()
        self._running  = False

        # Letzte Ausführungszeiten
        self._last: dict[str, float] = {k: 0.0 for k in self._ticks}

        # Interne Datenspeicher
        self._latest_snapshots: list = []
        self._latest_coord_matrix: Optional[CoordMatrix] = None
        self._active_proposals: list = []

    # ── Steuerung ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Startet den adaptiven Tick-Loop. Läuft bis stop() aufgerufen wird."""
        self._running = True
        log.info("MetaLayerOS gestartet.")
        while self._running:
            now = time.monotonic()
            await self._dispatch_ticks(now)
            await asyncio.sleep(0.5)   # Basis-Tick 0.5s

    def stop(self) -> None:
        """Beendet den Tick-Loop beim nächsten Basis-Tick."""
        self._running = False
        log.info("MetaLayerOS gestoppt.")

    def get_status(self) -> MetaLayerStatus:
        """Gibt den aktuellen Betriebsstatus zurück."""
        self._status.active_proposals = len(self._active_proposals)
        return self._status

    # ── Tick-Dispatcher ───────────────────────────────────────────────────────

    async def _dispatch_ticks(self, now: float) -> None:
        """Prüft welche Ticks fällig sind und führt sie sequenziell aus."""

        if now - self._last["snapshot"] >= self._ticks["snapshot"]:
            await self._tick_process_snapshot()
            self._last["snapshot"] = now
            self._status.tick_count += 1

        if now - self._last["pixel_map"] >= self._ticks["pixel_map"]:
            await self._tick_pixel_map()
            self._last["pixel_map"] = now

        if now - self._last["thinning"] >= self._ticks["thinning"]:
            await self._tick_thinning()
            self._last["thinning"] = now
            self._status.last_thinning_run = time.time()

        if now - self._last["path_opt"] >= self._ticks["path_opt"]:
            await self._tick_path_optimization()
            self._last["path_opt"] = now
            self._status.last_optimization_run = time.time()

        if now - self._last["vault"] >= self._ticks["vault"]:
            await self._tick_vault_report()
            self._last["vault"] = now

    # ── Tick-Implementierungen ────────────────────────────────────────────────

    async def _tick_process_snapshot(self) -> None:
        """1s-Tick: Prozess-Snapshots aller Benutzerprozesse."""
        if not _PSUTIL:
            return
        snapshots = []
        SYSTEM_USERS = frozenset({"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"})
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "username", "cpu_percent",
                 "memory_info", "io_counters", "num_threads", "status", "ppid"]
            ):
                try:
                    info = proc.info
                    username = str(info.get("username") or "")
                    user_short = username.split("\\")[-1].upper()
                    if user_short in SYSTEM_USERS:
                        continue
                    mem = info.get("memory_info") or type("M", (), {"rss": 0, "vms": 0})()
                    io  = info.get("io_counters") or type("I", (), {"read_bytes": 0, "write_bytes": 0})()
                    snapshots.append(_SimpleSnapshot(
                        pid=int(info.get("pid") or 0),
                        name=str(info.get("name") or ""),
                        cpu_percent=float(info.get("cpu_percent") or 0.0),
                        memory_rss=int(getattr(mem, "rss", 0)),
                        memory_vms=int(getattr(mem, "vms", 0)),
                        io_read_bytes=int(getattr(io, "read_bytes", 0)),
                        io_write_bytes=int(getattr(io, "write_bytes", 0)),
                        thread_count=int(info.get("num_threads") or 1),
                        status=str(info.get("status") or ""),
                        ppid=int(info.get("ppid") or 0),
                    ))
                except Exception:
                    continue
        except Exception:
            pass
        self._latest_snapshots = snapshots
        self._status.process_count = len(snapshots)

    async def _tick_pixel_map(self) -> None:
        """5s-Tick: Pixel-Mapping aller Benutzerprozesse."""
        try:
            self._mapper.map_all_user_processes(max_count=24)
        except Exception as exc:
            log.debug("pixel_map tick error: %s", exc)

    async def _tick_thinning(self) -> None:
        """30s-Tick: Redundanz-Analyse + Thinning-Vorschläge."""
        if not self._latest_snapshots:
            return
        try:
            pixel_maps = {
                m.pid: m
                for m in self._mapper.map_all_user_processes(max_count=16)
            }
            results = []
            for snap in self._latest_snapshots:
                pmap = pixel_maps.get(snap.pid)
                result = self._thinner.compute_redundancy_score(
                    snap, pmap, self._latest_snapshots
                )
                results.append(result)
            twins = self._thinner.detect_behavioral_twins(self._latest_snapshots)
            proposals = self._thinner.suggest_thinning(results)
            self._active_proposals = proposals
            if proposals:
                log.info(
                    "Thinning: %d Vorschläge, %d Zwillingspaare erkannt.",
                    len(proposals), len(twins)
                )
        except Exception as exc:
            log.debug("thinning tick error: %s", exc)

    async def _tick_path_optimization(self) -> None:
        """300s-Tick: Globale Koordinatenmatrix + Pfad-Optimierungsvorschläge."""
        try:
            pids = [s.pid for s in self._latest_snapshots[:32]]
            matrix = self._optimizer.compute_global_coord_matrix(pids)
            self._latest_coord_matrix = matrix
            total_proposals = 0
            for entry in matrix.entries:
                path = self._optimizer.analyze_render_path(entry.pid)
                opts = self._optimizer.suggest_path_optimization(path)
                total_proposals += len(opts)
            log.info(
                "Pfad-Optimierung: %d Prozesse, %d Vorschläge, Engpässe: %s",
                len(matrix.entries), total_proposals, matrix.global_bottlenecks,
            )
        except Exception as exc:
            log.debug("path_opt tick error: %s", exc)

    async def _tick_vault_report(self) -> None:
        """3600s-Tick: Vault-Commit und Shanway-Strukturbericht."""
        try:
            # Vault-Commit (wenn verfügbar)
            if self._vault is not None:
                try:
                    status_bytes = str(self.get_status().to_dict()).encode()
                    commit_fn = getattr(self._vault, "commit", None)
                    if callable(commit_fn):
                        commit_fn(status_bytes)
                        self._status.vault_committed_at = time.time()
                except Exception as exc:
                    log.debug("vault commit error: %s", exc)

            # Shanway-Bericht (wenn verfügbar)
            if self._shanway is not None:
                try:
                    query = (
                        f"MetaLayer OS Stundenbericht: "
                        f"{self._status.process_count} Prozesse, "
                        f"{self._status.active_proposals} aktive Vorschläge, "
                        f"Engpässe={getattr(self._latest_coord_matrix, 'global_bottlenecks', [])}"
                    )
                    measure = getattr(self._shanway, "measure_consensus", None)
                    if callable(measure):
                        result = measure(query, [])
                        summary = getattr(result, "summary", str(result))
                        self._status.last_shanway_report = str(summary)[:400]
                        log.info("Shanway-Report: %s", self._status.last_shanway_report)
                except Exception as exc:
                    log.debug("shanway report error: %s", exc)
        except Exception as exc:
            log.debug("vault_report tick error: %s", exc)


# ── Hilfsklasse ───────────────────────────────────────────────────────────────

@dataclass
class _SimpleSnapshot:
    """Einfacher Prozess-Snapshot kompatibel mit ProcessThinningEngine."""
    pid: int
    name: str
    cpu_percent: float
    memory_rss: int
    memory_vms: int
    io_read_bytes: int
    io_write_bytes: int
    thread_count: int
    status: str
    ppid: int
    integrity_level: str = "medium"
    timestamp: float = field(default_factory=time.time)
