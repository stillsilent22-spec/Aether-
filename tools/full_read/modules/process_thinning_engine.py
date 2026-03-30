"""process_thinning_engine.py — MetaLayer OS Phase B: Process Thinning.

Erkennt redundante und twin-artige Prozesse (gleiche Verhaltenssignatur,
unterschiedliche PIDs) und schlägt Konsolidierungsmaßnahmen vor.
Jede Aktion erfordert explizite Nutzer-Zustimmung (consent).
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

try:
    import numpy as np
    _NUMPY = True
except ImportError:
    _NUMPY = False

from modules.process_pixel_mapper import ProcessPixelMap

# ── Schwellenwerte ────────────────────────────────────────────────────────────

REDUNDANCY_THRESHOLD  = 0.65   # Score ab dem ein Prozess "redundant" gilt
TWIN_CORRELATION      = 0.82   # Pearson-Korrelation für Zwillinge
MAX_HISTORY_FRAMES    = 8      # CPU/IO-Verlauf für Korrelation
ROLLBACK_DIR_KEY      = "rollback_path"


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class RedundancyResult:
    """Bewertung der Redundanz eines einzelnen Prozesses."""
    pid: int
    process_name: str
    score: float                    # [0, 1] — 1 = maximal redundant
    reasons: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "pid":          self.pid,
            "process_name": self.process_name,
            "score":        round(self.score, 4),
            "reasons":      self.reasons,
            "timestamp":    self.timestamp,
        }


@dataclass
class TwinPair:
    """Zwei Prozesse mit nahezu identischem Verhaltensprofil."""
    pid_a: int
    pid_b: int
    name_a: str
    name_b: str
    correlation: float              # [0, 1]
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "pid_a":       self.pid_a,
            "pid_b":       self.pid_b,
            "name_a":      self.name_a,
            "name_b":      self.name_b,
            "correlation": round(self.correlation, 4),
            "description": self.description,
        }


@dataclass
class ThinningProposal:
    """Ein konkreter, reversibler Thinning-Vorschlag."""
    entry: RedundancyResult
    expected_ram_gain_mb: float = 0.0
    expected_cpu_gain_pct: float = 0.0
    rollback_path: str = ""
    confidence: float = 0.0
    action: str = "terminate"       # "terminate" | "suspend" | "deprioritize"

    def to_dict(self) -> dict:
        return {
            "pid":                  self.entry.pid,
            "process_name":         self.entry.process_name,
            "redundancy_score":     round(self.entry.score, 4),
            "expected_ram_gain_mb": round(self.expected_ram_gain_mb, 2),
            "expected_cpu_gain_pct":round(self.expected_cpu_gain_pct, 2),
            "rollback_path":        self.rollback_path,
            "confidence":           round(self.confidence, 4),
            "action":               self.action,
            "reasons":              self.entry.reasons,
        }


@dataclass
class ThinningResult:
    """Ergebnis einer ausgeführten Thinning-Aktion."""
    applied: bool
    pid: int
    process_name: str
    success: bool
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "applied":      self.applied,
            "pid":          self.pid,
            "process_name": self.process_name,
            "success":      self.success,
            "error":        self.error,
            "timestamp":    self.timestamp,
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class ProcessThinningEngine:
    """
    Analysiert laufende Prozesse auf Redundanz und schlägt Thinning vor.

    Sicherheitsprinzip: Kein Prozess wird ohne explizite Nutzer-Zustimmung
    (consent_callback returniert True) beendet oder suspendiert.
    System-Prozesse werden grundsätzlich ignoriert.
    """

    PROTECTED_NAMES = frozenset({
        "system", "svchost.exe", "lsass.exe", "csrss.exe",
        "wininit.exe", "services.exe", "smss.exe", "winlogon.exe",
        "explorer.exe", "dwm.exe",
    })

    def __init__(
        self,
        consent_callback: Optional[Callable[[ThinningProposal], bool]] = None,
    ) -> None:
        self._consent = consent_callback or (lambda _: False)
        self._cpu_history: Dict[int, list] = {}   # pid → [cpu%, …]
        self._io_history:  Dict[int, list] = {}   # pid → [io_total, …]

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def compute_redundancy_score(
        self,
        snapshot: "ProcessSnapshot",                    # type: ignore[name-defined]
        pixel_map: Optional[ProcessPixelMap] = None,
        history: Optional[list] = None,
    ) -> RedundancyResult:
        """
        Berechnet einen Redundanz-Score [0, 1] für einen Prozess.

        Kriterien:
          - Geringe CPU-Auslastung über Zeit
          - Leerr / konstante IO-Aktivität
          - Keine sichtbare Pixel-Präsenz (leerer Pixel-Footprint)
          - Name kommt mehrfach vor (mögliche Duplikate)
        """
        reasons: list[str] = []
        score = 0.0

        pid  = int(getattr(snapshot, "pid", 0))
        name = str(getattr(snapshot, "name", "unknown"))
        cpu  = float(getattr(snapshot, "cpu_percent", 0.0))
        rss  = int(getattr(snapshot, "memory_rss", 0))

        # CPU-Verlauf aktualisieren
        self._cpu_history.setdefault(pid, []).append(cpu)
        if len(self._cpu_history[pid]) > MAX_HISTORY_FRAMES:
            self._cpu_history[pid].pop(0)

        # IO-Verlauf aktualisieren
        io_total = (
            int(getattr(snapshot, "io_read_bytes", 0))
            + int(getattr(snapshot, "io_write_bytes", 0))
        )
        self._io_history.setdefault(pid, []).append(io_total)
        if len(self._io_history[pid]) > MAX_HISTORY_FRAMES:
            self._io_history[pid].pop(0)

        # Bewertung: CPU
        cpu_hist = self._cpu_history[pid]
        mean_cpu = sum(cpu_hist) / len(cpu_hist)
        if mean_cpu < 0.5:
            score += 0.30
            reasons.append(f"mean_cpu={round(mean_cpu,2)}% < 0.5%")

        # Bewertung: IO-Stagnation
        io_hist = self._io_history[pid]
        if len(io_hist) >= 2:
            io_delta = abs(io_hist[-1] - io_hist[0])
            if io_delta == 0:
                score += 0.20
                reasons.append("io_delta=0 (keine IO-Aktivität)")

        # Bewertung: Kein Pixel-Footprint
        if pixel_map is not None:
            if pixel_map.total_screen_coverage_pct < 0.001:
                score += 0.25
                reasons.append("screen_coverage<0.1% (unsichtbar)")
            elif pixel_map.render_cost_score < 0.05:
                score += 0.10
                reasons.append("render_cost<5% (kaum Renderaufwand)")

        # Bewertung: Geringes RAM-Gewicht
        rss_mb = rss / (1024 * 1024)
        if rss_mb < 8.0:
            score += 0.15
            reasons.append(f"rss={round(rss_mb,1)}MB < 8MB")

        # Bewertung: History-basierte Deduplizierung
        if history:
            same_name = [h for h in history if str(getattr(h, "name", "")) == name]
            if len(same_name) > 1:
                score += 0.10
                reasons.append(f"name_collision: {len(same_name)}× '{name}'")

        score = min(1.0, score)
        return RedundancyResult(pid=pid, process_name=name, score=score, reasons=reasons)

    def detect_behavioral_twins(
        self, snapshots: list
    ) -> list[TwinPair]:
        """
        Findet Prozesspaare mit nahezu identischer CPU/IO-Verlaufssignatur.
        Verwendet Pearson-Korrelation über gespeicherte Verlaufsdaten.
        """
        pairs: list[TwinPair] = []
        pids = [int(getattr(s, "pid", 0)) for s in snapshots]
        names = {int(getattr(s, "pid", 0)): str(getattr(s, "name", "")) for s in snapshots}

        for i in range(len(pids)):
            for j in range(i + 1, len(pids)):
                pid_a = pids[i]
                pid_b = pids[j]
                corr = self._cpu_io_correlation(pid_a, pid_b)
                if corr >= TWIN_CORRELATION:
                    pairs.append(TwinPair(
                        pid_a=pid_a,
                        pid_b=pid_b,
                        name_a=names.get(pid_a, ""),
                        name_b=names.get(pid_b, ""),
                        correlation=corr,
                        description=(
                            f"Verhaltens-Zwillinge: CPU/IO-Korrelation {round(corr,3)}"
                        ),
                    ))
        return pairs

    def suggest_thinning(
        self, results: list[RedundancyResult]
    ) -> list[ThinningProposal]:
        """
        Erzeugt Thinning-Vorschläge aus RedundancyResults mit Score ≥ Schwelle.
        """
        proposals: list[ThinningProposal] = []
        for r in results:
            if r.score < REDUNDANCY_THRESHOLD:
                continue
            if r.process_name.lower() in self.PROTECTED_NAMES:
                continue
            ram_gain, cpu_gain = self._estimate_gains(r.pid)
            action = "deprioritize" if r.score < 0.85 else "terminate"
            proposals.append(ThinningProposal(
                entry=r,
                expected_ram_gain_mb=ram_gain,
                expected_cpu_gain_pct=cpu_gain,
                rollback_path="",       # kein automatischer Snapshot
                confidence=round(r.score * 0.9, 4),
                action=action,
            ))
        # Sortierung: höchster Score zuerst
        proposals.sort(key=lambda p: p.entry.score, reverse=True)
        return proposals

    def apply_with_consent(
        self, proposal: ThinningProposal, user_confirmed: bool = False
    ) -> ThinningResult:
        """
        Führt eine Thinning-Aktion aus, wenn Nutzer zugestimmt hat.

        Gibt immer ein ThinningResult zurück.  Wenn nicht bestätigt → applied=False.
        """
        pid  = proposal.entry.pid
        name = proposal.entry.process_name

        if not user_confirmed:
            granted = self._consent(proposal)
            if not granted:
                return ThinningResult(applied=False, pid=pid, process_name=name, success=False)

        if name.lower() in self.PROTECTED_NAMES:
            return ThinningResult(
                applied=True, pid=pid, process_name=name, success=False,
                error="protected_process"
            )

        if not _PSUTIL:
            return ThinningResult(
                applied=True, pid=pid, process_name=name, success=False,
                error="psutil_unavailable"
            )
        try:
            proc = psutil.Process(pid)
            action = proposal.action
            if action == "terminate":
                proc.terminate()
            elif action == "suspend":
                proc.suspend()
            elif action == "deprioritize":
                proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if hasattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS") else 10)  # type: ignore[attr-defined]
            return ThinningResult(applied=True, pid=pid, process_name=name, success=True)
        except psutil.NoSuchProcess:
            return ThinningResult(applied=True, pid=pid, process_name=name, success=False, error="no_such_process")
        except psutil.AccessDenied:
            return ThinningResult(applied=True, pid=pid, process_name=name, success=False, error="access_denied")
        except Exception as exc:
            return ThinningResult(applied=True, pid=pid, process_name=name, success=False, error=str(exc))

    # ── Hilfsfunktionen ───────────────────────────────────────────────────────

    def _cpu_io_correlation(self, pid_a: int, pid_b: int) -> float:
        """Pearson-Korrelation zwischen CPU-Verläufen von pid_a und pid_b."""
        a = self._cpu_history.get(pid_a, [])
        b = self._cpu_history.get(pid_b, [])
        n = min(len(a), len(b))
        if n < 2:
            return 0.0
        a = a[-n:]
        b = b[-n:]
        if not _NUMPY:
            return _pearson_pure(a, b)
        import numpy as np
        return float(np.corrcoef(a, b)[0, 1])

    def _estimate_gains(self, pid: int) -> tuple[float, float]:
        """Schätzt RAM- (MB) und CPU-Gewinn (%) bei Beendigung dieses Prozesses."""
        if not _PSUTIL:
            return 0.0, 0.0
        try:
            proc = psutil.Process(pid)
            ram_mb = proc.memory_info().rss / (1024 * 1024)
            cpu = proc.cpu_percent(interval=None)
            return round(ram_mb, 2), round(cpu, 2)
        except Exception:
            return 0.0, 0.0


# ── Reine Python-Hilfsfunktionen ──────────────────────────────────────────────

def _pearson_pure(a: list, b: list) -> float:
    n = len(a)
    if n < 2:
        return 0.0
    mean_a = sum(a) / n
    mean_b = sum(b) / n
    cov = sum((a[i] - mean_a) * (b[i] - mean_b) for i in range(n))
    var_a = sum((x - mean_a) ** 2 for x in a)
    var_b = sum((x - mean_b) ** 2 for x in b)
    denom = math.sqrt(var_a * var_b)
    return cov / denom if denom > 1e-12 else 0.0
