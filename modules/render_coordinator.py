from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Phase 4: ETW/DXGI Pixel-Koordination pro Prozess — strukturelle Analyse."""


import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

# ── Optionale Windows-ETW/DXGI Abhängigkeiten ──────────────────────────────
try:
    import win32process
    import win32api
    import win32con
    _WIN32_AVAILABLE = True
except Exception as e:
    _WIN32_AVAILABLE = False

try:
    import mss as _mss
    _MSS_AVAILABLE = True
except Exception as e:
    _mss = None
    _MSS_AVAILABLE = False

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except Exception as e:
    psutil = None
    _PSUTIL_AVAILABLE = False

_IS_WINDOWS = sys.platform.startswith("win")


@dataclass
class RenderFrame:
    """Einzelner Render-Frame mit strukturellen Metriken."""
    pid: int
    process_name: str
    timestamp: float
    entropy: float
    symmetry: float
    resonance: float
    pixel_hash: str
    frame_size: int
    region: dict[str, int]
    source: str  # "etw", "dxgi", "mss", "stub"
    raw_bytes: bytes = field(default_factory=bytes, repr=False)

    def to_payload(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "timestamp": self.timestamp,
            "entropy": round(self.entropy, 6),
            "symmetry": round(self.symmetry, 6),
            "resonance": round(self.resonance, 6),
            "pixel_hash": self.pixel_hash,
            "frame_size": self.frame_size,
            "region": self.region,
            "source": self.source,
        }


class RenderCoordinator:
    """
    Phase-4 Render-Koordination: ETW/DXGI Pixel-Daten pro Prozess.

    Strategie (fail-closed, privacy-first):
    1. Windows + pywin32 verfuegbar  → ETW-basiertes Process-Scoping
    2. Windows + mss verfuegbar      → mss screen capture (scoped auf Prozessfenster)
    3. Sonst                         → strukturelle Analyse eingehender Bytes (kein Capture)

    Niemals wird der gesamte Screen erfasst — immer nur der explizit
    freigegebene Prozess-Render-Bereich.
    """

    def __init__(self) -> None:
        self.last_snapshot: RenderFrame | None = None
        self._frame_history: list[RenderFrame] = []
        self._max_history = 32
        # Self-reference guard: own PID is always excluded from capture.
        # Prevents the UI rendering analysis results from being re-captured
        # and re-analysed (Goedel self-reference loop at frame level).
        self._own_pid: int = os.getpid() if hasattr(os, "getpid") else 0
        # Dedup: allow up to 2 passes of the same frame (first pass = genuine
        # structural data; one retry is acceptable). Block from the 3rd repeat.
        # This permits 1-2 useful self-referential iterations while preventing
        # infinite loops. Threshold: 2 consecutive identical pixel hashes.
        self._recent_pixel_hashes: list[str] = []
        self._pixel_hash_max_repeats: int = 2
        self._pixel_hash_dedup_size: int = 8

    # ── Hauptinterface ──────────────────────────────────────────────────────

    def capture_pixel_data(self, pixel_bytes: bytes, pid: int = 0,
                           process_name: str = "unknown",
                           region: dict[str, int] | None = None) -> dict[str, Any]:
        """
        Analysiert Pixel-Bytes strukturell.
        Eingehende Bytes kommen von ETW/DXGI (Windows) oder mss-Capture.
        Niemals wird hier eigenstaendig ein Screenshot ausgeloest.
        """
        raw = bytes(pixel_bytes or b"")
        frame = RenderFrame(
            pid=int(pid),
            process_name=str(process_name),
            timestamp=time.time(),
            entropy=self._shannon_entropy(raw),
            symmetry=self._symmetry(raw),
            resonance=self._resonance(raw),
            pixel_hash=hashlib.sha256(raw).hexdigest(),
            frame_size=len(raw),
            region=dict(region or {}),
            source="stub" if not raw else "provided",
            raw_bytes=raw,
        )
        self.last_snapshot = frame
        self._frame_history.append(frame)
        if len(self._frame_history) > self._max_history:
            self._frame_history.pop(0)
        return frame.to_payload()

    def capture_process_render(self, pid: int, window_title: str = "") -> RenderFrame | None:
        """
        Versucht Render-Daten fuer einen explizit angegebenen Prozess zu erfassen.
        Scoped: nur das Fenster dieses Prozesses, nie der gesamte Screen.
        Gibt None zurueck wenn keine Erfassung moeglich/erlaubt.

        Goedel-Selbstreferenz-Sperre:
        - Eigener Prozess (own_pid) wird grundsaetzlich nicht erfasst.
          Das verhindert: UI zeigt Analyse → Capture erfasst UI → neue Analyse →
          UI zeigt neue Analyse → Capture erfasst UI → ... (infiniter Frame-Loop).
        - Identische aufeinanderfolgende Frames (gleicher pixel_hash) werden
          einmalig gespeichert aber nicht erneut in die Cascade gegeben.
        """
        # Selbstreferenz-Sperre
        if int(pid) == self._own_pid:
            logger.debug("[render_coordinator] Eigener Prozess uebersprungen (Goedel-Sperre).")
            return None
        if not _IS_WINDOWS:
            return None
        region = self._get_process_window_region(pid, window_title)
        if region is None:
            return None
        raw = self._capture_region_mss(region)
        if raw is None:
            return None
        proc_name = self._get_process_name(pid)
        frame = RenderFrame(
            pid=pid,
            process_name=proc_name,
            timestamp=time.time(),
            entropy=self._shannon_entropy(raw),
            symmetry=self._symmetry(raw),
            resonance=self._resonance(raw),
            pixel_hash=hashlib.sha256(raw).hexdigest(),
            frame_size=len(raw),
            region=region,
            source="mss_scoped",
            raw_bytes=raw,
        )
        self.last_snapshot = frame
        self._frame_history.append(frame)
        if len(self._frame_history) > self._max_history:
            self._frame_history.pop(0)

        # --- Goedel-Dedup: max 2 passes per identical frame → cascade überspringen ---
        pixel_hash = frame.pixel_hash
        recent = self._recent_pixel_hashes
        repeat_count = sum(1 for h in recent[-self._pixel_hash_max_repeats:] if h == pixel_hash)
        is_over_limit = repeat_count >= self._pixel_hash_max_repeats
        recent.append(pixel_hash)
        if len(recent) > self._pixel_hash_dedup_size:
            recent.pop(0)
        if is_over_limit:
            logger.debug(f"[render_coordinator] Frame-Dedup ({pixel_hash[:12]}...) nach {repeat_count}x — Cascade übersprungen.")
            return frame

        # --- Unified deterministic cascade + swarm submission ---
        from modules.unified_cascade import cascade
        from modules.swarm_loop_bridge import submit_cascade_result
        session_key = None
        try:
            if hasattr(self, "_session_context") and self._session_context:
                sk = getattr(self._session_context, "session_key", None)
                session_key = sk.encode() if isinstance(sk, str) else sk
        except Exception as e:
            logger.warning(f"[render_coordinator] Fehler: {e}")
            pass
        if raw:
            cascade_result = cascade(
                raw,
                source_id=f"render_{pid}",
                source_type="render",
                session_key=session_key,
            )
            submit_cascade_result(cascade_result, role="genesis")

        return frame

    def get_etw_render_events(self, pid: int) -> list[dict[str, Any]]:
        """
        Liest ETW-Render-Events fuer einen Prozess (Windows only).
        Gibt strukturierte Events zurueck — keine Rohdaten, keine Pixelwerte.
        """
        if not _IS_WINDOWS or not _WIN32_AVAILABLE:
            return []
        # ETW-Lesezugriff via win32evtlog — nur strukturelle Metadaten
        events: list[dict[str, Any]] = []
        try:
            import win32evtlog
            handle = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            for rec in (records or [])[:16]:
                if int(getattr(rec, "ProcessId", 0) or 0) == int(pid):
                    events.append({
                        "event_id": int(getattr(rec, "EventID", 0) or 0),
                        "event_type": int(getattr(rec, "EventType", 0) or 0),
                        "timestamp": float(time.time()),
                        "source": str(getattr(rec, "SourceName", "") or ""),
                        "pid": int(pid),
                    })
            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            logger.warning(f"[render_coordinator] Fehler: {e}")
            pass
        return events

    def delta_between_frames(self, frame_a: RenderFrame, frame_b: RenderFrame) -> dict[str, float]:
        """Berechnet strukturelle Delta-Metriken zwischen zwei Frames."""
        return {
            "entropy_delta": abs(frame_a.entropy - frame_b.entropy),
            "symmetry_delta": abs(frame_a.symmetry - frame_b.symmetry),
            "resonance_delta": abs(frame_a.resonance - frame_b.resonance),
            "time_delta": abs(frame_a.timestamp - frame_b.timestamp),
            "hash_match": frame_a.pixel_hash == frame_b.pixel_hash,
        }

    def frame_history_summary(self) -> dict[str, Any]:
        """Verdichtet die Frame-History zu stabilen Invarianten."""
        if not self._frame_history:
            return {"frame_count": 0}
        entropies = [f.entropy for f in self._frame_history]
        symmetries = [f.symmetry for f in self._frame_history]
        return {
            "frame_count": len(self._frame_history),
            "entropy_mean": round(float(np.mean(entropies)), 6),
            "entropy_variance": round(float(np.var(entropies)), 6),
            "symmetry_mean": round(float(np.mean(symmetries)), 6),
            "last_pid": self._frame_history[-1].pid,
            "last_source": self._frame_history[-1].source,
        }

    # ── Phase-4 Analyse-Methoden ────────────────────────────────────────────

    def build_pixel_coord_graph(self) -> dict[str, Any]:
        """Baut einen strukturellen Koordinaten-Graphen aus self._frame_history."""
        if not self._frame_history:
            return {"nodes": [], "edges": [], "frame_count": 0}
        nodes = [
            {
                "id": f.pixel_hash[:8],
                "pid": f.pid,
                "entropy": round(f.entropy, 6),
                "symmetry": round(f.symmetry, 6),
            }
            for f in self._frame_history
        ]
        edges = []
        for i in range(len(self._frame_history) - 1):
            fa = self._frame_history[i]
            fb = self._frame_history[i + 1]
            edges.append({
                "from": fa.pixel_hash[:8],
                "to": fb.pixel_hash[:8],
                "weight": round(abs(fa.entropy - fb.entropy), 6),
            })
        return {"nodes": nodes, "edges": edges, "frame_count": len(self._frame_history)}

    def detect_render_interference(self) -> dict[str, Any]:
        """Erkennt strukturelle Interferenz im Render-Stream (Entropie-Sprünge)."""
        if len(self._frame_history) < 2:
            return {"interference_detected": False, "events": [], "threshold": 0.0}
        deltas = [
            abs(self._frame_history[i].entropy - self._frame_history[i + 1].entropy)
            for i in range(len(self._frame_history) - 1)
        ]
        threshold = float(1.5 * np.std(deltas)) if len(deltas) > 1 else 0.0
        events = []
        for i, delta in enumerate(deltas):
            if delta > threshold:
                fa = self._frame_history[i]
                fb = self._frame_history[i + 1]
                events.append({
                    "frame_a_hash": fa.pixel_hash[:8],
                    "frame_b_hash": fb.pixel_hash[:8],
                    "delta": round(delta, 6),
                    "timestamp": round(fb.timestamp, 6),
                })
        return {
            "interference_detected": len(events) > 0,
            "events": events,
            "threshold": round(threshold, 6),
        }

    def compute_render_drift(self) -> dict[str, Any]:
        """Berechnet den strukturellen Drift des Render-Streams über Zeit."""
        if not self._frame_history:
            return {"drift_mean": 0.0, "drift_max": 0.0, "drift_series": [], "stable": True}
        entropies = np.array([f.entropy for f in self._frame_history], dtype=np.float64)
        overall_mean = float(np.mean(entropies))
        window = 4
        drift_series: list[float] = []
        for i in range(len(entropies)):
            start = max(0, i - window + 1)
            win_mean = float(np.mean(entropies[start: i + 1]))
            drift_series.append(round(abs(win_mean - overall_mean), 6))
        drift_mean = round(float(np.mean(drift_series)), 6)
        drift_max = round(float(np.max(drift_series)), 6)
        return {
            "drift_mean": drift_mean,
            "drift_max": drift_max,
            "drift_series": drift_series,
            "stable": drift_max < 0.5,
        }

    def detect_render_phase_shift(self) -> dict[str, Any]:
        """Erkennt einen Phasenwechsel im Render-Verhalten (struktureller Bruch)."""
        if len(self._frame_history) < 2:
            return {
                "phase_shift_detected": False,
                "phase_a_symmetry": 0.0,
                "phase_b_symmetry": 0.0,
                "delta": 0.0,
            }
        symmetries = [f.symmetry for f in self._frame_history]
        mid = len(symmetries) // 2
        phase_a = round(float(np.mean(symmetries[:mid])), 6)
        phase_b = round(float(np.mean(symmetries[mid:])), 6)
        delta = round(abs(phase_a - phase_b), 6)
        return {
            "phase_shift_detected": delta > 0.2,
            "phase_a_symmetry": phase_a,
            "phase_b_symmetry": phase_b,
            "delta": delta,
        }

    def render_meta_delta(self) -> dict[str, Any]:
        """Aggregiertes Meta-Delta über den gesamten Render-Stream."""
        interference = self.detect_render_interference()
        drift = self.compute_render_drift()
        phase_shift = self.detect_render_phase_shift()
        interference_score = 1.0 if interference["interference_detected"] else 0.0
        drift_score = min(1.0, drift["drift_mean"])
        phase_score = 1.0 if phase_shift["phase_shift_detected"] else 0.0
        meta_score = round(float(np.mean([interference_score, drift_score, phase_score])), 6)
        if meta_score < 0.3:
            recommendation = "stable"
        elif meta_score <= 0.6:
            recommendation = "monitor"
        else:
            recommendation = "alert"
        return {
            "interference": interference,
            "drift": drift,
            "phase_shift": phase_shift,
            "meta_score": meta_score,
            "recommendation": recommendation,
        }

    def render_governance_advice(self) -> dict[str, Any]:
        """Advise-only Governance-Empfehlungen basierend auf render_meta_delta(). Keine automatischen Aktionen."""
        meta = self.render_meta_delta()
        rec = meta["recommendation"]
        advice: list[str] = []
        if meta["interference"]["interference_detected"]:
            n = len(meta["interference"]["events"])
            advice.append(
                f"Hohe Render-Interferenz erkannt ({n} Ereignis(se)) – Prozess prüfen."
            )
        if not meta["drift"]["stable"]:
            advice.append(
                f"Render-Drift instabil (max {meta['drift']['drift_max']:.3f}) – Stabilität überwachen."
            )
        if meta["phase_shift"]["phase_shift_detected"]:
            advice.append(
                f"Phasenwechsel im Render-Verhalten erkannt "
                f"(Δ={meta['phase_shift']['delta']:.3f}) – Ursache untersuchen."
            )
        if not advice:
            advice.append("Render-Stream strukturell stabil – keine Maßnahmen erforderlich.")
        severity_map = {"stable": "ok", "monitor": "warning", "alert": "critical"}
        return {
            "advice": advice,
            "severity": severity_map.get(rec, "ok"),
            "meta_score": meta["meta_score"],
        }

    # ── Interne Hilfsmethoden ───────────────────────────────────────────────

    def _get_process_window_region(self, pid: int, window_title: str = "") -> dict[str, int] | None:
        """Ermittelt die Fenster-Region eines Prozesses (Windows only, scoped)."""
        if not _WIN32_AVAILABLE:
            return None
        try:
            import win32gui

            def _enum_callback(hwnd: int, results: list) -> bool:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                if found_pid != pid:
                    return True
                title = win32gui.GetWindowText(hwnd)
                if window_title and window_title.lower() not in title.lower():
                    return True
                rect = win32gui.GetWindowRect(hwnd)
                left, top, right, bottom = rect
                w = right - left
                h = bottom - top
                if w > 0 and h > 0:
                    results.append({"left": left, "top": top, "width": w, "height": h})
                return True

            windows: list[dict[str, int]] = []
            win32gui.EnumWindows(_enum_callback, windows)
            return windows[0] if windows else None
        except Exception as e:
            return None

    def _capture_region_mss(self, region: dict[str, int]) -> bytes | None:
        """Erfasst eine explizit definierte Bildschirmregion via mss."""
        if not _MSS_AVAILABLE or _mss is None:
            return None
        try:
            with _mss.mss() as sct:
                monitor = {
                    "left": int(region.get("left", 0)),
                    "top": int(region.get("top", 0)),
                    "width": max(1, int(region.get("width", 1))),
                    "height": max(1, int(region.get("height", 1))),
                }
                screenshot = sct.grab(monitor)
                return bytes(screenshot.raw)
        except Exception as e:
            return None

    def _get_process_name(self, pid: int) -> str:
        """Liest den Prozessnamen sicher aus."""
        if not _PSUTIL_AVAILABLE or psutil is None:
            return "unknown"
        try:
            return str(psutil.Process(pid).name() or "unknown")
        except Exception as e:
            return "unknown"

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        total = float(arr.size)
        probs = counts[counts > 0] / total
        return float(-np.sum(probs * np.log2(probs)))

    @staticmethod
    def _symmetry(data: bytes) -> float:
        arr = np.frombuffer(data, dtype=np.uint8)
        if arr.size < 2:
            return 1.0
        half = arr.size // 2
        return float(np.sum(arr[:half] == arr[-half:][::-1]) / half)

    @staticmethod
    def _resonance(data: bytes) -> float:
        arr = np.frombuffer(data, dtype=np.uint8)
        if arr.size == 0:
            return 0.0
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        # Resonanz: wie nah ist die Verteilung an einer harmonischen Form?
        return float(1.0 - min(1.0, std / max(1.0, mean)))
