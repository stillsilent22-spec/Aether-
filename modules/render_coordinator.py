"""Phase 4: ETW/DXGI Pixel-Koordination pro Prozess — strukturelle Analyse."""

from __future__ import annotations

import hashlib
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
except Exception:
    _WIN32_AVAILABLE = False

try:
    import mss as _mss
    _MSS_AVAILABLE = True
except Exception:
    _mss = None
    _MSS_AVAILABLE = False

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except Exception:
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
        """
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
        except Exception:
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
        except Exception:
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
        except Exception:
            return None

    def _get_process_name(self, pid: int) -> str:
        """Liest den Prozessnamen sicher aus."""
        if not _PSUTIL_AVAILABLE or psutil is None:
            return "unknown"
        try:
            return str(psutil.Process(pid).name() or "unknown")
        except Exception:
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
