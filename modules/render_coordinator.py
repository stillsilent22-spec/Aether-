from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Phase 4: ETW/DXGI Pixel-Koordination pro Prozess — strukturelle Analyse."""


import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
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
        # Log-delta gating: normalized entropy of the last processed frame.
        # Gaming-Optimierung: Idle-Frames (Entropie ändert sich kaum) werden
        # übersprungen — nur Nutzerinteraktionen lösen die Cascade aus.
        self._last_entropy: float = 0.0

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
        previous_frame = self.last_snapshot
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
        if previous_frame is not None:
            self._record_render_transition(previous_frame, frame)
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
        previous_frame = self.last_snapshot
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
        # Off-by-One-Fix: recent[-max_repeats:] enthält max_repeats Einträge;
        # repeat_count >= max_repeats bedeutet ALLE sind identisch — aber das
        # erfordert max_repeats+1 identische Frames. Korrekte Logik:
        # Überspringe wenn der aktuelle Frame BEREITS zum zweiten Mal in Folge gleich ist,
        # d.h. repeat_count in den letzten max_repeats-1 Einträgen >= max_repeats-1.
        window = recent[-(self._pixel_hash_max_repeats - 1):] if self._pixel_hash_max_repeats > 1 else []
        repeat_count = sum(1 for h in window if h == pixel_hash)
        is_over_limit = repeat_count >= (self._pixel_hash_max_repeats - 1)
        recent.append(pixel_hash)
        if len(recent) > self._pixel_hash_dedup_size:
            recent.pop(0)
        if is_over_limit:
            logger.debug(f"[render_coordinator] Frame-Dedup ({pixel_hash[:12]}...) nach {repeat_count}x — Cascade übersprungen.")
            return frame

        # --- Unified deterministic cascade + swarm submission ---
        from modules.unified_cascade import cascade
        try:
            from modules.swarm_loop_bridge import submit_cascade_result as _submit_cascade
        except ImportError as _e:
            logger.debug(f"[render_coordinator] swarm_loop_bridge nicht verfügbar: {_e}")
            _submit_cascade = None
        session_key = None
        try:
            if hasattr(self, "_session_context") and self._session_context:
                sk = getattr(self._session_context, "session_key", None)
                session_key = sk.encode() if isinstance(sk, str) else sk
        except Exception as e:
            logger.warning(f"[render_coordinator] Fehler: {e}")
            pass
        if raw:
            # Log-delta gating (Weber-Fechner):
            #   "skip"  → Idle-Frame, keine Nutzerinteraktion erkennbar → Cascade überspringen
            #   "token" → kleines Delta → Token-Lookup zuerst, nur bei Miss full cascade
            #   "full"  → signifikante Änderung (z.B. Nutzerinteraktion) → volle Cascade
            try:
                from modules.math_utils import log_delta_gate, _shannon_entropy as _mu_ent
                _curr_h = _mu_ent(raw) / 8.0   # normiert auf [0, 1]
                _gate = log_delta_gate(_curr_h, self._last_entropy)
                self._last_entropy = _curr_h
            except Exception:
                _gate = "full"
                _curr_h = 0.0

            if _gate == "skip":
                # Idle-Frame — keine Cascade nötig, Frame trotzdem zurückgeben
                logger.debug(f"[render_coordinator] Idle-Frame übersprungen (log-delta gate).")
                return frame

            # "token" oder "full" → Token-Lookup → Cascade
            if _gate == "token":
                try:
                    from modules.algo_share import AutoPropagator as _AP
                    from modules.math_utils import legacy_tier_from_capability_score
                    _best_tok = _AP.instance().get_best_token_for_tier(tier=2)
                    if _best_tok is not None:
                        logger.debug(
                            f"[render_coordinator] Token-Route: {_best_tok['token_id'][:12]}… "
                            f"(fitness={_best_tok.get('fitness_score', 0):.3f})"
                        )
                        return frame   # Token-Route: Cascade nicht nötig
                except Exception:
                    pass
                # Kein Token gefunden → fall through to full cascade

            signing_key_path = Path("keys/node_private.key")
            signer_node_id = ""
            settings_path = Path("data/settings.json")
            if settings_path.is_file():
                try:
                    settings = json.loads(settings_path.read_text(encoding="utf-8"))
                    signer_node_id = str(settings.get("node_id", "") or "").strip()
                except Exception:
                    signer_node_id = ""
            if not signing_key_path.is_file():
                signing_key_path = None
            if signer_node_id == "":
                signer_node_id = ""

            cascade_result = cascade(
                raw,
                source_id=f"render_{pid}",
                source_type="render",
                session_key=session_key,
                signing_key_path=str(signing_key_path) if signing_key_path else None,
                signer_node_id=signer_node_id,
            )
            if _submit_cascade is not None:
                _submit_cascade(cascade_result, role="genesis")
            if previous_frame is not None:
                self._record_render_transition(previous_frame, frame)

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

    def _build_frame_state_fp(self, frame: RenderFrame) -> str:
        """Erzeugt einen stabilen, anonymisierten Zustandshash aus Frame-Metriken."""
        try:
            payload = (
                f"{round(frame.entropy, 6)}:"
                f"{round(frame.symmetry, 6)}:"
                f"{round(frame.resonance, 6)}:"
                f"{frame.frame_size}"
            )
            return hashlib.sha256(payload.encode("utf-8")).hexdigest()
        except Exception:
            return frame.pixel_hash

    def _context_key_from_frame(self, frame: RenderFrame) -> str:
        return f"render:{frame.process_name}" if frame.process_name else "render:unknown"

    def _record_render_transition(self, previous: RenderFrame, current: RenderFrame) -> None:
        """Schreibt eine selbstbeobachtete Transition in die PredictionEngine."""
        try:
            from modules.prediction_engine import PredictionEngine, DecisionSignal
            state_fp = self._build_frame_state_fp(previous)
            decision = DecisionSignal.from_invariant_delta(
                [previous.entropy, previous.symmetry, previous.resonance],
                [current.entropy, current.symmetry, current.resonance],
                signal_type="render_delta",
            )
            context_key = self._context_key_from_frame(current)
            decision.context_key = context_key
            PredictionEngine.instance().record_transition(
                state_fp,
                decision,
                current.pixel_hash,
                context_key=context_key,
            )
        except Exception as exc:
            logger.debug(f"[render_coordinator] prediction record_transition: {exc}")

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
        from modules.math_utils import _shannon_entropy as _se
        return _se(data)

    @staticmethod
    def _symmetry(data: bytes) -> float:
        from modules.math_utils import _symmetry as _sym
        return _sym(data)

    @staticmethod
    def _resonance(data: bytes) -> float:
        from modules.math_utils import _resonance as _res
        return _res(data)
