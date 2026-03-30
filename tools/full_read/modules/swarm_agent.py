"""Persistent Background Agent for Aether Swarm.

Subscribes to SwarmController and manages the capture + analysis lifecycle:
  - SWARM_MODE=true  → start CaptureAdapter + DeltaPipeline
  - SWARM_MODE=false → graceful shutdown

Resource caps (configurable via settings.json):
  - max_cpu_percent: max CPU load before adaptive throttling (default 15%)
  - max_fps:         max capture frames per second (default 2.0)
  - ring_size:       frame ring buffer depth (default 4)

Privacy rules (enforced, non-negotiable):
  - Raw frames are NEVER written to disk.
  - Only SHA256 fingerprints and aggregated metrics are persisted.
  - Delta pipeline produces non-invertible outputs only.

Lifecycle:
  - start()       → begin controller poll + agent loop
  - stop()        → graceful shutdown (waits for current frame to finish)
  - health_check()→ returns health dict
  - is_running()  → True while agent loop is active
"""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

from modules.capture_adapter import CaptureAdapterBase, FrameData, StubCaptureAdapter, make_capture_adapter
from modules.swarm_controller import INTERBUS_DIR, STATUS_PATH, SwarmController, _utc_now


# --------------------------------------------------------------------------- #
#   Delta Pipeline (frame → metrics → fingerprint)                            #
# --------------------------------------------------------------------------- #

class DeltaPipeline:
    """Convert captured frames into structured metrics and non-invertible fingerprints."""

    def __init__(self) -> None:
        self._prev_fingerprint: Optional[str] = None
        self._frame_index: int = 0

    def process(self, frame: FrameData) -> Dict[str, Any]:
        """Process one frame. Returns metrics + fingerprint. Never stores raw pixels."""
        metrics = frame.metrics()
        fp = frame.fingerprint()
        changed = fp != self._prev_fingerprint
        delta_marker = "new" if self._prev_fingerprint is None else ("changed" if changed else "stable")
        self._prev_fingerprint = fp
        self._frame_index += 1
        return {
            "frame_index": self._frame_index,
            "timestamp": frame.timestamp,
            "fingerprint": fp,
            "delta_marker": delta_marker,
            "adapter_id": frame.adapter_id,
            **metrics,
        }

    def reset(self) -> None:
        self._prev_fingerprint = None
        self._frame_index = 0


# --------------------------------------------------------------------------- #
#   SwarmAgent                                                                 #
# --------------------------------------------------------------------------- #

class SwarmAgent:
    """Persistent background agent for Swarm capture and analysis."""

    def __init__(
        self,
        controller: Optional[SwarmController] = None,
        adapter_type: str = "desktop",
        max_fps: float = 2.0,
        ring_size: int = 4,
        max_cpu_percent: float = 15.0,
        poll_interval: float = 1.0,
        persist_path: Optional[str] = None,
    ) -> None:
        self._controller = controller
        self._adapter_type = adapter_type
        self._max_fps = max_fps
        self._ring_size = ring_size
        self._max_cpu_percent = max_cpu_percent
        self._poll_interval = poll_interval

        # Import swarm_persist lazily (avoids circular imports)
        if persist_path is None:
            self._persist_path = str(ROOT / "data" / "swarm_metrics.db")
        else:
            self._persist_path = persist_path

        self._stop_event = threading.Event()
        self._agent_thread: Optional[threading.Thread] = None
        self._capture: Optional[CaptureAdapterBase] = None
        self._pipeline = DeltaPipeline()
        self._lock = threading.RLock()

        # State tracking
        self._capture_active: bool = False
        self._frame_count: int = 0
        self._error_count: int = 0
        self._last_metrics: Dict[str, Any] = {}
        self._started_at: Optional[str] = None
        self._cpu_usage: float = 0.0
        self._last_health_check: float = 0.0  # Adaptive FPS: track last health sync
        self._last_overlap_check: float = 0.0  # Domain-overlap detection interval

    # ---- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._agent_thread and self._agent_thread.is_alive():
            return
        self._stop_event.clear()
        self._agent_thread = threading.Thread(
            target=self._agent_loop, daemon=True, name="swarm-agent"
        )
        self._agent_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._stop_capture()
        if self._agent_thread:
            self._agent_thread.join(timeout=5.0)
        self._agent_thread = None

    def is_running(self) -> bool:
        return bool(self._agent_thread and self._agent_thread.is_alive())

    # ---- Health ------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        cpu = self._sample_cpu()
        return {
            "ok": True,
            "agent_running": self.is_running(),
            "capture_active": self._capture_active,
            "frame_count": self._frame_count,
            "error_count": self._error_count,
            "cpu_percent": round(cpu, 1),
            "max_cpu_percent": self._max_cpu_percent,
            "adapter_type": self._adapter_type,
            "max_fps": self._max_fps,
            "ring_size": self._ring_size,
            "started_at": self._started_at,
            "last_metrics": self._last_metrics,
            "updated_at": _utc_now(),
        }

    # ---- Agent loop --------------------------------------------------------

    def _agent_loop(self) -> None:
        self._started_at = _utc_now()
        print("[SWARM-AGENT] Agent loop started")
        swarm_was_enabled = False

        while not self._stop_event.is_set():
            try:
                swarm_enabled = self._read_swarm_mode()

                if swarm_enabled and not swarm_was_enabled:
                    print("[SWARM-AGENT] SWARM_MODE enabled — starting capture")
                    self._start_capture()
                    swarm_was_enabled = True

                elif not swarm_enabled and swarm_was_enabled:
                    print("[SWARM-AGENT] SWARM_MODE disabled — stopping capture")
                    self._stop_capture()
                    swarm_was_enabled = False

                if self._capture_active and self._capture is not None:
                    self._process_frames()
                    self._adapt_cpu()

                # Adaptive FPS: check swarm health every 5 seconds
                now = time.monotonic()
                if now - self._last_health_check > 5.0:
                    self._adjust_fps_from_health()
                    self._last_health_check = now

                # Domain-overlap detection every 5 minutes
                if now - self._last_overlap_check > 300.0:
                    self._last_overlap_check = now
                    try:
                        from modules.swarm_overlap import detect_and_publish_overlaps
                        found = detect_and_publish_overlaps()
                        if found:
                            print(f"[SWARM-AGENT] {found} new domain overlap event(s) published")
                    except Exception as _oe:
                        print(f"[SWARM-AGENT] overlap detection error: {_oe}")

            except Exception as err:
                self._error_count += 1
                print(f"[SWARM-AGENT] loop error #{self._error_count}: {err}")
                time.sleep(2.0)

            time.sleep(self._poll_interval)

        self._stop_capture()
        print("[SWARM-AGENT] Agent loop stopped")

    def _read_swarm_mode(self) -> bool:
        """Read SWARM_MODE from controller or status file."""
        if self._controller is not None:
            return self._controller.enabled
        # File-based fallback
        try:
            if STATUS_PATH.is_file():
                raw = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
                return bool(raw.get("swarm_mode", False))
        except Exception:
            pass
        return False

    def _start_capture(self) -> None:
        with self._lock:
            if self._capture_active:
                return
            try:
                self._capture = make_capture_adapter(
                    self._adapter_type,
                    ring_size=self._ring_size,
                    max_fps=self._max_fps,
                )
            except Exception:
                # Fallback to stub if desktop capture unavailable
                self._capture = StubCaptureAdapter(ring_size=self._ring_size, max_fps=self._max_fps)
            self._pipeline.reset()
            self._capture.start()
            self._capture_active = True

    def _stop_capture(self) -> None:
        with self._lock:
            if not self._capture_active:
                return
            if self._capture is not None:
                try:
                    self._capture.stop()
                except Exception:
                    pass
                self._capture = None
            self._capture_active = False

    def _process_frames(self) -> None:
        """Drain ring buffer, process each frame through delta pipeline."""
        if self._capture is None:
            return

        processed = 0
        while True:
            # Stop if swarm disabled or agent stopping
            if self._stop_event.is_set():
                break
            if self._controller is not None and not self._controller.enabled:
                # Stop capture immediately to avoid waiting for the next poll cycle.
                self._stop_capture()
                break
            frame = self._capture.read_and_consume()
            if frame is None:
                break
            try:
                result = self._pipeline.process(frame)
                self._last_metrics = result
                self._frame_count += 1
                processed += 1
                self._persist_result(result)
            except Exception as err:
                self._error_count += 1
                print(f"[SWARM-AGENT] frame process error: {err}")
            if processed >= 8:
                # Don't starve the loop
                break

    def _persist_result(self, result: Dict[str, Any]) -> None:
        """Persist only metrics and fingerprint (never raw frames)."""
        try:
            from modules.swarm_persist import append_frame_metrics
            append_frame_metrics(result, db_path=self._persist_path)
        except Exception as err:
            print(f"[SWARM-AGENT] persist error: {err}")

    def _adapt_cpu(self) -> None:
        """Adaptive throttling: reduce fps if CPU exceeds cap."""
        cpu = self._sample_cpu()
        self._cpu_usage = cpu
        if self._capture is None:
            return
        if cpu > self._max_cpu_percent * 1.5:
            # Aggressively throttle
            self._capture.set_adaptive_fps(max(0.1, self._capture._adaptive_fps * 0.5))
        elif cpu > self._max_cpu_percent:
            self._capture.set_adaptive_fps(max(0.1, self._capture._adaptive_fps * 0.8))
        elif cpu < self._max_cpu_percent * 0.5 and self._capture._adaptive_fps < self._max_fps:
            # Recover toward max_fps when CPU is low
            self._capture.set_adaptive_fps(min(self._max_fps, self._capture._adaptive_fps * 1.1))

    @staticmethod
    def _sample_cpu() -> float:
        if _PSUTIL_OK:
            try:
                return float(psutil.cpu_percent(interval=None))
            except Exception:
                pass
        return 0.0

    def _adjust_fps_from_health(self) -> None:
        """Adaptive FPS based on swarm health_score: high health → higher FPS."""
        try:
            from modules.swarm_health import get_swarm_status
            status = get_swarm_status()
            health_score = status.get("health_score", 0.5)
            quorum_reachable = status.get("quorum_reachable", False)
            
            if self._capture is None:
                return
            
            # health_score [0.0, 1.0] maps to fps [0.5, max_fps]
            target_fps = 0.5 + health_score * (self._max_fps - 0.5)
            
            # If quorum not reachable, reduce to conservative baseline
            if not quorum_reachable:
                target_fps = min(target_fps, 1.0)
            
            with self._lock:
                self._capture.set_adaptive_fps(target_fps)
                if health_score < 0.3:
                    print(f"[SWARM-AGENT] Health degraded: {health_score:.2f}, throttling FPS to {target_fps:.2f}")
        except Exception as err:
            print(f"[SWARM-AGENT] health check failed: {err}")


# --------------------------------------------------------------------------- #
#  Entry point (standalone daemon)                                             #
# --------------------------------------------------------------------------- #

def _load_agent_config() -> Dict[str, Any]:
    """Load agent config from data/settings.json."""
    settings_path = ROOT / "data" / "settings.json"
    try:
        if settings_path.is_file():
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
            return dict(raw.get("swarm_agent", {}))
    except Exception:
        pass
    return {}


def run_agent_daemon() -> None:
    """Run the SwarmAgent as a standalone daemon (blocks until SIGINT/SIGTERM)."""
    import signal

    cfg = _load_agent_config()
    adapter_type = str(cfg.get("adapter_type", "desktop"))
    max_fps = float(cfg.get("max_fps", 2.0))
    ring_size = int(cfg.get("ring_size", 4))
    max_cpu = float(cfg.get("max_cpu_percent", 15.0))
    poll_interval = float(cfg.get("poll_interval", 1.0))

    from modules.swarm_controller import SwarmController
    controller = SwarmController()
    controller.start_ipc_server()

    agent = SwarmAgent(
        controller=controller,
        adapter_type=adapter_type,
        max_fps=max_fps,
        ring_size=ring_size,
        max_cpu_percent=max_cpu,
        poll_interval=poll_interval,
    )

    shutdown_event = threading.Event()

    def _shutdown(sig: Any, frame: Any) -> None:
        print("[SWARM-AGENT] Shutdown signal received")
        shutdown_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except AttributeError:
        pass  # SIGTERM not available on Windows

    agent.start()
    print("[SWARM-AGENT] Daemon running. Send SIGINT or disable_swarm to stop.")

    try:
        while not shutdown_event.is_set():
            # Write health to interbus every 5s
            health = agent.health_check()
            try:
                path = INTERBUS_DIR / "swarm_agent_health.json"
                INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(health, ensure_ascii=True, indent=2), encoding="utf-8")
            except Exception:
                pass
            time.sleep(5.0)
    finally:
        agent.stop()
        controller.stop()
        print("[SWARM-AGENT] Daemon exited cleanly")


if __name__ == "__main__":
    from modules.session_guard import require_session
    require_session()
    run_agent_daemon()
