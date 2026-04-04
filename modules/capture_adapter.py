from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Pluggable Capture Adapter for Aether Swarm.

Default Adapter: Desktop Mirror via mss (cross-platform).
  - Windows: uses DXGI via mss
  - Linux:   X11/Wayland via mss
  - macOS:   CGDisplayStream via mss

Interface:
    CaptureAdapterBase.start() / stop() / read_frame() -> Optional[FrameData]

FrameData: timestamp, resolution, format, data (bytes) — only kept in RAM.
Raw frames are NEVER written to disk; only metrics/fingerprints are persisted.

Ring buffer: thread-safe deque holding at most `ring_size` FrameData objects,
automatically discarding oldest frames when full (back-pressure prevention).

Anti-Cheat Safe Mode: automatically pauses capture when known anti-cheat
processes are detected (reduces sampling rate to 0).

Stub: GpuHookCaptureAdapter is present but raises NotImplementedError (lab-only).
"""


import collections
import hashlib
import io
import math
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

try:
    import psutil
    _PSUTIL_OK = True
except ImportError as e:
    _PSUTIL_OK = False

# mss is cross-platform; already listed in requirements.txt
try:
    import mss
    import mss.tools
    _MSS_OK = True
except ImportError as e:
    _MSS_OK = False


# --------------------------------------------------------------------------- #
#  Data types                                                                  #
# --------------------------------------------------------------------------- #

@dataclass
class FrameData:
    """A single captured frame — lives only in RAM."""
    timestamp: float          # Unix epoch, float
    width: int
    height: int
    format: str               # "BGRA", "RGB", "GRAY"
    data: bytes               # raw pixel bytes
    adapter_id: str = "desktop"

    @property
    def size_bytes(self) -> int:
        return len(self.data)

    def metrics(self) -> Dict[str, Any]:
        """Compute lightweight metrics from this frame without storing raw data."""
        n = len(self.data)
        if n == 0:
            return {"mean": 0.0, "std": 0.0, "entropy_approx": 0.0}
        byte_sum = sum(self.data)
        mean_val = byte_sum / n
        variance = sum((b - mean_val) ** 2 for b in self.data[:4096]) / min(n, 4096)
        std_val = math.sqrt(variance)
        # Approximate block entropy over first 256 bytes
        sample = self.data[:256]
        counts: Dict[int, int] = {}
        for b in sample:
            counts[b] = counts.get(b, 0) + 1
        ent = 0.0
        slen = len(sample)
        if slen > 1:
            ent = -sum((c / slen) * math.log2(c / slen) for c in counts.values())
        return {
            "mean": round(mean_val, 4),
            "std": round(std_val, 4),
            "entropy_approx": round(ent, 4),
            "width": self.width,
            "height": self.height,
            "size_bytes": n,
        }

    def fingerprint(self) -> str:
        """Non-invertible SHA256 fingerprint over metrics (not raw data)."""
        m = self.metrics()
        canonical = f"{m['mean']:.4f}|{m['std']:.4f}|{m['entropy_approx']:.4f}|{self.width}|{self.height}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
#  Anti-cheat detection                                                       #
# --------------------------------------------------------------------------- #

KNOWN_ANTICHEAT_PROCESSES = frozenset({
    # EasyAntiCheat
    "easyanticheat.exe", "easyanticheat_launcher.exe",
    # BattlEye
    "battleye.exe", "beservice.exe", "beservice_x64.exe",
    # Vanguard
    "vgc.exe", "vanguard.exe",
    # nProtect GameGuard
    "gamemon.des", "npggnt.des", "npggsvc.exe",
    # FACEIT / ESL Wire
    "faceit.exe", "faceit_ac.exe", "wire.exe",
    # Ricochet (CoD)
    "cod.exe",
    # Generic kernel-level AC signatures
    "anticheats.exe",
})


def detect_anticheat_running() -> List[str]:
    """Return list of detected anti-cheat process names (lower-case)."""
    if not _PSUTIL_OK:
        return []
    found: List[str] = []
    try:
        for proc in psutil.process_iter(attrs=["name"]):
            name = (proc.info.get("name") or "").lower()
            if name in KNOWN_ANTICHEAT_PROCESSES:
                found.append(name)
    except Exception as e:
        logger.warning(f"[capture_adapter] Fehler: {e}")
        pass
    return found


# --------------------------------------------------------------------------- #
#  Base interface                                                              #
# --------------------------------------------------------------------------- #

class CaptureAdapterBase:
    """Abstract base for all capture adapters."""

    adapter_id: str = "base"

    def __init__(self, ring_size: int = 4, max_fps: float = 2.0) -> None:
        self._ring_size = max(1, ring_size)
        self._max_fps = max(0.1, max_fps)
        self._ring: Deque[FrameData] = collections.deque(maxlen=self._ring_size)
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._frame_count: int = 0
        self._last_capture_ts: float = 0.0
        # Adaptive: reduces fps when overloaded
        self._adaptive_fps: float = self._max_fps

    def start(self) -> None:
        if self._running:
            return
        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop, daemon=True, name=f"capture-{self.adapter_id}"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        self._thread = None

    def read_frame(self) -> Optional[FrameData]:
        """Read latest frame from ring buffer (non-blocking)."""
        with self._lock:
            if self._ring:
                return self._ring[-1]
        return None

    def read_and_consume(self) -> Optional[FrameData]:
        """Pop oldest frame from ring buffer."""
        with self._lock:
            if self._ring:
                return self._ring.popleft()
        return None

    @property
    def frame_count(self) -> int:
        return self._frame_count

    @property
    def ring_depth(self) -> int:
        with self._lock:
            return len(self._ring)

    def _capture_loop(self) -> None:
        while not self._stop_event.is_set():
            # Rate limiting (interruptible so stop() returns quickly)
            interval = 1.0 / max(0.1, self._adaptive_fps)
            now = time.monotonic()
            elapsed = now - self._last_capture_ts
            if elapsed < interval:
                if self._stop_event.wait(timeout=interval - elapsed):
                    break
                continue
            try:
                frame = self._capture_one()
                if frame is not None:
                    with self._lock:
                        self._ring.append(frame)
                    self._frame_count += 1
                    self._last_capture_ts = time.monotonic()
            except Exception as err:
                print(f"[CAPTURE:{self.adapter_id}] capture error: {err}")
                if self._stop_event.wait(timeout=1.0):
                    break

    def _capture_one(self) -> Optional[FrameData]:
        raise NotImplementedError

    def set_adaptive_fps(self, fps: float) -> None:
        self._adaptive_fps = max(0.05, min(fps, self._max_fps))


# --------------------------------------------------------------------------- #
#  Desktop Capture Adapter (default)                                          #
# --------------------------------------------------------------------------- #

class DesktopCaptureAdapter(CaptureAdapterBase):
    """Desktop mirror capture via mss (DXGI/X11/Wayland/AVFoundation)."""

    adapter_id = "desktop"

    def __init__(
        self,
        monitor_index: int = 1,
        ring_size: int = 4,
        max_fps: float = 2.0,
        downscale: float = 0.25,
    ) -> None:
        super().__init__(ring_size=ring_size, max_fps=max_fps)
        self._monitor_index = max(0, monitor_index)
        self._downscale = max(0.05, min(1.0, downscale))
        self._mss: Optional[Any] = None

    def start(self) -> None:
        if not _MSS_OK:
            print("[CAPTURE:desktop] mss not available — install it via: pip install mss")
            return
        super().start()

    def _capture_loop(self) -> None:
        """Desktop-specific loop with anti-cheat detection (cached, every 30s)."""
        _ac_check_ts: float = 0.0
        _ac_blocked: bool = False
        while not self._stop_event.is_set():
            # Anti-cheat cached check (expensive psutil scan throttled to 30s)
            now = time.monotonic()
            if now - _ac_check_ts > 30.0:
                _ac_blocked = bool(detect_anticheat_running())
                _ac_check_ts = now
            if _ac_blocked:
                if self._stop_event.wait(timeout=1.0):
                    break
                continue
            # Rate limiting (interruptible)
            interval = 1.0 / max(0.1, self._adaptive_fps)
            elapsed = now - self._last_capture_ts
            if elapsed < interval:
                if self._stop_event.wait(timeout=interval - elapsed):
                    break
                continue
            try:
                frame = self._capture_one()
                if frame is not None:
                    with self._lock:
                        self._ring.append(frame)
                    self._frame_count += 1
                    self._last_capture_ts = time.monotonic()
            except Exception as err:
                print(f"[CAPTURE:{self.adapter_id}] grab error: {err}")
                if self._stop_event.wait(timeout=1.0):
                    break


    def _capture_one(self) -> Optional[FrameData]:
        if not _MSS_OK:
            return None
        try:
            with mss.mss() as sct:
                monitors = sct.monitors
                idx = min(self._monitor_index, len(monitors) - 1)
                mon = monitors[idx]
                img = sct.grab(mon)
                # img.rgb is the raw RGB bytes (no BGRA conversion needed for metrics)
                raw = bytes(img.rgb)
                w, h = img.width, img.height
                # Downscale via simple row/column sampling (no numpy deps here)
                if self._downscale < 1.0:
                    step = max(1, int(1.0 / self._downscale))
                    stride = w * 3
                    rows = [raw[r * stride:(r + 1) * stride:step * 3] for r in range(0, h, step)]
                    raw = b"".join(rows)
                    w = len(rows[0]) // 3 if rows else 1
                    h = len(rows)
                return FrameData(
                    timestamp=time.time(),
                    width=w,
                    height=h,
                    format="RGB",
                    data=raw,
                    adapter_id=self.adapter_id,
                )
        except Exception as err:
            print(f"[CAPTURE:desktop] grab error: {err}")
            return None


# --------------------------------------------------------------------------- #
#  Stub Capture Adapter (for testing without display)                         #
# --------------------------------------------------------------------------- #

class StubCaptureAdapter(CaptureAdapterBase):
    """Generates synthetic frames for testing — no real capture."""

    adapter_id = "stub"

    def __init__(self, width: int = 64, height: int = 64, ring_size: int = 4, max_fps: float = 5.0) -> None:
        super().__init__(ring_size=ring_size, max_fps=max_fps)
        self._width = width
        self._height = height
        self._seq = 0

    def _capture_one(self) -> Optional[FrameData]:
        self._seq += 1
        # Generate pseudo-random but deterministic frame data
        seed = self._seq & 0xFF
        data = bytes((seed + i) & 0xFF for i in range(self._width * self._height * 3))
        return FrameData(
            timestamp=time.time(),
            width=self._width,
            height=self._height,
            format="RGB",
            data=data,
            adapter_id=self.adapter_id,
        )


# --------------------------------------------------------------------------- #
#  GPU Hook Adapter stub (lab-only)                                           #
# --------------------------------------------------------------------------- #

class GpuHookCaptureAdapter(CaptureAdapterBase):
    """Lab-only GPU/API hook adapter. Not implemented in production builds."""

    adapter_id = "gpu_hook"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "GpuHookCaptureAdapter is a lab-only stub. "
            "Use DesktopCaptureAdapter (default) instead."
        )

    def _capture_one(self) -> Optional[FrameData]:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
#  Factory                                                                    #
# --------------------------------------------------------------------------- #

def make_capture_adapter(
    adapter_type: str = "desktop",
    ring_size: int = 4,
    max_fps: float = 2.0,
    **kwargs: Any,
) -> CaptureAdapterBase:
    """Create a capture adapter by type name."""
    if adapter_type == "desktop":
        return DesktopCaptureAdapter(ring_size=ring_size, max_fps=max_fps, **kwargs)
    if adapter_type == "stub":
        return StubCaptureAdapter(ring_size=ring_size, max_fps=max_fps, **kwargs)
    if adapter_type == "gpu_hook":
        raise NotImplementedError("gpu_hook adapter is lab-only")
    raise ValueError(f"Unknown capture adapter type: {adapter_type!r}")
