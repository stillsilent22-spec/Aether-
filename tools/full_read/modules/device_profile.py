"""Adaptive Laufzeitprofile fuer schwache und starke Geraete."""

from __future__ import annotations

import os
import platform
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    """Beschreibt das erkannte Leistungsprofil des lokalen Geraets."""

    cpu_count: int
    memory_gb: float | None
    architecture: str
    low_end: bool
    camera_interval_ms: int
    conway_interval_ms: int
    animation_interval_ms: int
    label: str
    detail: str


@dataclass(frozen=True)
class RuntimePressure:
    """Beschreibt die aktuelle Laufzeitlast und empfohlene Drosselung."""

    cpu_load: float | None
    memory_load: float | None
    loop_overrun: float
    delay_scale: float
    fps_scale: float
    label: str
    detail: str


class DeviceProfileEngine:
    """Leitet aus einfacher Hardware-Erkennung ein konservatives Laufzeitprofil ab."""

    def __init__(self) -> None:
        self._cpu_snapshot: tuple[int, int, int] | None = None
        self._last_runtime_sample_at = 0.0

    @staticmethod
    def _memory_snapshot() -> tuple[float | None, float | None]:
        """Versucht Groesse und aktuelle Last des Hauptspeichers zu bestimmen."""
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("length", ctypes.c_ulong),
                    ("memory_load", ctypes.c_ulong),
                    ("total_phys", ctypes.c_ulonglong),
                    ("avail_phys", ctypes.c_ulonglong),
                    ("total_page_file", ctypes.c_ulonglong),
                    ("avail_page_file", ctypes.c_ulonglong),
                    ("total_virtual", ctypes.c_ulonglong),
                    ("avail_virtual", ctypes.c_ulonglong),
                    ("avail_extended_virtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.length = ctypes.sizeof(MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                total_gb = float(status.total_phys) / float(1024**3)
                memory_load = float(status.memory_load)
                return total_gb, memory_load
        except Exception:
            return None, None
        return None, None

    @staticmethod
    def _filetime_to_int(filetime) -> int:
        """Konvertiert eine Windows-FILETIME in int."""
        return (int(filetime.dwHighDateTime) << 32) | int(filetime.dwLowDateTime)

    def _cpu_load_percent(self, cpu_count: int) -> float | None:
        """Leitet CPU-Last ohne externe Abhaengigkeiten ab."""
        if os.name == "nt":
            try:
                import ctypes

                class FileTime(ctypes.Structure):
                    _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

                idle = FileTime()
                kernel = FileTime()
                user = FileTime()
                if not ctypes.windll.kernel32.GetSystemTimes(
                    ctypes.byref(idle),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    return None
                current = (
                    self._filetime_to_int(idle),
                    self._filetime_to_int(kernel),
                    self._filetime_to_int(user),
                )
                previous = self._cpu_snapshot
                self._cpu_snapshot = current
                if previous is None:
                    return None
                idle_delta = max(0, current[0] - previous[0])
                kernel_delta = max(0, current[1] - previous[1])
                user_delta = max(0, current[2] - previous[2])
                total = kernel_delta + user_delta
                if total <= 0:
                    return None
                busy = max(0, total - idle_delta)
                return float(max(0.0, min(100.0, (busy / total) * 100.0)))
            except Exception:
                return None
        try:
            load = os.getloadavg()[0]
            if cpu_count <= 0:
                return None
            return float(max(0.0, min(100.0, (load / float(cpu_count)) * 100.0)))
        except Exception:
            return None

    def detect(self) -> DeviceProfile:
        """Erzeugt ein adaptives Profil ohne externe Abhaengigkeiten."""
        cpu_count = int(os.cpu_count() or 2)
        architecture = platform.machine().lower()
        memory_gb, _memory_load = self._memory_snapshot()

        pressure = 0
        if cpu_count <= 4:
            pressure += 2
        elif cpu_count <= 8:
            pressure += 1

        if memory_gb is not None:
            if memory_gb < 8.0:
                pressure += 2
            elif memory_gb < 16.0:
                pressure += 1

        if any(tag in architecture for tag in ("arm", "aarch", "rasp")):
            pressure += 1

        low_end = pressure >= 3
        adaptive = pressure >= 1

        if low_end:
            label = "LOW-END MODE AKTIV"
            camera_interval_ms = 130
            conway_interval_ms = 170
            animation_interval_ms = 95
        elif adaptive:
            label = "ADAPTIVE MODE"
            camera_interval_ms = 90
            conway_interval_ms = 120
            animation_interval_ms = 65
        else:
            label = "STANDARD MODE"
            camera_interval_ms = 70
            conway_interval_ms = 100
            animation_interval_ms = 45

        memory_label = f"{memory_gb:.1f} GB" if memory_gb is not None else "RAM ?"
        detail = f"CPU {cpu_count} | {memory_label} | {architecture or 'unknown'}"
        return DeviceProfile(
            cpu_count=cpu_count,
            memory_gb=memory_gb,
            architecture=architecture or "unknown",
            low_end=low_end,
            camera_interval_ms=camera_interval_ms,
            conway_interval_ms=conway_interval_ms,
            animation_interval_ms=animation_interval_ms,
            label=label,
            detail=detail,
        )

    def sample_runtime(self, profile: DeviceProfile, loop_overrun: float = 1.0) -> RuntimePressure:
        """Misst aktuelle CPU-/RAM-Last und liefert eine adaptive Drosselung."""
        cpu_load = self._cpu_load_percent(profile.cpu_count)
        _memory_gb, memory_load = self._memory_snapshot()
        overrun = float(max(0.5, loop_overrun))

        pressure = 0
        if cpu_load is not None:
            if cpu_load >= 90.0:
                pressure += 2
            elif cpu_load >= 75.0:
                pressure += 1
        if memory_load is not None:
            if memory_load >= 88.0:
                pressure += 2
            elif memory_load >= 72.0:
                pressure += 1
        if overrun >= 1.75:
            pressure += 2
        elif overrun >= 1.15:
            pressure += 1
        if profile.low_end:
            pressure += 1

        if pressure >= 4:
            delay_scale = 1.85
            fps_scale = 0.72
            label = "PRESSURE SHIELD"
        elif pressure >= 2:
            delay_scale = 1.35
            fps_scale = 0.86
            label = "ADAPTIVE FLOW"
        elif (
            not profile.low_end
            and overrun < 1.05
            and (cpu_load is None or cpu_load <= 38.0)
            and (memory_load is None or memory_load <= 62.0)
        ):
            delay_scale = 0.92
            fps_scale = 1.08
            label = "HEADROOM"
        else:
            delay_scale = 1.0
            fps_scale = 1.0
            label = "STEADY"

        cpu_text = f"CPU {cpu_load:.0f}%" if cpu_load is not None else "CPU ?"
        mem_text = f"RAM {memory_load:.0f}%" if memory_load is not None else "RAM ?"
        detail = f"{label} | {cpu_text} | {mem_text} | loop {overrun:.2f}x"
        self._last_runtime_sample_at = time.time()
        return RuntimePressure(
            cpu_load=cpu_load,
            memory_load=memory_load,
            loop_overrun=overrun,
            delay_scale=delay_scale,
            fps_scale=fps_scale,
            label=label,
            detail=detail,
        )
