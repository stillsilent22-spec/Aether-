from __future__ import annotations

from dataclasses import dataclass
import os
import platform

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


@dataclass
class EfficiencySample:
    ram_percent: float
    cpu_percent: float
    threads: int
    status: str


class EfficiencyMonitor:
    """Ein einfacher Effizienzmonitor für CPU/RAM/Thread-Samples."""

    def __init__(self) -> None:
        self._os = platform.system()

    def sample(self, status: str = "") -> EfficiencySample:
        if psutil is not None:
            try:
                ram = psutil.virtual_memory().percent
            except Exception:
                ram = 0.0
            try:
                cpu = psutil.cpu_percent(interval=0.1)
            except Exception:
                cpu = 0.0
            try:
                threads = sum(p.num_threads() for p in psutil.process_iter(attrs=["num_threads"]))
            except Exception:
                threads = 0
        else:
            ram = 0.0
            cpu = 0.0
            threads = 0
        return EfficiencySample(
            ram_percent=float(ram),
            cpu_percent=float(cpu),
            threads=int(threads),
            status=str(status or ""),
        )
