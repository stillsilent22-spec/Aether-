"""Phase 3: Windows Prozessdynamik - strukturelle Erfassung als X_t."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional

try:
    import psutil
except ImportError:
    psutil = None


@dataclass
class ProcessSnapshot:
    """Messbarer Prozesszustand X_t."""
    pid: int
    ppid: int
    name: str
    create_time: float
    status: str
    cpu_user: float
    cpu_system: float
    memory_rss: int
    memory_vms: int
    io_read: int
    io_write: int


def capture_process_state() -> List[ProcessSnapshot]:
    """Erfasst aktuelle Prozesse defensiv (psutil fallback)."""
    snapshots: List[ProcessSnapshot] = []
    if psutil is None:
        return snapshots  # Fail-closed

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'create_time', 'status', 'cpu_times', 'memory_info', 'io_counters']):
        try:
            with proc.oneshot():
                info = proc.info
                cpu_times = info.get('cpu_times', (0.0, 0.0))
                memory_info = info.get('memory_info', (0, 0))
                io_counters = info.get('io_counters', (0, 0))
                snapshots.append(ProcessSnapshot(
                    pid=info['pid'],
                    ppid=info.get('ppid', 0),
                    name=info['name'],
                    create_time=info.get('create_time', 0.0),
                    status=info['status'],
                    cpu_user=cpu_times[0],
                    cpu_system=cpu_times[1],
                    memory_rss=memory_info[0],
                    memory_vms=memory_info[1],
                    io_read=io_counters[0],
                    io_write=io_counters[1],
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return snapshots


def process_to_feature_vector(snapshot: ProcessSnapshot) -> bytes:
    """Mappt ProcessSnapshot deterministisch zu Feature-Bytes für analysis_engine."""
    # Normalisiere zu uint8-Vektor (deterministisch, bounded)
    fields = [
        snapshot.pid % 256,
        snapshot.ppid % 256,
        ord(snapshot.name[0]) if snapshot.name else 0,
        int(snapshot.create_time % 256),
        ord(snapshot.status[0]) if snapshot.status else 0,
        min(255, int(snapshot.cpu_user)),
        min(255, int(snapshot.cpu_system)),
        min(255, snapshot.memory_rss // 1024 % 256),
        min(255, snapshot.memory_vms // 1024 % 256),
        min(255, snapshot.io_read // 1024 % 256),
        min(255, snapshot.io_write // 1024 % 256),
    ]
    return bytes(fields)
