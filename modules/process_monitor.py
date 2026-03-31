import logging
logger = logging.getLogger(__name__)
"""Phase 4: Windows Prozessdynamik — strukturelle Erfassung als X_t."""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Any

_IS_WINDOWS = sys.platform.startswith("win")

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except Exception as e:
    psutil = None
    _PSUTIL_AVAILABLE = False

try:
    import win32process
    import win32api
    import win32con
    import win32security
    _WIN32_AVAILABLE = True
except Exception as e:
    _WIN32_AVAILABLE = False

try:
    import ctypes
    _CTYPES_AVAILABLE = True
except Exception as e:
    _CTYPES_AVAILABLE = False


@dataclass
class ProcessSnapshot:
    """Struktureller Snapshot eines Prozesses zum Zeitpunkt t."""
    pid: int
    name: str
    cpu_percent: float
    memory_rss: int
    memory_vms: int
    io_read_bytes: int
    io_write_bytes: int
    thread_count: int
    status: str
    timestamp: float
    ppid: int
    integrity_level: str  # Windows: Low/Medium/High/System; andere: "n/a"

    def to_payload(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "cpu_percent": round(self.cpu_percent, 4),
            "memory_rss": self.memory_rss,
            "memory_vms": self.memory_vms,
            "io_read_bytes": self.io_read_bytes,
            "io_write_bytes": self.io_write_bytes,
            "thread_count": self.thread_count,
            "status": self.status,
            "timestamp": self.timestamp,
            "ppid": self.ppid,
            "integrity_level": self.integrity_level,
        }


class ProcessMonitor:
    """
    Phase-4 Prozessmonitor: strukturelle Erfassung ohne Inhalts-Zugriff.

    Erfasst nur Metadaten (CPU, RAM, IO, Threads, Integritaetslevel) —
    niemals Speicherinhalte, Fensterinhalte oder User-Eingaben.
    Privacy-Boundary: SYSTEM-Prozesse werden gefiltert.
    """

    SYSTEM_USERS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
    _INTEGRITY_LABELS = {
        0x0000: "Untrusted",
        0x1000: "Low",
        0x2000: "Medium",
        0x3000: "High",
        0x4000: "System",
    }

    def snapshot_process(self, pid: int) -> ProcessSnapshot | None:
        """Erstellt einen strukturellen Snapshot fuer einen Prozess."""
        if not _PSUTIL_AVAILABLE or psutil is None:
            return self._stub_snapshot(pid)
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                mem = p.memory_info()
                try:
                    io = p.io_counters()
                    io_read = int(io.read_bytes)
                    io_write = int(io.write_bytes)
                except Exception as e:
                    io_read = io_write = 0
                return ProcessSnapshot(
                    pid=int(pid),
                    name=str(p.name() or ""),
                    cpu_percent=float(p.cpu_percent(interval=0.05)),
                    memory_rss=int(mem.rss),
                    memory_vms=int(mem.vms),
                    io_read_bytes=io_read,
                    io_write_bytes=io_write,
                    thread_count=int(p.num_threads()),
                    status=str(p.status() or ""),
                    timestamp=time.time(),
                    ppid=int(p.ppid() or 0),
                    integrity_level=self._get_integrity_level(pid),
                )
        except Exception as e:
            return None

    def monitor_windows_process(self, pid: int) -> dict[str, Any]:
        """Kompatibilitaetsinterface — gibt Snapshot als dict zurueck."""
        snap = self.snapshot_process(pid)
        if snap is None:
            raise ValueError(f"Prozess {pid} nicht erreichbar.")
        return snap.to_payload()

    def snapshot_all_user_processes(self, max_count: int = 64) -> list[ProcessSnapshot]:
        """
        Erfasst strukturelle Snapshots aller Nutzerprozesse.
        Filtert System-Prozesse heraus (privacy-boundary).
        """
        if not _PSUTIL_AVAILABLE or psutil is None:
            return []
        snapshots = []
        for p in psutil.process_iter(["pid", "name", "username", "status"]):
            try:
                info = p.info
                uname = str(info.get("username") or "").split("\\")[-1].upper()
                if uname in self.SYSTEM_USERS:
                    continue
                snap = self.snapshot_process(int(info["pid"]))
                if snap is not None:
                    snapshots.append(snap)
                if len(snapshots) >= max_count:
                    break
            except Exception as e:
                continue
        return snapshots

    def process_delta(self, snap_a: ProcessSnapshot, snap_b: ProcessSnapshot) -> dict[str, float]:
        """Strukturelles Delta zwischen zwei Snapshots desselben Prozesses."""
        if snap_a.pid != snap_b.pid:
            raise ValueError("Delta nur zwischen Snapshots desselben Prozesses.")
        dt = max(1e-6, snap_b.timestamp - snap_a.timestamp)
        return {
            "cpu_delta": abs(snap_b.cpu_percent - snap_a.cpu_percent),
            "memory_delta": snap_b.memory_rss - snap_a.memory_rss,
            "io_read_rate": (snap_b.io_read_bytes - snap_a.io_read_bytes) / dt,
            "io_write_rate": (snap_b.io_write_bytes - snap_a.io_write_bytes) / dt,
            "thread_delta": snap_b.thread_count - snap_a.thread_count,
            "time_delta": dt,
        }

    # ── Windows Integrity Level (ETW-Ergaenzung) ────────────────────────────

    def _get_integrity_level(self, pid: int) -> str:
        """Liest Windows Integrity Level eines Prozesses (Vista+)."""
        if not _IS_WINDOWS or not _WIN32_AVAILABLE or not _CTYPES_AVAILABLE:
            return "n/a"
        try:
            import ctypes.wintypes
            TOKEN_QUERY = 0x0008
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            token_handle = win32security.OpenProcessToken(handle, TOKEN_QUERY)
            # GetTokenInformation — TokenIntegrityLevel = 25
            info_size = ctypes.c_ulong(0)
            ctypes.windll.advapi32.GetTokenInformation(
                int(token_handle), 25, None, 0, ctypes.byref(info_size)
            )
            buf = (ctypes.c_byte * info_size.value)()
            ctypes.windll.advapi32.GetTokenInformation(
                int(token_handle), 25, buf, info_size.value, ctypes.byref(info_size)
            )
            # Last 4 bytes = SubAuthority[0] = RID
            if info_size.value >= 4:
                rid = int.from_bytes(bytes(buf[-4:]), "little") & 0xF000
                return self._INTEGRITY_LABELS.get(rid, f"Unknown(0x{rid:04X})")
            return "Unknown"
        except Exception as e:
            return "n/a"

    @staticmethod
    def _stub_snapshot(pid: int) -> ProcessSnapshot:
        """Gibt einen leeren Stub-Snapshot zurueck wenn psutil nicht verfuegbar."""
        return ProcessSnapshot(
            pid=pid, name="unknown", cpu_percent=0.0,
            memory_rss=0, memory_vms=0, io_read_bytes=0, io_write_bytes=0,
            thread_count=0, status="unknown", timestamp=time.time(),
            ppid=0, integrity_level="n/a",
        )
