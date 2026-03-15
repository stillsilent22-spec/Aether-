"""Structural Windows privacy observer without content inspection."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import statistics
import subprocess
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .screen_vision_engine import is_private_context

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    import winreg
except Exception:  # pragma: no cover
    winreg = None


SYSTEM_USERS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
AUTOSTART_KEYS = [
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run"),
]


@dataclass
class ProcessSignal:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    io_read_bytes: int
    io_write_bytes: int
    thread_count: int
    open_connections: int
    start_time_iso: str
    is_system: bool
    has_window: bool
    snapshot_ts: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": int(self.pid),
            "name": str(self.name),
            "cpu_percent": float(self.cpu_percent),
            "memory_mb": float(self.memory_mb),
            "io_read_bytes": int(self.io_read_bytes),
            "io_write_bytes": int(self.io_write_bytes),
            "thread_count": int(self.thread_count),
            "open_connections": int(self.open_connections),
            "start_time_iso": str(self.start_time_iso),
            "is_system": bool(self.is_system),
            "has_window": bool(self.has_window),
            "snapshot_ts": str(self.snapshot_ts),
        }


@dataclass
class NetworkSignal:
    remote_domain: str
    remote_port: int
    local_port: int
    protocol: str
    process_name: str
    pid: int
    packet_size_bucket: str
    connection_count_last_min: int
    interval_regularity: float
    snapshot_ts: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "remote_domain": str(self.remote_domain),
            "remote_port": int(self.remote_port),
            "local_port": int(self.local_port),
            "protocol": str(self.protocol),
            "process_name": str(self.process_name),
            "pid": int(self.pid),
            "packet_size_bucket": str(self.packet_size_bucket),
            "connection_count_last_min": int(self.connection_count_last_min),
            "interval_regularity": float(self.interval_regularity),
            "snapshot_ts": str(self.snapshot_ts),
        }


@dataclass
class SystemSignal:
    autostart_count: int
    autostart_names: list[str]
    scheduled_task_count: int
    scheduled_task_names: list[str]
    background_service_count: int
    background_service_names: list[str]
    registry_change_count_since_last: int
    snapshot_ts: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "autostart_count": int(self.autostart_count),
            "autostart_names": list(self.autostart_names),
            "scheduled_task_count": int(self.scheduled_task_count),
            "scheduled_task_names": list(self.scheduled_task_names),
            "background_service_count": int(self.background_service_count),
            "background_service_names": list(self.background_service_names),
            "registry_change_count_since_last": int(self.registry_change_count_since_last),
            "snapshot_ts": str(self.snapshot_ts),
        }


class WindowsPrivacyObserver:
    """Collects structural process, network and system signals."""

    def __init__(
        self,
        snapshot_interval_sec: float = 15.0,
        history_depth: int = 20,
        data_path: str = "data/privacy_snapshots",
    ) -> None:
        self.snapshot_interval_sec = max(1.0, float(snapshot_interval_sec))
        self.history_depth = max(2, int(history_depth))
        self.data_path = Path(data_path)
        self.data_path.mkdir(parents=True, exist_ok=True)
        self._network_history: dict[tuple[int, str, int], deque[float]] = defaultdict(
            lambda: deque(maxlen=self.history_depth)
        )
        self._registry_subkey_count = self._count_software_subkeys()
        self._running = False
        self._thread: threading.Thread | None = None

    def collect_process_signals(self) -> list[ProcessSignal]:
        if psutil is None:
            return []
        snapshot_ts = datetime.now(timezone.utc).isoformat()
        connections_by_pid = self._connections_by_pid()
        window_pids = self._window_pid_set()
        signals: list[ProcessSignal] = []
        for process in psutil.process_iter(["pid", "name", "memory_info", "create_time", "username", "status"]):
            try:
                info = process.info
                if str(info.get("status", "") or "").lower() == "zombie":
                    continue
                pid = int(info.get("pid", 0) or 0)
                name = str(info.get("name", "") or "")
                if pid <= 0 or is_private_context(name, name):
                    continue
                io_counters = process.io_counters() if hasattr(process, "io_counters") else None
                cpu_percent = float(process.cpu_percent(interval=None) or 0.0)
                memory_info = info.get("memory_info")
                username = str(info.get("username", "") or "")
                signals.append(
                    ProcessSignal(
                        pid=pid,
                        name=name,
                        cpu_percent=cpu_percent,
                        memory_mb=float(getattr(memory_info, "rss", 0) or 0) / (1024.0 * 1024.0),
                        io_read_bytes=int(getattr(io_counters, "read_bytes", 0) or 0),
                        io_write_bytes=int(getattr(io_counters, "write_bytes", 0) or 0),
                        thread_count=int(process.num_threads() or 0),
                        open_connections=int(connections_by_pid.get(pid, 0)),
                        start_time_iso=self._iso_from_timestamp(float(info.get("create_time", 0.0) or 0.0)),
                        is_system=username.upper() in SYSTEM_USERS,
                        has_window=pid in window_pids,
                        snapshot_ts=snapshot_ts,
                    )
                )
            except Exception:
                continue
        signals.sort(key=lambda item: (-float(item.cpu_percent), str(item.name), int(item.pid)))
        return signals[:200]

    def collect_network_signals(self) -> list[NetworkSignal]:
        if psutil is None:
            return []
        snapshot_ts = datetime.now(timezone.utc).isoformat()
        signals: list[NetworkSignal] = []
        process_io_map = self._process_io_map()
        for conn in list(psutil.net_connections(kind="inet") or []):
            try:
                pid = int(getattr(conn, "pid", 0) or 0)
                if pid <= 0:
                    continue
                laddr = getattr(conn, "laddr", None)
                raddr = getattr(conn, "raddr", None)
                if not raddr or not getattr(raddr, "ip", None):
                    continue
                process_name = ""
                try:
                    process_name = str(psutil.Process(pid).name() or "")
                except Exception:
                    process_name = ""
                if is_private_context(process_name, ""):
                    continue
                domain = self._reverse_dns(str(getattr(raddr, "ip", "") or ""))
                if is_private_context(process_name, domain):
                    continue
                key = (pid, domain, int(getattr(raddr, "port", 0) or 0))
                history = self._network_history[key]
                history.append(time.time())
                now = time.time()
                connection_count_last_min = sum(1 for ts in history if (now - ts) <= 60.0)
                interval_regularity = self._interval_regularity(list(history))
                packet_size_bucket = self._packet_bucket(
                    process_io_map.get(pid, (0, 0)),
                    max(1, connection_count_last_min),
                )
                protocol = "TCP" if int(getattr(conn, "type", 0) or 0) == socket.SOCK_STREAM else "UDP"
                signals.append(
                    NetworkSignal(
                        remote_domain=domain,
                        remote_port=int(getattr(raddr, "port", 0) or 0),
                        local_port=int(getattr(laddr, "port", 0) or 0),
                        protocol=protocol,
                        process_name=process_name,
                        pid=pid,
                        packet_size_bucket=packet_size_bucket,
                        connection_count_last_min=connection_count_last_min,
                        interval_regularity=interval_regularity,
                        snapshot_ts=snapshot_ts,
                    )
                )
            except Exception:
                continue
        return signals

    def collect_system_signals(self) -> SystemSignal:
        snapshot_ts = datetime.now(timezone.utc).isoformat()
        if os.name != "nt":
            return SystemSignal(0, [], 0, [], 0, [], 0, snapshot_ts)
        autostarts = self._autostart_names()
        tasks = self._command_names(["schtasks", "/query", "/fo", "LIST"], "TaskName:")
        services = self._command_names(["sc", "query", "type=", "all", "state=", "running"], "SERVICE_NAME:")
        current_subkeys = self._count_software_subkeys()
        change_count = max(0, current_subkeys - self._registry_subkey_count)
        self._registry_subkey_count = current_subkeys
        return SystemSignal(
            autostart_count=len(autostarts),
            autostart_names=autostarts,
            scheduled_task_count=len(tasks),
            scheduled_task_names=tasks,
            background_service_count=len(services),
            background_service_names=services,
            registry_change_count_since_last=change_count,
            snapshot_ts=snapshot_ts,
        )

    def take_snapshot(self) -> dict[str, Any]:
        process_signals = self.collect_process_signals()
        network_signals = self.collect_network_signals()
        system_signal = self.collect_system_signals()
        snapshot = {
            "snapshot_ts": datetime.now(timezone.utc).isoformat(),
            "process_signals": [item.to_dict() for item in process_signals],
            "network_signals": [item.to_dict() for item in network_signals],
            "system_signal": system_signal.to_dict(),
        }
        target = self.data_path / f"snapshot_{int(time.time())}.json"
        target.write_text(json.dumps(snapshot, ensure_ascii=True, sort_keys=True, indent=2), encoding="utf-8")
        self._trim_snapshots()
        return snapshot

    def start_continuous(self, callback: callable) -> None:
        if self._running:
            return
        self._running = True

        def _loop() -> None:
            while self._running:
                snapshot = self.take_snapshot()
                try:
                    callback(snapshot)
                except Exception:
                    pass
                time.sleep(self.snapshot_interval_sec)

        self._thread = threading.Thread(target=_loop, daemon=True, name="WindowsPrivacyObserver")
        self._thread.start()

    def stop_continuous(self) -> None:
        self._running = False

    def _trim_snapshots(self) -> None:
        files = sorted(self.data_path.glob("snapshot_*.json"))
        for file_path in files[:-50]:
            try:
                file_path.unlink()
            except Exception:
                continue

    def _connections_by_pid(self) -> dict[int, int]:
        if psutil is None:
            return {}
        counts: dict[int, int] = defaultdict(int)
        try:
            for conn in list(psutil.net_connections(kind="inet") or []):
                pid = int(getattr(conn, "pid", 0) or 0)
                if pid > 0:
                    counts[pid] += 1
        except Exception:
            return {}
        return dict(counts)

    def _process_io_map(self) -> dict[int, tuple[int, int]]:
        result: dict[int, tuple[int, int]] = {}
        if psutil is None:
            return result
        for process in psutil.process_iter(["pid"]):
            try:
                io = process.io_counters()
                result[int(process.pid)] = (
                    int(getattr(io, "read_bytes", 0) or 0),
                    int(getattr(io, "write_bytes", 0) or 0),
                )
            except Exception:
                continue
        return result

    def _reverse_dns(self, ip_address: str) -> str:
        if not ip_address:
            return "unknown"
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(socket.gethostbyaddr, ip_address)
                host, _aliases, _addresses = future.result(timeout=2.0)
            host = str(host or "").strip().lower()
            if not host or host == ip_address:
                return "unknown"
            return host
        except (FuturesTimeoutError, Exception):
            return "unknown"

    @staticmethod
    def _interval_regularity(values: list[float]) -> float:
        if len(values) < 3:
            return 0.0
        intervals = [float(values[index] - values[index - 1]) for index in range(1, len(values))]
        mean = statistics.fmean(intervals) if intervals else 0.0
        if mean <= 0.0:
            return 0.0
        stddev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        return max(0.0, min(1.0, 1.0 - (stddev / mean)))

    @staticmethod
    def _packet_bucket(io_values: tuple[int, int], connection_count: int) -> str:
        total_bytes = max(0, int(io_values[0]) + int(io_values[1]))
        approx = total_bytes / max(1, int(connection_count))
        if approx < 100:
            return "tiny"
        if approx < 1024:
            return "small"
        if approx < 10240:
            return "medium"
        return "large"

    @staticmethod
    def _iso_from_timestamp(timestamp: float) -> str:
        try:
            return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()
        except Exception:
            return ""

    def _autostart_names(self) -> list[str]:
        if winreg is None or os.name != "nt":
            return []
        mapping = {
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        }
        names: list[str] = []
        for root_name, subkey in AUTOSTART_KEYS:
            root = mapping.get(root_name)
            if root is None:
                continue
            try:
                handle = winreg.OpenKey(root, subkey)
            except Exception:
                continue
            index = 0
            while True:
                try:
                    name, _value, _typ = winreg.EnumValue(handle, index)
                    if name and not is_private_context(name, ""):
                        names.append(str(name))
                    index += 1
                except OSError:
                    break
            try:
                winreg.CloseKey(handle)
            except Exception:
                pass
        return sorted(set(names))

    @staticmethod
    def _command_names(command: list[str], prefix: str) -> list[str]:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=6.0,
                check=False,
            )
        except Exception:
            return []
        names: list[str] = []
        for line in str(result.stdout or "").splitlines():
            if line.strip().startswith(prefix):
                name = line.split(":", 1)[1].strip()
                if name and not is_private_context(name, ""):
                    names.append(name)
        return sorted(set(names))

    def _count_software_subkeys(self) -> int:
        if winreg is None or os.name != "nt":
            return 0
        try:
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software")
            count, _values, _modified = winreg.QueryInfoKey(handle)
            winreg.CloseKey(handle)
            return int(count)
        except Exception:
            return 0

    @staticmethod
    def _window_pid_set() -> set[int]:
        if os.name != "nt":
            return set()
        result: set[int] = set()

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def enum_proc(hwnd: int, _lparam: int) -> bool:
            if not ctypes.windll.user32.IsWindowVisible(hwnd):
                return True
            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if int(pid.value) > 0:
                result.add(int(pid.value))
            return True

        try:
            ctypes.windll.user32.EnumWindows(enum_proc, 0)
        except Exception:
            return set()
        return result
