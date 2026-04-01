from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Atomic Global Controller for Aether Swarm Mode.

IPC: localhost TCP socket (port 7387) with JSON line-protocol.
     Fallback: file-based command polling via data/interbus/swarm_cmd.json.

Commands (JSON objects, newline-terminated):
    {"cmd": "enable_swarm"}
    {"cmd": "disable_swarm"}
    {"cmd": "status"}
    {"cmd": "health"}

Responses: JSON objects with {"ok": bool, ...payload}.

SWARM_MODE is persisted transactionally in SQLite (data/swarm_ctrl.db).
Status is exposted to JSON at data/interbus/swarm_status.json for UIs/Agents.
"""


import json
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CTRL_DB_PATH = ROOT / "data" / "swarm_ctrl.db"
INTERBUS_DIR = ROOT / "data" / "interbus"
STATUS_PATH = INTERBUS_DIR / "swarm_status.json"
CMD_PATH = INTERBUS_DIR / "swarm_cmd.json"

IPC_HOST = "127.0.0.1"
IPC_PORT = 7387
SCHEMA_VERSION = 1


# --------------------------------------------------------------------------- #
#  Database (transactional SWARM_MODE persistence)                            #
# --------------------------------------------------------------------------- #

def _db_connect() -> sqlite3.Connection:
    CTRL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CTRL_DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS swarm_flags (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS swarm_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor      TEXT DEFAULT 'local',
            details    TEXT,
            ts         TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_get(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute(
        "SELECT value FROM swarm_flags WHERE key = ?", (key,)
    ).fetchone()
    return str(row[0]) if row else default


def _db_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("""
        INSERT INTO swarm_flags(key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    """, (key, value, _utc_now()))
    conn.commit()


def _db_log_event(conn: sqlite3.Connection, event_type: str, details: str = "", actor: str = "local") -> None:
    conn.execute(
        "INSERT INTO swarm_events(event_type, actor, details, ts) VALUES (?, ?, ?, ?)",
        (event_type, actor, details, _utc_now()),
    )
    conn.commit()


# --------------------------------------------------------------------------- #
#  Status file (read by UI, Rust shell, other agents)                         #
# --------------------------------------------------------------------------- #

def _write_status(enabled: bool, mode: str, extra: Optional[Dict[str, Any]] = None) -> None:
    INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "swarm_mode": enabled,
        "mode": mode,
        "updated_at": _utc_now(),
    }
    if extra:
        payload.update(extra)
    STATUS_PATH.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8"
    )


def read_status() -> Dict[str, Any]:
    """Read current swarm status from the interbus JSON file."""
    try:
        if STATUS_PATH.is_file():
            raw = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return dict(raw)
    except Exception as e:
        logger.warning(f"[swarm_controller] Stiller Fehler: {e}")
        pass
    return {"swarm_mode": False, "mode": "offline", "schema_version": SCHEMA_VERSION}


# --------------------------------------------------------------------------- #
#  SwarmController                                                              #
# --------------------------------------------------------------------------- #

import os


_ANDROID = os.environ.get("AETHER_PLATFORM") == "android"

class SwarmController:
    """Thread-safe atomic controller for Swarm Mode."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = Path(db_path) if db_path else CTRL_DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = _db_connect() if db_path is None else self._open_db(path)
        self._lock = threading.RLock()
        self._enabled: bool = self._db_read_mode()
        self._server_thread: Optional[threading.Thread] = None
        self._cmd_poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._health_extra: Dict[str, Any] = {}

    @staticmethod
    def _open_db(path: Path) -> sqlite3.Connection:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS swarm_flags (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS swarm_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL, actor TEXT DEFAULT 'local',
                details TEXT, ts TEXT NOT NULL
            )
        """)
        conn.commit()
        return conn

    def _db_read_mode(self) -> bool:
        val = _db_get(self._conn, "SWARM_MODE", "false")
        return val.strip().lower() == "true"

    # ---- Public API --------------------------------------------------------

    def enable_swarm(self, actor: str = "local") -> Dict[str, Any]:
        with self._lock:
            _db_set(self._conn, "SWARM_MODE", "true")
            _db_log_event(self._conn, "enable_swarm", actor=actor)
            self._enabled = True
            _write_status(True, "active")
            return {"ok": True, "swarm_mode": True, "event": "enabled"}

    def disable_swarm(self, actor: str = "local") -> Dict[str, Any]:
        with self._lock:
            _db_set(self._conn, "SWARM_MODE", "false")
            _db_log_event(self._conn, "disable_swarm", actor=actor)
            self._enabled = False
            _write_status(False, "idle")
            return {"ok": True, "swarm_mode": False, "event": "disabled"}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "ok": True,
                "swarm_mode": self._enabled,
                "mode": "active" if self._enabled else "idle",
                "ipc_port": IPC_PORT,
                "updated_at": _utc_now(),
                **self._health_extra,
            }

    def get_health(self) -> Dict[str, Any]:
        try:
            from modules.swarm_health import get_swarm_status
            status = get_swarm_status()
        except Exception as err:
            status = {"error": str(err)}
        return {"ok": True, "swarm_mode": self._enabled, **status}

    def update_health_extra(self, extra: Dict[str, Any]) -> None:
        with self._lock:
            self._health_extra.update(extra)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def dispatch(self, cmd: str, actor: str = "local") -> Dict[str, Any]:
        """Dispatch a command string and return response dict."""
        if cmd == "enable_swarm":
            return self.enable_swarm(actor=actor)
        if cmd == "disable_swarm":
            return self.disable_swarm(actor=actor)
        if cmd == "status":
            return self.get_status()
        if cmd == "health":
            return self.get_health()
        return {"ok": False, "error": f"unknown_command: {cmd}"}

    # ---- IPC TCP server -------------------------------------------------------

    def start_ipc_server(self) -> bool:
        """Start background TCP IPC server. Returns True if started."""
        if self._server_thread and self._server_thread.is_alive():
            return False
        self._stop_event.clear()
        self._server_thread = threading.Thread(
            target=self._ipc_server_loop, daemon=True, name="swarm-ctrl-ipc"
        )
        self._server_thread.start()
        # Also start file-command poll thread
        self._cmd_poll_thread = threading.Thread(
            target=self._file_cmd_poll_loop, daemon=True, name="swarm-ctrl-poll"
        )
        self._cmd_poll_thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
        if self._cmd_poll_thread and self._cmd_poll_thread.is_alive():
            self._cmd_poll_thread.join(timeout=1.0)
        self._server_thread = None
        self._cmd_poll_thread = None
        try:
            self._conn.close()
        except Exception as e:
            logger.warning(f"[swarm_controller] Stiller Fehler: {e}")
            pass

    def _ipc_server_loop(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((IPC_HOST, IPC_PORT))
            srv.listen(8)
            srv.settimeout(0.2)
        except OSError as err:
            print(f"[SWARM-CTRL] IPC bind failed ({IPC_HOST}:{IPC_PORT}): {err}")
            return

        print(f"[SWARM-CTRL] IPC server listening on {IPC_HOST}:{IPC_PORT}")
        while not self._stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout as e:
                continue
            except Exception as e:
                break
            threading.Thread(
                target=self._handle_client, args=(conn, addr), daemon=True
            ).start()
        srv.close()

    def _handle_client(self, conn: socket.socket, addr: Any) -> None:
        try:
            conn.settimeout(5.0)
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            raw = data.decode("utf-8", errors="replace").strip()
            try:
                obj = json.loads(raw)
                cmd = str(obj.get("cmd", "")).strip()
                actor = str(obj.get("actor", str(addr[0]))).strip()
            except Exception as e:
                cmd, actor = raw, str(addr[0])
            response = self.dispatch(cmd, actor=actor)
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except Exception as err:
            try:
                conn.sendall((json.dumps({"ok": False, "error": str(err)}) + "\n").encode("utf-8"))
            except Exception as e:
                logger.warning(f"[swarm_controller] Stiller Fehler: {e}")
                pass
        finally:
            try:
                conn.close()
            except Exception as e:
                logger.warning(f"[swarm_controller] Stiller Fehler: {e}")
                pass

    def _file_cmd_poll_loop(self) -> None:
        """Poll data/interbus/swarm_cmd.json for file-based IPC commands."""
        last_mtime: float = 0.0
        while not self._stop_event.is_set():
            time.sleep(0.5)
            try:
                if not CMD_PATH.is_file():
                    continue
                mtime = CMD_PATH.stat().st_mtime
                if mtime <= last_mtime:
                    continue
                last_mtime = mtime
                raw = json.loads(CMD_PATH.read_text(encoding="utf-8"))
                cmd = str(raw.get("cmd", "")).strip()
                actor = str(raw.get("actor", "file")).strip()
                if cmd:
                    result = self.dispatch(cmd, actor=actor)
                    # Write result back alongside command file
                    result_path = CMD_PATH.with_suffix(".result.json")
                    result_path.write_text(
                        json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8"
                    )
                # Consume the command (truncate)
                CMD_PATH.write_text("{}", encoding="utf-8")
            except Exception as e:
                logger.warning(f"[swarm_controller] Stiller Fehler: {e}")
                pass


# --------------------------------------------------------------------------- #
#  Standalone client helper                                                    #
# --------------------------------------------------------------------------- #

def send_command(cmd: str, host: str = IPC_HOST, port: int = IPC_PORT, timeout: float = 3.0) -> Dict[str, Any]:
    """Send a command to a running SwarmController IPC server and return the response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall((json.dumps({"cmd": cmd}) + "\n").encode("utf-8"))
        data = b""
        sock.settimeout(timeout)
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return json.loads(data.decode("utf-8").strip())
    except Exception as err:
        logger.warning(f"[swarm_controller] Fehler: {err}")
        return {"ok": False, "error": str(err), "fallback": "file"}


def send_command_via_file(cmd: str) -> Dict[str, Any]:
    """File-based fallback: write command to swarm_cmd.json, wait for result."""
    try:
        INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
        CMD_PATH.write_text(
            json.dumps({"cmd": cmd, "actor": "file_client", "ts": _utc_now()}),
            encoding="utf-8",
        )
        result_path = CMD_PATH.with_suffix(".result.json")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            time.sleep(0.1)
            if result_path.is_file():
                try:
                    raw = json.loads(result_path.read_text(encoding="utf-8"))
                    if isinstance(raw, dict) and "ok" in raw:
                        return raw
                except Exception as e:
                    logger.warning(f"[swarm_controller] Stiller Fehler: {e}")
                    pass
        return {"ok": False, "error": "timeout"}
    except Exception as err:
        logger.warning(f"[swarm_controller] Fehler: {err}")
        return {"ok": False, "error": str(err)}


# --------------------------------------------------------------------------- #
#  Singleton accessor                                                          #
# --------------------------------------------------------------------------- #

_controller_instance: Optional[SwarmController] = None
_controller_lock = threading.Lock()


def get_controller() -> SwarmController:
    global _controller_instance
    with _controller_lock:
        if _controller_instance is None:
            _controller_instance = SwarmController()
        return _controller_instance
