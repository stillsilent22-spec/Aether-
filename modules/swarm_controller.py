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


import base64
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

# Cross-node compute listener — accepts requests from any swarm node (PC or mobile).
# Binds to 0.0.0.0 so remote nodes can reach this machine over LAN.
COMPUTE_LISTENER_PORT = 7389
COMPUTE_MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MB hard cap per request


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
            start_compute_listener()
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
#  Cross-node compute listener (port 7389, all interfaces)                    #
# --------------------------------------------------------------------------- #

def _handle_compute_request(conn: socket.socket, addr: Any) -> None:
    """Handle a single inbound compute request from another swarm node.

    Protocol (newline-delimited JSON over TCP, port 7389):
      Request:  {"type": "compute_request", "raw_b64": "<base64>",
                 "label": "<str>", "previous_b64": "<base64|''>"}
      Response: {"ok": true, "metrics": {...}, "shared_anchor_pack": {...},
                 "godel_loop": {...}, "anomaly_flags": [...]}
      Error:    {"ok": false, "error": "<reason>"}

    Gate: swarm consent required. Payload capped at COMPUTE_MAX_PAYLOAD_BYTES.
    local_delta is intentionally excluded from the response.
    """
    try:
        conn.settimeout(10.0)
        raw_request = b""
        while b"\n" not in raw_request:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw_request += chunk
            if len(raw_request) > COMPUTE_MAX_PAYLOAD_BYTES + 4096:
                conn.sendall(json.dumps({"ok": False, "error": "payload_too_large"}).encode() + b"\n")
                return

        # Consent gate — re-checked per request, never cached
        try:
            consent_path = ROOT / "data" / "swarm_consent.json"
            consented = False
            if consent_path.exists():
                cdata = json.loads(consent_path.read_text(encoding="utf-8"))
                consented = bool(
                    cdata.get("consented") or cdata.get("consent_ok") or cdata.get("approved")
                )
        except Exception:
            consented = False
        if not consented:
            conn.sendall(json.dumps({"ok": False, "error": "consent_not_given"}).encode() + b"\n")
            return

        try:
            request = json.loads(raw_request.split(b"\n")[0].decode("utf-8"))
        except Exception:
            conn.sendall(json.dumps({"ok": False, "error": "invalid_json"}).encode() + b"\n")
            return

        if request.get("type") != "compute_request":
            conn.sendall(json.dumps({"ok": False, "error": "unknown_request_type"}).encode() + b"\n")
            return

        raw_b64 = str(request.get("raw_b64") or "")
        if not raw_b64:
            conn.sendall(json.dumps({"ok": False, "error": "missing_raw_b64"}).encode() + b"\n")
            return

        raw_bytes = base64.b64decode(raw_b64)
        if len(raw_bytes) > COMPUTE_MAX_PAYLOAD_BYTES:
            conn.sendall(json.dumps({"ok": False, "error": "payload_too_large"}).encode() + b"\n")
            return

        previous_b64 = str(request.get("previous_b64") or "")
        previous_bytes = base64.b64decode(previous_b64) if previous_b64 else None
        source_label = str(request.get("label") or "remote_compute")

        from modules.analysis_capsule import AnalysisCapsuleEngine
        engine = AnalysisCapsuleEngine(trust_threshold=0.65)
        result = engine.from_live_signal(
            raw_bytes,
            source_label=source_label,
            previous_signal=previous_bytes,
        )

        response = {
            "ok": True,
            "platform": sys.platform,
            "metrics": result.metrics.to_dict(),
            "shared_anchor_pack": result.shared_anchor_pack,
            "godel_loop": result.godel_loop,
            "anomaly_flags": result.anomaly_flags,
            # local_delta intentionally excluded — stays on this node
        }
        conn.sendall(json.dumps(response, ensure_ascii=True).encode() + b"\n")
        logger.info("[swarm_controller] compute_request from %s — trust=%.3f",
                    addr[0], result.metrics.trust_score)

    except Exception as exc:
        try:
            conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode() + b"\n")
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_compute_listener() -> None:
    """Start the cross-node compute listener on COMPUTE_LISTENER_PORT (0.0.0.0).

    Runs as a single daemon thread; each accepted connection is dispatched to
    its own thread so slow requests never block the listener.
    Idempotent — safe to call multiple times.
    """
    _started_flag = getattr(start_compute_listener, "_started", False)
    if _started_flag:
        return
    start_compute_listener._started = True  # type: ignore[attr-defined]

    def _loop() -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", COMPUTE_LISTENER_PORT))
            srv.listen(8)
            logger.info("[swarm_controller] Compute listener on 0.0.0.0:%d", COMPUTE_LISTENER_PORT)
            while True:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=_handle_compute_request,
                        args=(conn, addr),
                        daemon=True,
                    ).start()
                except Exception as exc:
                    logger.warning("[swarm_controller] compute accept error: %s", exc)
        except Exception as exc:
            logger.error("[swarm_controller] Compute listener failed: %s", exc)

    threading.Thread(target=_loop, daemon=True, name="swarm-compute-listener").start()


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


# --------------------------------------------------------------------------- #
#  Automatische Aufgabenverteilung an Peer-Nodes                             #
# --------------------------------------------------------------------------- #

def _discover_lan_compute_peers(
    port: int = COMPUTE_LISTENER_PORT,
    timeout: float = 0.4,
    max_peers: int = 8,
) -> List[str]:
    """Scannt das LAN-Subnetz nach erreichbaren Compute-Nodes (Port 7389).

    Liest bekannte Node-Adressen aus data/swarm/nodes/ und ergaenzt sie mit
    der Yggdrasil-/LAN-Beacon-Tabelle.  Gibt Liste von IP-Strings zurueck.
    """
    known: List[str] = []

    # 1) Aus nodes-Verzeichnis laden
    nodes_dir = ROOT / "data" / "swarm" / "nodes"
    if nodes_dir.is_dir():
        for f in nodes_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                addr = str(data.get("address") or data.get("ip") or "").strip()
                if addr and addr not in known:
                    known.append(addr)
            except Exception:
                pass

    # 2) Aus LAN-Beacon-Tabelle (data/interbus/lan_peers.json)
    lan_peers_path = ROOT / "data" / "interbus" / "lan_peers.json"
    if lan_peers_path.is_file():
        try:
            data = json.loads(lan_peers_path.read_text(encoding="utf-8"))
            for entry in (data if isinstance(data, list) else data.get("peers", [])):
                addr = str(entry.get("address") or entry.get("ip") or "").strip()
                if addr and addr not in known:
                    known.append(addr)
        except Exception:
            pass

    # 3) Ping-Test: nur erreichbare Nodes behalten
    reachable: List[str] = []
    for addr in known[:max_peers]:
        try:
            s = socket.create_connection((addr, port), timeout=timeout)
            s.close()
            reachable.append(addr)
        except Exception:
            pass

    return reachable


def request_help_from_peers(
    raw: bytes,
    source_label: str = "auto_task",
    previous_signal: Optional[bytes] = None,
    timeout: float = 8.0,
    max_peers: int = 3,
) -> List[Dict[str, Any]]:
    """Sendet einen Analyse-Task an verfuegbare Peer-Nodes und sammelt Ergebnisse.

    Wird automatisch aus auto_dispatch_task() aufgerufen wenn die lokale Last hoch
    ist oder ein quorum-basiertes Ergebnis benoetigt wird.

    Protocol: identisch mit dem bestehenden compute_request-Protokoll auf Port 7389.
    Gibt Liste von Peer-Antworten zurueck (leere Liste wenn keine Peers erreichbar).
    """
    # Consent-Gate: Hilfsanfragen nur versenden wenn Consent vorliegt
    try:
        from modules.swarm_consent import has_consent
        if not has_consent():
            logger.info("[swarm_controller] request_help_from_peers: kein Consent — abgebrochen")
            return []
    except Exception:
        pass

    peers = _discover_lan_compute_peers(max_peers=max_peers)
    if not peers:
        logger.debug("[swarm_controller] request_help_from_peers: keine Peers gefunden")
        return []

    import base64

    raw_b64 = base64.b64encode(raw).decode("ascii")
    prev_b64 = base64.b64encode(previous_signal).decode("ascii") if previous_signal else ""
    payload = json.dumps({
        "type": "compute_request",
        "raw_b64": raw_b64,
        "previous_b64": prev_b64,
        "label": source_label,
    }).encode("utf-8") + b"\n"

    results: List[Dict[str, Any]] = []

    def _query_peer(addr: str) -> None:
        try:
            conn = socket.create_connection((addr, COMPUTE_LISTENER_PORT), timeout=timeout)
            conn.sendall(payload)
            conn.settimeout(timeout)
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > COMPUTE_MAX_PAYLOAD_BYTES:
                    break
            conn.close()
            resp = json.loads(data.split(b"\n")[0].decode("utf-8"))
            if resp.get("ok"):
                resp["_peer_addr"] = addr
                results.append(resp)
                logger.info("[swarm_controller] Peer %s geantwortet (trust=%.3f)",
                            addr, resp.get("metrics", {}).get("trust_score", 0))
        except Exception as exc:
            logger.debug("[swarm_controller] Peer %s nicht erreichbar: %s", addr, exc)

    threads = [threading.Thread(target=_query_peer, args=(addr,), daemon=True) for addr in peers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 1.0)

    return results


def auto_dispatch_task(
    raw: bytes,
    source_label: str = "auto_task",
    previous_signal: Optional[bytes] = None,
    cpu_threshold: float = 70.0,
    always_replicate: bool = False,
) -> Dict[str, Any]:
    """Koordiniert automatisch ob ein Task lokal oder an Peer-Nodes delegiert wird.

    Logik:
      - CPU-Last > cpu_threshold ODER always_replicate=True:
            Task wird parallel an verfuegbare Peers gesendet (Hilfsanfrage).
      - Peer-Ergebnisse werden mit lokalem Ergebnis zusammengefuehrt
            (Quorum-Vergleich via Trust-Score-Mittelwert).
      - Immer deterministisch: lokales Ergebnis ist primary, Peers sind confirmatory.

    Gibt zusammengefuehrtes Ergebnis-Dict zurueck.
    """
    # Lokale CPU-Last pruefen
    local_cpu: float = 0.0
    try:
        import psutil
        local_cpu = psutil.cpu_percent(interval=0.1)
    except Exception:
        pass

    should_delegate = always_replicate or (local_cpu > cpu_threshold)

    # Lokale Analyse (immer)
    local_result: Dict[str, Any] = {}
    try:
        from modules.analysis_capsule import AnalysisCapsuleEngine
        engine = AnalysisCapsuleEngine(trust_threshold=0.65)
        capsule = engine.from_live_signal(raw, source_label=source_label, previous_signal=previous_signal)
        local_result = {
            "ok": True,
            "metrics": capsule.metrics.to_dict(),
            "shared_anchor_pack": capsule.shared_anchor_pack,
            "godel_loop": capsule.godel_loop,
            "anomaly_flags": capsule.anomaly_flags,
            "_source": "local",
            "_cpu_at_dispatch": local_cpu,
        }
    except Exception as exc:
        local_result = {"ok": False, "error": str(exc), "_source": "local"}

    peer_results: List[Dict[str, Any]] = []
    if should_delegate:
        peer_results = request_help_from_peers(
            raw=raw,
            source_label=source_label,
            previous_signal=previous_signal,
        )

    # Trust-Quorum: Mittelwert ueber alle Ergebnisse berechnen
    all_trusts = [
        r.get("metrics", {}).get("trust_score", 0.0)
        for r in ([local_result] + peer_results)
        if r.get("ok")
    ]
    quorum_trust = sum(all_trusts) / len(all_trusts) if all_trusts else 0.0

    return {
        "local": local_result,
        "peers": peer_results,
        "peer_count": len(peer_results),
        "quorum_trust": quorum_trust,
        "delegated": should_delegate,
        "cpu_at_dispatch": local_cpu,
    }
