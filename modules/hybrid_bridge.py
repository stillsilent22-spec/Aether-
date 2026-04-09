"""
modules/hybrid_bridge.py — Aether Hybrid-Bridge

Wird von Rust (py_bridge.rs) als Hintergrundprozess gestartet.
Schreibt alle poll_seconds den Laufzeit-Status nach data/interbus/hybrid_status.json.
Startet optional den Symbiont-Server (aether-symbiont).
Startet optional Yggdrasil P2P-Overlay (wenn verfuegbar und aktiviert).
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[hybrid_bridge] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS_PATH = _ROOT / "data" / "settings.json"
_STATUS_PATH = _ROOT / "data" / "interbus" / "hybrid_status.json"
_SWARM_NODES_DIR = _ROOT / "data" / "swarm" / "nodes"
_YGG_CONF_PATH = _ROOT / "data" / "yggdrasil.conf"

# Stelle sicher, dass das Projektverzeichnis importierbar ist
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _load_settings() -> dict:
    try:
        return json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _count_swarm_nodes() -> int:
    try:
        return len(list(_SWARM_NODES_DIR.glob("*.json")))
    except Exception:
        return 0


def _write_status(
    *,
    bridge_running: bool,
    symbiont_running: bool,
    symbiont_pid: int,
    symbiont_host: str,
    symbiont_port: int,
    last_error: str,
    yggdrasil_running: bool = False,
    yggdrasil_addr: str = "",
    swarm_peer_count: int = 0,
) -> None:
    status = {
        "bridge_running": bridge_running,
        "symbiont_running": symbiont_running,
        "aethernet_running": False,
        "aethernet_receiver_port": 0,
        "bridge_pid": os.getpid(),
        "symbiont_pid": symbiont_pid,
        "symbiont_host": symbiont_host,
        "symbiont_port": symbiont_port,
        "swarm_node_count": _count_swarm_nodes(),
        "swarm_pack_count": 0,
        "swarm_consensus_count": 0,
        "swarm_candidate_count": 0,
        "swarm_summary": f"{swarm_peer_count} aktive Peers" if swarm_peer_count > 0 else "",
        "last_error": last_error,
        "last_tick": datetime.now(timezone.utc).isoformat(),
        "yggdrasil_running": yggdrasil_running,
        "yggdrasil_addr": yggdrasil_addr,
    }
    try:
        _STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATUS_PATH.write_text(json.dumps(status, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Status-Schreiben fehlgeschlagen: %s", exc)


def _get_yggdrasil_addr() -> str:
    """Liest die eigene Yggdrasil IPv6-Adresse aus der Konfigurationsdatei.

    Parst den PrivateKey aus der HJSON-Konfiguration und leitet die Adresse
    deterministisch ab — kein Netzwerkzugriff, kein externer Prozess.
    """
    if not _YGG_CONF_PATH.is_file():
        return ""
    try:
        from modules.yggdrasil_addr import derive_yggdrasil_address  # noqa: PLC0415

        config_text = _YGG_CONF_PATH.read_text(encoding="utf-8")
        # Yggdrasil HJSON: PrivateKey: <128 hex chars>  oder  "PrivateKey": "<hex>"
        m = re.search(r'"?PrivateKey"?\s*:\s*"?([0-9a-fA-F]{64,128})"?', config_text)
        if not m:
            return ""
        key_hex = m.group(1)
        # Erste 32 Bytes = Ed25519 Seed (Yggdrasil speichert seed||pubkey als 64 Bytes)
        seed_bytes = bytes.fromhex(key_hex[:64])
        return derive_yggdrasil_address(seed_bytes)
    except Exception as exc:
        logger.debug("Yggdrasil-Adresse konnte nicht ermittelt werden: %s", exc)
        return ""


def _is_yggdrasil_enabled(settings: dict) -> bool:
    return bool(settings.get("hybrid", {}).get("yggdrasil", {}).get("enabled", True))


def _try_start_yggdrasil(settings: dict) -> bool:
    """Startet Yggdrasil wenn aktiviert und verfuegbar. Gibt True bei Erfolg."""
    if not _is_yggdrasil_enabled(settings):
        return False
    try:
        from modules.yggdrasil_install import (  # noqa: PLC0415
            is_yggdrasil_available,
            start_yggdrasil_subprocess,
        )

        if not is_yggdrasil_available():
            logger.info("Yggdrasil nicht installiert — P2P-Overlay deaktiviert.")
            return False
        start_yggdrasil_subprocess()
        logger.info("Yggdrasil P2P-Overlay gestartet.")
        return True
    except Exception as exc:
        logger.warning("Yggdrasil-Start fehlgeschlagen: %s", exc)
        return False


def _is_yggdrasil_still_running() -> bool:
    """Prueft ob der verwaltete Yggdrasil-Prozess noch laeuft."""
    try:
        from modules.yggdrasil_install import is_yggdrasil_managed_running  # noqa: PLC0415

        return is_yggdrasil_managed_running()
    except Exception:
        return False



    sym = settings.get("hybrid", {}).get("symbiont", {})
    if not sym.get("enabled", True):
        return None
    server_path = Path(sym.get("server_path", "aether-symbiont/server/symbiont_server.py"))
    if not (_ROOT / server_path).is_file():
        logger.info("Symbiont-Server nicht gefunden (%s) — übersprungen.", server_path)
        return None
    python = sym.get("python_path", "python") or "python"
    try:
        proc = subprocess.Popen(
            [python, str(_ROOT / server_path)],
            cwd=str(_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("Symbiont gestartet (PID %d).", proc.pid)
        return proc
    except Exception as exc:
        logger.warning("Symbiont-Start fehlgeschlagen: %s", exc)
        return None


def main() -> None:
    logger.info("Hybrid-Bridge gestartet (PID %d).", os.getpid())
    settings = _load_settings()
    poll = float(
        settings.get("hybrid", {}).get("poll_seconds", 2.0)
    )
    poll = max(0.5, min(poll, 10.0))

    sym_settings = settings.get("hybrid", {}).get("symbiont", {})
    sym_host = sym_settings.get("host", "127.0.0.1")
    sym_port = int(sym_settings.get("port", 38571))

    # Yggdrasil P2P-Overlay starten (wenn aktiviert und verfuegbar)
    ygg_started = _try_start_yggdrasil(settings)
    ygg_addr = _get_yggdrasil_addr() if ygg_started or _YGG_CONF_PATH.is_file() else ""
    if ygg_started and ygg_addr:
        logger.info("Eigene Yggdrasil-Adresse: [%s]", ygg_addr)

    # Swarm P2P-Layer automatisch starten (opt-out: swarm_p2p.enabled=false zum Deaktivieren)
    _p2p_layer = None
    try:
        from modules.swarm_p2p import make_p2p_layer  # noqa: PLC0415
        import uuid as _uuid
        node_id_path = _ROOT / "data" / "swarm" / "node_id.txt"
        if node_id_path.is_file():
            _node_id = node_id_path.read_text(encoding="utf-8").strip()
        else:
            _node_id = "node-" + _uuid.uuid4().hex[:16]
            node_id_path.parent.mkdir(parents=True, exist_ok=True)
            node_id_path.write_text(_node_id, encoding="utf-8")
        _p2p_layer = make_p2p_layer(node_id=_node_id)
        if _p2p_layer.enabled:
            _p2p_layer.start()
            logger.info("Swarm P2P-Layer gestartet (NodeID=%s).", _node_id[:20])
        else:
            logger.info("Swarm P2P deaktiviert (swarm_p2p.enabled=false in settings.json).")
            _p2p_layer = None
    except Exception as _p2p_exc:
        logger.warning("Swarm P2P-Start fehlgeschlagen (nicht kritisch): %s", _p2p_exc)
        _p2p_layer = None

    symbiont_proc = _start_symbiont(settings)
    last_error = ""

    def _shutdown(signum, frame):  # noqa: ANN001
        logger.info("Shutdown-Signal empfangen.")
        if _p2p_layer is not None:
            try:
                _p2p_layer.stop()
            except Exception:
                pass
        if symbiont_proc and symbiont_proc.poll() is None:
            symbiont_proc.terminate()
        try:
            from modules.yggdrasil_install import stop_yggdrasil_subprocess  # noqa: PLC0415
            if ygg_started:
                stop_yggdrasil_subprocess()
        except Exception:
            pass
        _write_status(
            bridge_running=False,
            symbiont_running=False,
            symbiont_pid=0,
            symbiont_host=sym_host,
            symbiont_port=sym_port,
            last_error="",
            yggdrasil_running=False,
            yggdrasil_addr="",
        )
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, _shutdown)

    while True:
        sym_running = bool(symbiont_proc and symbiont_proc.poll() is None)
        sym_pid = symbiont_proc.pid if sym_running else 0

        # Neustart des Symbiont bei unerwartetem Absturz
        if not sym_running and symbiont_proc is not None:
            logger.info("Symbiont abgestürzt — Neustart.")
            symbiont_proc = _start_symbiont(settings)
            last_error = "Symbiont neu gestartet."

        ygg_running = _is_yggdrasil_still_running() if ygg_started else False

        # Aktive Peer-Anzahl aus P2P-Layer lesen (0 wenn nicht aktiv)
        swarm_peer_count = 0
        if _p2p_layer is not None:
            try:
                swarm_peer_count = _p2p_layer._leader_election.peer_count()
            except Exception:
                pass

        _write_status(
            bridge_running=True,
            symbiont_running=sym_running,
            symbiont_pid=sym_pid,
            symbiont_host=sym_host,
            symbiont_port=sym_port,
            last_error=last_error,
            yggdrasil_running=ygg_running,
            yggdrasil_addr=ygg_addr,
            swarm_peer_count=swarm_peer_count,
        )
        last_error = ""
        time.sleep(poll)


if __name__ == "__main__":
    main()
