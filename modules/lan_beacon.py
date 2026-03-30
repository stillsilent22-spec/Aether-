from __future__ import annotations

import json
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Optional

import hashlib
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    Encoding,
    PublicFormat,
)

LAN_MULTICAST_GROUP = "239.255.42.7"
LAN_MULTICAST_PORT = 7742
YGGDRASIL_MULTICAST_PORT = 7743
BEACON_INTERVAL_SECONDS = 10.0
_START_LOCK = threading.Lock()
_STARTED = False


def _root_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def _node_record_path() -> Path:
    return _root_dir() / "data" / "swarm" / "node.json"


def _nodes_dir() -> Path:
    return _root_dir() / "data" / "swarm" / "nodes"


def _yggdrasil_config_path() -> Path:
    return _root_dir() / "data" / "yggdrasil.conf"


def _load_local_node_record() -> dict[str, Any]:
    path = _node_record_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _store_remote_node(payload: dict[str, Any]) -> None:
    node_id = str(payload.get("node_id", "") or "").strip()
    if not node_id:
        return
    target = _nodes_dir() / f"{node_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")


def _verify_node_record(payload: dict[str, Any]) -> bool:
    """node_id must be mathematically derived from public_key_pem.
    Prevents spoofed beacon packets from polluting the node registry."""
    try:
        pem = str(payload.get("public_key_pem", "") or "").strip()
        node_id = str(payload.get("node_id", "") or "").strip()
        if not pem or not node_id:
            return False
        pub = load_pem_public_key(pem.encode("utf-8"))
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        expected_id = hashlib.sha256(raw).hexdigest()[:16]
        return expected_id == node_id
    except Exception:
        return False


def _is_fresh(payload: dict[str, Any], max_age_seconds: float = 300.0) -> bool:
    """Reject replayed old beacon packets."""
    try:
        ts = str(payload.get("beacon_ts", "") or "").strip()
        if not ts:
            return True  # No timestamp = old format, accept for now
        beacon_time = float(ts)
        return abs(time.time() - beacon_time) <= max_age_seconds
    except Exception:
        return True


def _apply_interface_binding(sock: socket.socket, interface_name: Optional[str]) -> None:
    if not interface_name:
        return
    bind_to_device = getattr(socket, "SO_BINDTODEVICE", None)
    if bind_to_device is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, bind_to_device, interface_name.encode("ascii", errors="ignore") + b"\0")
    except Exception:
        pass


def _join_multicast_group(sock: socket.socket) -> None:
    membership = struct.pack("4s4s", socket.inet_aton(LAN_MULTICAST_GROUP), socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)


def _create_listener(port: int, interface_name: Optional[str] = None) -> Optional[socket.socket]:
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _apply_interface_binding(sock, interface_name)
        sock.bind(("", port))
        _join_multicast_group(sock)
        sock.settimeout(1.0)
        return sock
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None


def _create_sender(interface_name: Optional[str] = None) -> Optional[socket.socket]:
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        _apply_interface_binding(sock, interface_name)
        return sock
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None


def _beacon_payload_bytes() -> Optional[bytes]:
    payload = _load_local_node_record()
    if not payload:
        return None
    try:
        payload_dict = dict(payload)
        payload_dict["beacon_ts"] = str(time.time())
        return json.dumps(payload_dict, ensure_ascii=True, sort_keys=True).encode("utf-8")
    except Exception:
        return None


def _receive_once(sock: socket.socket) -> None:
    try:
        data, _addr = sock.recvfrom(65535)
    except socket.timeout:
        return
    except Exception:
        return
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception:
        return
    if not isinstance(payload, dict):
        return
    local_node_id = str(_load_local_node_record().get("node_id", "") or "").strip()
    remote_node_id = str(payload.get("node_id", "") or "").strip()
    if remote_node_id and remote_node_id == local_node_id:
        return
    if not _is_fresh(payload):
        return
    if not _verify_node_record(payload):
        return
    _store_remote_node(payload)


def _lan_sender_loop() -> None:
    sock = _create_sender()
    if sock is None:
        return
    try:
        while True:
            payload = _beacon_payload_bytes()
            if payload is not None:
                try:
                    sock.sendto(payload, (LAN_MULTICAST_GROUP, LAN_MULTICAST_PORT))
                except Exception:
                    pass
            time.sleep(BEACON_INTERVAL_SECONDS)
    finally:
        sock.close()


def _lan_listener_loop() -> None:
    sock = _create_listener(LAN_MULTICAST_PORT)
    if sock is None:
        return
    try:
        while True:
            _receive_once(sock)
    finally:
        sock.close()


def _get_yggdrasil_interface() -> Optional[str]:
    """Finds the Yggdrasil TUN interface name (tun0, tap0, etc.)"""
    config_path = _yggdrasil_config_path()
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        interface_name = str(payload.get("InterfaceName", "") or "").strip()
        if interface_name:
            return interface_name
    except Exception:
        pass
    try:
        available = {name for _, name in socket.if_nameindex()}
    except Exception:
        available = set()
    for name in ["tun0", "tun1", "tap0", "aether0"]:
        if name in available:
            return name
    return None


def _yggdrasil_overlay_loop() -> None:
    interface_name = _get_yggdrasil_interface()
    if not interface_name:
        return
    sender = _create_sender(interface_name)
    listener = _create_listener(YGGDRASIL_MULTICAST_PORT, interface_name)
    if sender is None or listener is None:
        if sender is not None:
            sender.close()
        if listener is not None:
            listener.close()
        return
    next_send = 0.0
    try:
        while True:
            now = time.monotonic()
            if now >= next_send:
                payload = _beacon_payload_bytes()
                if payload is not None:
                    try:
                        sender.sendto(payload, (LAN_MULTICAST_GROUP, YGGDRASIL_MULTICAST_PORT))
                    except Exception:
                        pass
                next_send = now + BEACON_INTERVAL_SECONDS
            _receive_once(listener)
    finally:
        sender.close()
        listener.close()


def start() -> None:
    global _STARTED
    with _START_LOCK:
        if _STARTED:
            return
        _STARTED = True
    threading.Thread(target=_lan_sender_loop, daemon=True, name="aether-lan-beacon-send").start()
    threading.Thread(target=_lan_listener_loop, daemon=True, name="aether-lan-beacon-listen").start()
    threading.Thread(target=_yggdrasil_overlay_loop, daemon=True, name="aether-yggdrasil-beacon").start()


__all__ = ["start", "_get_yggdrasil_interface"]
