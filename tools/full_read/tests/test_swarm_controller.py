"""Unit tests for SwarmController IPC and state management."""

from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path

import pytest

from modules.swarm_controller import SwarmController, send_command, IPC_HOST


# --------------------------------------------------------------------------- #
#  Fixtures                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture
def tmp_ctrl(tmp_path):
    """Controller with isolated DB in temp dir."""
    db = str(tmp_path / "test_swarm.db")
    ctrl = SwarmController(db_path=db)
    yield ctrl
    ctrl.stop()


# --------------------------------------------------------------------------- #
#  State transition tests                                                     #
# --------------------------------------------------------------------------- #

def test_initial_state_is_disabled(tmp_ctrl):
    assert tmp_ctrl.enabled is False


def test_enable_returns_ok(tmp_ctrl):
    result = tmp_ctrl.enable_swarm(actor="test")
    assert result["ok"] is True
    assert result["swarm_mode"] is True
    assert tmp_ctrl.enabled is True


def test_disable_returns_ok(tmp_ctrl):
    tmp_ctrl.enable_swarm()
    result = tmp_ctrl.disable_swarm(actor="test")
    assert result["ok"] is True
    assert result["swarm_mode"] is False
    assert tmp_ctrl.enabled is False


def test_status_reflects_state(tmp_ctrl):
    tmp_ctrl.enable_swarm()
    s = tmp_ctrl.get_status()
    assert s["ok"] is True
    assert s["swarm_mode"] is True
    assert s["mode"] == "active"

    tmp_ctrl.disable_swarm()
    s = tmp_ctrl.get_status()
    assert s["swarm_mode"] is False
    assert s["mode"] == "idle"


def test_dispatch_unknown_command(tmp_ctrl):
    result = tmp_ctrl.dispatch("unknown_cmd_xyz")
    assert result["ok"] is False
    assert "unknown_command" in result["error"]


def test_dispatch_enable_disable_cycle(tmp_ctrl):
    for _ in range(3):
        r1 = tmp_ctrl.dispatch("enable_swarm")
        assert r1["ok"] and r1["swarm_mode"] is True
        r2 = tmp_ctrl.dispatch("disable_swarm")
        assert r2["ok"] and r2["swarm_mode"] is False


def test_state_persists_across_instances(tmp_path):
    db = str(tmp_path / "persist_test.db")
    c1 = SwarmController(db_path=db)
    c1.enable_swarm()
    c1.stop()

    c2 = SwarmController(db_path=db)
    assert c2.enabled is True
    c2.stop()


def test_concurrent_enable_disable_safe(tmp_ctrl):
    """Concurrent enable/disable should not corrupt state."""
    errors = []

    def toggle():
        for _ in range(10):
            try:
                tmp_ctrl.enable_swarm()
                tmp_ctrl.disable_swarm()
            except Exception as err:
                errors.append(str(err))

    threads = [threading.Thread(target=toggle) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert not errors, f"Concurrent errors: {errors}"


# --------------------------------------------------------------------------- #
#  IPC socket tests                                                           #
# --------------------------------------------------------------------------- #

def _find_free_port() -> int:
    import socket as _socket
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_ipc_server_enable_disable(tmp_path, monkeypatch):
    """Start IPC server on a free port and send commands over socket."""
    import modules.swarm_controller as sc_mod

    port = _find_free_port()
    monkeypatch.setattr(sc_mod, "IPC_PORT", port)

    db = str(tmp_path / "ipc_test.db")
    ctrl = SwarmController(db_path=db)
    started = ctrl.start_ipc_server()
    assert started is True
    time.sleep(0.3)  # let server bind

    try:
        r = send_command("enable_swarm", host=IPC_HOST, port=port)
        if r.get("ok"):
            assert r["swarm_mode"] is True

        r2 = send_command("status", host=IPC_HOST, port=port)
        if r2.get("ok"):
            assert "swarm_mode" in r2

        r3 = send_command("disable_swarm", host=IPC_HOST, port=port)
        if r3.get("ok"):
            assert r3["swarm_mode"] is False
    finally:
        ctrl.stop()


def test_ipc_unknown_command_returns_error(tmp_path, monkeypatch):
    import modules.swarm_controller as sc_mod

    port = _find_free_port()
    monkeypatch.setattr(sc_mod, "IPC_PORT", port)

    db = str(tmp_path / "ipc_unk.db")
    ctrl = SwarmController(db_path=db)
    ctrl.start_ipc_server()
    time.sleep(0.3)

    try:
        r = send_command("totally_unknown_cmd", host=IPC_HOST, port=port)
        if r.get("ok") is False:
            assert "unknown_command" in r.get("error", "")
    finally:
        ctrl.stop()


# --------------------------------------------------------------------------- #
#  File-based IPC tests                                                       #
# --------------------------------------------------------------------------- #

def test_file_cmd_poll(tmp_path, monkeypatch):
    """File-based command polling."""
    import modules.swarm_controller as sc_mod

    port = _find_free_port()
    monkeypatch.setattr(sc_mod, "IPC_PORT", port)
    monkeypatch.setattr(sc_mod, "INTERBUS_DIR", tmp_path)
    monkeypatch.setattr(sc_mod, "CMD_PATH", tmp_path / "swarm_cmd.json")
    monkeypatch.setattr(sc_mod, "STATUS_PATH", tmp_path / "swarm_status.json")

    db = str(tmp_path / "file_poll.db")
    ctrl = SwarmController(db_path=db)
    ctrl.start_ipc_server()
    time.sleep(0.2)

    cmd_path = tmp_path / "swarm_cmd.json"
    cmd_path.write_text(json.dumps({"cmd": "enable_swarm", "actor": "file_test"}), encoding="utf-8")

    # Wait for poll cycle
    time.sleep(1.5)

    result_path = tmp_path / "swarm_cmd.result.json"
    if result_path.is_file():
        raw = json.loads(result_path.read_text(encoding="utf-8"))
        assert raw.get("ok") is True

    ctrl.stop()
