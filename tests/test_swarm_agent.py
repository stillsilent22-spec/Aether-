"""Unit tests for SwarmAgent: start/stop, capture lifecycle, adaptive CPU."""

from __future__ import annotations

import json
import time
import threading
from pathlib import Path

import pytest

from modules.capture_adapter import StubCaptureAdapter, FrameData, make_capture_adapter
from modules.swarm_agent import SwarmAgent, DeltaPipeline
from modules.swarm_controller import SwarmController


# --------------------------------------------------------------------------- #
#  DeltaPipeline tests                                                        #
# --------------------------------------------------------------------------- #

def test_delta_pipeline_processes_frame():
    pipeline = DeltaPipeline()
    frame = FrameData(
        timestamp=1000.0, width=4, height=4, format="RGB",
        data=bytes(range(48)), adapter_id="stub"
    )
    result = pipeline.process(frame)
    assert "fingerprint" in result
    assert len(result["fingerprint"]) == 64  # SHA256 hex
    assert result["delta_marker"] == "new"
    assert result["frame_index"] == 1


def test_delta_pipeline_detects_stable():
    pipeline = DeltaPipeline()
    data = bytes(range(48))
    frame = FrameData(timestamp=1.0, width=4, height=4, format="RGB", data=data, adapter_id="stub")
    pipeline.process(frame)
    result2 = pipeline.process(frame)
    assert result2["delta_marker"] == "stable"


def test_delta_pipeline_detects_changed():
    pipeline = DeltaPipeline()
    frame1 = FrameData(timestamp=1.0, width=4, height=4, format="RGB", data=bytes(48), adapter_id="stub")
    frame2 = FrameData(timestamp=2.0, width=4, height=4, format="RGB", data=bytes([255] * 48), adapter_id="stub")
    pipeline.process(frame1)
    result = pipeline.process(frame2)
    assert result["delta_marker"] == "changed"


def test_delta_pipeline_reset():
    pipeline = DeltaPipeline()
    frame = FrameData(timestamp=1.0, width=4, height=4, format="RGB", data=bytes(48), adapter_id="stub")
    pipeline.process(frame)
    pipeline.reset()
    result = pipeline.process(frame)
    assert result["delta_marker"] == "new"
    assert result["frame_index"] == 1


# --------------------------------------------------------------------------- #
#  Capture Adapter tests                                                      #
# --------------------------------------------------------------------------- #

def test_stub_adapter_produces_frames():
    adapter = StubCaptureAdapter(width=8, height=8, ring_size=4, max_fps=10.0)
    adapter.start()
    time.sleep(0.5)
    frame = adapter.read_frame()
    adapter.stop()
    assert frame is not None
    assert frame.width == 8
    assert frame.height == 8
    assert len(frame.data) > 0


def test_stub_adapter_ring_overflow():
    """Ring buffer should not grow beyond ring_size."""
    adapter = StubCaptureAdapter(width=4, height=4, ring_size=2, max_fps=20.0)
    adapter.start()
    time.sleep(0.5)
    adapter.stop()
    assert adapter.ring_depth <= 2


def test_frame_metrics_no_raw_data():
    """Metrics output must not contain raw frame bytes."""
    frame = FrameData(timestamp=1.0, width=4, height=4, format="RGB", data=bytes(48), adapter_id="stub")
    m = frame.metrics()
    # Verify no raw data field
    assert "data" not in m
    assert isinstance(m["mean"], float)
    assert isinstance(m["entropy_approx"], float)


def test_frame_fingerprint_is_sha256():
    frame = FrameData(timestamp=1.0, width=4, height=4, format="RGB", data=bytes(48), adapter_id="stub")
    fp = frame.fingerprint()
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_frame_fingerprint_is_stable():
    """Same data should always produce the same fingerprint."""
    data = bytes(range(48))
    f1 = FrameData(timestamp=1.0, width=4, height=4, format="RGB", data=data, adapter_id="stub")
    f2 = FrameData(timestamp=2.0, width=4, height=4, format="RGB", data=data, adapter_id="stub")
    assert f1.fingerprint() == f2.fingerprint()


def test_make_capture_adapter_stub():
    adapter = make_capture_adapter("stub", ring_size=2, max_fps=5.0)
    assert adapter.adapter_id == "stub"


def test_make_capture_adapter_unknown_raises():
    with pytest.raises(ValueError):
        make_capture_adapter("does_not_exist")


# --------------------------------------------------------------------------- #
#  SwarmAgent lifecycle tests                                                 #
# --------------------------------------------------------------------------- #

def _make_agent(tmp_path, adapter_type="stub") -> SwarmAgent:
    db = str(tmp_path / "agent_test.db")
    ctrl = SwarmController(db_path=str(tmp_path / "ctrl.db"))
    return SwarmAgent(
        controller=ctrl,
        adapter_type=adapter_type,
        max_fps=5.0,
        ring_size=2,
        max_cpu_percent=50.0,
        poll_interval=0.1,
        persist_path=db,
    ), ctrl


def test_agent_starts_and_stops(tmp_path):
    agent, ctrl = _make_agent(tmp_path)
    agent.start()
    time.sleep(0.2)
    assert agent.is_running()
    agent.stop()
    time.sleep(0.2)
    assert not agent.is_running()
    ctrl.stop()


def test_agent_starts_capture_on_enable(tmp_path):
    agent, ctrl = _make_agent(tmp_path)
    agent.start()
    time.sleep(0.2)
    assert not agent._capture_active

    ctrl.enable_swarm()
    time.sleep(1.0)  # Let agent detect the state change (SQLite init may be slow)
    assert agent._capture_active

    ctrl.disable_swarm()
    time.sleep(2.0)  # Let agent finish current SQLite write, detect disable, stop capture
    assert not agent._capture_active

    agent.stop()
    ctrl.stop()


def test_agent_stops_capture_on_disable(tmp_path):
    agent, ctrl = _make_agent(tmp_path)
    agent.start()
    ctrl.enable_swarm()
    time.sleep(1.0)
    assert agent._capture_active

    ctrl.disable_swarm()
    time.sleep(2.0)
    assert not agent._capture_active

    agent.stop()
    ctrl.stop()


def test_agent_processes_frames(tmp_path):
    agent, ctrl = _make_agent(tmp_path)
    agent.start()
    ctrl.enable_swarm()
    time.sleep(1.0)  # Let frames accumulate

    count = agent._frame_count
    agent.stop()
    ctrl.stop()

    assert count > 0, f"Expected frames to be processed, got {count}"


def test_agent_health_check(tmp_path):
    agent, ctrl = _make_agent(tmp_path)
    agent.start()
    health = agent.health_check()
    agent.stop()
    ctrl.stop()

    assert health["ok"] is True
    assert "frame_count" in health
    assert "cpu_percent" in health
    assert "adapter_type" in health


def test_agent_no_raw_frames_persisted(tmp_path):
    """Verify only metrics/fingerprints are stored, never raw frame bytes."""
    from modules.swarm_persist import _connect, _db_lock

    db_path = str(tmp_path / "no_raw.db")
    agent, ctrl = _make_agent(tmp_path, adapter_type="stub")
    agent._persist_path = db_path
    agent.start()
    ctrl.enable_swarm()
    time.sleep(1.0)
    agent.stop()
    ctrl.stop()

    with _db_lock:
        conn = _connect(db_path)
        try:
            cols = [row[1] for row in conn.execute("PRAGMA table_info(frame_metrics)").fetchall()]
        finally:
            conn.close()
    assert "data" not in cols
    assert "fingerprint" in cols
    assert "mean_val" in cols
