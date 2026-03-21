"""Tests für Phase-4 Analyse-Methoden in RenderCoordinator."""
import hashlib
import time

import pytest
from modules.render_coordinator import RenderCoordinator, RenderFrame


def _make_frame(entropy: float = 1.0, symmetry: float = 0.5,
                pid: int = 1234, idx: int = 0) -> RenderFrame:
    raw = bytes([idx % 256] * 64)
    return RenderFrame(
        pid=pid,
        process_name="test_proc",
        timestamp=time.time() + idx * 0.1,
        entropy=entropy,
        symmetry=symmetry,
        resonance=0.5,
        pixel_hash=hashlib.sha256(raw + idx.to_bytes(4, "little")).hexdigest(),
        frame_size=64,
        region={"left": 0, "top": 0, "width": 100, "height": 100},
        source="stub",
        raw_bytes=raw,
    )


def test_build_pixel_coord_graph():
    rc = RenderCoordinator()
    rc._frame_history = [_make_frame(entropy=1.0 + i * 0.1, idx=i) for i in range(5)]
    result = rc.build_pixel_coord_graph()
    assert "nodes" in result
    assert "edges" in result
    assert "frame_count" in result
    assert result["frame_count"] == 5
    assert len(result["nodes"]) == 5
    assert len(result["edges"]) == 4
    assert all("id" in n and "pid" in n and "entropy" in n and "symmetry" in n
               for n in result["nodes"])
    assert all("from" in e and "to" in e and "weight" in e for e in result["edges"])


def test_detect_render_interference():
    rc = RenderCoordinator()
    frames = [_make_frame(entropy=1.0, idx=i) for i in range(6)]
    frames[3] = _make_frame(entropy=9.0, idx=3)  # starker Ausreißer
    rc._frame_history = frames
    result = rc.detect_render_interference()
    assert "interference_detected" in result
    assert "events" in result
    assert "threshold" in result
    assert isinstance(result["interference_detected"], bool)
    assert isinstance(result["events"], list)
    assert result["interference_detected"] is True


def test_compute_render_drift():
    rc = RenderCoordinator()
    rc._frame_history = [_make_frame(entropy=float(i % 3), idx=i) for i in range(8)]
    result = rc.compute_render_drift()
    assert "drift_mean" in result
    assert "drift_max" in result
    assert "drift_series" in result
    assert "stable" in result
    assert isinstance(result["stable"], bool)
    assert len(result["drift_series"]) == 8
    assert result["drift_max"] >= 0.0


def test_detect_render_phase_shift():
    rc = RenderCoordinator()
    first_half = [_make_frame(symmetry=0.1, idx=i) for i in range(4)]
    second_half = [_make_frame(symmetry=0.9, idx=i + 4) for i in range(4)]
    rc._frame_history = first_half + second_half
    result = rc.detect_render_phase_shift()
    assert "phase_shift_detected" in result
    assert "phase_a_symmetry" in result
    assert "phase_b_symmetry" in result
    assert "delta" in result
    assert result["phase_shift_detected"] is True
    assert result["delta"] > 0.2


def test_render_meta_delta():
    rc = RenderCoordinator()
    rc._frame_history = [_make_frame(entropy=1.0 + i * 0.05, idx=i) for i in range(8)]
    result = rc.render_meta_delta()
    assert "interference" in result
    assert "drift" in result
    assert "phase_shift" in result
    assert "meta_score" in result
    assert "recommendation" in result
    assert 0.0 <= result["meta_score"] <= 1.0
    assert result["recommendation"] in ("stable", "monitor", "alert")


def test_render_governance_advice():
    rc = RenderCoordinator()
    rc._frame_history = [_make_frame(entropy=1.0 + i * 0.05, idx=i) for i in range(8)]
    result = rc.render_governance_advice()
    assert "advice" in result
    assert "severity" in result
    assert "meta_score" in result
    assert isinstance(result["advice"], list)
    assert len(result["advice"]) >= 1
    assert result["severity"] in ("ok", "warning", "critical")
    assert 0.0 <= result["meta_score"] <= 1.0
