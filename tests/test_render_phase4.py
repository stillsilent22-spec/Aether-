from modules.reconstruction_engine import (
    ReconstructionEngine as FullReconstructionEngine,
    RenderFingerprint,
    GovernanceContext as FullGovernanceContext,
)

def _make_render_snapshot(engine, entropy_val: float):
    """Hilfsfunktion: Erstellt einen Snapshot mit simuliertem Render-Layer."""
    render_bytes = bytes([int(entropy_val * 32) % 256] * 512)
    return engine.create_snapshot(
        data={"render": render_bytes},
        include_processes=False,
        governance=FullGovernanceContext(),
    )

def test_pixel_coordination_graph():
    engine = FullReconstructionEngine()
    rf = RenderFingerprint(
        process_id=0,
        frame_resolution=(0, 0),
        pixel_regions=[{"entropy": 1.0}, {"entropy": 1.2}, {"entropy": 1.1}],
        gpu_time=0.0,
        present_intervals=[],
        swapchain_pattern="unknown",
        entropy_profile=[1.0, 1.2, 1.1],
        symmetry_profile={},
        resonance_profile={},
        delta_profile={},
        graph_signature={},
        invariants=[],
    )
    result = engine.pixel_coordination_graph(rf)
    assert result["node_count"] == 3
    assert result["edge_count"] >= 1
    assert result["coordination_score"] >= 0

def test_render_interference_and_drift():
    engine = FullReconstructionEngine()
    snap1 = _make_render_snapshot(engine, 1.0)
    snap2 = _make_render_snapshot(engine, 1.5)
    interference = engine.detect_render_interference(snap1, snap2)
    assert "interference_score" in interference
    drift = engine.compute_render_drift([snap1, snap2])
    assert "combined_drift" in drift

def test_render_meta_delta_and_governance():
    engine = FullReconstructionEngine()
    snap1 = _make_render_snapshot(engine, 1.0)
    snap2 = _make_render_snapshot(engine, 1.5)
    meta = engine.render_meta_delta(snap1, snap2)
    assert "combined_severity" in meta
    gov = FullGovernanceContext()
    recs = engine.render_governance_recommendations(meta, gov)
    assert "recommendations" in recs
    verdict = engine.apply_render_delta_governance(meta, gov)
    assert verdict["verdict"] in ("PASS", "WARN", "BLOCK")
import pytest
import numpy as np
from modules.render_coordinator import RenderCoordinator
from modules.reconstruction_engine import ReconstructionEngine

def test_capture_pixel_data_features():
    rc = RenderCoordinator()
    data = bytes([i % 256 for i in range(1024)])
    features = rc.capture_pixel_data(data)
    assert features["entropy"] > 0
    assert 0 <= features["symmetry"] <= 1
    assert features["resonance"] >= 0
    assert len(features["fingerprint"]) == 64
    assert features["timestamp"] > 0

def test_render_attractor_tracking():
    re = ReconstructionEngine()
    # Simuliere Snapshots mit variierender Entropie
    snaps = [
        {"entropy": 1.0},
        {"entropy": 1.2},
        {"entropy": 0.8},
        {"entropy": 1.1}
    ]
    result = re.detect_render_attractor(snaps)
    assert "drift_variance" in result
    assert result["drift_variance"] >= 0
