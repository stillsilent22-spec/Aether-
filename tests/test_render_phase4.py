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
