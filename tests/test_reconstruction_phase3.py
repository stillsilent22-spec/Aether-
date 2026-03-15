"""Tests fuer Aether Roadmap Phase 3: Rekonstruktion & Multi-Modalitaet."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.reconstruction_engine import GovernanceContext, ReconstructionEngine


def _governance() -> GovernanceContext:
    return GovernanceContext(
        rights={
            "camera": ["read"],
            "audio": ["read"],
            "file": ["read"],
            "reconstruction": ["write"],
        },
        invariants={
            "camera.max_entropy_delta_per_time": 0.75,
            "audio.max_entropy_delta_per_time": 0.75,
            "file.max_entropy_delta_per_time": 0.95,
            "camera.allowed_symmetry_break": 1.0,
            "audio.allowed_symmetry_break": 1.0,
            "file.allowed_symmetry_break": 1.0,
            "camera.resonance_range": [0.0, 1.0],
            "audio.resonance_range": [0.0, 1.0],
            "file.resonance_range": [0.0, 1.0],
        },
        keys={"signature_material": "phase3-test-key"},
    )


def test_phase3_snapshot_projection_and_modality_governance() -> None:
    engine = ReconstructionEngine()
    snapshot = engine.create_snapshot(
        data={
            "camera": b"\x01\x02\x03\x04" * 32,
            "audio": b"\x10\x20\x10\x20" * 32,
            "file": b"AETHER_PHASE3\n" * 16,
        },
        governance=_governance(),
        observer={"drift": 0.1},
        timestamp="2026-03-15T00:00:00+00:00",
    )

    assert snapshot.features.entropy >= 0.0
    assert snapshot.features.symmetry >= 0.0
    assert snapshot.features.resonance >= 0.0
    assert len(snapshot.features.fingerprints) == 3
    assert set(snapshot.modality_features.keys()) == {"camera", "audio", "file"}

    assert engine.validate_modality_operation("camera", "read", snapshot) is True
    assert engine.validate_modality_operation("audio", "write", snapshot) is False
    assert engine.validate_modality_operation("unknown", "read", snapshot) is False


def test_phase3_residual_reconstruction_and_validation() -> None:
    engine = ReconstructionEngine()
    governance = _governance()

    start = engine.create_snapshot(
        data={
            "camera": b"\x00\x01\x02\x03" * 16,
            "audio": b"\x05\x06\x07\x08" * 16,
            "file": b"state-a" * 12,
        },
        governance=governance,
        observer={"drift": 0.1},
        timestamp="2026-03-15T00:00:00+00:00",
    )
    end = engine.create_snapshot(
        data={
            "camera": b"\x00\x01\x02\x04" * 16,
            "audio": b"\x05\x06\x07\x09" * 16,
            "file": b"state-b" * 12,
        },
        governance=governance,
        observer={"drift": 0.15},
        timestamp="2026-03-15T00:00:10+00:00",
    )

    residual = engine.create_residual(start, end)
    reconstructed = engine.reconstruct(start, [residual.residual_id])
    validation = engine.validate_reconstruction(start, end, [residual.residual_id])

    assert residual.hash == residual.residual_id
    assert residual.signature
    assert residual.invariants["time_monotonic"] is True
    assert reconstructed.data_hashes == end.data_hashes
    assert validation["valid"] is True
    assert engine.reconstruction_graph.find_path(start.snapshot_id, end.snapshot_id) == [residual.residual_id]


def test_phase3_validator_fail_closed_on_tampered_residual() -> None:
    engine = ReconstructionEngine()
    governance = _governance()

    start = engine.create_snapshot(
        data={"file": b"alpha"},
        governance=governance,
        observer={"drift": 0.05},
        timestamp="2026-03-15T00:00:00+00:00",
    )
    end = engine.create_snapshot(
        data={"file": b"beta"},
        governance=governance,
        observer={"drift": 0.07},
        timestamp="2026-03-15T00:00:05+00:00",
    )
    residual = engine.create_residual(start, end)
    residual.hash = "tampered"

    validation = engine.validate_reconstruction(start, end, [residual.residual_id])

    assert validation["valid"] is False
    assert "hash_mismatch" in validation["reason"]
    assert start.observer["alarm_state"] == "closed"
    assert len(list(start.governance.audit.get("events", []))) >= 1


def test_phase3_attractor_tracking_stability_and_prediction() -> None:
    engine = ReconstructionEngine()
    governance = _governance()

    s1 = engine.create_snapshot(
        data={"camera": b"\x01\x01\x02\x02" * 16, "file": b"node-a" * 8},
        governance=governance,
        observer={"drift": 0.08},
        timestamp="2026-03-15T00:00:00+00:00",
    )
    s2 = engine.create_snapshot(
        data={"camera": b"\x01\x01\x02\x03" * 16, "file": b"node-b" * 8},
        governance=governance,
        observer={"drift": 0.09},
        timestamp="2026-03-15T00:00:05+00:00",
    )
    s3 = engine.create_snapshot(
        data={"camera": b"\x01\x01\x02\x03" * 16, "file": b"node-b" * 8},
        governance=governance,
        observer={"drift": 0.09},
        timestamp="2026-03-15T00:00:10+00:00",
    )

    a1 = engine.detect_attractor(s1)
    a2 = engine.detect_attractor(s2)
    assert a1 is not None
    assert a2 is not None

    engine.track_attractor_transition(a1, a2, s1, s2)
    stability = engine.compute_attractor_stability(a2, [s1, s2, s3])
    prediction = engine.predict_next_attractor(s2, [s1, s2, s3])

    assert "drift_variance" in stability
    assert "resonance_stability" in stability
    assert "symmetry_persistence" in stability
    assert stability["drift_variance"] >= 0.0
    assert prediction in {a1, a2}
