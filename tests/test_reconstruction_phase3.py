"""Tests fuer Aether Roadmap Phase 3: Rekonstruktion & Multi-Modalitaet."""
from __future__ import annotations

import pytest
from modules.reconstruction_engine import ReconstructionEngine, GovernanceContext


def _governance() -> GovernanceContext:
    return GovernanceContext()


@pytest.fixture
def engine() -> ReconstructionEngine:
    return ReconstructionEngine()


def test_phase3_snapshot_projection_and_modality_governance() -> None:
    """Prueft Snapshot-Erstellung und Governance-Basis."""
    engine = ReconstructionEngine()
    governance = _governance()
    s1 = engine.create_snapshot(
        data={"file": b"abcabc" * 12},
        governance=governance,
        include_processes=False,
        timestamp="2026-03-15T00:00:00+00:00",
    )
    s2 = engine.create_snapshot(
        data={"file": b"abcdabcd" * 12},
        governance=governance,
        include_processes=False,
        timestamp="2026-03-15T00:00:01+00:00",
    )
    residual = engine.create_residual(s1, s2)
    s3 = engine.reconstruct(s1, [residual.residual_id])
    assert s3.data_hashes == s2.data_hashes


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
