from __future__ import annotations

from pathlib import Path

from modules.analysis_capsule import AnalysisCapsuleEngine
from modules.trust_engine import TrustScoreEngine
from aether_pipeline import AetherPipeline


def test_analysis_capsule_from_file_exposes_core_metrics(tmp_path) -> None:
    sample_path = Path(tmp_path) / "sample.bin"
    sample_path.write_bytes((b"AETHER-STRUCTURE-" * 32) + bytes(range(64)))

    engine = AnalysisCapsuleEngine()
    capsule = engine.from_file(sample_path)

    assert capsule.spec.trigger == "drag_drop"
    assert capsule.envelope.size_bytes == sample_path.stat().st_size
    assert capsule.metrics.entropy >= 0.0
    assert capsule.metrics.zipf_alpha >= 0.0
    assert 0.0 <= capsule.metrics.benford_score <= 1.0
    assert 0.0 <= capsule.metrics.bit_position_score <= 1.0
    assert capsule.metrics.katz_dimension >= 1.0
    assert "coherence_score" in capsule.sce
    assert capsule.godel_loop.get("deterministic") is True
    assert isinstance(capsule.shared_anchor_pack.get("anchors", []), list)


def test_analysis_capsule_live_signal_tracks_local_delta() -> None:
    previous_signal = (b"frame-0000" * 24) + b"AAAA"
    current_signal = (b"frame-0000" * 24) + b"BBBB"

    engine = AnalysisCapsuleEngine()
    capsule = engine.from_live_signal(current_signal, previous_signal=previous_signal)

    assert capsule.spec.trigger == "live_render"
    assert capsule.local_delta.get("available") is True
    assert float(capsule.local_delta.get("delta_ratio", 0.0)) > 0.0
    assert capsule.metrics.delta_ratio > 0.0


def test_aether_pipeline_process_live_signal_returns_capsule_payload() -> None:
    pipeline = AetherPipeline()
    result = pipeline.process_live_signal(b"live-render-telemetry" * 16, source_label="live_render:test")

    assert "capsule" in result
    assert result["capsule"]["capsule"]["trigger"] == "live_render"
    assert "godel_loop" in result
    assert "anomaly_flags" in result
    assert result["trust"] >= 0.0


def test_trust_engine_reads_bit_position_score_from_inputs() -> None:
    engine = TrustScoreEngine(threshold=0.5)
    anchor_data = {
        "trust_inputs": {
            "bayes_overall_confidence": 0.85,
            "noether_score": 70.0,
            "benford_score": 0.8,
            "bit_position_score": 0.75,
            "sce_score": 65.0,
            "zipf_alpha": 1.0,
        }
    }
    score, trusted, breakdown, bayes_flags, flags = engine.evaluate(anchor_data)

    assert score >= 0.0
    assert isinstance(trusted, bool)
    assert breakdown["bit_position_score"] == 0.75
    assert not bayes_flags.get("bayes_inconsistent", False)
