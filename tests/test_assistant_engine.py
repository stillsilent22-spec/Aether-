from __future__ import annotations

from modules.assistant_engine import assistant_interference_score, assistant_reduce


def test_assistant_reduce_returns_structural_features() -> None:
    result = assistant_reduce("Aether anchor delta entropy observer symmetry")

    assert result["length"] > 0
    assert result["entropy"] >= 0.0
    assert result["token_count"] >= 5
    assert result["anchor_count"] >= 1
    assert isinstance(result["anchor_hits"], list)
    assert 0.0 <= float(result["reference_alignment"]) <= 1.0
    assert 0.0 <= float(result["markov_coherence"]) <= 1.0
    assert 0.0 <= float(result["structure_score"]) <= 1.0
    assert isinstance(result["reference_candidates"], list)


def test_assistant_interference_prefers_similar_inputs() -> None:
    close_score = assistant_interference_score(
        "Aether anchor delta graph",
        "Aether anchor delta sphere",
    )
    far_score = assistant_interference_score(
        "Aether anchor delta graph",
        "banana invoice volcano orchard",
    )

    assert 0.0 <= close_score <= 1.0
    assert 0.0 <= far_score <= 1.0
    assert close_score < far_score


def test_assistant_reduce_exposes_reference_candidates() -> None:
    result = assistant_reduce("observer-relative structural intelligence and local anchor analysis")

    assert result["corpus_ready"] is True
    assert len(result["reference_candidates"]) >= 1