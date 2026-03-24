from __future__ import annotations

from modules.shanway_engine import shanway_interference_score, shanway_reduce


def test_shanway_reduce_returns_structural_features() -> None:
    result = shanway_reduce("Aether anchor delta entropy observer symmetry")

    assert result["length"] > 0
    assert result["entropy"] >= 0.0
    assert result["token_count"] >= 5
    assert result["anchor_count"] >= 1
    assert isinstance(result["anchor_hits"], list)
    assert 0.0 <= float(result["reference_alignment"]) <= 1.0
    assert 0.0 <= float(result["markov_coherence"]) <= 1.0
    assert 0.0 <= float(result["structure_score"]) <= 1.0
    assert isinstance(result["reference_candidates"], list)


def test_shanway_interference_prefers_similar_inputs() -> None:
    close_score = shanway_interference_score(
        "Aether anchor delta graph",
        "Aether anchor delta sphere",
    )
    far_score = shanway_interference_score(
        "Aether anchor delta graph",
        "banana invoice volcano orchard",
    )

    assert 0.0 <= close_score <= 1.0
    assert 0.0 <= far_score <= 1.0
    assert close_score < far_score


def test_shanway_reduce_exposes_reference_candidates() -> None:
    result = shanway_reduce("observer-relative structural intelligence and local anchor analysis")

    assert result["corpus_ready"] is True
    assert len(result["reference_candidates"]) >= 1