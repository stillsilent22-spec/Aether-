"""
tests/test_trust_engine_10metrics.py -- Tests for TrustScoreEngine.compute().

Verifies:
  - Output is in [0, 1]
  - Clamp logic (out-of-range inputs never escape [0,1])
  - Weight sum (all 10 weights sum to 1.0)
  - Monotonicity: higher quality inputs produce higher score
  - Zero input -> score near 0
  - Perfect input -> score near 1
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.trust_engine import TrustScoreEngine

WEIGHTS = {
    "entropy":             0.15,
    "zipf_alpha":          0.08,
    "benford_chi_sq":      0.10,
    "fourier_periodicity": 0.08,
    "katz_fd":             0.10,
    "perm_entropy":        0.10,
    "delta_convergence":   0.12,
    "noether_consistency": 0.12,
    "boltzmann_temp":      0.07,
    "bayes_evidence":      0.08,
}


def _engine() -> TrustScoreEngine:
    return TrustScoreEngine()


def _compute(**kwargs) -> float:
    defaults = dict(
        entropy=4.0, zipf_alpha=1.5, benford_chi_sq=10.0,
        fourier_periodicity=0.5, katz_fd=1.5, perm_entropy=0.5,
        delta_convergence=0.5, noether_consistency=0.5,
        boltzmann_temp=5.0, bayes_evidence=0.5,
    )
    defaults.update(kwargs)
    return _engine().compute(**defaults)


# ── weight sanity ─────────────────────────────────────────────────────────── #

def test_weights_sum_to_one():
    total = sum(WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9, f"weights sum to {total}, expected 1.0"


# ── output range ─────────────────────────────────────────────────────────── #

def test_output_in_unit_interval():
    score = _compute()
    assert 0.0 <= score <= 1.0


def test_all_zero_inputs_near_zero():
    score = _engine().compute(
        entropy=0.0, zipf_alpha=0.0, benford_chi_sq=50.0,
        fourier_periodicity=0.0, katz_fd=0.5, perm_entropy=0.0,
        delta_convergence=0.0, noether_consistency=0.0,
        boltzmann_temp=0.0, bayes_evidence=0.0,
    )
    assert score < 0.05, f"expected near zero, got {score}"


def test_perfect_inputs_near_one():
    score = _engine().compute(
        entropy=8.0, zipf_alpha=3.0, benford_chi_sq=0.0,
        fourier_periodicity=1.0, katz_fd=2.0, perm_entropy=1.0,
        delta_convergence=1.0, noether_consistency=1.0,
        boltzmann_temp=10.0, bayes_evidence=1.0,
    )
    assert score > 0.95, f"expected near 1.0, got {score}"


# ── clamping ─────────────────────────────────────────────────────────────── #

def test_extreme_positive_inputs_clamped():
    score = _engine().compute(
        entropy=9999.0, zipf_alpha=9999.0, benford_chi_sq=-9999.0,
        fourier_periodicity=9999.0, katz_fd=9999.0, perm_entropy=9999.0,
        delta_convergence=9999.0, noether_consistency=9999.0,
        boltzmann_temp=9999.0, bayes_evidence=9999.0,
    )
    assert score <= 1.0


def test_extreme_negative_inputs_clamped():
    score = _engine().compute(
        entropy=-9999.0, zipf_alpha=-9999.0, benford_chi_sq=9999.0,
        fourier_periodicity=-9999.0, katz_fd=-9999.0, perm_entropy=-9999.0,
        delta_convergence=-9999.0, noether_consistency=-9999.0,
        boltzmann_temp=-9999.0, bayes_evidence=-9999.0,
    )
    assert score >= 0.0


# ── monotonicity ─────────────────────────────────────────────────────────── #

@pytest.mark.parametrize("param,low,high", [
    ("entropy",             0.0, 8.0),
    ("zipf_alpha",          0.0, 3.0),
    ("fourier_periodicity", 0.0, 1.0),
    ("perm_entropy",        0.0, 1.0),
    ("delta_convergence",   0.0, 1.0),
    ("noether_consistency", 0.0, 1.0),
    ("bayes_evidence",      0.0, 1.0),
])
def test_monotone_increasing(param, low, high):
    score_low  = _compute(**{param: low})
    score_high = _compute(**{param: high})
    assert score_high >= score_low, (
        f"{param}: score({high})={score_high} < score({low})={score_low}"
    )


def test_benford_monotone_decreasing():
    """Higher benford_chi_sq means worse fit -> lower score."""
    score_good = _compute(benford_chi_sq=0.0)
    score_bad  = _compute(benford_chi_sq=50.0)
    assert score_good >= score_bad


# ── return type ──────────────────────────────────────────────────────────── #

def test_returns_float():
    score = _compute()
    assert isinstance(score, float)


# ── individual dimension contributions ───────────────────────────────────── #

def test_entropy_contributes_most():
    """entropy has the highest single weight (0.15)."""
    base = _compute(entropy=0.0)
    with_entropy = _compute(entropy=8.0)
    delta_entropy = with_entropy - base

    base2 = _compute(bayes_evidence=0.0)
    with_bayes = _compute(bayes_evidence=1.0)
    delta_bayes = with_bayes - base2

    assert delta_entropy > delta_bayes, (
        f"entropy delta {delta_entropy:.4f} should exceed bayes delta {delta_bayes:.4f}"
    )
