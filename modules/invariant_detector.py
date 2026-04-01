from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""
Invariant Detector: Mathematical invariant discovery for Aether Swarm.

Detects 4 core invariants from delta streams using Fourier, Benford, Zipf, Mandelbrot analysis:
  1. Fourier Periodicity: Repeating patterns in anchor change frequencies
  2. Benford's Law: First-digit distribution in file sizes (compression efficiency metric)
  3. Zipf Distribution: Rank-frequency law for anchor access patterns
  4. Mandelbrot Scaling: Self-similar structure in recursive anchor trees (scaling exponent)

These invariants guide:
  - Cache preload priorities (Zipf ranking)
  - Performance targets (Benford deviation → compression ratio)
  - Adaptive FPS (scaling exponent → coherence strength)
  - Consensus quorum sizing (Fourier periodicity → sync cycle length)
"""


import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


# =========================================================================== #
#  1. FOURIER PERIODICITY: Detect repeating change patterns                  #
# =========================================================================== #

def detect_fourier_periodicity(change_sequence: List[int], min_period: int = 2, max_period: int = 256) -> Optional[float]:
    """
    Detect dominant period in anchor change sequence using autocorrelation.
    Returns: period length (in indices) if strong periodicity detected, else None.
    Threshold: autocorrelation peak > 0.6
    """
    if len(change_sequence) < max_period * 2:
        return None
    
    # Compute autocorrelation via FFT
    signal = np.array(change_sequence, dtype=np.float32)
    signal = (signal - np.mean(signal)) / (np.std(signal) + 1e-8)
    
    fft_result = np.fft.fft(signal)
    power = np.abs(fft_result) ** 2
    autocorr = np.fft.ifft(power).real
    autocorr = autocorr / autocorr[0] if autocorr[0] > 0 else autocorr
    
    # Search for dominant period in [min_period, max_period]
    acf_slice = autocorr[min_period:max_period]
    if len(acf_slice) == 0:
        return None
    
    dominant_idx = np.argmax(acf_slice)
    dominant_period = float(dominant_idx + min_period)
    peak_acf = float(acf_slice[dominant_idx])
    
    return dominant_period if peak_acf > 0.6 else None


# =========================================================================== #
#  2. BENFORD'S LAW: First-digit distribution analysis                       #
# =========================================================================== #

def benford_first_digit(value: int) -> int:
    """Extract first digit of a positive integer."""
    if value <= 0:
        return 0
    return int(str(value)[0])


def detect_benford_law(file_sizes: List[int]) -> Dict[str, Any]:
    """
    Analyze first-digit distribution against Benford's Law.
    Returns: deviation score [0.0 = perfect match, 1.0 = maximum deviation]
    and per-digit statistics.
    
    Benford prediction: P(d) = log10(1 + 1/d) for digits 1-9
    """
    if not file_sizes:
        return {"benford_conformance": 0.0, "digits": {}}
    
    # Count first digits
    first_digits = [benford_first_digit(sz) for sz in file_sizes if sz > 0]
    if not first_digits:
        return {"benford_conformance": 0.0, "digits": {}}
    
    digit_counts = Counter(first_digits)
    total = len(first_digits)
    
    # Benford expected frequencies
    benford_expected = {d: math.log10(1.0 + 1.0 / d) for d in range(1, 10)}
    
    # Chi-squared test
    chi_squared = 0.0
    digit_stats = {}
    for d in range(1, 10):
        observed_freq = digit_counts.get(d, 0) / total
        expected_freq = benford_expected[d]
        expected_count = expected_freq * total
        
        if expected_count > 0:
            chi_squared += ((digit_counts.get(d, 0) - expected_count) ** 2) / expected_count
        
        digit_stats[str(d)] = {
            "observed_freq": round(observed_freq, 4),
            "expected_freq": round(expected_freq, 4),
            "count": digit_counts.get(d, 0),
        }
    
    # Normalize chi-squared to [0, 1] conformance
    max_chi_squared = total  # Worst case
    conformance = 1.0 - min(chi_squared / max_chi_squared, 1.0) if max_chi_squared > 0 else 0.0
    
    return {
        "benford_conformance": round(conformance, 4),
        "chi_squared": round(chi_squared, 4),
        "digits": digit_stats,
    }


# =========================================================================== #
#  3. ZIPF DISTRIBUTION: Rank-frequency law for file/anchor popularity       #
# =========================================================================== #

def detect_zipf_distribution(anchor_frequencies: Dict[str, int], alpha_range: Tuple[float, float] = (0.5, 3.0)) -> Dict[str, Any]:
    """
    Fit Zipf's Law: f(r) ∝ r^(-α) where r = rank, f = frequency.
    Returns: estimated α exponent, R² goodness-of-fit, and interpretation.
    
    Community interpretation:
      α ≈ 1.0: Classic Zipf (50-50 rule: top 10% accounts for ~90% usage)
      α < 1.0: More uniform distribution (good for cache balancing)
      α > 1.5: Highly skewed (strong preload opportunity)
    """
    if not anchor_frequencies:
        return {"alpha": 0.0, "r_squared": 0.0, "interpretation": "insufficient_data"}
    
    # Sort by frequency (descending)
    sorted_freqs = sorted(anchor_frequencies.values(), reverse=True)
    if len(sorted_freqs) < 3:
        return {"alpha": 0.0, "r_squared": 0.0, "interpretation": "insufficient_data"}
    
    ranks = np.arange(1, len(sorted_freqs) + 1, dtype=np.float32)
    freqs = np.array(sorted_freqs, dtype=np.float32)
    
    # Log-linear fit on log-rank, log-freq
    log_ranks = np.log(ranks)
    log_freqs = np.log(freqs)
    
    # Fit: log(f) = log(c) - α * log(r)
    # → slope ≈ -α
    coeffs = np.polyfit(log_ranks, log_freqs, 1)
    alpha = -coeffs[0]  # Negate to get positive α
    
    # Compute R²
    fitted_log_freqs = np.polyval(coeffs, log_ranks)
    ss_res = np.sum((log_freqs - fitted_log_freqs) ** 2)
    ss_tot = np.sum((log_freqs - np.mean(log_freqs)) ** 2)
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    
    # Interpretation
    if alpha < 0.8:
        interp = "uniform: good cache balancing"
    elif alpha < 1.2:
        interp = "classic_zipf: standard rank-frequency"
    elif alpha < 1.6:
        interp = "skewed: preload top 20%"
    else:
        interp = "highly_skewed: aggressive preload top 10%"
    
    return {
        "alpha": round(float(alpha), 4),
        "r_squared": round(float(r_squared), 4),
        "interpretation": interp,
        "estimated_top_10_percent_share": round(float(np.sum(sorted_freqs[:max(1, len(sorted_freqs)//10)]) / np.sum(sorted_freqs)), 4),
    }


# =========================================================================== #
#  4. MANDELBROT SCALING: Self-similarity in anchor tree structure           #
# =========================================================================== #

def detect_mandelbrot_scaling(tree_depths: List[int], max_depth_checked: int = 8) -> Dict[str, Any]:
    """
    Fit power-law scaling to tree structure: count(depth) ∝ depth^(-β).
    Returns: scaling exponent β, interpretation for cache coherence.
    
    High β (e.g., 1.5): Fractal-like hierarchy (strong locality → smaller cache needed)
    Low β (< 0.8): Shallow distribution (weak locality → larger cache needed)
    """
    if not tree_depths or len(tree_depths) < 2:
        return {"beta": 0.0, "r_squared": 0.0, "interpretation": "insufficient_data"}
    
    # Count nodes at each depth
    depth_counts = Counter(tree_depths)
    max_d = min(max(depth_counts.keys()) + 1, max_depth_checked)
    
    if max_d < 2:
        return {"beta": 0.0, "r_squared": 0.0, "interpretation": "shallow_tree"}
    
    depths_array = np.arange(1, max_d + 1, dtype=np.float32)
    counts_array = np.array([depth_counts.get(d, 1) for d in range(1, max_d + 1)], dtype=np.float32)
    
    # Log-log fit: log(count) = log(c) - β * log(depth)
    log_depths = np.log(depths_array)
    log_counts = np.log(counts_array + 0.5)  # Avoid log(0)
    
    coeffs = np.polyfit(log_depths, log_counts, 1)
    beta = -coeffs[0]
    
    # R²
    fitted_log_counts = np.polyval(coeffs, log_depths)
    ss_res = np.sum((log_counts - fitted_log_counts) ** 2)
    ss_tot = np.sum((log_counts - np.mean(log_counts)) ** 2)
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    
    if beta > 1.2:
        interp = "fractal: strong self-similarity, excellent locality"
    elif beta > 0.8:
        interp = "power_law: moderate locality"
    else:
        interp = "shallow: weak locality, flat structure"
    
    return {
        "beta": round(float(beta), 4),
        "r_squared": round(float(r_squared), 4),
        "interpretation": interp,
        "max_depth_sampled": int(max_d),
    }


# =========================================================================== #
#  Composite Invariant Analysis (used by swarm consensus)                    #
# =========================================================================== #

def compute_invariant_score(
    change_sequence: List[int],
    anchor_frequencies: Dict[str, int],
    file_sizes: List[int],
    tree_depths: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """
    Compute composite invariant score from all 4 detectors.
    Used by swarm to:
      - Guide cache preload (Zipf α → priority ranking)
      - Assess data coherence (Benford conformance → compression ratio)
      - Tune consensus sync (Fourier period → quorum message cycle)
      - Optimize tree traversal (Mandelbrot β → algorithm selection)
    
    Returns: dict with all invariant findings + overall "invariant_strength" [0.0, 1.0]
    """
    results: Dict[str, Any] = {
        "fourier": {"period": None, "detected": False},
        "benford": detect_benford_law(file_sizes),
        "zipf": detect_zipf_distribution(anchor_frequencies),
        "mandelbrot": detect_mandelbrot_scaling(tree_depths or []),
        "timestamp": str(__import__("datetime").datetime.now().__class__.now(__import__("datetime").timezone.utc).isoformat()),
    }
    
    # Fourier periodicity
    if change_sequence and len(change_sequence) >= 16:
        period = detect_fourier_periodicity(change_sequence)
        if period is not None:
            results["fourier"]["period"] = round(period, 2)
            results["fourier"]["detected"] = True
    
    # Composite strength: average evidence weight across all invariants
    scores = [
        results["benford"].get("benford_conformance", 0.0),
        results["zipf"].get("r_squared", 0.0),
        results["mandelbrot"].get("r_squared", 0.0),
        (0.8 if results["fourier"]["detected"] else 0.0),  # Fourier is binary
    ]
    invariant_strength = float(np.mean(scores))
    
    results["invariant_strength"] = round(invariant_strength, 4)
    results["recommendation"] = _form_recommendation(results)
    
    return results


def _form_recommendation(invariants: Dict[str, Any]) -> str:
    """Form actionable recommendation from invariant analysis."""
    lines = []
    
    # Benford
    benford_conf = invariants["benford"].get("benford_conformance", 0.0)
    if benford_conf > 0.85:
        lines.append("• High compression potential detected (Benford conformance)")
    
    # Zipf
    zipf_alpha = invariants["zipf"].get("alpha", 0.0)
    if zipf_alpha > 1.4:
        lines.append("• Strong skew detected: aggressive preload top 10-15% anchors")
    elif zipf_alpha > 1.0:
        lines.append("• Moderate skew: preload top 20% anchors")
    
    # Fourier
    if invariants["fourier"]["detected"]:
        period = invariants["fourier"].get("period", 0)
        lines.append(f"• Periodic sync pattern detected (period ≈ {period:.0f} ms)")
    
    # Mandelbrot
    mandel_beta = invariants["mandelbrot"].get("beta", 0.0)
    if mandel_beta > 1.2:
        lines.append("• Fractal-like structure: use recursive tree traversal")
    
    if not lines:
        lines.append("• No strong invariants: use conservative defaults")
    
    return " | ".join(lines)


if __name__ == "__main__":
    from modules.session_guard import require_session
    require_session()
    # Quick test
    test_changes = [1, 2, 3, 2, 1, 2, 3, 2, 1, 2, 3, 2]  # Periodic seq
    test_freqs = {"a": 100, "b": 50, "c": 25, "d": 10, "e": 5}
    test_sizes = [100, 200, 300, 150, 250, 400, 50]
    
    result = compute_invariant_score(test_changes, test_freqs, test_sizes, [1, 1, 1, 2, 2, 3, 4])
    print(json.dumps(result, indent=2))
