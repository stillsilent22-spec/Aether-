"""
Invariant Consensus Bridge: Wire mathematical invariants to swarm decisions.

Maps invariant_detector.compute_invariant_score() → swarm consensus:
  - Fourier period → quorum sync cycle length
  - Benford conformance → expected compression ratio target
  - Zipf α → preload priority ranking
  - Mandelbrot β → cache coherence strategy
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime, timezone


def digest_invariants_to_consensus(
    invariants: Dict[str, Any],
    consensus_db: str = "data/consensus.db",
) -> Dict[str, Any]:
    """
    Transform raw invariant scores → actionable consensus directives.
    Persists to consensus metadata for quorum use.
    
    Returns: directive dict with:
      - sync_cycle_ms: from Fourier period
      - compression_target: from Benford conformance
      - preload_top_n: from Zipf α
      - cache_strategy: from Mandelbrot β
    """
    directives = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "invariant_strength": invariants.get("invariant_strength", 0.0),
    }
    
    # 1. Fourier → sync cycle
    fourier_period = invariants.get("fourier", {}).get("period")
    if fourier_period:
        directives["sync_cycle_ms"] = int(max(100, fourier_period * 10))
    else:
        directives["sync_cycle_ms"] = 500  # Default
    
    # 2. Benford → compression target
    benford_conf = invariants.get("benford", {}).get("benford_conformance", 0.5)
    directives["compression_target_percent"] = int(40 + benford_conf * 40)  # 40-80%
    
    # 3. Zipf → preload ranking
    zipf_alpha = invariants.get("zipf", {}).get("alpha", 1.0)
    if zipf_alpha > 1.5:
        directives["preload_top_n"] = 10  # Top 10%
    elif zipf_alpha > 1.0:
        directives["preload_top_n"] = 20  # Top 20%
    else:
        directives["preload_top_n"] = 50  # Top 50% (uniform)
    
    # 4. Mandelbrot → cache strategy
    mandel_beta = invariants.get("mandelbrot", {}).get("beta", 0.0)
    if mandel_beta > 1.2:
        directives["cache_strategy"] = "fractal_recursive"
    elif mandel_beta > 0.8:
        directives["cache_strategy"] = "power_law_linear"
    else:
        directives["cache_strategy"] = "uniform_breadth_first"
    
    # Overall recommendation
    directives["recommendation"] = invariants.get("recommendation", "")
    
    return directives


def persist_invariant_directives(
    directives: Dict[str, Any],
    output_path: str = "data/interbus/invariant_directives.json",
) -> None:
    """Persist directives to interbus JSON for all swarm nodes to read."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(directives, f, ensure_ascii=True, indent=2)


def read_invariant_directives(
    path: str = "data/interbus/invariant_directives.json",
) -> Dict[str, Any]:
    """Read consensus directives from last invariant analysis."""
    try:
        if Path(path).is_file():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


if __name__ == "__main__":
    # Example: digest sample invariants
    sample_invariants = {
        "fourier": {"period": 48.5, "detected": True},
        "benford": {"benford_conformance": 0.82},
        "zipf": {"alpha": 1.35, "r_squared": 0.94},
        "mandelbrot": {"beta": 1.18, "r_squared": 0.88},
        "invariant_strength": 0.88,
        "recommendation": "Strong patterns detected",
    }
    
    directives = digest_invariants_to_consensus(sample_invariants)
    print(json.dumps(directives, indent=2))
    
    persist_invariant_directives(directives)
    print(f"Persisted to interbus for swarm consensus")
