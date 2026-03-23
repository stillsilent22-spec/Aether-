def reconstruction_engine(B):
    """Reconstruct a structural profile from analysis dict B.

    Steps:
      (a) Compressibility delta — fraction of valid fields weighted by signal
          compressibility (low-entropy signals are more faithfully recoverable).
      (b) error_map — fields outside their expected ranges.
      (c) Return reconstructed profile R with clamped values, error_map, and
          a quality_score in [0, 1].
    """
    # Canonical field ranges for the Aether structural analysis domain
    FIELD_RANGES: dict = {
        "entropy":            (0.0, 8.0),
        "entropy_mean":       (0.0, 8.0),
        "symmetry":           (0.0, 1.0),
        "symmetry_score":     (0.0, 1.0),
        "sce_score":          (0.0, 1.0),
        "anchor_coverage":    (0.0, 1.0),
        "trust_score":        (0.0, 1.0),
        "bayes_posterior":    (0.0, 1.0),
        "delta_score":        (0.0, 1.0),
        "periodicity_score":  (0.0, 1.0),
    }

    # (b) Build error_map: flag each monitored field that is out of range
    error_map: dict = {}
    for field, (lo, hi) in FIELD_RANGES.items():
        if field in B and isinstance(B[field], (int, float)):
            val = float(B[field])
            if not (lo <= val <= hi):
                excess = max(lo - val, val - hi, 0.0)
                error_map[field] = {
                    "value":    val,
                    "expected": [lo, hi],
                    "excess":   round(excess, 4),
                }

    # Reconstruct profile: clamp out-of-range numeric values into valid range
    R: dict = {}
    for key, val in B.items():
        if key in FIELD_RANGES and isinstance(val, (int, float)):
            lo, hi = FIELD_RANGES[key]
            R[key] = round(max(lo, min(hi, float(val))), 6)
        else:
            R[key] = val

    # (a) Compressibility delta: measure how much information was preserved.
    # Rationale: low-entropy (highly compressible) signals can be reconstructed
    # with less loss than high-entropy (near-random) signals.
    total_monitored = len(FIELD_RANGES)
    entropy_raw = B.get("entropy_mean", B.get("entropy", 4.0))
    entropy_val = max(0.0, min(8.0, float(entropy_raw) if isinstance(entropy_raw, (int, float)) else 4.0))
    compressibility = 1.0 - entropy_val / 8.0  # 1.0 = fully compressible, 0.0 = white noise

    # Preservation ratio: fraction of monitored fields that are present and in-range
    valid_count = sum(
        1 for f, (lo, hi) in FIELD_RANGES.items()
        if f in B and isinstance(B[f], (int, float)) and lo <= float(B[f]) <= hi
    )
    preservation_ratio = valid_count / total_monitored

    # Compressibility delta blends structural coverage with signal recoverability
    delta = 0.6 * preservation_ratio + 0.4 * compressibility

    # Error penalty: normalised sum of excess magnitudes across monitored fields
    if error_map:
        penalty = sum(
            min(1.0, e["excess"] / 8.0) for e in error_map.values()
        ) / total_monitored
    else:
        penalty = 0.0

    quality_score = max(0.0, min(1.0, delta - penalty))

    return {
        "R":             R,
        "error_map":     error_map,
        "quality_score": round(quality_score, 4),
    }
