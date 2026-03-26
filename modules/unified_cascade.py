"""
Unified Deterministic Cascade — Aether core analysis pipeline.

INVARIANTS (never change without incrementing CASCADE_VERSION):
  - Metric order is fixed: entropy → zipf → benford → fourier →
    katz → attractor → delta_convergence → noether
  - run_id = SHA256(data + CASCADE_VERSION.encode())
  - Deltas are XOR-encrypted with session_key, never stored plaintext
  - cascade_version is included in every audit entry

CASCADE_VERSION must be incremented whenever:
  - Any metric implementation changes
  - Metric order changes
  - Weight changes
  - Any parameter changes

Swarm nodes running different CASCADE_VERSION cannot form quorum.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

CASCADE_VERSION = "1"
AUDIT_LOG_PATH = Path("logs/cascade_audit.jsonl")

# In-memory: source_id → last CascadeResult (for delta convergence)
_prev_results: dict[str, "CascadeResult"] = {}


@dataclass
class CascadeResult:
    # Identity
    run_id: str              # SHA256(data + CASCADE_VERSION) — content-addressed
    source_id: str           # caller label: file path, "render_42", "audio_chunk_7"
    source_type: str         # "file" | "render" | "audio" | "bytes"
    cascade_version: str     # must equal CASCADE_VERSION or swarm rejects

    timestamp: str           # UTC ISO
    byte_length: int

    # 8 metrics — fixed order, fixed meaning
    entropy: float           # 1. Shannon H(X) ∈ [0, 8]
    zipf_alpha: float        # 2. Zipf rank-frequency exponent
    benford_score: float    # 3. Benford first-digit conformance ∈ [0, 1]
    fourier_period: float    # 4. Dominant autocorrelation period (0.0 = none)
    katz_dimension: float    # 5. Katz fractal dimension
    attractor_stability: float  # 6. Lyapunov-like convergence ∈ [0, 1]
    delta_convergence: float # 7. Distance from previous run same source_id
    noether_consistency: float  # 8. Symmetry-preservation invariant ∈ [0, 1]

    # Derived
    trust_score: float       # weighted composite ∈ [0, 1]
    anomaly_flags: list[str]

    # Delta — encrypted, never plaintext
    delta_encrypted_hex: str  # XOR(raw_delta, session_key) as hex — empty if no session_key
    delta_hash: str           # SHA256(raw_delta) — public, for verification

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_json(self) -> str:
        """Deterministic JSON for signing and audit log."""
        return json.dumps(self.to_dict(), ensure_ascii=True,
                         sort_keys=True, separators=(",", ":"))

def cascade(
    data: bytes,
    source_id: str = "unknown",
    source_type: str = "bytes",
    session_key: Optional[bytes] = None,
) -> CascadeResult:
    """
    Run the unified deterministic cascade on any byte input.

    run_id is SHA256(data + CASCADE_VERSION.encode()) — deterministic,
    content-addressed, version-bound. Two nodes running the same
    CASCADE_VERSION on the same data will always produce the same run_id.

    XOR delta is encrypted with session_key if provided.
    Never stored or transmitted in plaintext.
    """
    run_id = hashlib.sha256(data + CASCADE_VERSION.encode()).hexdigest()

    # Entropy
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data) or 1
    entropy = -sum((c/total) * math.log2(c/total) for c in counts if c > 0)

    # Zipf-Alpha
    from modules.invariant_detector import detect_zipf_distribution
    freq = {}
    for b in data:
        freq[str(b)] = freq.get(str(b), 0) + 1
    zipf_alpha = float(detect_zipf_distribution(freq).get("alpha", 1.0))

    # Benford-Score
    from modules.invariant_detector import detect_benford_law
    chunk_sizes = [len(data[i:i+256]) for i in range(0, len(data), 256)]
    benford_score = float(detect_benford_law(chunk_sizes).get("benford_conformance", 0.5))

    # Fourier period
    from modules.invariant_detector import detect_fourier_periodicity
    diffs = [abs(int(data[i]) - int(data[i-1])) for i in range(1, min(len(data), 4096))]
    fourier_period = float(detect_fourier_periodicity(diffs) or 0.0)

    # Katz dimension
    def _katz(b: bytes) -> float:
        arr = list(b[:2048])
        if len(arr) < 2:
            return 1.0
        diffs = [abs(arr[i] - arr[i-1]) for i in range(1, len(arr))]
        L = sum(diffs)
        d = max((abs(arr[i] - arr[0]) for i in range(len(arr))), default=1)
        n = len(arr) - 1
        if d == 0 or n == 0 or L == 0:
            return 1.0
        avg = L / n
        return math.log10(n) / (math.log10(n) + math.log10(d / avg + 1e-9))
    katz_dimension = _katz(data)

    # Attractor stability
    from modules.attractor_engine import attractor_track
    history = [hashlib.md5(data[i:i+64]).hexdigest()[:8]
               for i in range(0, min(len(data), 4096), 64)]
    track = attractor_track(history)
    total_blocks = len(history) or 1
    attractor_stability = len(track.get("attractors", [])) / total_blocks

    # Delta convergence
    prev = _prev_results.get(source_id)
    if prev is None:
        delta_convergence = 0.0
    else:
        delta_convergence = math.sqrt(sum([
            (entropy           - prev.entropy)            ** 2,
            (zipf_alpha        - prev.zipf_alpha)         ** 2,
            (benford_score     - prev.benford_score)       ** 2,
            (katz_dimension    - prev.katz_dimension)      ** 2,
            (attractor_stability - prev.attractor_stability) ** 2,
        ])) / math.sqrt(5)

    # Noether consistency
    half = len(data) // 2
    def _h(b: bytes) -> float:
        c = [0] * 256
        for x in b:
            c[x] += 1
        t = len(b) or 1
        return -sum((v/t)*math.log2(v/t) for v in c if v > 0)
    if half > 0:
        noether_consistency = 1.0 - abs(_h(data[:half]) - _h(data[half:])) / 8.0
    else:
        noether_consistency = 1.0

    # Delta: compute, hash, encrypt
    delta_key = hashlib.sha256(data).digest()
    raw_delta = bytes(b ^ delta_key[i % 32] for i, b in enumerate(data[:256]))
    delta_hash = hashlib.sha256(raw_delta).hexdigest()

    if session_key:
        encrypted = bytes(b ^ session_key[i % len(session_key)]
                         for i, b in enumerate(raw_delta))
        delta_encrypted_hex = encrypted.hex()
    else:
        delta_encrypted_hex = ""

    # Trust score
    trust_score = max(0.0, min(1.0,
        0.20 * (1.0 - entropy / 8.0) +
        0.15 * min(zipf_alpha / 2.0, 1.0) +
        0.15 * benford_score +
        0.10 * min(fourier_period / 128.0, 1.0) +
        0.15 * min(katz_dimension / 2.0, 1.0) +
        0.10 * attractor_stability +
        0.05 * (1.0 - min(delta_convergence, 1.0)) +
        0.10 * noether_consistency
    ))

    # Anomaly flags
    anomaly_flags = []
    if entropy > 7.5:                  anomaly_flags.append("HIGH_ENTROPY")
    if benford_score < 0.3:            anomaly_flags.append("BENFORD_VIOLATION")
    if delta_convergence > 0.5:        anomaly_flags.append("HIGH_DELTA")
    if noether_consistency < 0.4:      anomaly_flags.append("NOETHER_BROKEN")
    if attractor_stability > 0.8:      anomaly_flags.append("STRONG_ATTRACTOR")
    if katz_dimension > 1.8:           anomaly_flags.append("HIGH_FRACTAL")

    result = CascadeResult(
        run_id=run_id,
        source_id=source_id,
        source_type=source_type,
        cascade_version=CASCADE_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        byte_length=len(data),
        entropy=round(entropy, 5),
        zipf_alpha=round(zipf_alpha, 5),
        benford_score=round(benford_score, 5),
        fourier_period=round(fourier_period, 5),
        katz_dimension=round(katz_dimension, 5),
        attractor_stability=round(attractor_stability, 5),
        delta_convergence=round(delta_convergence, 5),
        noether_consistency=round(noether_consistency, 5),
        trust_score=round(trust_score, 5),
        anomaly_flags=anomaly_flags,
        delta_encrypted_hex=delta_encrypted_hex,
        delta_hash=delta_hash,
    )

    # Append-only audit log — canonical JSON, one line per run
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(result.canonical_json() + "\n")

    _prev_results[source_id] = result
    return result

def cascade_to_swarm_kpi(result: CascadeResult) -> dict[str, float]:
    """
    Extract the KPI dict that swarm_loop.rs expects for aggregation.
    Does NOT include delta_encrypted_hex — that never leaves the device.
    """
    return {
        "trust_score":          result.trust_score,
        "entropy_mean":         result.entropy,
        "zipf_alpha":           result.zipf_alpha,
        "benford_score":        result.benford_score,
        "fourier_period":       result.fourier_period,
        "katz_dimension":       result.katz_dimension,
        "attractor_stability":  result.attractor_stability,
        "delta_convergence":    result.delta_convergence,
        "noether_consistency":  result.noether_consistency,
        "compression_gain_percent": (1.0 - result.entropy / 8.0) * 100.0,
    }
