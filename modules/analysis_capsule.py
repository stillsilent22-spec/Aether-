"""Unified analysis capsule for drop and live-render structural analysis.

This module builds a signal-agnostic capsule around a single observation pass.
It keeps local deltas private, exposes shareable invariant anchors, and computes
the core structural metrics used across Aether.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from .godel_loop_renderer import GoedelLoopRenderer
    from .invariant_detector import (
        compute_invariant_score,
        detect_benford_law,
        detect_zipf_distribution,
    )
    from .trust_engine import TrustScoreEngine
except ImportError:
    from godel_loop_renderer import GoedelLoopRenderer
    from invariant_detector import compute_invariant_score, detect_benford_law, detect_zipf_distribution
    from trust_engine import TrustScoreEngine

try:
    from .bayes_engine import BayesianBeliefEngine
except Exception:  # pragma: no cover - optional heavy dependency chain
    BayesianBeliefEngine = None  # type: ignore[assignment]

try:
    from sce_engine import sce_engine
except Exception:  # pragma: no cover - root-level helper may be unavailable in some tests
    sce_engine = None  # type: ignore[assignment]


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return float(max(low, min(high, value)))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


@dataclass
class CapsuleSpec:
    trigger: str
    source_type: str
    source_label: str
    enable_godel_loop: bool = True
    max_godel_depth: int = 3
    share_invariants: bool = True
    retain_local_delta: bool = True
    domain_hint: str = "generic"


@dataclass
class SignalEnvelope:
    source_hash: str
    size_bytes: int
    source_type: str
    source_label: str
    domain_hint: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_hash": str(self.source_hash),
            "size_bytes": int(self.size_bytes),
            "source_type": str(self.source_type),
            "source_label": str(self.source_label),
            "domain_hint": str(self.domain_hint),
        }


@dataclass
class CapsuleMetricBundle:
    entropy: float
    h_lambda: float
    symmetry: float
    periodicity: float
    zipf_alpha: float
    benford_score: float
    katz_dimension: float
    sce_score: float
    bayes_confidence: float
    trust_score: float
    noether_consistency: float
    delta_ratio: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "entropy": round(float(self.entropy), 12),
            "h_lambda": round(float(self.h_lambda), 12),
            "symmetry": round(float(self.symmetry), 12),
            "periodicity": round(float(self.periodicity), 12),
            "zipf_alpha": round(float(self.zipf_alpha), 12),
            "benford_score": round(float(self.benford_score), 12),
            "katz_dimension": round(float(self.katz_dimension), 12),
            "sce_score": round(float(self.sce_score), 12),
            "bayes_confidence": round(float(self.bayes_confidence), 12),
            "trust_score": round(float(self.trust_score), 12),
            "noether_consistency": round(float(self.noether_consistency), 12),
            "delta_ratio": round(float(self.delta_ratio), 12),
        }


@dataclass
class AnalysisCapsuleResult:
    spec: CapsuleSpec
    envelope: SignalEnvelope
    metrics: CapsuleMetricBundle
    local_delta: Dict[str, Any]
    shared_anchor_pack: Dict[str, Any]
    invariants: Dict[str, Any]
    sce: Dict[str, Any]
    godel_loop: Dict[str, Any]
    anomaly_flags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capsule": {
                "trigger": str(self.spec.trigger),
                "source_type": str(self.spec.source_type),
                "source_label": str(self.spec.source_label),
                "domain_hint": str(self.spec.domain_hint),
                "share_invariants": bool(self.spec.share_invariants),
                "retain_local_delta": bool(self.spec.retain_local_delta),
            },
            "envelope": self.envelope.to_dict(),
            "metrics": self.metrics.to_dict(),
            "local_delta": dict(self.local_delta),
            "shared_anchor_pack": dict(self.shared_anchor_pack),
            "invariants": dict(self.invariants),
            "sce": dict(self.sce),
            "godel_loop": dict(self.godel_loop),
            "anomaly_flags": list(self.anomaly_flags),
        }


class AnalysisCapsuleEngine:
    """Builds a unified structural capsule for file-drop and live-render inputs."""

    def __init__(self, trust_threshold: float = 0.65) -> None:
        self._godel = GoedelLoopRenderer()
        self._trust = TrustScoreEngine(threshold=float(trust_threshold))
        self._bayes = BayesianBeliefEngine() if BayesianBeliefEngine is not None else None

    def from_file(
        self,
        file_path: Union[str, Path],
        previous_signal: Optional[bytes] = None,
        trigger: str = "drag_drop",
    ) -> AnalysisCapsuleResult:
        path = Path(file_path)
        raw = path.read_bytes()
        spec = CapsuleSpec(
            trigger=str(trigger),
            source_type="file",
            source_label=str(path),
            domain_hint=str(path.suffix.lower().lstrip(".") or "file"),
        )
        return self.from_bytes(raw, spec=spec, previous_signal=previous_signal)

    def from_live_signal(
        self,
        raw: bytes,
        source_label: str = "live_render",
        previous_signal: Optional[bytes] = None,
    ) -> AnalysisCapsuleResult:
        spec = CapsuleSpec(
            trigger="live_render",
            source_type="runtime_signal",
            source_label=str(source_label),
            domain_hint="live",
        )
        return self.from_bytes(raw, spec=spec, previous_signal=previous_signal)

    def from_bytes(
        self,
        raw: bytes,
        spec: CapsuleSpec,
        previous_signal: Optional[bytes] = None,
    ) -> AnalysisCapsuleResult:
        signal = bytes(raw or b"")
        envelope = SignalEnvelope(
            source_hash=hashlib.sha256(signal).hexdigest(),
            size_bytes=len(signal),
            source_type=str(spec.source_type),
            source_label=str(spec.source_label),
            domain_hint=str(spec.domain_hint),
        )
        entropy = self._entropy(signal)
        entropy_blocks = self._entropy_blocks(signal)
        periodicity = self._periodicity(signal)
        symmetry = self._symmetry(signal)
        katz_dimension = self._katz_fractal_dimension(entropy_blocks or [entropy])
        benford = self._benford_score(signal)
        zipf_alpha = self._zipf_alpha(signal)
        local_delta = self._build_local_delta(signal, previous_signal, spec)
        h_lambda = self._h_lambda(entropy, local_delta["delta_ratio"], symmetry)
        noether_consistency = self._noether_consistency(entropy_blocks, signal, local_delta)
        sce = self._sce_payload(symmetry, benford, entropy_blocks)
        sce_score = _safe_float(sce.get("coherence_score", 0.0))
        invariants = self._invariants(signal)
        bayes_confidence = self._bayes_confidence(
            entropy=entropy,
            symmetry=symmetry,
            sce_score=sce_score,
            benford_score=benford,
            delta_ratio=local_delta["delta_ratio"],
        )
        trust_score = self._trust_score(
            bayes_confidence=bayes_confidence,
            benford_score=benford,
            noether_consistency=noether_consistency,
            sce_score=sce_score,
            local_delta=local_delta,
        )
        metrics = CapsuleMetricBundle(
            entropy=entropy,
            h_lambda=h_lambda,
            symmetry=symmetry,
            periodicity=periodicity,
            zipf_alpha=zipf_alpha,
            benford_score=benford,
            katz_dimension=katz_dimension,
            sce_score=sce_score,
            bayes_confidence=bayes_confidence,
            trust_score=trust_score,
            noether_consistency=noether_consistency,
            delta_ratio=float(local_delta["delta_ratio"]),
        )
        shared_anchor_pack = self._shared_anchor_pack(signal, spec, invariants, entropy_blocks)
        godel_loop = self._godel.render_with_self_reference(signal, max_depth=spec.max_godel_depth) if spec.enable_godel_loop else {}
        anomaly_flags = self._anomaly_flags(metrics, invariants, godel_loop)
        return AnalysisCapsuleResult(
            spec=spec,
            envelope=envelope,
            metrics=metrics,
            local_delta=local_delta,
            shared_anchor_pack=shared_anchor_pack,
            invariants=invariants,
            sce=sce,
            godel_loop=godel_loop,
            anomaly_flags=anomaly_flags,
        )

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for byte_value in data:
            counts[byte_value] = counts.get(byte_value, 0) + 1
        total = float(len(data))
        return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))

    def _entropy_blocks(self, data: bytes, block_size: int = 256) -> List[float]:
        if not data:
            return []
        blocks: List[float] = []
        for index in range(0, len(data), max(8, int(block_size))):
            block = data[index : index + max(8, int(block_size))]
            if block:
                blocks.append(self._entropy(block))
        return blocks

    def _periodicity(self, data: bytes) -> float:
        return _clamp(_safe_float(self._godel._periodicity_score(data), 0.0), 0.0, 1.0)

    @staticmethod
    def _symmetry(data: bytes) -> float:
        if not data:
            return 1.0
        counts = [0] * 256
        for byte_value in data:
            counts[byte_value] += 1
        non_zero = [count for count in counts if count > 0]
        if not non_zero:
            return 1.0
        mean = float(sum(non_zero)) / float(len(non_zero))
        deviation = sum(abs(float(count) - mean) for count in non_zero) / float(len(non_zero))
        score = 1.0 - min(1.0, deviation / max(mean, 1.0))
        return float(max(0.0, min(1.0, score)))

    @staticmethod
    def _katz_fractal_dimension(values: List[float]) -> float:
        if len(values) < 2:
            return 1.0
        curve_length = 0.0
        for index in range(1, len(values)):
            curve_length += math.hypot(1.0, float(values[index]) - float(values[index - 1]))
        if curve_length <= 0.0:
            return 1.0
        diameter = max(
            math.hypot(float(index), float(value) - float(values[0]))
            for index, value in enumerate(values)
        )
        if diameter <= 0.0:
            return 1.0
        n = float(len(values))
        denominator = math.log10(diameter / curve_length) + math.log10(max(n, 1.0))
        if abs(denominator) < 1e-9:
            return 1.0
        fd = math.log10(max(n, 1.0)) / denominator
        return float(max(1.0, min(2.5, fd)))

    @staticmethod
    def _zipf_alpha(data: bytes) -> float:
        if not data:
            return 0.0
        frequencies: Dict[str, int] = {}
        for byte_value in data:
            key = f"b{int(byte_value)}"
            frequencies[key] = frequencies.get(key, 0) + 1
        return _safe_float(detect_zipf_distribution(frequencies).get("alpha", 0.0), 0.0)

    @staticmethod
    def _benford_score(data: bytes) -> float:
        if not data:
            return 0.0
        values: List[int] = []
        window = 4
        for index in range(0, len(data), window):
            chunk = data[index : index + window]
            if chunk:
                values.append(int.from_bytes(chunk, "big", signed=False))
        return _safe_float(detect_benford_law(values).get("benford_conformance", 0.0), 0.0)

    def _build_local_delta(
        self,
        current: bytes,
        previous: Optional[bytes],
        spec: CapsuleSpec,
    ) -> Dict[str, Any]:
        if not spec.retain_local_delta:
            return {"available": False, "delta_ratio": 0.0, "changed_bytes": 0, "delta_hash": ""}
        prev = bytes(previous or b"")
        if not prev:
            delta_hash = hashlib.sha256(current).hexdigest() if current else ""
            return {
                "available": bool(current),
                "delta_ratio": 1.0 if current else 0.0,
                "changed_bytes": int(len(current)),
                "delta_hash": delta_hash,
                "mode": "genesis",
            }
        size = max(len(current), len(prev))
        left = prev.ljust(size, b"\x00")
        right = current.ljust(size, b"\x00")
        xor_bytes = bytes(a ^ b for a, b in zip(left, right))
        changed = sum(1 for byte_value in xor_bytes if byte_value != 0)
        return {
            "available": True,
            "delta_ratio": float(changed / float(max(1, size))),
            "changed_bytes": int(changed),
            "delta_hash": hashlib.sha256(xor_bytes).hexdigest(),
            "mode": "xor_delta",
        }

    @staticmethod
    def _h_lambda(entropy: float, delta_ratio: float, symmetry: float) -> float:
        return float(max(0.0, min(8.0, float(entropy) * float(delta_ratio) * (1.0 - float(symmetry) + 0.1))))

    def _invariants(self, data: bytes) -> Dict[str, Any]:
        if not data:
            return compute_invariant_score([], {}, [], [])
        arr = list(data)
        change_sequence = [abs(arr[index] - arr[index - 1]) for index in range(1, len(arr))]
        anchor_frequencies: Dict[str, int] = {}
        for index in range(0, len(data), 128):
            block = data[index : index + 128]
            if not block:
                continue
            block_hash = hashlib.sha256(block).hexdigest()
            anchor_frequencies[block_hash] = anchor_frequencies.get(block_hash, 0) + 1
        tree_depths = [1 + int(index / 128) % 6 for index in range(max(1, len(anchor_frequencies)))]
        return compute_invariant_score(
            change_sequence=change_sequence,
            anchor_frequencies=anchor_frequencies,
            file_sizes=[len(data)],
            tree_depths=tree_depths,
        )

    @staticmethod
    def _gradient_coherence(entropy_blocks: List[float]) -> float:
        if len(entropy_blocks) < 2:
            return 1.0
        diffs = [abs(float(entropy_blocks[index]) - float(entropy_blocks[index - 1])) for index in range(1, len(entropy_blocks))]
        mean_diff = sum(diffs) / float(max(1, len(diffs)))
        return float(max(0.0, min(1.0, 1.0 - (mean_diff / 8.0))))

    def _sce_payload(self, symmetry: float, benford_score: float, entropy_blocks: List[float]) -> Dict[str, Any]:
        if sce_engine is None:
            coherence = (0.4 * symmetry) + (0.3 * benford_score) + (0.3 * self._gradient_coherence(entropy_blocks))
            return {
                "coherence_score": float(_clamp(coherence, 0.0, 1.0)),
                "control_signals": {},
                "structural_explanation": {
                    "symmetry": float(symmetry),
                    "proportion": float(benford_score),
                    "gradient_coherence": float(self._gradient_coherence(entropy_blocks)),
                },
            }
        return dict(
            sce_engine(
                {
                    "symmetry": float(symmetry),
                    "proportion": float(benford_score),
                    "gradient_coherence": float(self._gradient_coherence(entropy_blocks)),
                }
            )
        )

    def _bayes_confidence(
        self,
        entropy: float,
        symmetry: float,
        sce_score: float,
        benford_score: float,
        delta_ratio: float,
    ) -> float:
        prior = _clamp((0.30 * symmetry) + (0.30 * sce_score) + (0.20 * benford_score) + (0.20 * (1.0 - delta_ratio)))
        likelihood_true = _clamp(0.35 + (0.50 * prior) + (0.15 * (1.0 - min(1.0, entropy / 8.0))), 1e-4, 0.9999)
        likelihood_false = _clamp(0.65 - (0.40 * prior), 1e-4, 0.9999)
        if self._bayes is not None:
            try:
                return float(self._bayes._posterior(prior, likelihood_true, likelihood_false))
            except Exception:
                pass
        numerator = likelihood_true * prior
        denominator = numerator + (likelihood_false * (1.0 - prior))
        if denominator <= 1e-9:
            return float(prior)
        return float(_clamp(numerator / denominator))

    def _trust_score(
        self,
        bayes_confidence: float,
        benford_score: float,
        noether_consistency: float,
        sce_score: float,
        local_delta: Dict[str, Any],
    ) -> float:
        score, _passed, _breakdown, _bayes_flags, _flags = self._trust.evaluate(
            {
                "anchor_pattern_hash": str(local_delta.get("delta_hash", "") or "capsule"),
                "trust_inputs": {
                    "bayes_overall_confidence": float(bayes_confidence),
                    "noether_score": float(noether_consistency) * 100.0,
                    "benford_score": float(benford_score),
                    "graph_confidence_mean": float(sce_score),
                    "sce_score": float(sce_score) * 100.0,
                    "anchor_coverage_ratio": float(1.0 - float(local_delta.get("delta_ratio", 1.0))),
                    "unresolved_residual_ratio": float(local_delta.get("delta_ratio", 1.0)),
                    "coverage_verified": bool(float(local_delta.get("delta_ratio", 1.0)) < 0.35),
                    "reconstruction_verified": bool(float(local_delta.get("delta_ratio", 1.0)) < 0.35),
                    "heisenberg_uncertainty": float(local_delta.get("delta_ratio", 1.0)),
                },
            },
            pattern_counts={str(local_delta.get("delta_hash", "") or "capsule"): 2},
        )
        return float(score)

    @staticmethod
    def _noether_consistency(entropy_blocks: List[float], signal: bytes, local_delta: Dict[str, Any]) -> float:
        if not signal:
            return 0.0
        periodicity_proxy = _clamp(len(set(signal[: min(len(signal), 512)])) / 256.0)
        entropy_delta = 0.0
        if len(entropy_blocks) >= 2:
            entropy_delta = abs(float(entropy_blocks[-1]) - float(entropy_blocks[0])) / 8.0
        delta_penalty = float(local_delta.get("delta_ratio", 1.0))
        return float(
            _clamp(
                (0.40 * periodicity_proxy)
                + (0.30 * (1.0 - entropy_delta))
                + (0.30 * (1.0 - delta_penalty))
            )
        )

    @staticmethod
    def _shared_anchor_pack(
        signal: bytes,
        spec: CapsuleSpec,
        invariants: Dict[str, Any],
        entropy_blocks: List[float],
    ) -> Dict[str, Any]:
        if not spec.share_invariants:
            return {"shareable": False, "anchors": []}
        anchors: List[Dict[str, Any]] = []
        for index in range(0, len(signal), 256):
            block = signal[index : index + 256]
            if not block:
                continue
            anchors.append(
                {
                    "anchor_id": f"{spec.source_label}:{index // 256}",
                    "anchor_hash": hashlib.sha256(block).hexdigest(),
                    "entropy": round(float(entropy_blocks[index // 256]) if index // 256 < len(entropy_blocks) else 0.0, 6),
                }
            )
        return {
            "shareable": True,
            "anchor_count": int(len(anchors)),
            "anchors": anchors[:32],
            "invariant_strength": float(invariants.get("invariant_strength", 0.0) or 0.0),
        }

    @staticmethod
    def _anomaly_flags(
        metrics: CapsuleMetricBundle,
        invariants: Dict[str, Any],
        godel_loop: Dict[str, Any],
    ) -> List[str]:
        flags: List[str] = []
        if metrics.entropy >= 7.2:
            flags.append("high_entropy")
        if metrics.benford_score <= 0.35:
            flags.append("benford_break")
        if metrics.katz_dimension >= 1.85:
            flags.append("fractal_roughness")
        if metrics.sce_score <= 0.35:
            flags.append("low_structural_coherence")
        if metrics.trust_score <= 0.35:
            flags.append("low_trust")
        if metrics.h_lambda >= 4.8:
            flags.append("observer_uncertainty")
        if _safe_float(invariants.get("invariant_strength", 0.0), 0.0) >= 0.8:
            flags.append("strong_invariants")
        if str(godel_loop.get("stop_reason", "")) == "cycle":
            flags.append("godel_cycle")
        return flags
