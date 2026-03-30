"""AetherGuard: deterministic security layer for Aether.

The layer evaluates structural metrics and policy flags with fixed rules.
Same input produces the same verdict, score, and fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return float(max(low, min(high, value)))


def _f(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _b(value: Any) -> bool:
    return bool(value)


@dataclass
class AetherGuardDecision:
    """Deterministic output of the security layer."""

    layer: str
    verdict: str
    risk_score: float
    confidence: float
    reasons: List[str]
    deterministic_fingerprint: str

    def to_payload(self) -> Dict[str, Any]:
        return {
            "layer": str(self.layer),
            "verdict": str(self.verdict),
            "risk_score": float(self.risk_score),
            "confidence": float(self.confidence),
            "reasons": list(self.reasons),
            "deterministic_fingerprint": str(self.deterministic_fingerprint),
        }


class AetherGuard:
    """Deterministic policy layer: allow, monitor, quarantine, block."""

    LAYER_NAME = "AetherGuard Deterministic Security Layer"

    def __init__(self) -> None:
        self.version = "v1"

    @staticmethod
    def _fingerprint(payload: Dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def evaluate(self, evidence: Dict[str, Any]) -> AetherGuardDecision:
        """Evaluate evidence with deterministic rules and fixed thresholds."""
        metrics = dict(evidence.get("metrics", {}) or {})
        flags = dict(evidence.get("flags", {}) or {})

        trust_score = _clamp(_f(metrics.get("trust_score", 0.0)))
        entropy = _f(metrics.get("entropy", 0.0))
        periodicity = _clamp(_f(metrics.get("periodicity", 0.0)))
        asymmetry = _clamp(_f(metrics.get("asymmetry", 0.0)))
        reconstruction_ok = _b(metrics.get("reconstruction_ok", True))

        eicar_hit = _b(flags.get("eicar_hit", False))
        policy_hit = _b(flags.get("policy_hit", False))
        sensitive_hit = _b(flags.get("sensitive_hit", False))

        reasons: List[str] = []

        risk = 0.0
        risk += (1.0 - trust_score) * 0.45
        risk += asymmetry * 0.20
        risk += periodicity * 0.10
        if entropy > 7.6:
            risk += 0.10
            reasons.append("high_entropy")
        if not reconstruction_ok:
            risk += 0.10
            reasons.append("reconstruction_failed")
        if sensitive_hit:
            risk += 0.08
            reasons.append("sensitive_pattern")
        if policy_hit:
            risk += 0.20
            reasons.append("policy_hit")
        if eicar_hit:
            risk = 1.0
            reasons.append("eicar_test_signature")

        risk = _clamp(risk)

        if eicar_hit:
            verdict = "block"
        elif risk >= 0.75:
            verdict = "quarantine"
        elif risk >= 0.45:
            verdict = "monitor"
        else:
            verdict = "allow"

        confidence = _clamp(0.55 + abs(risk - 0.50) * 0.90)

        stable_input = {
            "version": self.version,
            "trust_score": round(trust_score, 8),
            "entropy": round(entropy, 8),
            "periodicity": round(periodicity, 8),
            "asymmetry": round(asymmetry, 8),
            "reconstruction_ok": bool(reconstruction_ok),
            "eicar_hit": bool(eicar_hit),
            "policy_hit": bool(policy_hit),
            "sensitive_hit": bool(sensitive_hit),
            "risk": round(risk, 8),
            "verdict": str(verdict),
        }
        deterministic_fingerprint = self._fingerprint(stable_input)

        if not reasons:
            reasons.append("no_strong_risk_signal")

        return AetherGuardDecision(
            layer=self.LAYER_NAME,
            verdict=verdict,
            risk_score=float(risk),
            confidence=float(confidence),
            reasons=sorted(set(reasons)),
            deterministic_fingerprint=deterministic_fingerprint,
        )


def evaluate_aetherguard(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience helper for pipeline usage."""
    guard = AetherGuard()
    return guard.evaluate(evidence).to_payload()
