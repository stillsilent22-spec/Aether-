"""Bayesianische Vertrauensschicht fuer AETHER-Metriken."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Sequence

from .analysis_engine import AetherFingerprint
from .embedding_engine import PatternCluster
from .graph_engine import GraphFieldSnapshot
from .observer_engine import AnchorPoint


@dataclass
class BayesianBeliefSnapshot:
    """Posterior-Schicht ueber deterministischen AETHER-Metriken."""

    anchor_posterior: float
    graph_posteriors: dict[str, float]
    graph_phase_label: str
    graph_phase_confidence: float
    pattern_posterior: float
    interference_posterior: float
    alarm_posterior: float
    overall_confidence: float


class BayesianBeliefEngine:
    """Berechnet additive Bayes-Posterioren fuer Prior-, Graph- und Alarmzustand."""

    def __init__(self) -> None:
        self._collective_feedback: dict[str, Any] = {}

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        return float(max(low, min(high, value)))

    def set_collective_feedback(self, feedback: dict[str, Any] | None) -> None:
        """Setzt sanfte kollektive Priors fuer Bayes-Posterioren."""
        self._collective_feedback = dict(feedback or {})

    def _posterior(self, prior: float, likelihood_true: float, likelihood_false: float) -> float:
        """Berechnet einen robusten binären Posterior."""
        prior = self._clamp(prior, 1e-4, 1.0 - 1e-4)
        likelihood_true = self._clamp(likelihood_true, 1e-4, 1.0 - 1e-4)
        likelihood_false = self._clamp(likelihood_false, 1e-4, 1.0 - 1e-4)
        numerator = likelihood_true * prior
        denominator = numerator + (likelihood_false * (1.0 - prior))
        if denominator <= 1e-9:
            return prior
        return self._clamp(numerator / denominator, 0.0, 1.0)

    def _normalize(self, probabilities: dict[str, float]) -> dict[str, float]:
        """Normiert Wahrscheinlichkeiten auf Summe 1."""
        total = float(sum(max(0.0, value) for value in probabilities.values()))
        if total <= 1e-9:
            count = max(1, len(probabilities))
            return {key: 1.0 / float(count) for key in probabilities}
        return {key: max(0.0, value) / total for key, value in probabilities.items()}

    def anchor_prior_posterior(
        self,
        prior_cells: Sequence[dict[str, float | int]],
        anchors: Sequence[AnchorPoint],
    ) -> float:
        """Bayes-Posterior fuer die Frage, ob aktuelle Anker die gelernten Priors bestaetigen."""
        if not anchors or not prior_cells:
            return 0.0

        total_count = float(sum(float(cell.get("count", 0.0)) for cell in prior_cells))
        max_count = max(1.0, max(float(cell.get("count", 1.0)) for cell in prior_cells))
        prior = self._clamp(total_count / (total_count + 48.0), 0.12, 0.96)

        weighted_hits = 0.0
        for anchor in anchors:
            best_match = 0.0
            for cell in prior_cells:
                dx = abs(float(cell.get("x_norm", 0.5)) - float(anchor.x))
                dy = abs(float(cell.get("y_norm", 0.5)) - float(anchor.y))
                distance = math.hypot(dx, dy)
                if distance > 0.12:
                    continue
                local = (1.0 - (distance / 0.12)) * (float(cell.get("count", 0.0)) / max_count)
                best_match = max(best_match, local)
            weighted_hits += best_match
        evidence = self._clamp(weighted_hits / max(1.0, float(len(anchors))), 0.0, 1.0)
        confidence_mean = float(
            sum(float(getattr(anchor, "confidence", getattr(anchor, "strength", 0.0)) or 0.0) for anchor in anchors)
            / max(1, len(anchors))
        )
        interference_mean = float(
            sum(float(getattr(anchor, "interference", 0.0) or 0.0) for anchor in anchors)
            / max(1, len(anchors))
        )
        interference_support = self._clamp(0.5 + (0.5 * interference_mean), 0.0, 1.0)
        evidence = self._clamp(
            (0.72 * evidence) + (0.18 * confidence_mean) + (0.10 * interference_support),
            0.0,
            1.0,
        )
        return self._posterior(
            prior=prior,
            likelihood_true=0.45 + (0.45 * evidence),
            likelihood_false=0.55 - (0.35 * evidence),
        )

    def graph_phase_posteriors(self, snapshot: GraphFieldSnapshot) -> dict[str, float]:
        """Posterioren fuer die Graph-Phasen ATTRACTOR_LOCK, EMERGENT und PHASE_SHIFT."""
        attractor = self._clamp(float(snapshot.attractor_score) / 100.0, 0.0, 1.0)
        phase_shift = self._clamp(float(snapshot.phase_transition_score) / 100.0, 0.0, 1.0)
        subgraph_density = self._clamp(float(snapshot.stable_subgraphs) / 3.0, 0.0, 1.0)
        confidence = self._clamp(float(snapshot.confidence_mean), 0.0, 1.0)
        constructive = self._clamp(float(snapshot.constructive_ratio), 0.0, 1.0)
        destructive = self._clamp(float(snapshot.destructive_ratio), 0.0, 1.0)
        interference_support = self._clamp(0.5 + (0.5 * float(snapshot.interference_mean)), 0.0, 1.0)

        lock_score = 0.34 * (
            0.22
            + (0.42 * attractor)
            + (0.12 * subgraph_density)
            + (0.10 * (1.0 - phase_shift))
            + (0.08 * confidence)
            + (0.06 * constructive)
        )
        emergent_balance = 1.0 - abs(attractor - 0.55)
        emergent_score = 0.33 * (
            0.28
            + (0.27 * emergent_balance)
            + (0.12 * (1.0 - abs(phase_shift - 0.25)))
            + (0.10 * (1.0 - abs(subgraph_density - 0.45)))
            + (0.13 * confidence)
            + (0.10 * (1.0 - abs(interference_support - 0.5) * 2.0))
        )
        shift_score = 0.33 * (
            0.18
            + (0.42 * phase_shift)
            + (0.13 * (1.0 - subgraph_density))
            + (0.15 * destructive)
            + (0.12 * (1.0 - confidence))
        )
        if snapshot.phase_state == "ATTRACTOR_LOCK":
            lock_score *= 1.18
        elif snapshot.phase_state == "PHASE_SHIFT":
            shift_score *= 1.18
        else:
            emergent_score *= 1.12
        probabilities = self._normalize(
            {
                "ATTRACTOR_LOCK": lock_score,
                "EMERGENT": emergent_score,
                "PHASE_SHIFT": shift_score,
            }
        )
        priors = dict(
            dict(self._collective_feedback.get("bayes_feedback", {}) or {}).get("graph_phase_priors", {}) or {}
        )
        if priors:
            probabilities = self._normalize(
                {
                    key: (0.84 * float(probabilities.get(key, 0.0))) + (0.16 * float(priors.get(key, 0.0) or 0.0))
                    for key in probabilities
                }
            )
        return probabilities

    def pattern_posterior(
        self,
        similarity_best: float,
        pattern: PatternCluster | None,
    ) -> float:
        """Posterior dafuer, dass ein neues Objekt stabil zu einem Muster gehoert."""
        similarity = self._clamp(float(similarity_best), 0.0, 1.0)
        if pattern is None:
            posterior = self._posterior(
                prior=0.24,
                likelihood_true=0.25 + (0.25 * similarity),
                likelihood_false=0.76 - (0.20 * similarity),
            )
            prior_pattern = float(
                dict(self._collective_feedback.get("pattern_feedback", {}) or {}).get("similarity_mean", posterior) or posterior
            )
            return self._clamp((0.90 * posterior) + (0.10 * prior_pattern), 0.0, 1.0)

        variance_conf = self._clamp(1.0 - (float(pattern.variance) / 0.05), 0.0, 1.0)
        member_conf = self._clamp(float(len(pattern.members)) / 6.0, 0.0, 1.0)
        evidence = self._clamp((0.45 * similarity) + (0.35 * variance_conf) + (0.20 * member_conf), 0.0, 1.0)
        posterior = self._posterior(
            prior=0.42,
            likelihood_true=0.48 + (0.45 * evidence),
            likelihood_false=0.52 - (0.30 * evidence),
        )
        prior_pattern = float(
            dict(self._collective_feedback.get("bayes_feedback", {}) or {}).get("pattern_mean", posterior) or posterior
        )
        return self._clamp((0.88 * posterior) + (0.12 * prior_pattern), 0.0, 1.0)

    def vault_membership_posterior(
        self,
        similarity_best: float,
        pattern_posterior: float,
        overall_confidence: float,
        observer_knowledge_ratio: float,
    ) -> float:
        """Posterior dafuer, dass ein Objekt stabil in einen Vault-Orbit passt."""
        evidence = self._clamp(
            (0.34 * float(similarity_best))
            + (0.28 * float(pattern_posterior))
            + (0.22 * float(overall_confidence))
            + (0.16 * float(observer_knowledge_ratio)),
            0.0,
            1.0,
        )
        return self._posterior(
            prior=0.38,
            likelihood_true=0.40 + (0.48 * evidence),
            likelihood_false=0.60 - (0.32 * evidence),
        )

    def vault_reconstruction_posterior(
        self,
        fingerprint: AetherFingerprint,
        overall_confidence: float,
        reconstruction_verified: bool,
    ) -> float:
        """Posterior fuer die belastbare Wiederherstellbarkeit eines Vault-Eintrags."""
        compression_affinity = self._clamp(1.0 - float(getattr(fingerprint, "delta_ratio", 0.0) or 0.0), 0.0, 1.0)
        ethics_affinity = self._clamp(float(getattr(fingerprint, "ethics_score", 0.0) or 0.0) / 100.0, 0.0, 1.0)
        observer_affinity = self._clamp(float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0), 0.0, 1.0)
        verified_boost = 1.0 if bool(reconstruction_verified) else 0.0
        evidence = self._clamp(
            (0.34 * compression_affinity)
            + (0.22 * ethics_affinity)
            + (0.22 * observer_affinity)
            + (0.12 * float(overall_confidence))
            + (0.10 * verified_boost),
            0.0,
            1.0,
        )
        return self._posterior(
            prior=0.34,
            likelihood_true=0.36 + (0.56 * evidence),
            likelihood_false=0.64 - (0.32 * evidence),
        )

    def interference_posterior(
        self,
        anchors: Sequence[AnchorPoint],
        graph_snapshot: GraphFieldSnapshot,
    ) -> float:
        """Posterior dafuer, dass beide Analysepfade strukturell konsistent sind."""
        if anchors:
            confidence_mean = float(
                sum(float(getattr(anchor, "confidence", getattr(anchor, "strength", 0.0)) or 0.0) for anchor in anchors)
                / max(1, len(anchors))
            )
            interference_mean = float(
                sum(float(getattr(anchor, "interference", 0.0) or 0.0) for anchor in anchors)
                / max(1, len(anchors))
            )
            constructive = float(sum(1 for anchor in anchors if float(getattr(anchor, "interference", 0.0) or 0.0) > 0.05)) / max(1, len(anchors))
            destructive = float(sum(1 for anchor in anchors if float(getattr(anchor, "interference", 0.0) or 0.0) < -0.05)) / max(1, len(anchors))
        else:
            confidence_mean = float(graph_snapshot.confidence_mean)
            interference_mean = float(graph_snapshot.interference_mean)
            constructive = float(graph_snapshot.constructive_ratio)
            destructive = float(graph_snapshot.destructive_ratio)
        support = self._clamp(0.5 + (0.5 * interference_mean), 0.0, 1.0)
        evidence = self._clamp(
            (0.34 * constructive)
            + (0.24 * (1.0 - destructive))
            + (0.20 * confidence_mean)
            + (0.22 * support),
            0.0,
            1.0,
        )
        return self._posterior(
            prior=0.46,
            likelihood_true=0.44 + (0.44 * evidence),
            likelihood_false=0.56 - (0.30 * evidence),
        )

    def alarm_posterior(
        self,
        fingerprint: AetherFingerprint,
        graph_snapshot: GraphFieldSnapshot,
    ) -> float:
        """Posterior fuer strukturelle Alarmwahrscheinlichkeit."""
        entropy = self._clamp(float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0) / 8.0, 0.0, 1.0)
        ethics_risk = 1.0 - self._clamp(float(getattr(fingerprint, "ethics_score", 0.0) or 0.0) / 100.0, 0.0, 1.0)
        coherence_risk = 1.0 - self._clamp(float(getattr(fingerprint, "coherence_score", 0.0) or 0.0) / 100.0, 0.0, 1.0)
        phase_risk = self._clamp(float(graph_snapshot.phase_transition_score) / 100.0, 0.0, 1.0)
        destructive_risk = self._clamp(float(graph_snapshot.destructive_ratio), 0.0, 1.0)
        interference_risk = self._clamp(0.5 - (0.5 * float(graph_snapshot.interference_mean)), 0.0, 1.0)
        shift_bonus = 0.15 if graph_snapshot.phase_state == "PHASE_SHIFT" else 0.0
        evidence = self._clamp(
            (0.24 * ethics_risk)
            + (0.20 * coherence_risk)
            + (0.18 * entropy)
            + (0.16 * phase_risk)
            + (0.12 * destructive_risk)
            + (0.10 * interference_risk)
            + shift_bonus,
            0.0,
            1.0,
        )
        posterior = self._posterior(
            prior=0.18,
            likelihood_true=0.32 + (0.58 * evidence),
            likelihood_false=0.68 - (0.35 * evidence),
        )
        prior_alarm = float(
            dict(self._collective_feedback.get("bayes_feedback", {}) or {}).get("alarm_mean", posterior) or posterior
        )
        return self._clamp((0.88 * posterior) + (0.12 * prior_alarm), 0.0, 1.0)

    def evaluate(
        self,
        prior_cells: Sequence[dict[str, float | int]],
        anchors: Sequence[AnchorPoint],
        graph_snapshot: GraphFieldSnapshot,
        fingerprint: AetherFingerprint,
        similarity_best: float,
        pattern: PatternCluster | None,
    ) -> BayesianBeliefSnapshot:
        """Berechnet alle Posterioren fuer einen AETHER-Zustand."""
        anchor_posterior = self.anchor_prior_posterior(prior_cells, anchors)
        graph_posteriors = self.graph_phase_posteriors(graph_snapshot)
        graph_phase_label = max(graph_posteriors, key=graph_posteriors.get)
        graph_phase_confidence = float(graph_posteriors[graph_phase_label])
        pattern_post = self.pattern_posterior(similarity_best, pattern)
        interference_post = self.interference_posterior(anchors, graph_snapshot)
        alarm_post = self.alarm_posterior(fingerprint, graph_snapshot)
        overall = self._clamp(
            (0.24 * anchor_posterior)
            + (0.21 * graph_phase_confidence)
            + (0.20 * pattern_post)
            + (0.15 * interference_post)
            + (0.20 * (1.0 - alarm_post)),
            0.0,
            1.0,
        )
        prior_overall = float(
            dict(self._collective_feedback.get("bayes_feedback", {}) or {}).get("overall_mean", overall) or overall
        )
        overall = self._clamp((0.90 * overall) + (0.10 * prior_overall), 0.0, 1.0)
        return BayesianBeliefSnapshot(
            anchor_posterior=float(anchor_posterior),
            graph_posteriors=graph_posteriors,
            graph_phase_label=str(graph_phase_label),
            graph_phase_confidence=float(graph_phase_confidence),
            pattern_posterior=float(pattern_post),
            interference_posterior=float(interference_post),
            alarm_posterior=float(alarm_post),
            overall_confidence=float(overall),
        )
