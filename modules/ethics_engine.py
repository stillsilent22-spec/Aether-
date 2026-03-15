def ethics_score(text: str) -> float:
    """Minimaler deterministischer Score: 1 - (matches / words), clamp [0,1]"""
    if not text:
        return 1.0
    words = text.split()
    n_words = len(words)
    if n_words == 0:
        return 1.0
    matches = sum(1 for w in words if w.lower() in {"harm", "violence", "abuse"})
    score = 1.0 - (matches / n_words)
    return max(0.0, min(1.0, score))
"""Ethik-Engine zur strukturellen Integritaetsmessung ueber Entropiephysik."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass
class EthicsAssessment:
    """Kapselt das Ergebnis der strukturellen Integritaetsanalyse."""

    symmetry_component: float
    coherence_score: float
    resonance_score: float
    ethics_score: float
    integrity_state: str
    integrity_text: str

    def to_dict(self) -> dict[str, float | str]:
        """Serialisiert die Ethikbewertung als Dictionary."""
        return {
            "symmetry_component": float(self.symmetry_component),
            "coherence_score": float(self.coherence_score),
            "resonance_score": float(self.resonance_score),
            "ethics_score": float(self.ethics_score),
            "integrity_state": self.integrity_state,
            "integrity_text": self.integrity_text,
        }


class EthicsEngine:
    """Berechnet Integritaet aus Symmetrie, Kohaerenz und Resonanz."""

    def __init__(self, w_symmetry: float = 0.4, w_coherence: float = 0.4, w_resonance: float = 0.2) -> None:
        """
        Initialisiert Gewichte des kombinierten Ethik-Scores.

        Args:
            w_symmetry: Gewicht fuer den Symmetrieanteil.
            w_coherence: Gewicht fuer den Kohaerenzanteil.
            w_resonance: Gewicht fuer den Resonanzanteil.
        """
        self.w_symmetry = float(w_symmetry)
        self.w_coherence = float(w_coherence)
        self.w_resonance = float(w_resonance)

    @staticmethod
    def _clamp_score(value: float) -> float:
        """Begrenzt einen Score robust auf den Bereich 0 bis 100."""
        return float(max(0.0, min(100.0, value)))

    def compute_coherence_score(self, entropy_blocks: Sequence[float]) -> float:
        """
        Misst die Stabilitaet der Entropiekurve als Kohaerenz.

        Eine stabile, sanfte Kurve fuehrt zu hohen Werten.
        Spruenge und abrupte Brueche reduzieren den Score.
        """
        if not entropy_blocks:
            return 100.0
        if len(entropy_blocks) == 1:
            return 96.0

        arr = np.array(list(entropy_blocks), dtype=np.float64)
        diffs = np.diff(arr)
        mean_entropy = float(arr.mean())
        std_entropy = float(arr.std())
        mean_jump = float(np.mean(np.abs(diffs)))
        jump_std = float(np.std(diffs))

        # Normalisierung auf den Entropieraum [0, 8]
        normalized_std = min(1.0, std_entropy / 2.6)
        normalized_jump = min(1.0, mean_jump / 2.0)
        normalized_jump_std = min(1.0, jump_std / 2.0)

        # In unnatuerlich niedriger Entropie steckt oft starres, manipuliertes Muster.
        low_entropy_penalty = 0.0
        if mean_entropy < 1.0:
            low_entropy_penalty = min(0.3, (1.0 - mean_entropy) * 0.2)

        instability = (
            0.45 * normalized_std
            + 0.35 * normalized_jump
            + 0.20 * normalized_jump_std
            + low_entropy_penalty
        )
        coherence = 100.0 * (1.0 - min(1.0, instability))
        return self._clamp_score(coherence)

    def compute_resonance_score(
        self,
        entropy_mean: float,
        symmetry_score: float,
        periodicity: int,
        delta_ratio: float,
        healthy_references: Sequence[dict[str, float | int]],
    ) -> float:
        """
        Misst harmonische Naehe zu gesunden Referenzstroemen in der Registry.

        Args:
            entropy_mean: Mittlere Entropie des aktuellen Stroms.
            symmetry_score: Symmetrie des aktuellen Stroms.
            periodicity: Dominante Periodizitaet.
            delta_ratio: Delta-Verhaeltnis.
            healthy_references: Historische Referenzvektoren.
        """
        refs = list(healthy_references)
        if not refs:
            return 60.0

        similarities: list[float] = []
        for ref in refs:
            ref_entropy = float(ref.get("entropy_mean", entropy_mean))
            ref_symmetry = float(ref.get("symmetry_score", symmetry_score))
            ref_periodicity = int(ref.get("periodicity", 0))
            ref_delta = float(ref.get("delta_ratio", delta_ratio))
            ref_integrity = float(ref.get("ethics_score", 75.0))

            d_entropy = min(1.0, abs(entropy_mean - ref_entropy) / 8.0)
            d_symmetry = min(1.0, abs(symmetry_score - ref_symmetry) / 100.0)
            d_delta = min(1.0, abs(delta_ratio - ref_delta))

            if periodicity > 0 and ref_periodicity > 0:
                ratio = max(ref_periodicity, periodicity) / max(1.0, min(ref_periodicity, periodicity))
                harmonic_distance = min(1.0, abs(math.log2(ratio)) / 4.0)
            elif periodicity == ref_periodicity:
                harmonic_distance = 0.0
            else:
                harmonic_distance = 0.5

            distance = (
                0.35 * d_entropy
                + 0.35 * d_symmetry
                + 0.20 * d_delta
                + 0.10 * harmonic_distance
            )
            similarity = max(0.0, 1.0 - distance)
            integrity_weight = max(0.4, min(1.0, ref_integrity / 100.0))
            similarities.append(similarity * integrity_weight)

        if not similarities:
            return 58.0
        similarities.sort(reverse=True)
        top = similarities[: min(8, len(similarities))]
        resonance = 100.0 * float(np.mean(top))
        return self._clamp_score(resonance)

    def integrity_state(self, ethics_score: float) -> tuple[str, str]:
        """
        Uebersetzt den Ethik-Score in einen strukturellen Zustandstext.

        Returns:
            Tupel aus internem Zustandscode und deutscher Beschreibung.
        """
        score = self._clamp_score(ethics_score)
        if score < 40.0:
            return "STRUCTURAL_ANOMALY", "Strukturelle Anomalie erkannt"
        if score < 70.0:
            return "STRUCTURAL_TENSION", "Strukturelle Spannung erkannt"
        return "STRUCTURAL_HEALTH", "Strukturell gesund"

    def evaluate(
        self,
        symmetry_score: float,
        entropy_blocks: Sequence[float],
        entropy_mean: float,
        periodicity: int,
        delta_ratio: float,
        healthy_references: Sequence[dict[str, float | int]],
    ) -> EthicsAssessment:
        """
        Fuehrt die komplette Integritaetsbewertung fuer einen Datenstrom durch.

        Args:
            symmetry_score: Symmetrieanteil aus der Analyse-Engine.
            entropy_blocks: Blockweise Entropiekurve.
            entropy_mean: Durchschnittliche Entropie.
            periodicity: Dominante Periodizitaet.
            delta_ratio: Delta-Verhaeltnis.
            healthy_references: Gesunde Referenzstroeme aus der Registry.
        """
        symmetry_component = self._clamp_score(symmetry_score)
        coherence_score = self.compute_coherence_score(entropy_blocks)
        resonance_score = self.compute_resonance_score(
            entropy_mean=entropy_mean,
            symmetry_score=symmetry_component,
            periodicity=periodicity,
            delta_ratio=delta_ratio,
            healthy_references=healthy_references,
        )

        ethics_score = (
            self.w_symmetry * symmetry_component
            + self.w_coherence * coherence_score
            + self.w_resonance * resonance_score
        )
        ethics_score = self._clamp_score(ethics_score)
        state, text = self.integrity_state(ethics_score)
        return EthicsAssessment(
            symmetry_component=symmetry_component,
            coherence_score=coherence_score,
            resonance_score=resonance_score,
            ethics_score=ethics_score,
            integrity_state=state,
            integrity_text=text,
        )
