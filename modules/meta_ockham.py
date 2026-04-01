from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""meta_ockham.py — Aether Symbiont: Meta-Ockham Razor Engine.

Findet strukturelle Redundanzen, Abstraktions-Inversionen und Twin-Cluster
in beliebigen Signal-Mengen. Wendet das Ockham-Prinzip rein strukturell an:
die einfachere Variante gewinnt — ohne semantische Annahmen.
"""

import math
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from modules.symbiont_core import AetherSymbiont, Signal, StructuralProfile

# ── Konstanten ────────────────────────────────────────────────────────────────

TWIN_SIMILARITY_THRESHOLD   = 0.85    # Cosinus-Ähnlichkeit ≥ 0.85 → Zwilling
ABSTRACTION_OVERHEAD_RATIO  = 1.30    # overhead_ratio > 1.3 → Abstraktions-Inversion
OCKHAM_CONFIDENCE_MIN       = 0.55    # Mindest-Konfidenz für RazorReport-Ausgabe


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class OckhamScore:
    """
    Kombiniertes Ockham-Maß: Complexity / Coherence.

    Niedrige Werte = strukturell einfacher und kohärenter.
    """
    signal_id: str
    complexity: float       # [0, 1]
    coherence: float        # [0, 1]
    razor_score: float      # complexity / max(coherence, 1e-9) — niedriger = besser
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "signal_id":  self.signal_id,
            "complexity": round(self.complexity, 4),
            "coherence":  round(self.coherence, 4),
            "razor_score":round(self.razor_score, 4),
            "timestamp":  self.timestamp,
        }


@dataclass
class TwinCluster:
    """Gruppe strukturell äquivalenter Signale (Cosinus-Ähnlichkeit ≥ 0.85)."""
    cluster_id: str             # Hash der Mitglieder-IDs
    members: List[str]          # signal_id-Liste
    mean_similarity: float      # Mittlere Paarweise Ähnlichkeit
    preferred_member: str       # Strukturell einfachstes Mitglied
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "cluster_id":      self.cluster_id,
            "members":         self.members,
            "mean_similarity": round(self.mean_similarity, 4),
            "preferred_member":self.preferred_member,
            "timestamp":       self.timestamp,
        }


@dataclass
class AbstractionInversion:
    """
    Eine Abstraktions-Inversion: eine Indirektionsschicht hat mehr Komplexität
    als das, was sie abstrahiert (overhead_ratio > 1.3).
    """
    wrapper_id: str
    wrapped_id: str
    overhead_ratio: float         # wrapper_complexity / wrapped_complexity
    description: str

    def to_dict(self) -> dict:
        return {
            "wrapper_id":     self.wrapper_id,
            "wrapped_id":     self.wrapped_id,
            "overhead_ratio": round(self.overhead_ratio, 3),
            "description":    self.description,
        }


@dataclass
class RazorReport:
    """Vollständiger Meta-Ockham-Bericht für eine Menge von Signalen."""
    scores: List[OckhamScore] = field(default_factory=list)
    twin_clusters: List[TwinCluster] = field(default_factory=list)
    abstraction_inversions: List[AbstractionInversion] = field(default_factory=list)
    eliminated_count: int = 0           # Anzahl Signale die vereinfacht werden könnten
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "scores":                 [s.to_dict() for s in self.scores],
            "twin_clusters":          [c.to_dict() for c in self.twin_clusters],
            "abstraction_inversions": [a.to_dict() for a in self.abstraction_inversions],
            "eliminated_count":       self.eliminated_count,
            "confidence":             round(self.confidence, 4),
            "timestamp":              self.timestamp,
        }

    def summary(self) -> str:
        lines = [
            f"[MetaOckham] {len(self.scores)} Signale analysiert | "
            f"Confidence={round(self.confidence, 3)}",
        ]
        if self.twin_clusters:
            for c in self.twin_clusters[:3]:
                lines.append(
                    f"  TwinCluster: {len(c.members)} Mitglieder, "
                    f"preferred='{c.preferred_member}'"
                )
        if self.abstraction_inversions:
            for inv in self.abstraction_inversions[:3]:
                lines.append(
                    f"  AbstractionInversion: overhead={round(inv.overhead_ratio,2)}× "
                    f"wrapper='{inv.wrapper_id}'"
                )
        if self.eliminated_count > 0:
            lines.append(
                f"  {self.eliminated_count} Signale könnten vereinfacht werden."
            )
        return "\n".join(lines)


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class MetaOckhamEngine:
    """
    Wendet den Meta-Ockham-Razor auf beliebige Signalmengen an.

    Keine semantischen Annahmen — nur strukturelle Metriken:
    Entropie, Token-Dichte, Tiefe, Symmetrie, Ähnlichkeit.
    """

    def __init__(self) -> None:
        self._symbiont = AetherSymbiont()

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def score_signal(self, signal: Signal) -> OckhamScore:
        """Berechnet den OckhamScore eines einzelnen Signals."""
        profile = self._symbiont.profile(signal)
        complexity = self._complexity(profile)
        coherence  = self._coherence(profile)
        razor      = complexity / max(coherence, 1e-9)
        return OckhamScore(
            signal_id   = profile.signal_id,
            complexity  = round(complexity, 4),
            coherence   = round(coherence, 4),
            razor_score = round(razor, 4),
        )

    def find_twin_clusters(
        self, signals: List[Signal]
    ) -> list[TwinCluster]:
        """
        Gruppiert strukturell äquivalente Signale (Cosinus-Ähnlichkeit ≥ 0.85).
        Bevorzugt das strukturell einfachste Mitglied als Repräsentant.
        """
        if len(signals) < 2:
            return []

        profiles = [self._symbiont.profile(s) for s in signals]
        feature_vecs = [self._feature_vector(p) for p in profiles]

        # Paarweise Ähnlichkeit
        sim_matrix = [
            [_cosine(feature_vecs[i], feature_vecs[j]) for j in range(len(signals))]
            for i in range(len(signals))
        ]

        # Einfaches Union-Find für Cluster
        parent = list(range(len(signals)))
        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        def union(a: int, b: int) -> None:
            parent[find(a)] = find(b)

        for i in range(len(signals)):
            for j in range(i + 1, len(signals)):
                if sim_matrix[i][j] >= TWIN_SIMILARITY_THRESHOLD:
                    union(i, j)

        # Cluster zusammenfassen
        cluster_map: Dict[int, list[int]] = {}
        for i in range(len(signals)):
            root = find(i)
            cluster_map.setdefault(root, []).append(i)

        clusters: list[TwinCluster] = []
        for indices in cluster_map.values():
            if len(indices) < 2:
                continue
            # Mittlere Ähnlichkeit
            sims = [
                sim_matrix[indices[a]][indices[b]]
                for a in range(len(indices))
                for b in range(a + 1, len(indices))
            ]
            mean_sim = sum(sims) / max(1, len(sims))
            # Bevorzugtes Mitglied: geringstes Complexity-Score
            preferred_idx = min(
                indices, key=lambda i: self._complexity(profiles[i])
            )
            member_ids = [profiles[i].signal_id for i in indices]
            cluster_id = _short_hash("".join(sorted(member_ids)))
            clusters.append(TwinCluster(
                cluster_id      = cluster_id,
                members         = member_ids,
                mean_similarity = round(mean_sim, 4),
                preferred_member= profiles[preferred_idx].signal_id,
            ))
        return clusters

    def detect_abstraction_inversions(
        self,
        wrapper_signal: Signal,
        wrapped_signal: Signal,
    ) -> Optional[AbstractionInversion]:
        """
        Prüft ob wrapper_signal komplexer ist als wrapped_signal
        (overhead_ratio > ABSTRACTION_OVERHEAD_RATIO).
        """
        pw = self._symbiont.profile(wrapper_signal)
        pi = self._symbiont.profile(wrapped_signal)
        c_wrapper = self._complexity(pw)
        c_wrapped  = self._complexity(pi)
        if c_wrapped < 1e-9:
            return None
        ratio = c_wrapper / c_wrapped
        if ratio <= ABSTRACTION_OVERHEAD_RATIO:
            return None
        return AbstractionInversion(
            wrapper_id     = pw.signal_id,
            wrapped_id     = pi.signal_id,
            overhead_ratio = round(ratio, 3),
            description    = (
                f"Wrapper '{pw.signal_id}' ist {round(ratio,2)}× komplexer als "
                f"das Wrapped '{pi.signal_id}' — Abstraktions-Inversion erkannt."
            ),
        )

    def apply_razor(self, signals: List[Signal]) -> RazorReport:
        """
        Führt die vollständige Meta-Ockham-Analyse für eine Signalmenge durch.
        Gibt einen RazorReport zurück.
        """
        if not signals:
            return RazorReport()

        scores  = [self.score_signal(s) for s in signals]
        twins   = self.find_twin_clusters(signals)

        # Abstractions-Inversionen: Benachbarte Paare in der Liste prüfen
        inversions: list[AbstractionInversion] = []
        for i in range(len(signals) - 1):
            inv = self.detect_abstraction_inversions(signals[i], signals[i + 1])
            if inv is not None:
                inversions.append(inv)

        # Anzahl vereinfachbarer Signale
        eliminated = sum(len(c.members) - 1 for c in twins)
        eliminated += len(inversions)

        # Gesamt-Konfidenz
        if scores:
            mean_razor = sum(s.razor_score for s in scores) / len(scores)
            confidence = max(0.0, min(1.0, 1.0 - mean_razor * 0.5))
        else:
            confidence = 0.0

        return RazorReport(
            scores                 = scores,
            twin_clusters          = twins,
            abstraction_inversions = inversions,
            eliminated_count       = eliminated,
            confidence             = round(confidence, 4),
        )

    # ── Interne Metriken ──────────────────────────────────────────────────────

    @staticmethod
    def _complexity(p: StructuralProfile) -> float:
        return (
            p.entropy / 8.0 * 0.4
            + min(1.0, p.token_count / 1000) * 0.3
            + p.structural_depth / max(1, p.structural_depth + 5) * 0.2
            + (1.0 - p.unique_token_ratio) * 0.1
        )

    @staticmethod
    def _coherence(p: StructuralProfile) -> float:
        """
        Kohärenz: Wie intern konsistent ist das Signal?
        Hohe Unique-Ratio + niedrige Entropie = hohe Kohärenz.
        """
        return (
            p.unique_token_ratio * 0.5
            + (1.0 - p.entropy / 8.0) * 0.3
            + p.symmetry * 0.2
        )

    @staticmethod
    def _feature_vector(p: StructuralProfile) -> list[float]:
        """Normierter Feature-Vektor für Cosinus-Ähnlichkeit."""
        return [
            p.entropy / 8.0,
            p.compression_ratio,
            min(1.0, p.token_count / 1000),
            p.unique_token_ratio,
            p.structural_depth / max(1, p.structural_depth + 5),
            p.symmetry,
        ]


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _cosine(a: list[float], b: list[float]) -> float:
    dot   = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    denom = mag_a * mag_b
    return (dot / denom) if denom > 1e-9 else 0.0


def _short_hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:12]
