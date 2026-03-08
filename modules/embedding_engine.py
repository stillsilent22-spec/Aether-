"""Cross-Domain-Embeddings fuer anchor-basierte Vault-Vektoren."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .observer_engine import AnchorPoint


@dataclass
class PatternCluster:
    """Beschreibt einen verdichteten Pattern-Cluster."""

    label: str
    variance: float
    members: list[str]


class CrossDomainEmbeddingEngine:
    """Projiziert Ankergeometrien auf einen festen 16D-Sitzungsraum."""

    def __init__(self, session_seed: int) -> None:
        rng = np.random.default_rng(int(session_seed) & 0xFFFFFFFF)
        self.matrix = rng.normal(0.0, 1.0, size=(16, 3)).astype(np.float64)

    @staticmethod
    def _normalize(vector: np.ndarray) -> np.ndarray:
        """Normiert einen Vektor auf Laenge 1."""
        norm = float(np.linalg.norm(vector))
        if norm <= 1e-9:
            return np.zeros_like(vector)
        return vector / norm

    def embedding_from_anchors(self, anchors: Sequence[AnchorPoint]) -> list[float]:
        """Erzeugt einen 16D-Embeddingvektor aus dem Anker-Schwerpunkt."""
        if not anchors:
            return [0.0] * 16
        mean_anchor = np.array(
            [
                float(np.mean([anchor.x for anchor in anchors])),
                float(np.mean([anchor.y for anchor in anchors])),
                float(np.mean([anchor.strength for anchor in anchors])),
            ],
            dtype=np.float64,
        )
        projected = self.matrix @ mean_anchor
        normalized = self._normalize(projected)
        return [float(value) for value in normalized]

    @staticmethod
    def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
        """Berechnet Kosinus-Similaritaet im Embeddingraum."""
        lhs = np.array(left, dtype=np.float64)
        rhs = np.array(right, dtype=np.float64)
        denom = float(np.linalg.norm(lhs) * np.linalg.norm(rhs))
        if denom <= 1e-9:
            return 0.0
        return float(np.dot(lhs, rhs) / denom)

    def kmeans_labels(self, embeddings: list[list[float]], k: int = 3) -> list[int]:
        """Fuehrt deterministisches k-means im Embeddingraum aus."""
        if not embeddings:
            return []
        data = np.array(embeddings, dtype=np.float64)
        k = max(1, min(int(k), len(embeddings)))
        centroids = data[np.linspace(0, len(embeddings) - 1, k, dtype=np.int64)]
        labels = np.zeros(len(embeddings), dtype=np.int64)
        for _ in range(10):
            distances = np.linalg.norm(data[:, None, :] - centroids[None, :, :], axis=2)
            labels = np.argmin(distances, axis=1)
            for index in range(k):
                subset = data[labels == index]
                if subset.size > 0:
                    centroids[index] = np.mean(subset, axis=0)
        return labels.tolist()

    def pattern_found(self, labels: list[int], embeddings: list[list[float]], members: list[str]) -> PatternCluster | None:
        """Findet Cluster mit enger Varianz unter 0.05."""
        if not embeddings or not labels or len(labels) != len(embeddings):
            return None
        data = np.array(embeddings, dtype=np.float64)
        best_cluster: PatternCluster | None = None
        for cluster_id in sorted(set(labels)):
            subset = data[np.array(labels) == cluster_id]
            if subset.shape[0] < 2:
                continue
            variance = float(np.mean(np.var(subset, axis=0)))
            if variance >= 0.05:
                continue
            cluster_members = [members[index] for index, label in enumerate(labels) if label == cluster_id]
            candidate = PatternCluster(
                label=f"PATTERN FOUND #{cluster_id + 1}",
                variance=variance,
                members=cluster_members,
            )
            if best_cluster is None or candidate.variance < best_cluster.variance:
                best_cluster = candidate
        return best_cluster
