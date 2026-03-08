"""Additive Graph-Feldanalyse fuer lokale AETHER-Attraktoren."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .analysis_engine import AetherFingerprint
from .observer_engine import AnchorPoint
from .session_engine import SessionContext


@dataclass
class GraphFieldSnapshot:
    """Verdichtete Graphmetriken fuer das aktuelle AETHER-Feld."""

    node_count: int
    edge_count: int
    attractor_score: float
    geodesic_energy: float
    phase_transition_score: float
    phase_state: str
    stable_subgraphs: int
    largest_subgraph: int
    stable_component_sizes: list[int]
    benford_aux_score: float
    region_label: str
    region_node_count: int
    confidence_mean: float
    interference_mean: float
    constructive_ratio: float
    destructive_ratio: float


class GraphFieldEngine:
    """Berechnet lokale Regeln, Delta-Propagation und globale Attraktoren."""

    def __init__(self) -> None:
        self._previous_energy: np.ndarray | None = None
        self._collective_feedback: dict[str, object] = {}

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        return float(max(low, min(high, value)))

    def reset(self) -> None:
        """Vergisst die zuletzt beobachtete Energielandschaft."""
        self._previous_energy = None

    def set_collective_feedback(self, feedback: dict[str, object] | None) -> None:
        """Setzt sanfte kollektive Priors fuer Attraktor- und Phasenlage."""
        self._collective_feedback = dict(feedback or {})

    def _fallback_nodes(self, fingerprint: AetherFingerprint, limit: int = 14) -> list[AnchorPoint]:
        """Leitet Knoten aus den staerksten Entropieregionen ab, falls keine Anker existieren."""
        entropy_values = list(getattr(fingerprint, "entropy_blocks", [])[:256])
        if not entropy_values:
            return []
        max_entropy = max(1e-9, max(float(value) for value in entropy_values))
        top_indices = np.argsort(np.array(entropy_values, dtype=np.float64))[::-1][: max(1, int(limit))]
        nodes: list[AnchorPoint] = []
        for index in top_indices.tolist():
            x_pos = index % 16
            y_pos = index // 16
            nodes.append(
                AnchorPoint(
                    x=float(x_pos) / 15.0,
                    y=float(y_pos) / 15.0,
                    strength=self._clamp(float(entropy_values[index]) / max_entropy, 0.0, 1.0),
                )
            )
        return nodes

    def _node_matrix(
        self,
        fingerprint: AetherFingerprint,
        anchors: Sequence[AnchorPoint],
    ) -> np.ndarray:
        """Wandelt Anker in ein kompaktes Knotenarray um."""
        selected = list(anchors) if anchors else self._fallback_nodes(fingerprint)
        if not selected:
            return np.zeros((0, 5), dtype=np.float64)
        return np.array(
            [
                [
                    float(item.x),
                    float(item.y),
                    float(item.strength),
                    float(getattr(item, "confidence", item.strength) or item.strength),
                    float(getattr(item, "interference", 0.0) or 0.0),
                ]
                for item in selected
            ],
            dtype=np.float64,
        )

    def _build_graph(self, nodes: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Erzeugt lokale Kanten auf Basis geodesischer Naehe."""
        count = int(nodes.shape[0])
        weights = np.zeros((count, count), dtype=np.float64)
        lengths = np.full((count, count), np.inf, dtype=np.float64)
        if count <= 1:
            return weights, lengths

        for left in range(count):
            for right in range(left + 1, count):
                dx = float(nodes[left, 0] - nodes[right, 0])
                dy = float(nodes[left, 1] - nodes[right, 1])
                spatial = math.hypot(dx, dy)
                strength_gap = abs(float(nodes[left, 2] - nodes[right, 2]))
                mean_confidence = 0.5 * (float(nodes[left, 3]) + float(nodes[right, 3]))
                interference_bias = 0.5 * (float(nodes[left, 4]) + float(nodes[right, 4]))
                geodesic_length = max(
                    1e-6,
                    spatial
                    + 0.12
                    + (0.28 * strength_gap)
                    + (0.10 * (1.0 - mean_confidence))
                    + (0.18 * max(0.0, -interference_bias))
                    - (0.08 * max(0.0, interference_bias)),
                )
                lengths[left, right] = geodesic_length
                lengths[right, left] = geodesic_length

        neighbor_count = min(4, max(1, count - 1))
        for index in range(count):
            nearest = np.argsort(lengths[index])[:neighbor_count]
            for target in nearest.tolist():
                if target == index or not np.isfinite(lengths[index, target]):
                    continue
                weight = 1.0 / float(lengths[index, target])
                weights[index, target] = max(weights[index, target], weight)
                weights[target, index] = max(weights[target, index], weight)
        return weights, lengths

    def _propagate(self, nodes: np.ndarray, weights: np.ndarray) -> tuple[np.ndarray, list[np.ndarray]]:
        """Propagiert lokale Delta-Energie ueber das geodesische Kantennetz."""
        if int(nodes.shape[0]) <= 0:
            return np.zeros(0, dtype=np.float64), []

        strengths = np.array(nodes[:, 2], dtype=np.float64)
        confidence = np.array(nodes[:, 3], dtype=np.float64)
        interference = np.array(nodes[:, 4], dtype=np.float64)
        bias = np.linspace(1.0, 1.08, num=len(strengths), dtype=np.float64)
        constructive = np.maximum(0.0, interference)
        destructive = np.maximum(0.0, -interference)
        current = np.maximum(
            1e-9,
            strengths
            * (0.55 + (0.45 * confidence))
            * (1.0 + (0.22 * constructive))
            * (1.0 - (0.35 * destructive))
            * bias,
        )
        current = current / max(1e-9, float(np.sum(current)))
        history = [current.copy()]
        degree = np.sum(weights, axis=1)

        for _ in range(6):
            neighbor = current.copy()
            active = degree > 1e-9
            if np.any(active):
                neighbor[active] = np.dot(weights[active], current) / degree[active]
            current = (0.58 * current) + (0.42 * neighbor)
            current = np.maximum(current, 1e-9)
            current = current / max(1e-9, float(np.sum(current)))
            history.append(current.copy())
        return current, history

    def _phase_transition_score(self, energy: np.ndarray) -> float:
        """Misst den Abstand zur zuvor beobachteten Energielandschaft."""
        if self._previous_energy is None:
            self._previous_energy = np.array(energy, dtype=np.float64)
            return 0.0

        current = np.sort(np.array(energy, dtype=np.float64))[::-1]
        previous = np.sort(np.array(self._previous_energy, dtype=np.float64))[::-1]
        size = max(len(current), len(previous))
        padded_current = np.pad(current, (0, max(0, size - len(current))))
        padded_previous = np.pad(previous, (0, max(0, size - len(previous))))
        score = float(np.mean(np.abs(padded_current - padded_previous)))
        self._previous_energy = np.array(energy, dtype=np.float64)
        return score

    def _components(self, mask: np.ndarray, weights: np.ndarray) -> list[int]:
        """Zaehlt stabile Teilgraphen ueber den aktiven Knoten."""
        active_indices = {int(index) for index, value in enumerate(mask.tolist()) if bool(value)}
        if not active_indices:
            return []

        components: list[int] = []
        while active_indices:
            start = active_indices.pop()
            stack = [start]
            size = 1
            while stack:
                current = stack.pop()
                neighbors = np.where(weights[current] > 0.0)[0].tolist()
                for neighbor in neighbors:
                    if neighbor in active_indices:
                        active_indices.remove(int(neighbor))
                        stack.append(int(neighbor))
                        size += 1
            components.append(size)
        components.sort(reverse=True)
        return components

    def _benford_aux_score(self, values: Sequence[float]) -> float:
        """Nutzen Benford nur als schwaches Zusatzsignal, nicht als Clusteringregel."""
        counts = {str(index): 0 for index in range(1, 10)}
        total = 0
        for raw in values:
            magnitude = abs(float(raw))
            if magnitude <= 1e-9:
                continue
            while magnitude < 1.0:
                magnitude *= 10.0
            while magnitude >= 10.0:
                magnitude /= 10.0
            digit = str(int(magnitude))
            if digit in counts:
                counts[digit] += 1
                total += 1
        if total <= 0:
            return 0.0
        expected = {
            str(index): float(math.log10(1.0 + (1.0 / float(index))))
            for index in range(1, 10)
        }
        observed = {digit: float(count) / float(total) for digit, count in counts.items()}
        mad = float(sum(abs(observed[digit] - expected[digit]) for digit in counts) / 9.0)
        return self._clamp(100.0 * (1.0 - (mad / 0.12)), 0.0, 100.0)

    def _region_selector(self, session_context: SessionContext) -> tuple[float, float, float, str]:
        """Leitet eine live Session-Key-Region fuer die Graphnavigation ab."""
        key_material = (
            f"{getattr(session_context, 'live_session_key', '')}|"
            f"{session_context.session_id}|{session_context.seed}"
        ).encode("utf-8")
        digest = hashlib.sha256(key_material).digest()
        center_x = float(digest[0]) / 255.0
        center_y = float(digest[1]) / 255.0
        radius = 0.20 + (float(digest[2]) / 255.0) * 0.18
        label = f"REGION {digest[0] % 8}-{digest[1] % 8}"
        return center_x, center_y, radius, label

    def analyze(
        self,
        fingerprint: AetherFingerprint,
        anchors: Sequence[AnchorPoint],
        session_context: SessionContext,
    ) -> GraphFieldSnapshot:
        """Berechnet Graph-Feldmetriken fuer einen Fingerprint."""
        nodes = self._node_matrix(fingerprint, anchors)
        center_x, center_y, radius, region_label = self._region_selector(session_context)
        if int(nodes.shape[0]) <= 0:
            return GraphFieldSnapshot(
                node_count=0,
                edge_count=0,
                attractor_score=0.0,
                geodesic_energy=0.0,
                phase_transition_score=0.0,
                phase_state="EMERGENT",
                stable_subgraphs=0,
                largest_subgraph=0,
                stable_component_sizes=[],
                benford_aux_score=0.0,
                region_label=region_label,
                region_node_count=0,
                confidence_mean=0.0,
                interference_mean=0.0,
                constructive_ratio=0.0,
                destructive_ratio=0.0,
            )

        weights, lengths = self._build_graph(nodes)
        energy, history = self._propagate(nodes, weights)
        phase_transition = self._phase_transition_score(energy)
        confidence_mean = float(np.mean(nodes[:, 3])) if nodes.shape[1] > 3 else float(np.mean(nodes[:, 2]))
        interference_values = nodes[:, 4] if nodes.shape[1] > 4 else np.zeros(int(nodes.shape[0]), dtype=np.float64)
        interference_mean = float(np.mean(interference_values)) if interference_values.size > 0 else 0.0
        constructive_ratio = float(np.mean(interference_values > 0.05)) if interference_values.size > 0 else 0.0
        destructive_ratio = float(np.mean(interference_values < -0.05)) if interference_values.size > 0 else 0.0
        finite_lengths = lengths[np.isfinite(lengths)]
        edge_count = int(np.count_nonzero(np.triu(weights > 0.0, k=1)))
        mean_lengths = np.where(np.isfinite(lengths), lengths, 0.0)
        degree_count = np.maximum(1, np.count_nonzero(weights > 0.0, axis=1))
        mean_geodesic = np.sum(mean_lengths, axis=1) / degree_count
        geodesic_energy = 100.0 * float(np.sum(energy / np.maximum(0.2, mean_geodesic + 0.2)))

        top_count = min(3, len(energy))
        attractor_core = float(np.sum(np.sort(energy)[::-1][:top_count]))
        stability = 1.0
        if len(history) >= 2:
            stability = 1.0 - float(np.mean(np.abs(history[-1] - history[-2])))
        attractor_score = self._clamp(
            100.0
            * (
                (0.52 * attractor_core)
                + (0.24 * self._clamp(stability, 0.0, 1.0))
                + (0.10 * confidence_mean)
                + (0.08 * constructive_ratio)
                + (0.06 * (1.0 - destructive_ratio))
            ),
            0.0,
            100.0,
        )
        phase_transition = self._clamp(
            float(phase_transition)
            + (0.12 * destructive_ratio)
            - (0.08 * constructive_ratio)
            - (0.05 * max(0.0, interference_mean)),
            0.0,
            1.0,
        )

        graph_feedback = dict(self._collective_feedback.get("graph_feedback", {}) or {})
        if graph_feedback:
            attractor_score = self._clamp(
                (0.88 * attractor_score) + (0.12 * float(graph_feedback.get("attractor_mean", attractor_score) or attractor_score)),
                0.0,
                100.0,
            )
            phase_transition = self._clamp(
                (0.88 * phase_transition)
                + (0.12 * (float(graph_feedback.get("phase_transition_mean", phase_transition * 100.0) or (phase_transition * 100.0)) / 100.0)),
                0.0,
                1.0,
            )
            confidence_mean = self._clamp(
                (0.90 * confidence_mean) + (0.10 * float(graph_feedback.get("confidence_mean", confidence_mean) or confidence_mean)),
                0.0,
                1.0,
            )
            constructive_ratio = self._clamp(
                (0.90 * constructive_ratio) + (0.10 * float(graph_feedback.get("constructive_mean", constructive_ratio) or constructive_ratio)),
                0.0,
                1.0,
            )
            destructive_ratio = self._clamp(
                (0.90 * destructive_ratio) + (0.10 * float(graph_feedback.get("destructive_mean", destructive_ratio) or destructive_ratio)),
                0.0,
                1.0,
            )
            interference_mean = self._clamp(
                (0.90 * interference_mean) + (0.10 * float(graph_feedback.get("interference_mean", interference_mean) or interference_mean)),
                -1.0,
                1.0,
            )

        threshold = float(np.mean(energy) + (0.35 * np.std(energy)))
        active_mask = energy >= max(threshold, float(np.max(energy)) * 0.72)
        component_sizes = self._components(active_mask, weights)
        stable_subgraphs = len([size for size in component_sizes if size >= 2])
        largest_subgraph = max(component_sizes) if component_sizes else (1 if len(energy) else 0)

        region_dist = np.sqrt(((nodes[:, 0] - center_x) ** 2) + ((nodes[:, 1] - center_y) ** 2))
        region_node_count = int(np.count_nonzero(region_dist <= radius))

        benford_values = list((energy * 10_000.0).tolist())
        if finite_lengths.size > 0:
            benford_values.extend((finite_lengths * 1000.0).tolist())
        benford_values.extend((nodes[:, 2] * 1000.0).tolist())
        benford_aux = self._benford_aux_score(benford_values)

        if attractor_score >= 68.0 and phase_transition <= 0.14 and stable_subgraphs >= 1 and destructive_ratio < 0.34:
            phase_state = "ATTRACTOR_LOCK"
        elif phase_transition >= 0.30 or stable_subgraphs <= 0 or destructive_ratio >= 0.45:
            phase_state = "PHASE_SHIFT"
        else:
            phase_state = "EMERGENT"

        return GraphFieldSnapshot(
            node_count=int(nodes.shape[0]),
            edge_count=edge_count,
            attractor_score=round(attractor_score, 1),
            geodesic_energy=round(geodesic_energy, 1),
            phase_transition_score=round(float(phase_transition) * 100.0, 1),
            phase_state=phase_state,
            stable_subgraphs=int(stable_subgraphs),
            largest_subgraph=int(largest_subgraph),
            stable_component_sizes=[int(size) for size in component_sizes],
            benford_aux_score=round(benford_aux, 1),
            region_label=region_label,
            region_node_count=region_node_count,
            confidence_mean=round(confidence_mean, 3),
            interference_mean=round(interference_mean, 3),
            constructive_ratio=round(constructive_ratio, 3),
            destructive_ratio=round(destructive_ratio, 3),
        )
