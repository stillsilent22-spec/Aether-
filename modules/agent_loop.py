"""Steuernder Agent-Loop fuer sparse Clusterbereiche im Embeddingraum."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass
class AgentDirective:
    """Beschreibt die aktuelle Agent-Anweisung fuer die Kameraansicht."""

    instruction: str
    resolved_flash: bool
    resolved_count: int
    target_cluster: int | None


class AgentLoopEngine:
    """Leitet visuelle Suchanweisungen aus Vault-Clustern und Coverage-Luecken ab."""

    def __init__(self) -> None:
        self._last_instruction_update = 0.0
        self._last_resolved_until = 0.0
        self._current_instruction = ""
        self._target_cluster: int | None = None
        self._target_vector = np.zeros(3, dtype=np.float64)
        self.resolved_count = 0

    def reset(self) -> None:
        """Setzt den Agentenzustand zurueck."""
        self._last_instruction_update = 0.0
        self._last_resolved_until = 0.0
        self._current_instruction = ""
        self._target_cluster = None
        self._target_vector = np.zeros(3, dtype=np.float64)
        self.resolved_count = 0

    def update(
        self,
        vault_entries: Sequence[dict[str, object]],
        current_embedding: Sequence[float],
        active: bool,
    ) -> AgentDirective:
        """Bestimmt die aktuelle Steueranweisung und prueft Clusterauflosung."""
        if not active:
            return AgentDirective("", False, self.resolved_count, None)

        now = time.time()
        if now - self._last_instruction_update >= 2.0 or not self._current_instruction:
            self._choose_target_cluster(vault_entries)
            self._last_instruction_update = now

        resolved = self._check_resolution(current_embedding)
        if resolved:
            self.resolved_count += 1
            self._last_resolved_until = now + 1.0

        if now <= self._last_resolved_until:
            return AgentDirective("CLUSTER RESOLVED \u2713", True, self.resolved_count, self._target_cluster)
        return AgentDirective(self._current_instruction, False, self.resolved_count, self._target_cluster)

    def _choose_target_cluster(self, vault_entries: Sequence[dict[str, object]]) -> None:
        """Waehlt den Cluster mit der groessten internen Varianz."""
        clusters: dict[str, list[np.ndarray]] = {}
        for entry in vault_entries:
            label = str(entry.get("cluster_label", "TRANSITIONAL"))
            embedding = entry.get("embedding_vector", [])
            if not embedding:
                continue
            vector = np.array(list(embedding)[:3], dtype=np.float64)
            clusters.setdefault(label, []).append(vector)

        if not clusters:
            self._current_instruction = ""
            self._target_cluster = None
            self._target_vector = np.zeros(3, dtype=np.float64)
            return

        best_label = None
        best_variance = -1.0
        best_vectors: list[np.ndarray] = []
        for label, vectors in clusters.items():
            data = np.vstack(vectors)
            variance = float(np.mean(np.var(data, axis=0)))
            if variance > best_variance:
                best_variance = variance
                best_label = label
                best_vectors = vectors

        assert best_label is not None
        self._target_cluster = {"HARMONIC": 0, "TRANSITIONAL": 1, "CHAOTIC": 2}.get(best_label, 1)
        data = np.vstack(best_vectors)
        centroid = np.mean(data, axis=0)
        spread = np.var(data, axis=0)
        sparse_axis = int(np.argmax(spread))
        direction = 1.0 if float(centroid[sparse_axis]) < 0.0 else -1.0
        self._target_vector = np.array(centroid, copy=True)
        self._target_vector[sparse_axis] += 0.35 * direction
        if sparse_axis == 0:
            self._current_instruction = "ZEIG MIR: Textur"
        elif sparse_axis == 1:
            self._current_instruction = "ZEIG MIR: Flaeche"
        else:
            self._current_instruction = "ZEIG MIR: Kante"

    def _check_resolution(self, current_embedding: Sequence[float]) -> bool:
        """Prueft, ob die aktuelle Beobachtung die Zielregion fuellt."""
        if not self._current_instruction:
            return False
        vector = np.array(list(current_embedding)[:3], dtype=np.float64)
        distance = float(np.linalg.norm(vector - self._target_vector))
        return bool(distance <= 0.18)
