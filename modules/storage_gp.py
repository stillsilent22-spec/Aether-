"""Deterministische GP-Entscheidungen fuer den lokalen Dual-Mode-Storage."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any


@dataclass
class DualModeStorageDecision:
    """Beschreibt die lokale GP-Empfehlung fuer Rohdatenhaltung."""

    recommend_store_raw: bool
    recommend_reconstruction: bool
    unusual_delta: bool
    recommend_validation: bool
    gp_score: float
    rationale: str
    gp_rules: list[str]
    evolution_path: list[dict[str, Any]]
    metrics: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entscheidung fuer lokale Payloads."""
        return {
            "recommend_store_raw": bool(self.recommend_store_raw),
            "recommend_reconstruction": bool(self.recommend_reconstruction),
            "unusual_delta": bool(self.unusual_delta),
            "recommend_validation": bool(self.recommend_validation),
            "gp_score": float(self.gp_score),
            "rationale": str(self.rationale),
            "gp_rules": [str(item) for item in self.gp_rules],
            "evolution_path": [dict(item) for item in self.evolution_path],
            "metrics": {str(key): float(value) for key, value in self.metrics.items()},
        }


class DualModeStorageEngine:
    """Evolviert lokale Storage-Regeln nur aus Strukturmetriken."""

    FEATURES = (
        "delta_ratio",
        "entropy_mean",
        "symmetry",
        "periodicity",
        "coherence",
        "resonance",
        "h_lambda",
        "knowledge",
        "file_size",
        "kolmogorov",
        "benford",
        "encryption",
    )
    OPERATORS = ("avg", "min", "max", "mix", "contrast")

    def __init__(self, session_seed: int) -> None:
        self.session_seed = int(session_seed) & 0xFFFFFFFF
        self.population_size = 24
        self.generations = 10
        self.elite_count = 6

    @staticmethod
    def _clamp(value: float) -> float:
        return float(max(0.0, min(1.0, value)))

    def _feature_vector(self, fingerprint: Any) -> dict[str, float]:
        beauty_signature = dict(getattr(fingerprint, "beauty_signature", {}) or {})
        file_size = float(getattr(fingerprint, "file_size", 0) or 0.0)
        return {
            "delta_ratio": self._clamp(float(getattr(fingerprint, "delta_ratio", 0.0) or 0.0)),
            "entropy_mean": self._clamp(float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0) / 8.0),
            "symmetry": self._clamp(float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0) / 100.0),
            "periodicity": self._clamp(float(getattr(fingerprint, "periodicity", 0.0) or 0.0) / 256.0),
            "coherence": self._clamp(float(getattr(fingerprint, "coherence_score", 0.0) or 0.0) / 100.0),
            "resonance": self._clamp(float(getattr(fingerprint, "resonance_score", 0.0) or 0.0) / 100.0),
            "h_lambda": self._clamp(float(getattr(fingerprint, "h_lambda", 0.0) or 0.0) / 8.0),
            "knowledge": self._clamp(float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0)),
            "file_size": self._clamp(math.log2(max(2.0, file_size + 1.0)) / 22.0),
            "kolmogorov": self._clamp(float(beauty_signature.get("kolmogorov_k", 0.0) or 0.0)),
            "benford": self._clamp(float(beauty_signature.get("benford_b", 0.0) or 0.0)),
            "encryption": self._clamp(float(beauty_signature.get("encryption_flag", 0.0) or 0.0)),
        }

    def _target_score(self, fingerprint: Any, features: dict[str, float]) -> float:
        """Verdichtet lokale Strukturregeln zu einem GP-Ziel ohne Rohdatenzugriff."""
        source_is_file = 1.0 if str(getattr(fingerprint, "source_type", "file")) == "file" else 0.0
        compressed_pressure = max(features["delta_ratio"], 1.0 - features["kolmogorov"])
        structural_uncertainty = (
            (0.38 * compressed_pressure)
            + (0.16 * (1.0 - features["coherence"]))
            + (0.12 * (1.0 - features["resonance"]))
            + (0.12 * (1.0 - features["symmetry"]))
            + (0.12 * features["h_lambda"])
            + (0.10 * features["encryption"])
        )
        size_bias = 0.30 + (0.70 * features["file_size"])
        return self._clamp(source_is_file * structural_uncertainty * size_bias)

    def _random_leaf(self, rng: random.Random) -> dict[str, Any]:
        if rng.random() < 0.22:
            return {"kind": "const", "value": round(rng.uniform(0.0, 1.0), 4)}
        return {"kind": "feature", "name": rng.choice(self.FEATURES)}

    def _random_tree(self, rng: random.Random, depth: int = 0) -> dict[str, Any]:
        if depth >= 2 or rng.random() < 0.38:
            return self._random_leaf(rng)
        return {
            "kind": "op",
            "name": rng.choice(self.OPERATORS),
            "left": self._random_tree(rng, depth + 1),
            "right": self._random_tree(rng, depth + 1),
        }

    def _mutate(self, rng: random.Random, tree: dict[str, Any], rate: float = 0.18) -> dict[str, Any]:
        if rng.random() < rate:
            return self._random_tree(rng)
        node = dict(tree)
        if node.get("kind") == "op":
            node["left"] = self._mutate(rng, dict(node["left"]), rate)
            node["right"] = self._mutate(rng, dict(node["right"]), rate)
            if rng.random() < rate:
                node["name"] = rng.choice(self.OPERATORS)
        elif node.get("kind") == "feature" and rng.random() < rate:
            node["name"] = rng.choice(self.FEATURES)
        elif node.get("kind") == "const" and rng.random() < rate:
            node["value"] = round(rng.uniform(0.0, 1.0), 4)
        return node

    def _crossover(self, rng: random.Random, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
        if left.get("kind") != "op" or right.get("kind") != "op":
            return dict(rng.choice([left, right]))
        return {
            "kind": "op",
            "name": rng.choice([left.get("name", "avg"), right.get("name", "avg")]),
            "left": dict(rng.choice([left["left"], right["left"]])),
            "right": dict(rng.choice([left["right"], right["right"]])),
        }

    def _eval_tree(self, tree: dict[str, Any], features: dict[str, float]) -> float:
        kind = str(tree.get("kind", "feature"))
        if kind == "feature":
            return self._clamp(float(features.get(str(tree.get("name", "")), 0.0)))
        if kind == "const":
            return self._clamp(float(tree.get("value", 0.0) or 0.0))
        left = self._eval_tree(dict(tree.get("left", {})), features)
        right = self._eval_tree(dict(tree.get("right", {})), features)
        name = str(tree.get("name", "avg"))
        if name == "min":
            return min(left, right)
        if name == "max":
            return max(left, right)
        if name == "mix":
            return self._clamp((0.65 * left) + (0.35 * right))
        if name == "contrast":
            return self._clamp(abs(left - right))
        return self._clamp((left + right) / 2.0)

    def _tree_depth(self, tree: dict[str, Any]) -> int:
        if str(tree.get("kind", "")) != "op":
            return 1
        return 1 + max(self._tree_depth(dict(tree.get("left", {}))), self._tree_depth(dict(tree.get("right", {}))))

    def _fitness(self, score: float, target: float, tree: dict[str, Any]) -> float:
        penalty = 0.03 * max(0, self._tree_depth(tree) - 2)
        return 1.0 - abs(score - target) - penalty

    def _tree_text(self, tree: dict[str, Any]) -> str:
        kind = str(tree.get("kind", "feature"))
        if kind == "feature":
            return str(tree.get("name", "x"))
        if kind == "const":
            return f"{float(tree.get('value', 0.0) or 0.0):.2f}"
        left = self._tree_text(dict(tree.get("left", {})))
        right = self._tree_text(dict(tree.get("right", {})))
        name = str(tree.get("name", "avg"))
        if name == "avg":
            return f"avg({left}, {right})"
        if name == "mix":
            return f"mix({left}, {right})"
        if name == "contrast":
            return f"contrast({left}, {right})"
        return f"{name}({left}, {right})"

    def evaluate(self, fingerprint: Any) -> DualModeStorageDecision:
        """Evolviert eine lokale Empfehlung nur aus Strukturmetriken."""
        file_hash = str(getattr(fingerprint, "file_hash", "0" * 8))
        seed_part = int(file_hash[:8], 16) if len(file_hash) >= 8 else 0
        rng = random.Random(self.session_seed ^ seed_part)
        features = self._feature_vector(fingerprint)
        target = self._target_score(fingerprint, features)
        population = [self._random_tree(rng) for _ in range(self.population_size)]
        evolution_path: list[dict[str, Any]] = []
        latest_scored: list[tuple[float, float, dict[str, Any]]] = []

        for generation in range(self.generations):
            latest_scored = []
            for tree in population:
                value = self._eval_tree(tree, features)
                latest_scored.append((self._fitness(value, target, tree), value, tree))
            latest_scored.sort(key=lambda item: item[0], reverse=True)
            leader = latest_scored[0]
            if generation == 0 or generation == self.generations - 1 or generation % 3 == 0:
                evolution_path.append(
                    {
                        "generation": int(generation),
                        "fitness": float(max(0.0, leader[0])),
                        "score": float(leader[1]),
                        "rule": self._tree_text(leader[2]),
                    }
                )
            elites = [dict(item[2]) for item in latest_scored[: self.elite_count]]
            new_population = list(elites)
            while len(new_population) < self.population_size:
                parent_a = dict(rng.choice(elites))
                parent_b = dict(rng.choice(elites))
                child = self._crossover(rng, parent_a, parent_b)
                new_population.append(self._mutate(rng, child))
            population = new_population[: self.population_size]

        best_fitness, best_score, best_tree = latest_scored[0]
        top_rules = [self._tree_text(item[2]) for item in latest_scored[:3]]
        unusual_delta = bool(
            features["delta_ratio"] >= 0.92
            or (features["delta_ratio"] >= 0.82 and features["kolmogorov"] <= 0.18)
        )
        recommend_validation = bool(
            unusual_delta
            or features["encryption"] >= 0.5
            or best_score >= 0.62
        )
        recommend_store_raw = bool(
            str(getattr(fingerprint, "source_type", "file")) == "file"
            and (best_score >= 0.58 or recommend_validation)
        )
        recommend_reconstruction = bool(
            recommend_validation
            or features["knowledge"] >= 0.72
            or features["h_lambda"] <= 0.22
        )
        rationale = (
            f"GP {self._tree_text(best_tree)} | Ziel {target:.2f} | "
            f"Delta {features['delta_ratio']:.2f} | K {features['kolmogorov']:.2f}"
        )
        return DualModeStorageDecision(
            recommend_store_raw=recommend_store_raw,
            recommend_reconstruction=recommend_reconstruction,
            unusual_delta=unusual_delta,
            recommend_validation=recommend_validation,
            gp_score=float(max(0.0, min(1.0, best_score))),
            rationale=rationale,
            gp_rules=top_rules,
            evolution_path=evolution_path,
            metrics=features,
        )
