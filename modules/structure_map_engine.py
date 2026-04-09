from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Deterministic structure-map projection for capsule results.

This module converts a capsule result into a stable, shareable structure-map
payload that can be consumed by UI layers without re-implementing layout logic.
"""


import hashlib
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from .analysis_capsule import AnalysisCapsuleResult
from .structure_grid import StructureGrid


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return float(max(low, min(high, value)))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception as e:
        return float(default)


@dataclass
class StructureMapNode:
    node_id: str
    x: float
    y: float
    z: float
    t: float
    delta: float
    freq: float
    amp: float
    interference: float
    anchor_hash: str
    entropy: float
    role: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.node_id),
            "x": round(float(self.x), 12),
            "y": round(float(self.y), 12),
            "z": round(float(self.z), 12),
            "t": round(float(self.t), 12),
            "delta": round(float(self.delta), 12),
            "freq": round(float(self.freq), 12),
            "amp": round(float(self.amp), 12),
            "interference": round(float(self.interference), 12),
            "anchor_hash": str(self.anchor_hash),
            "entropy": round(float(self.entropy), 12),
            "role": str(self.role),
        }


@dataclass
class StructureMapEdge:
    source: str
    target: str
    weight: float
    distance: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": str(self.source),
            "target": str(self.target),
            "weight": round(float(self.weight), 12),
            "distance": round(float(self.distance), 12),
        }


@dataclass
class StructureMapSnapshot:
    region_label: str
    node_count: int
    edge_count: int
    anchor_count: int
    anomaly_count: int
    locked: bool
    trust_score: float
    coherence_score: float
    nodes: List[StructureMapNode]
    edges: List[StructureMapEdge]
    heatmap: List[List[float]]
    scene_points: List[List[float]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "region_label": str(self.region_label),
            "node_count": int(self.node_count),
            "edge_count": int(self.edge_count),
            "anchor_count": int(self.anchor_count),
            "anomaly_count": int(self.anomaly_count),
            "locked": bool(self.locked),
            "trust_score": round(float(self.trust_score), 12),
            "coherence_score": round(float(self.coherence_score), 12),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "heatmap": [[round(float(value), 12) for value in row] for row in self.heatmap],
            "scene_points": [[round(float(value), 12) for value in row] for row in self.scene_points],
        }


class StructureMapEngine:
    """Projects capsule outputs into a reusable deterministic structure map."""

    def __init__(self, grid_size: int = 16, max_points: int = 256) -> None:
        self._grid_size = max(8, int(grid_size))
        self._max_points = max(32, int(max_points))

    def build_from_capsule(self, capsule: AnalysisCapsuleResult) -> StructureMapSnapshot:
        anchors = list(capsule.shared_anchor_pack.get("anchors", []) or [])
        nodes = self._build_nodes(capsule, anchors)
        edges = self._build_edges(nodes)
        grid = StructureGrid(max_points=self._max_points, grid_size=self._grid_size)
        for node in nodes:
            grid.set_point(
                node.x,
                node.y,
                node.z,
                node.t,
                node.delta,
                node.freq,
                node.amp,
                interference=node.interference,
            )
        heatmap = grid.build_heatmap_grid(size=self._grid_size)
        if hasattr(heatmap, "tolist"):
            heatmap = heatmap.tolist()
        scene_points_raw = grid.render_points(limit=self._max_points)
        scene_points = [list(point) for point in scene_points_raw]
        source_hash = str(capsule.envelope.source_hash)
        region_label = "REGION {}-{}".format(source_hash[:4], source_hash[-4:]) if source_hash else "REGION LOCAL"
        return StructureMapSnapshot(
            region_label=region_label,
            node_count=len(nodes),
            edge_count=len(edges),
            anchor_count=len(anchors),
            anomaly_count=len(capsule.anomaly_flags),
            locked=bool(capsule.metrics.trust_score >= 0.68 and capsule.metrics.sce_score >= 0.42),
            trust_score=float(capsule.metrics.trust_score),
            coherence_score=float(capsule.metrics.sce_score),
            nodes=nodes,
            edges=edges,
            heatmap=heatmap,
            scene_points=scene_points,
        )

    def _build_nodes(
        self,
        capsule: AnalysisCapsuleResult,
        anchors: Sequence[Dict[str, Any]],
    ) -> List[StructureMapNode]:
        if anchors:
            return [
                self._node_from_anchor(capsule, anchor, index, len(anchors))
                for index, anchor in enumerate(list(anchors)[:32])
            ]
        return self._fallback_nodes(capsule)

    def _node_from_anchor(
        self,
        capsule: AnalysisCapsuleResult,
        anchor: Dict[str, Any],
        index: int,
        total: int,
    ) -> StructureMapNode:
        anchor_hash = str(anchor.get("anchor_hash", "") or "")
        digest = hashlib.sha256(anchor_hash.encode("utf-8")).digest() if anchor_hash else hashlib.sha256(str(index).encode("utf-8")).digest()
        entropy = _safe_float(anchor.get("entropy", 0.0), 0.0)
        theta = (2.0 * math.pi * float(index)) / float(max(1, total))
        radial = 0.34 + (float(digest[0]) / 255.0) * 0.56
        x = 0.5 + math.cos(theta) * radial * 0.5
        y = 0.5 + math.sin(theta) * radial * 0.5
        z = _clamp(entropy / 8.0)
        t = float(index) / float(max(1, total - 1)) if total > 1 else 0.0
        delta = _clamp(float(capsule.metrics.delta_ratio))
        freq = _clamp(float(capsule.metrics.periodicity))
        amp = _clamp(float(capsule.metrics.trust_score))
        interference = _clamp(float(capsule.metrics.sce_score) - float(capsule.metrics.bayes_confidence), -1.0, 1.0)
        return StructureMapNode(
            node_id=str(anchor.get("anchor_id", "anchor:{}".format(index)) or "anchor:{}".format(index)),
            x=x,
            y=y,
            z=z,
            t=t,
            delta=delta,
            freq=freq,
            amp=amp,
            interference=interference,
            anchor_hash=anchor_hash,
            entropy=entropy,
            role="anchor",
        )

    def _fallback_nodes(self, capsule: AnalysisCapsuleResult) -> List[StructureMapNode]:
        metrics = capsule.metrics
        fallback_specs = [
            ("entropy", 0.16, 0.22, _clamp(metrics.entropy / 8.0), "metric"),
            ("symmetry", 0.78, 0.24, _clamp(metrics.symmetry), "metric"),
            ("coherence", 0.24, 0.78, _clamp(metrics.sce_score), "metric"),
            ("trust", 0.76, 0.76, _clamp(metrics.trust_score), "metric"),
        ]
        nodes: List[StructureMapNode] = []
        for index, (label, x_pos, y_pos, z_pos, role) in enumerate(fallback_specs):
            nodes.append(
                StructureMapNode(
                    node_id=label,
                    x=float(x_pos),
                    y=float(y_pos),
                    z=float(z_pos),
                    t=float(index) / float(max(1, len(fallback_specs) - 1)),
                    delta=_clamp(metrics.delta_ratio),
                    freq=_clamp(metrics.periodicity),
                    amp=_clamp(metrics.trust_score),
                    interference=_clamp(metrics.sce_score - metrics.bayes_confidence, -1.0, 1.0),
                    anchor_hash="",
                    entropy=float(metrics.entropy),
                    role=role,
                )
            )
        return nodes

    def _build_edges(self, nodes: Sequence[StructureMapNode]) -> List[StructureMapEdge]:
        if len(nodes) <= 1:
            return []
        edges: List[StructureMapEdge] = []
        seen = set()
        for index, node in enumerate(nodes):
            neighbor_specs = []
            if index + 1 < len(nodes):
                neighbor_specs.append(nodes[index + 1])
            distances = sorted(
                (
                    self._distance(node, other),
                    other,
                )
                for other in nodes
                if other.node_id != node.node_id
            )
            for _distance, other in distances[:2]:
                neighbor_specs.append(other)
            for other in neighbor_specs:
                key = tuple(sorted((str(node.node_id), str(other.node_id))))
                if key in seen:
                    continue
                seen.add(key)
                distance = self._distance(node, other)
                edges.append(
                    StructureMapEdge(
                        source=str(node.node_id),
                        target=str(other.node_id),
                        weight=1.0 - min(1.0, distance),
                        distance=distance,
                    )
                )
        return edges

    @staticmethod
    def _distance(left: StructureMapNode, right: StructureMapNode) -> float:
        return float(
            math.sqrt(
                ((float(left.x) - float(right.x)) ** 2)
                + ((float(left.y) - float(right.y)) ** 2)
                + ((float(left.z) - float(right.z)) ** 2)
            )
        )