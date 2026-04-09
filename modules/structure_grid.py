"""
Räumlicher Index für Strukturanalyse-Punkte.
Kein Netzwerk, kein I/O. Verwendet von registry.py und structure_map_engine.py.
"""
import math
from collections import deque
from dataclasses import dataclass, field
from typing import List


@dataclass
class StructurePoint:
    x: float          # normiert [0.0, 1.0]
    y: float          # normiert [0.0, 1.0]
    z: float          # normiert [0.0, 1.0] — optional
    label: str        # Beschriftung des Punktes
    anchor_hash: str  # SHA256 des zugehörigen Anchors
    entropy: float    # Shannon H ∈ [0, 8]
    trust_score: float

    def to_dict(self) -> dict:
        return {
            "x": round(self.x, 6),
            "y": round(self.y, 6),
            "z": round(self.z, 6),
            "label": self.label,
            "anchor_hash": self.anchor_hash,
            "entropy": round(self.entropy, 6),
            "trust_score": round(self.trust_score, 6),
        }


class StructureGrid:
    def __init__(self, max_points: int = 1024, grid_size: int = 32):
        self._max_points = max_points
        self._grid_size = grid_size
        self._points: deque = deque()

    def add(self, point: StructurePoint) -> None:
        """Fügt Punkt hinzu. Wenn max_points erreicht: ältesten entfernen (FIFO)."""
        if len(self._points) >= self._max_points:
            self._points.popleft()
        self._points.append(point)

    def query_radius(self, x: float, y: float, radius: float) -> List[StructurePoint]:
        """Gibt alle Punkte zurück deren euklidische Distanz zu (x, y) <= radius."""
        result = []
        r2 = radius * radius
        for p in self._points:
            dx = p.x - x
            dy = p.y - y
            if dx * dx + dy * dy <= r2:
                result.append(p)
        return result

    def nearest(self, x: float, y: float, n: int = 5) -> List[StructurePoint]:
        """Gibt die n nächsten Punkte zurück, sortiert nach Distanz aufsteigend."""
        def dist2(p: StructurePoint) -> float:
            return (p.x - x) ** 2 + (p.y - y) ** 2

        sorted_points = sorted(self._points, key=dist2)
        return sorted_points[:n]

    def to_dict(self) -> dict:
        return {
            "points": [p.to_dict() for p in self._points],
            "grid_size": self._grid_size,
            "max_points": self._max_points,
            "count": len(self._points),
        }

    def clear(self) -> None:
        """Leert das Gitter."""
        self._points.clear()

    def set_point(
        self,
        x: float,
        y: float,
        z: float,
        t: float = 0.0,
        delta: float = 0.0,
        freq: float = 0.0,
        amp: float = 0.0,
        *,
        interference: float = 0.0,
        label: str = "",
        anchor_hash: str = "",
        entropy: float = 0.0,
        trust_score: float = 0.0,
    ) -> None:
        """Kompatibilitäts-API: erstellt einen StructurePoint und ruft add() auf."""
        point = StructurePoint(
            x=float(x),
            y=float(y),
            z=float(z),
            label=label or f"p{len(self._points)}",
            anchor_hash=anchor_hash,
            entropy=entropy if entropy > 0.0 else float(z) * 8.0,
            trust_score=trust_score if trust_score > 0.0 else float(amp),
        )
        self.add(point)

    def build_heatmap_grid(self, size: int = 16):
        """Erstellt ein 2D-Dichte-Grid als Liste von Listen (size x size)."""
        n = max(4, int(size))
        grid = [[0.0] * n for _ in range(n)]
        for p in self._points:
            col = min(n - 1, int(p.x * n))
            row = min(n - 1, int(p.y * n))
            grid[row][col] += 1.0
        # Normalisieren auf [0, 1]
        max_val = max((cell for row in grid for cell in row), default=1.0) or 1.0
        return [[cell / max_val for cell in row] for row in grid]

    def render_points(self, limit: int = 256) -> List[List[float]]:
        """Gibt Punkte als Liste von [x, y, z, entropy, trust_score] zurück."""
        result = []
        for p in list(self._points)[-limit:]:
            result.append([p.x, p.y, p.z, p.entropy, p.trust_score])
        return result
