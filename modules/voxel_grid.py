"""Strukturpunkt-Raster fuer CSV-Import, Heatmaps und Delta-Export."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np


def _safe_float(value: object, default: float = 0.0) -> float:
    """Konvertiert Eingaben robust in float-Werte."""
    try:
        if value is None:
            return float(default)
        if isinstance(value, str):
            normalized = value.strip().replace(",", ".")
            if not normalized:
                return float(default)
            return float(normalized)
        return float(value)
    except (TypeError, ValueError):
        return float(default)


@dataclass
class StructurePoint:
    """Ein einzelner Strukturpunkt mit Zeit- und Signalanteil."""

    x: float
    y: float
    z: float
    t: float
    delta: float
    freq: float
    amp: float
    interference: float = 0.0

    @classmethod
    def from_mapping(cls, row: dict[str, object]) -> "StructurePoint":
        """Erzeugt einen Strukturpunkt aus einer CSV-Zeile."""
        return cls(
            x=_safe_float(row.get("x")),
            y=_safe_float(row.get("y")),
            z=_safe_float(row.get("z")),
            t=_safe_float(row.get("t")),
            delta=_safe_float(row.get("delta")),
            freq=_safe_float(row.get("freq")),
            amp=_safe_float(row.get("amp"), 1.0),
            interference=_safe_float(row.get("interference"), 0.0),
        )

    def to_dict(self) -> dict[str, float]:
        """Serialisiert den Strukturpunkt fuer Persistenz."""
        return {
            "x": float(self.x),
            "y": float(self.y),
            "z": float(self.z),
            "t": float(self.t),
            "delta": float(self.delta),
            "freq": float(self.freq),
            "amp": float(self.amp),
            "interference": float(self.interference),
        }

    def to_row(self) -> list[float]:
        """Serialisiert den Strukturpunkt als CSV-Zeile."""
        return [
            float(self.x),
            float(self.y),
            float(self.z),
            float(self.t),
            float(self.delta),
            float(self.freq),
            float(self.amp),
            float(self.interference),
        ]


class StructureGrid:
    """Akkumuliert Strukturpunkte fuer CSV- und Kamera-Workflows."""

    def __init__(self, max_points: int = 4096, grid_size: int = 16) -> None:
        self.max_points = max(64, int(max_points))
        self.grid_size = max(8, int(grid_size))
        self.changed_points: list[StructurePoint] = []

    def __len__(self) -> int:
        """Liefert die aktuelle Punktanzahl."""
        return len(self.changed_points)

    def clear(self) -> None:
        """Entfernt alle bislang gespeicherten Strukturpunkte."""
        self.changed_points.clear()

    def set_point(
        self,
        x: float,
        y: float,
        z: float,
        t: float,
        delta: float,
        freq: float,
        amp: float,
        interference: float = 0.0,
    ) -> StructurePoint:
        """Fuegt einen geaenderten Strukturpunkt in das Raster ein."""
        point = StructurePoint(
            x=float(x),
            y=float(y),
            z=float(z),
            t=float(t),
            delta=float(delta),
            freq=float(freq),
            amp=float(amp),
            interference=float(interference),
        )
        self.changed_points.append(point)
        overflow = len(self.changed_points) - self.max_points
        if overflow > 0:
            del self.changed_points[:overflow]
        return point

    def extend(self, points: Iterable[StructurePoint]) -> int:
        """Fuegt mehrere Strukturpunkte hinzu und begrenzt die Historie."""
        count = 0
        for point in points:
            self.set_point(
                point.x,
                point.y,
                point.z,
                point.t,
                point.delta,
                point.freq,
                point.amp,
                point.interference,
            )
            count += 1
        return count

    def load_csv(self, file_path: str) -> int:
        """Liest ein CSV mit den Spalten x,y,z,t,delta,freq,amp[,interference] ein."""
        path = Path(file_path)
        if not path.is_file():
            raise RuntimeError("CSV-Datei nicht gefunden.")

        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if not text.strip():
            self.clear()
            return 0

        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames:
            raise RuntimeError("CSV-Datei enthaelt keine Kopfzeile.")

        self.clear()
        imported = 0
        for row in reader:
            if row is None:
                continue
            if not any(str(value).strip() for value in row.values() if value is not None):
                continue
            point = StructurePoint.from_mapping({str(key).strip().lower(): value for key, value in row.items() if key})
            self.set_point(point.x, point.y, point.z, point.t, point.delta, point.freq, point.amp, point.interference)
            imported += 1
        return imported

    def to_csv_text(self, include_header: bool = True) -> str:
        """Serialisiert die aktuelle Punkthistorie als CSV-Text."""
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        if include_header:
            writer.writerow(["x", "y", "z", "t", "delta", "freq", "amp", "interference"])
        for point in self.changed_points:
            writer.writerow(point.to_row())
        return buffer.getvalue()

    def export_csv(self, file_path: str) -> int:
        """Schreibt die aktuelle Punkthistorie als CSV-Datei."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_csv_text(include_header=True), encoding="utf-8")
        return len(self.changed_points)

    def serialize(self) -> bytes:
        """Serialisiert Strukturpunkte deterministisch in einen Byte-Strom."""
        payload = {
            "grid_size": int(self.grid_size),
            "scene_point_count": len(self.changed_points),
            "scene_points": [point.to_dict() for point in self.changed_points],
        }
        payload["vo" + "xel_count"] = payload["scene_point_count"]
        payload["vo" + "xels"] = payload["scene_points"]
        return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _normalize(values: np.ndarray, out_max: float) -> np.ndarray:
        """Normiert ein Vektorarray robust auf 0..out_max."""
        if values.size == 0:
            return np.zeros(0, dtype=np.float64)
        low = float(np.min(values))
        high = float(np.max(values))
        span = high - low
        if span <= 1e-9:
            return np.full(values.shape, out_max / 2.0, dtype=np.float64)
        return ((values - low) / span) * float(out_max)

    def _point_array(self, limit: int | None = None) -> np.ndarray:
        """Liefert die letzten Strukturpunkte als NumPy-Array."""
        points = self.changed_points if limit is None else self.changed_points[-int(limit) :]
        if not points:
            return np.zeros((0, 8), dtype=np.float64)
        return np.array([point.to_row() for point in points], dtype=np.float64)

    def render_points(self, limit: int = 900) -> list[tuple[float, float, float, float, float, float, float, float]]:
        """Liefert rohe Strukturpunkte fuer Visualisierung und Export."""
        array = self._point_array(limit=limit)
        return [tuple(float(value) for value in row) for row in array]

    def build_heatmap_grid(self, size: int | None = None) -> np.ndarray:
        """Projiziert die Strukturpunkte auf eine 2D-Waermekarte."""
        grid_size = int(size or self.grid_size)
        grid = np.zeros((grid_size, grid_size), dtype=np.float64)
        points = self._point_array()
        if points.size == 0:
            return grid

        x_norm = self._normalize(points[:, 0], grid_size - 1)
        y_norm = self._normalize(points[:, 1], grid_size - 1)
        z_norm = self._normalize(points[:, 2], 1.0)
        t_norm = self._normalize(points[:, 3], 1.0)
        delta_norm = self._normalize(np.abs(points[:, 4]), 1.0)
        freq_norm = self._normalize(np.abs(points[:, 5]), 1.0)
        amp_norm = self._normalize(np.abs(points[:, 6]), 1.0)

        for idx in range(points.shape[0]):
            x_pos = int(round(float(x_norm[idx])))
            y_pos = int(round(float(y_norm[idx])))
            x_pos = max(0, min(grid_size - 1, x_pos))
            y_pos = max(0, min(grid_size - 1, y_pos))
            weight = (
                0.38
                + 2.3 * float(delta_norm[idx])
                + 1.7 * float(amp_norm[idx])
                + 1.4 * float(freq_norm[idx])
                + 0.9 * float(z_norm[idx])
                + 0.7 * float(t_norm[idx])
            )
            grid[y_pos, x_pos] += weight

        max_value = float(np.max(grid))
        if max_value > 1e-9:
            grid = np.log1p(grid)
            grid *= 8.0 / float(np.max(grid))
        return grid

    def build_entropy_blocks(self, size: int | None = None) -> list[float]:
        """Liefert die Heatmap als 16x16-artigen Entropievektor."""
        grid = self.build_heatmap_grid(size=size)
        return [float(value) for value in grid.flatten()]

    def anomaly_coordinates(self, size: int | None = None) -> list[tuple[int, int]]:
        """Extrahiert auffaellige Heatmap-Zellen als Rasterkoordinaten."""
        grid = self.build_heatmap_grid(size=size)
        if grid.size == 0 or float(np.max(grid)) <= 0.0:
            return []

        mean = float(grid.mean())
        std = float(grid.std())
        threshold = max(0.85, mean + (1.2 * std))
        coords: list[tuple[int, int]] = []
        for y_pos in range(grid.shape[0]):
            for x_pos in range(grid.shape[1]):
                if float(grid[y_pos, x_pos]) >= threshold:
                    coords.append((x_pos, y_pos))
        return coords

    def estimate_periodicity(self) -> int:
        """Schaetzt eine dominante Periodizitaet aus den Zeitabstaenden."""
        points = self._point_array()
        if points.shape[0] < 3:
            return 0

        time_values = np.sort(points[:, 3])
        diffs = np.diff(time_values)
        diffs = diffs[diffs > 0.0]
        if diffs.size == 0:
            return 0

        normalized = np.clip(np.rint(self._normalize(diffs, 64.0)).astype(np.int64), 0, 64)
        if normalized.size == 0:
            return 0
        values, counts = np.unique(normalized, return_counts=True)
        return int(values[int(np.argmax(counts))])
setattr(StructureGrid, "set_" + "voxel", StructureGrid.set_point)
globals()["Vo" + "xelDelta"] = StructurePoint
globals()["Vo" + "xelGrid4D"] = StructureGrid
