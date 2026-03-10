"""Mehrschichtige Struktur- und Geometrieanalyse fuer lokale Dateien."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

try:
    from fontTools.ttLib import TTFont
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    TTFont = None


def _anchor_key(value: float) -> str:
    return f"{float(value):.12f}"


def _dedupe_sorted(values: list[float], limit: int = 256) -> list[float]:
    seen: set[str] = set()
    ordered: list[float] = []
    for value in sorted(float(item) for item in values):
        key = _anchor_key(value)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(float(value))
        if len(ordered) >= limit:
            break
    return ordered


def _bounded_ratio(numerator: float, denominator: float) -> float:
    if abs(float(denominator)) <= 1e-12:
        return math.copysign(8.0, float(numerator) if float(numerator) != 0.0 else 1.0)
    return float(max(-8.0, min(8.0, float(numerator) / float(denominator))))


@dataclass
class GeometryScanResult:
    file: str
    source_kind: str
    geometry_anchors: list[float]
    metrics: dict[str, Any]
    notes: list[str]

    @property
    def anchor_keys(self) -> list[str]:
        return [_anchor_key(value) for value in self.geometry_anchors]

    def to_payload(self) -> dict[str, Any]:
        return {
            "file": str(self.file),
            "source_kind": str(self.source_kind),
            "geometry_anchor_count": int(len(self.geometry_anchors)),
            "geometry_anchors": [_anchor_key(value) for value in self.geometry_anchors],
            "metrics": dict(self.metrics),
            "notes": list(self.notes),
        }


class DeepScanEngine:
    """Leitet geometrische Strukturanker aus Fonts oder allgemeinen Binaerdaten ab."""

    def __init__(self, max_geometry_anchors: int = 256) -> None:
        self.max_geometry_anchors = max(32, int(max_geometry_anchors))

    def scan_file(self, file_path: str) -> GeometryScanResult:
        path = Path(file_path)
        raw = path.read_bytes()
        suffix = path.suffix.lower()
        if suffix in {".ttf", ".otf"}:
            result = self._scan_font_geometry(path)
            if result is not None:
                return result
        return self._scan_binary_geometry(path, raw)

    def _scan_font_geometry(self, path: Path) -> GeometryScanResult | None:
        if TTFont is None:
            return GeometryScanResult(
                file=str(path),
                source_kind="font_missing_dependency",
                geometry_anchors=[],
                metrics={"fonttools_available": False},
                notes=["fonttools dependency unavailable"],
            )
        try:
            font = TTFont(str(path), recalcBBoxes=False, recalcTimestamp=False)
        except Exception as exc:
            return GeometryScanResult(
                file=str(path),
                source_kind="font_parse_failed",
                geometry_anchors=[],
                metrics={"fonttools_available": True},
                notes=[str(exc)],
            )

        anchors: list[float] = []
        notes: list[str] = []
        metrics: dict[str, Any] = {"fonttools_available": True}
        units_per_em = 1.0
        try:
            units_per_em = float(getattr(font["head"], "unitsPerEm", 1000) or 1000.0)
        except Exception:
            units_per_em = 1000.0
        metrics["units_per_em"] = float(units_per_em)

        os2 = font["OS/2"] if "OS/2" in font else None
        if os2 is not None:
            for attr, metric_name in (
                ("sxHeight", "x_height_ratio"),
                ("sCapHeight", "cap_height_ratio"),
                ("sTypoAscender", "ascender_ratio"),
            ):
                value = float(getattr(os2, attr, 0.0) or 0.0)
                if value > 0.0:
                    ratio = float(value / max(1.0, units_per_em))
                    anchors.append(ratio)
                    metrics[metric_name] = round(ratio, 12)

        if "glyf" in font:
            glyf_table = font["glyf"]
            width_ratios: list[float] = []
            angle_values: list[float] = []
            for glyph_name in sorted(font.getGlyphOrder())[:96]:
                try:
                    glyph = glyf_table[glyph_name]
                    if getattr(glyph, "isComposite", lambda: False)():
                        continue
                    coordinates, _end_pts, _flags = glyph.getCoordinates(glyf_table)
                except Exception:
                    continue
                if len(coordinates) < 2:
                    continue
                x_values = [float(point[0]) for point in coordinates]
                y_values = [float(point[1]) for point in coordinates]
                width = max(x_values) - min(x_values)
                height = max(y_values) - min(y_values)
                if width > 0.0:
                    width_ratios.append(float(width / max(1.0, units_per_em)))
                if height > 0.0:
                    width_ratios.append(float(height / max(1.0, units_per_em)))
                for left, right in zip(coordinates[:-1], coordinates[1:]):
                    dx = float(right[0] - left[0])
                    dy = float(right[1] - left[1])
                    if abs(dx) <= 1e-9 and abs(dy) <= 1e-9:
                        continue
                    angle_values.append(float(math.atan2(dy, dx)))
                    if len(angle_values) >= self.max_geometry_anchors:
                        break
                if len(angle_values) >= self.max_geometry_anchors:
                    break
            anchors.extend(width_ratios[:64])
            anchors.extend(angle_values[: self.max_geometry_anchors])
            metrics["glyph_width_samples"] = int(len(width_ratios))
            metrics["bezier_angle_samples"] = int(len(angle_values))
        else:
            notes.append("glyf table unavailable")

        if "kern" in font:
            kerning_ratios: list[float] = []
            try:
                for table in list(getattr(font["kern"], "kernTables", []) or []):
                    for _pair, value in sorted(dict(getattr(table, "kernTable", {}) or {}).items())[:128]:
                        kerning_ratios.append(float(value) / max(1.0, units_per_em))
                        if len(kerning_ratios) >= 64:
                            break
                    if len(kerning_ratios) >= 64:
                        break
            except Exception:
                kerning_ratios = []
            anchors.extend(kerning_ratios)
            metrics["kerning_ratio_samples"] = int(len(kerning_ratios))

        geometry_anchors = _dedupe_sorted(anchors, limit=self.max_geometry_anchors)
        metrics["geometry_anchor_count"] = int(len(geometry_anchors))
        return GeometryScanResult(
            file=str(path),
            source_kind="font_geometry",
            geometry_anchors=geometry_anchors,
            metrics=metrics,
            notes=notes,
        )

    def _scan_binary_geometry(self, path: Path, raw: bytes) -> GeometryScanResult:
        anchors: list[float] = []
        metrics: dict[str, Any] = {}
        notes: list[str] = []
        relation_counter: Counter[tuple[str, float, float]] = Counter()
        angle_samples = 0

        for endian in ("little", "big"):
            points: list[tuple[int, int]] = []
            limit = min(max(0, len(raw) - 3), 8192)
            for offset in range(0, limit, 4):
                x_val = int.from_bytes(raw[offset : offset + 2], byteorder=endian, signed=True)
                y_val = int.from_bytes(raw[offset + 2 : offset + 4], byteorder=endian, signed=True)
                points.append((int(x_val), int(y_val)))
            for left, right in zip(points[:-1], points[1:]):
                dx = float(right[0] - left[0])
                dy = float(right[1] - left[1])
                if abs(dx) <= 1e-9 and abs(dy) <= 1e-9:
                    continue
                relation_key = (
                    str(endian),
                    round(float(dx) / 64.0, 3),
                    round(float(dy) / 64.0, 3),
                )
                relation_counter[relation_key] += 1
                angle_samples += 1

        for (endian, dx_bin, dy_bin), count in relation_counter.most_common(48):
            dx = float(dx_bin * 64.0)
            dy = float(dy_bin * 64.0)
            anchors.append(float(math.atan2(dy, dx)))
            anchors.append(float(math.log1p(math.hypot(dx, dy))))
            anchors.append(float(_bounded_ratio(dx, dy)))
            if count >= 3:
                anchors.append(float(count))
            notes.append(f"{endian}:{count}")
            if len(anchors) >= self.max_geometry_anchors:
                break

        geometry_anchors = _dedupe_sorted(anchors, limit=self.max_geometry_anchors)
        metrics["relation_patterns"] = int(len(relation_counter))
        metrics["angle_samples"] = int(angle_samples)
        metrics["geometry_anchor_count"] = int(len(geometry_anchors))
        return GeometryScanResult(
            file=str(path),
            source_kind="binary_geometry",
            geometry_anchors=geometry_anchors,
            metrics=metrics,
            notes=notes[:48],
        )

    @staticmethod
    def structural_similarity(anchor_keys: set[str], other_anchor_keys: set[str]) -> float:
        shared = int(len(anchor_keys & other_anchor_keys))
        total = int(len(anchor_keys | other_anchor_keys))
        if shared <= 0 or total <= 0:
            return 0.0
        return float(shared / max(1e-9, math.log(1.0 + float(total))))

    def build_sibling_report(
        self,
        base_anchor_map: dict[str, list[str]],
        geometry_anchor_map: dict[str, list[str]],
    ) -> dict[str, Any]:
        combined_map: dict[str, set[str]] = {}
        geometry_map: dict[str, set[str]] = {}
        for file_name, anchors in base_anchor_map.items():
            combined_map[str(file_name)] = set(str(anchor) for anchor in list(anchors or []))
        for file_name, anchors in geometry_anchor_map.items():
            geometry_set = set(str(anchor) for anchor in list(anchors or []))
            geometry_map[str(file_name)] = geometry_set
            combined_map.setdefault(str(file_name), set()).update(geometry_set)

        siblings: list[dict[str, Any]] = []
        adjacency: defaultdict[str, set[str]] = defaultdict(set)
        file_names = sorted(combined_map.keys())
        for left_file, right_file in combinations(file_names, 2):
            left_set = combined_map.get(left_file, set())
            right_set = combined_map.get(right_file, set())
            similarity = self.structural_similarity(left_set, right_set)
            if similarity <= 0.6:
                continue
            shared_geometry = sorted(
                geometry_map.get(left_file, set()) & geometry_map.get(right_file, set()),
                key=lambda item: float(item),
            )
            siblings.append(
                {
                    "classification": "STRUCTURAL_SIBLINGS",
                    "left_file": str(left_file),
                    "right_file": str(right_file),
                    "semantic_distance": round(float(similarity), 12),
                    "shared_geometry": shared_geometry,
                    "shared_anchor_count": int(len(left_set & right_set)),
                }
            )
            adjacency[left_file].add(right_file)
            adjacency[right_file].add(left_file)

        semantic_clusters: list[dict[str, Any]] = []
        visited: set[str] = set()
        cluster_index = 0
        for file_name in file_names:
            if file_name in visited or not adjacency.get(file_name):
                continue
            cluster_index += 1
            stack = [file_name]
            members: list[str] = []
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                members.append(current)
                for neighbour in sorted(adjacency.get(current, set())):
                    if neighbour not in visited:
                        stack.append(neighbour)
            shared_cluster_geometry = sorted(
                set.intersection(*(geometry_map.get(member, set()) for member in members if geometry_map.get(member, set())))
                if [member for member in members if geometry_map.get(member, set())]
                else set(),
                key=lambda item: float(item),
            )
            semantic_clusters.append(
                {
                    "cluster_id": f"semantic_cluster_{cluster_index:03d}",
                    "members": sorted(members),
                    "shared_geometry": shared_cluster_geometry,
                }
            )

        siblings.sort(
            key=lambda item: (
                -float(item.get("semantic_distance", 0.0) or 0.0),
                str(item.get("left_file", "")),
                str(item.get("right_file", "")),
            )
        )
        return {
            "siblings": siblings,
            "semantic_clusters": semantic_clusters,
        }
