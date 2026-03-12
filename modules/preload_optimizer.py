"""Adaptive preload recommendations based on vault analysis."""

from __future__ import annotations

import json
import math
import threading
from pathlib import Path
from typing import Any


def _round12(value: float) -> float:
    return round(float(value), 12)


class PreloadOptimizer:
    """Computes logarithmic preload recommendations from anchor statistics."""

    def __init__(
        self,
        vault_analysis_path: str = "data/aelab_vault/vault_analysis.json",
        public_library_path: str = "data/public_anchor_library",
        history_path: str = "data/preload_history.json",
    ) -> None:
        self.vault_analysis_path = Path(vault_analysis_path)
        self.public_library_path = Path(public_library_path)
        self.history_path = Path(history_path)
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def compute_anchor_weights(self, anchor_frequencies: dict[str, int]) -> dict[str, float]:
        counts = {
            str(anchor): max(0, int(count))
            for anchor, count in dict(anchor_frequencies or {}).items()
        }
        if not counts:
            return {}
        max_count = max(counts.values()) if counts else 0
        if max_count <= 0:
            return {anchor: 0.0 for anchor in counts}
        result: dict[str, float] = {}
        for anchor, count in counts.items():
            if count <= 0:
                result[anchor] = 0.0
                continue
            weight = math.log(1.0 + float(count)) / math.log(1.0 + float(max_count))
            try:
                anchor_value = float(anchor)
            except Exception:
                anchor_value = 0.0
            if abs(anchor_value - 3.14159) <= 0.01:
                weight = min(1.0, weight * 1.2)
            result[anchor] = _round12(weight)
        return result

    def score_file_type_priority(self, vault_analysis: dict[str, Any]) -> list[dict[str, Any]]:
        priority_map: dict[str, float] = {}
        reason_map: dict[str, list[str]] = {}
        for pair in list(dict(vault_analysis or {}).get("interference_pairs", []) or []):
            if not isinstance(pair, dict):
                continue
            shared_count = max(0, int(pair.get("shared_count", 0) or 0))
            interference = float(pair.get("interference_score", 0.0) or 0.0)
            if shared_count <= 0 or interference <= 0.0:
                continue
            score = interference * math.log(1.0 + float(shared_count))
            for key in ("left_file", "right_file"):
                ext = Path(str(pair.get(key, "") or "")).suffix.lower()
                if not ext:
                    continue
                priority_map[ext] = float(priority_map.get(ext, 0.0) + score)
                reason_map.setdefault(ext, []).append(
                    f"{Path(str(pair.get('left_file', '') or '')).suffix.lower() or '--'} / "
                    f"{Path(str(pair.get('right_file', '') or '')).suffix.lower() or '--'} "
                    f"| shared {shared_count}"
                )
        ranked = [
            {
                "file_type": str(ext),
                "priority": _round12(score),
                "reason": "; ".join(reason_map.get(ext, [])[:3]) or "Keine dominanten Paare",
            }
            for ext, score in priority_map.items()
        ]
        ranked.sort(key=lambda item: (-float(item["priority"]), str(item["file_type"])))
        return ranked

    def recommend_preloads(self, top_n: int = 5) -> list[dict[str, Any]]:
        analysis = self._load_vault_analysis()
        if not analysis:
            return []
        anchor_frequencies = {
            str(item.get("anchor_value", "")): int(item.get("frequency", 0) or 0)
            for item in list(analysis.get("anchor_frequency_table", []) or [])
            if isinstance(item, dict)
        }
        anchor_weights = self.compute_anchor_weights(anchor_frequencies)
        file_priorities = self.score_file_type_priority(analysis)
        coverage = self._current_coverage(analysis)
        weighted_anchors = sorted(
            anchor_weights.items(),
            key=lambda item: (-float(item[1]), str(item[0])),
        )
        recommendations: list[dict[str, Any]] = []
        for rank, entry in enumerate(file_priorities[: max(1, int(top_n))], start=1):
            preload_anchors = [anchor for anchor, _weight in weighted_anchors[:3]]
            anchor_gap_score = self._anchor_gap_score(analysis, entry["file_type"])
            anchor_count_delta = len(preload_anchors) + int(round(anchor_gap_score * 10.0))
            estimated_gain = self.log_scale_coverage_gain(coverage, anchor_count_delta)
            top_priority = max(1.0, float(file_priorities[0]["priority"])) if file_priorities else 1.0
            log_weight = max(0.0, min(1.0, float(entry["priority"]) / top_priority))
            recommendations.append(
                {
                    "rank": int(rank),
                    "file_type": str(entry["file_type"]),
                    "priority_score": _round12(float(entry["priority"])),
                    "anchor_gap_score": _round12(anchor_gap_score),
                    "payload_hint": self._payload_hint(str(entry["file_type"])),
                    "preload_anchors": preload_anchors,
                    "estimated_coverage_gain": _round12(estimated_gain),
                    "log_weight": _round12(log_weight),
                    "reason": str(entry["reason"]),
                }
            )
        return recommendations

    def log_scale_coverage_gain(self, current_coverage: float, anchor_count_delta: int) -> float:
        history = self._load_history()
        k = self.adaptive_k_factor(history)
        current = max(0.0, min(1.0, float(current_coverage)))
        delta = max(0, int(anchor_count_delta))
        gain = (1.0 - current) * (1.0 - math.exp(-k * math.log(1.0 + float(delta))))
        return _round12(max(0.0, min(1.0, gain)))

    def adaptive_k_factor(self, history: list[dict[str, Any]]) -> float:
        entries = [dict(item) for item in list(history or []) if isinstance(item, dict)]
        total = len(entries)
        successful = sum(
            1
            for item in entries
            if bool(dict(item.get("outcome", {}) or {}).get("coverage_improved", False))
        )
        numerator = math.log(1.0 + float(successful))
        denominator = math.log(2.0 + float(total))
        factor = 0.15 * (1.0 + (numerator / denominator if denominator > 0.0 else 0.0))
        return _round12(max(0.15, factor))

    def record_history(self, entry: dict[str, Any]) -> None:
        payload = dict(entry or {})
        with self._lock:
            history = self._load_history()
            history.append(payload)
            self.history_path.write_text(
                json.dumps(history[-256:], ensure_ascii=True, sort_keys=True, indent=2),
                encoding="utf-8",
            )

    def note_anchor_hit(self, anchor_hash: str, confidence: float) -> None:
        self.record_history(
            {
                "kind": "workflow_anchor_hit",
                "anchor_hash": str(anchor_hash),
                "outcome": {"coverage_improved": float(confidence) >= 0.65},
            }
        )

    def _load_vault_analysis(self) -> dict[str, Any]:
        try:
            return json.loads(self.vault_analysis_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _load_history(self) -> list[dict[str, Any]]:
        try:
            payload = json.loads(self.history_path.read_text(encoding="utf-8"))
        except Exception:
            return []
        return [dict(item) for item in list(payload or []) if isinstance(item, dict)]

    def _current_coverage(self, analysis: dict[str, Any]) -> float:
        anchors = list(analysis.get("anchor_frequency_table", []) or [])
        invariants = list(analysis.get("invariants", []) or [])
        if not anchors:
            return 0.0
        return _round12(min(1.0, float(len(invariants)) / max(1.0, float(len(anchors)))))

    def _anchor_gap_score(self, analysis: dict[str, Any], file_type: str) -> float:
        normalized = str(file_type or "").lower().lstrip(".")
        rare = [
            dict(item)
            for item in list(dict(analysis.get("vault_gaps", {}) or {}).get("rare_anchor_candidates", []) or [])
            if isinstance(item, dict)
        ]
        if not rare:
            return 0.0
        matching = sum(
            1
            for item in rare
            if normalized and normalized in str(item.get("band_label", "") or "").lower()
        )
        return max(0.0, min(1.0, float(max(1, matching)) / max(1.0, float(len(rare)))))

    @staticmethod
    def _payload_hint(file_type: str) -> str:
        hints = {
            ".pdf": "Weitere wissenschaftliche PDFs einspeisen",
            ".json": "Strukturierte JSON-Datensaetze nachladen",
            ".png": "Bildmuster mit wiederkehrenden Texturen vorbereiten",
            ".txt": "Textkorpus fuer Shanway lokal erweitern",
            ".zip": "Archivstrukturen und Manifeste vorbereiten",
        }
        return str(hints.get(str(file_type), "Weitere strukturkompatible Daten lokal vorbereiten"))
