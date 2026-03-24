"""Deterministic Goedel strange-loop renderer for structural self-observation.

This renderer computes structure metrics for:
  - Level 0: the original input signal
  - Level n>0: the serialized analysis output of level n-1

Stop criteria (Goedel-Stop):
  - convergence: metric delta < 1%
  - depth limit: level >= max_depth
  - cycle: repeated fingerprint
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


class GoedelLoopRenderer:
    """Deterministic structural self-reference renderer with bounded recursion."""

    def __init__(self, convergence_threshold: float = 0.01) -> None:
        self.convergence_threshold = max(0.0, float(convergence_threshold))

    @staticmethod
    def _to_bytes(input_source: Any) -> bytes:
        """Convert supported input to deterministic bytes."""
        if isinstance(input_source, bytes):
            return input_source
        if isinstance(input_source, str):
            path = Path(input_source)
            if path.is_file():
                try:
                    return path.read_bytes()
                except Exception:
                    pass
            return input_source.encode("utf-8", errors="replace")
        if isinstance(input_source, Path):
            if input_source.is_file():
                try:
                    return input_source.read_bytes()
                except Exception:
                    return b""
            return str(input_source).encode("utf-8", errors="replace")
        if isinstance(input_source, (dict, list, tuple)):
            return json.dumps(
                input_source,
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        return str(input_source).encode("utf-8", errors="replace")

    @staticmethod
    def _fingerprint(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for byte_val in data:
            counts[byte_val] = counts.get(byte_val, 0) + 1
        total = float(len(data))
        entropy = 0.0
        for count in counts.values():
            p = float(count) / total
            entropy -= p * math.log2(max(p, 1e-12))
        return float(entropy)

    @staticmethod
    def _periodicity_score(data: bytes) -> float:
        """Simple periodicity proxy in [0,1] based on lag matches."""
        n = len(data)
        if n < 4:
            return 0.0
        best = 0.0
        max_lag = min(64, max(2, n // 3))
        for lag in range(1, max_lag + 1):
            matches = 0
            comparisons = n - lag
            if comparisons <= 0:
                continue
            for i in range(comparisons):
                if data[i] == data[i + lag]:
                    matches += 1
            score = float(matches) / float(comparisons)
            if score > best:
                best = score
        return float(max(0.0, min(1.0, best)))

    @staticmethod
    def _fractal_dimension_proxy(data: bytes) -> float:
        """Box-counting-like proxy over byte occupancy; deterministic in [1,2]."""
        if not data:
            return 1.0
        occupied = len(set(data))
        occupancy = float(occupied) / 256.0
        length_factor = math.log2(float(len(data)) + 1.0) / 16.0
        value = 1.0 + max(0.0, min(1.0, 0.7 * occupancy + 0.3 * length_factor))
        return float(max(1.0, min(2.0, value)))

    def _metrics(self, data: bytes) -> Dict[str, float]:
        return {
            "entropy": self._entropy(data),
            "fractal_dimension": self._fractal_dimension_proxy(data),
            "periodicity": self._periodicity_score(data),
            "size": float(len(data)),
        }

    @staticmethod
    def _analysis_payload(metrics: Dict[str, float], fingerprint: str) -> bytes:
        payload = {
            "metrics": {
                "entropy": round(_safe_float(metrics.get("entropy", 0.0)), 12),
                "fractal_dimension": round(_safe_float(metrics.get("fractal_dimension", 1.0)), 12),
                "periodicity": round(_safe_float(metrics.get("periodicity", 0.0)), 12),
                "size": round(_safe_float(metrics.get("size", 0.0)), 6),
            },
            "fingerprint": str(fingerprint),
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _delta_percent(prev_metrics: Dict[str, float], curr_metrics: Dict[str, float]) -> float:
        keys = ("entropy", "fractal_dimension", "periodicity", "size")
        diffs: List[float] = []
        for key in keys:
            prev = _safe_float(prev_metrics.get(key, 0.0))
            curr = _safe_float(curr_metrics.get(key, 0.0))
            denom = max(abs(prev), 1e-9)
            diffs.append(abs(curr - prev) / denom)
        if not diffs:
            return 0.0
        return float(sum(diffs) / float(len(diffs)) * 100.0)

    def render_with_self_reference(self, input_path: Any, max_depth: int = 3) -> Dict[str, Any]:
        """Run deterministic self-referential rendering until Goedel-Stop."""
        depth_limit = max(0, int(max_depth))
        levels: List[Dict[str, Any]] = []
        seen_fingerprints = set()

        signal = self._to_bytes(input_path)
        stop_reached = False
        stop_reason = ""
        stop_level = 0
        complexity_delta_percent = 0.0

        prev_metrics: Optional[Dict[str, float]] = None

        for level in range(depth_limit + 1):
            metrics = self._metrics(signal)
            fingerprint = self._fingerprint(signal)
            delta_percent = 0.0
            if prev_metrics is not None:
                delta_percent = self._delta_percent(prev_metrics, metrics)

            level_payload = {
                "level": int(level),
                "metrics": {
                    "entropy": float(metrics["entropy"]),
                    "fractal_dimension": float(metrics["fractal_dimension"]),
                    "periodicity": float(metrics["periodicity"]),
                    "size": int(metrics["size"]),
                },
                "fingerprint": str(fingerprint),
                "complexity_delta_percent": float(delta_percent),
            }
            levels.append(level_payload)

            if fingerprint in seen_fingerprints:
                stop_reached = True
                stop_reason = "cycle"
                stop_level = int(level)
                complexity_delta_percent = float(delta_percent)
                break
            seen_fingerprints.add(fingerprint)

            if prev_metrics is not None and delta_percent < (self.convergence_threshold * 100.0):
                stop_reached = True
                stop_reason = "convergence"
                stop_level = int(level)
                complexity_delta_percent = float(delta_percent)
                break

            if level >= depth_limit:
                stop_reached = True
                stop_reason = "max_depth"
                stop_level = int(level)
                complexity_delta_percent = float(delta_percent)
                break

            signal = self._analysis_payload(metrics, fingerprint)
            prev_metrics = metrics

        status = f"Goedel Loop aktiv - Ebene {stop_level} / Stop erreicht"
        stop_message = (
            "Goedel-Stop erreicht - stabile Selbstreferenz auf Ebene "
            f"{stop_level}. Komplexitaets-Delta: {complexity_delta_percent:.2f}%"
        )

        return {
            "levels": levels,
            "stop_reached": bool(stop_reached),
            "stop_reason": str(stop_reason),
            "stop_level": int(stop_level),
            "complexity_delta_percent": float(complexity_delta_percent),
            "status": status,
            "stop_message": stop_message,
            "deterministic": True,
        }


def demo_conway_glider() -> Dict[str, Any]:
    """Small deterministic demo using a classic Conway glider pattern."""
    glider = "\n".join([
        ".#.",
        "..#",
        "###",
    ])
    renderer = GoedelLoopRenderer()
    result = renderer.render_with_self_reference(glider, max_depth=3)
    print(result.get("status", ""))
    print(result.get("stop_message", ""))
    return result


if __name__ == "__main__":
    demo_conway_glider()