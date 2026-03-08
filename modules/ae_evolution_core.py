"""AE-Evolution-Core fuer internen, begrenzten Hintergrundbetrieb."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import random
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def _json_safe(value: Any) -> Any:
    """Normalisiert komplexe Python-Werte fuer stabile Persistenz."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _to_number(value: Any) -> float:
    """Leitet aus heterogenen Werten robust eine numerische Form ab."""
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        if "value" in value:
            return _to_number(value.get("value"))
        if "pi_resonance" in value:
            return _to_number(value.get("pi_resonance"))
        return float(len(value))
    if isinstance(value, (list, tuple, set)):
        return float(len(value))
    try:
        return float(str(value).strip())
    except Exception:
        return float(len(str(value)))


KNOWN_CONSTANTS: dict[str, float] = {
    "PI": math.pi,
    "E": math.e,
    "PHI": (1.0 + math.sqrt(5.0)) / 2.0,
    "LOG2": math.log(2.0),
}

ALLOWED_SPEC_KINDS: set[str] = {
    "extract_index",
    "extract_key",
    "hash_text",
    "constant",
    "sum",
    "legacy_dna",
    "asymmetry_detector",
}

FORBIDDEN_SPEC_KEYS: set[str] = {
    "path",
    "file",
    "filepath",
    "command",
    "cmd",
    "shell",
    "script",
    "url",
    "uri",
    "request",
    "requests",
    "socket",
    "system",
    "process",
    "exe",
    "dll",
    "registry",
    "delete",
    "remove",
    "rename",
    "move",
    "copy",
    "write",
    "import",
    "module",
}

FORBIDDEN_SPEC_TOKENS: tuple[str, ...] = (
    "exec(",
    "eval(",
    "subprocess",
    "powershell",
    "cmd.exe",
    "start-process",
    "shutdown",
    "remove-item",
    "format c:",
    "del /",
    "rm -",
    "http://",
    "https://",
    "ftp://",
    "\\\\",
)


def anchor_numeric_value(anchor: Any) -> float:
    """Leitet aus einem AE-Anker robust einen skalaren Wert ab."""
    payload = anchor
    if isinstance(anchor, dict) and "value" in anchor:
        payload = anchor.get("value")
    if isinstance(payload, dict):
        if "dominant_constant" in payload:
            return float(payload.get("dominant_constant", 0.0) or 0.0)
        if "value" in payload:
            return _to_number(payload.get("value"))
        if "pi_resonance" in payload:
            return float(payload.get("dominant_constant", math.pi) or math.pi)
    return float(_to_number(payload))


def describe_anchor_value(anchor: Any) -> dict[str, Any]:
    """Beschreibt einen skalaren AE-Anker relativ zu bekannten Konstanten."""
    scalar = float(anchor_numeric_value(anchor))
    nearest_label = "PI"
    nearest_value = float(KNOWN_CONSTANTS["PI"])
    nearest_deviation = abs(scalar - nearest_value)
    for label, constant in KNOWN_CONSTANTS.items():
        deviation = abs(scalar - float(constant))
        if deviation < nearest_deviation:
            nearest_label = str(label)
            nearest_value = float(constant)
            nearest_deviation = float(deviation)
    integer_deviation = abs(scalar - round(scalar))
    if integer_deviation <= 0.05:
        type_label = "INTEGER"
    elif nearest_deviation <= 0.05:
        type_label = f"{nearest_label}_LIKE"
    else:
        type_label = "EMERGENT"
    return {
        "value": float(scalar),
        "type_label": str(type_label),
        "nearest_constant": str(nearest_label),
        "nearest_constant_value": float(nearest_value),
        "deviation": float(nearest_deviation),
        "integer_deviation": float(integer_deviation),
    }


def normalize_anchor_entries(anchors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Erweitert rohe AE-Anker um skalare Diagnosefelder fuer GUI, Chain und Audio."""
    normalized: list[dict[str, Any]] = []
    for index, anchor in enumerate(list(anchors)):
        descriptor = describe_anchor_value(anchor)
        normalized.append(
            {
                "index": int(index),
                "value": float(descriptor["value"]),
                "type_label": str(descriptor["type_label"]),
                "nearest_constant": str(descriptor["nearest_constant"]),
                "nearest_constant_value": float(descriptor["nearest_constant_value"]),
                "deviation": float(descriptor["deviation"]),
                "origin": str(anchor.get("origin", "")),
                "anchor_kind": str(anchor.get("type", "")),
                "stability": bool(anchor.get("stability", False)),
                "reproducible": bool(anchor.get("reproducible", False)),
                "hash": str(anchor.get("hash", "")),
                "noether_symmetry": float(anchor.get("noether_symmetry", 0.0) or 0.0),
                "dual_path_agreement": float(anchor.get("dual_path_agreement", 0.0) or 0.0),
                "heisenberg_uncertainty": float(anchor.get("heisenberg_uncertainty", 0.0) or 0.0),
                "vault_posterior_confidence": float(anchor.get("vault_posterior_confidence", 0.0) or 0.0),
                "guard_state": str(anchor.get("guard_state", "")),
                "payload": _json_safe(anchor.get("value")),
            }
        )
    return normalized


class AlgorithmCandidate:
    def __init__(
        self,
        logic: Callable | None = None,
        origin: str = "",
        params: dict[str, Any] | None = None,
        spec: dict[str, Any] | None = None,
    ):
        self.logic = logic
        self.origin = origin
        self.params = dict(params or {})
        self.spec = _json_safe(spec or {})
        self.fitness = 0.0
        self.anchor_points: list[Any] = []
        self.stable = False
        self.reproducible = False
        self.type = "experimental"
        self.source_kind = str(self.params.get("source_kind", "runtime") or "runtime")
        self.bucket = str(self.params.get("bucket", "sub") or "sub")

    def run(self, data: Any) -> Any:
        """Fuehrt den Kandidaten auf Basis des serialisierten Specs aus."""
        if isinstance(self.spec, dict) and self.spec:
            return self._evaluate_spec(self.spec, data)
        return 0

    @classmethod
    def _evaluate_spec(cls, spec: dict[str, Any], data: Any) -> Any:
        kind = str(spec.get("kind", "")).strip().lower()
        if kind == "extract_index":
            index = int(spec.get("index", 0) or 0)
            if isinstance(data, list) and 0 <= index < len(data):
                return data[index]
            return 0
        if kind == "extract_key":
            key = str(spec.get("key", ""))
            if isinstance(data, dict):
                return data.get(key, 0)
            return 0
        if kind == "hash_text":
            if isinstance(data, str):
                return hashlib.sha256(data.encode()).hexdigest()
            return ""
        if kind == "constant":
            return spec.get("value", 0.0)
        if kind == "sum":
            left = cls._evaluate_spec(dict(spec.get("left", {})), data)
            right = cls._evaluate_spec(dict(spec.get("right", {})), data)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            return _to_number(left) + _to_number(right)
        if kind == "legacy_dna":
            constants = [float(item) for item in list(spec.get("constants", []))]
            entropy_mean = float(data.get("entropy_mean", 0.0) or 0.0) if isinstance(data, dict) else 0.0
            h_lambda = float(data.get("h_lambda", 0.0) or 0.0) if isinstance(data, dict) else 0.0
            pi_resonance = 0.0
            dominant_constant = float(constants[0]) if constants else 0.0
            dominant_label = "PI"
            dominant_deviation = abs(dominant_constant - math.pi) if constants else 0.0
            for constant in constants:
                resonance = max(0.0, 1.0 - (abs(float(constant) - math.pi) / 0.25))
                pi_resonance = max(pi_resonance, resonance)
                descriptor = describe_anchor_value(float(constant))
                deviation = float(descriptor["deviation"])
                if deviation < dominant_deviation:
                    dominant_constant = float(constant)
                    dominant_label = str(descriptor["nearest_constant"])
                    dominant_deviation = float(deviation)
            return {
                "legacy_id": str(spec.get("legacy_id", "")),
                "node_count": int(spec.get("node_count", 0) or 0),
                "constant_count": int(spec.get("constant_count", len(constants)) or 0),
                "pi_resonance": float(pi_resonance),
                "dominant_constant": float(dominant_constant),
                "nearest_constant": str(dominant_label),
                "deviation": float(dominant_deviation),
                "entropy_alignment": float(max(0.0, 1.0 - min(1.0, abs(entropy_mean - h_lambda) / 8.0))),
                "source_hash": str(spec.get("source_hash", "")),
            }
        if kind == "asymmetry_detector":
            if not isinstance(data, dict):
                return 0.0
            return {
                "detector_kind": "asymmetry",
                "classification": str(data.get("classification", "")),
                "toxicity_score": float(data.get("toxicity_score", 0.0) or 0.0),
                "asymmetry_score": float(data.get("asymmetry_score", 0.0) or 0.0),
                "noether_symmetry": float(data.get("noether_symmetry", 0.0) or 0.0),
                "coherence_proxy": float(data.get("coherence_proxy", 0.0) or 0.0),
                "entropy_asymmetry": float(data.get("entropy_asymmetry", 0.0) or 0.0),
                "reversibility": float(data.get("reversibility", 0.0) or 0.0),
                "sentence_balance": float(data.get("sentence_balance", 0.0) or 0.0),
                "anchor_alignment": float(data.get("anchor_alignment", 0.0) or 0.0),
                "anchor_constant_value": float(data.get("anchor_constant_value", 0.0) or 0.0),
                "threat_terms": int(data.get("threat_terms", 0) or 0),
                "collective_terms": int(data.get("collective_terms", 0) or 0),
                "dehumanization_terms": int(data.get("dehumanization_terms", 0) or 0),
                "sensitive": bool(data.get("sensitive", False)),
                "blacklisted": bool(data.get("blacklisted", False)),
            }
        return 0

    def signature(self) -> str:
        """Erzeugt eine stabile Signatur fuer Persistenz und Deduplikation."""
        payload = {
            "origin": str(self.origin),
            "spec": _json_safe(self.spec),
            "params": _json_safe(self.params),
            "source_kind": str(self.source_kind),
        }
        return hashlib.sha256(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def to_payload(self, bucket: str | None = None) -> dict[str, Any]:
        """Serialisiert den Kandidaten fuer Registry und Rehydrierung."""
        resolved_bucket = str(bucket or self.bucket or "sub")
        payload = {
            "signature": self.signature(),
            "origin": str(self.origin),
            "bucket": resolved_bucket,
            "type": str(self.type),
            "source_kind": str(self.source_kind),
            "spec": _json_safe(self.spec),
            "params": _json_safe(self.params),
            "fitness": float(self.fitness),
            "stable": bool(self.stable),
            "reproducible": bool(self.reproducible),
            "anchor_points": _json_safe(self.anchor_points),
        }
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "AlgorithmCandidate":
        """Stellt einen Kandidaten aus einem serialisierten Zustand wieder her."""
        params = dict(payload.get("params", {}) or {})
        params.setdefault("bucket", str(payload.get("bucket", "sub")))
        params.setdefault("source_kind", str(payload.get("source_kind", "runtime")))
        candidate = cls(
            logic=None,
            origin=str(payload.get("origin", "")),
            params=params,
            spec=dict(payload.get("spec", {}) or {}),
        )
        candidate.fitness = float(payload.get("fitness", 0.0) or 0.0)
        candidate.stable = bool(payload.get("stable", False))
        candidate.reproducible = bool(payload.get("reproducible", False))
        candidate.type = str(payload.get("type", "experimental") or "experimental")
        candidate.source_kind = str(payload.get("source_kind", "runtime") or "runtime")
        candidate.bucket = str(payload.get("bucket", "sub") or "sub")
        candidate.anchor_points = list(payload.get("anchor_points", []) or [])
        return candidate


class AEAlgorithmVault:
    def __init__(
        self,
        max_main: int = 64,
        max_sub: int = 24,
        max_mutations: int = 12,
        max_hybrids: int = 18,
        export_dir: str | Path | None = None,
    ):
        self.main_vault: list[AlgorithmCandidate] = []
        self.sub_vaults: list[AlgorithmCandidate] = []
        self.max_main = max(8, int(max_main))
        self.max_sub = max(8, int(max_sub))
        self.max_mutations = max(4, int(max_mutations))
        self.max_hybrids = max(4, int(max_hybrids))
        self.export_dir = Path(export_dir) if export_dir is not None else Path("data") / "aelab_vault"
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.legacy_import_dir = self.export_dir / "legacy_imports"
        self.legacy_import_dir.mkdir(parents=True, exist_ok=True)
        self.last_anchor_export_path = ""
        self.current_iteration = 0
        self.current_phase = "idle"
        self.stop_requested = False
        self.last_run_stopped = False
        self.last_stop_iteration = 0
        self.quarantined_total = 0

    def request_stop(self) -> dict[str, Any]:
        """Markiert die laufende oder naechste Evolution zur fruehzeitigen Beendigung."""
        self.stop_requested = True
        self.last_stop_iteration = int(self.current_iteration)
        return {
            "stop_requested": True,
            "current_iteration": int(self.current_iteration),
            "phase": str(self.current_phase),
        }

    def clear_stop_request(self) -> None:
        """Setzt den Stopp-Zustand nach einer beendeten Evolution zurueck."""
        self.stop_requested = False
        self.last_run_stopped = False
        self.last_stop_iteration = 0

    def _mark_iteration(self, phase: str, step: int | None = None) -> None:
        """Aktualisiert die sichtbare Evolutionsphase fuer GUI und Stop-Logik."""
        self.current_phase = str(phase)
        if step is None:
            self.current_iteration = int(self.current_iteration) + 1
        else:
            self.current_iteration = max(0, int(step))

    def _stop_now(self) -> bool:
        """Prueft, ob eine Evolution abgebrochen werden soll."""
        if not self.stop_requested:
            return False
        self.last_run_stopped = True
        self.last_stop_iteration = int(self.current_iteration)
        return True

    @staticmethod
    def _is_abs_windows_path(text: str) -> bool:
        return bool(len(text) > 2 and text[1] == ":" and text[2] in {"\\", "/"})

    def _validate_spec_value(self, value: Any, depth: int = 0) -> bool:
        """Validiert serialisierte Kandidaten strikt auf side-effect-freie Datenformen."""
        if depth > 5:
            return False
        if isinstance(value, (bool, int, float)) or value is None:
            return True
        if isinstance(value, str):
            lowered = value.strip().lower()
            if len(lowered) > 512:
                return False
            if self._is_abs_windows_path(value):
                return False
            if any(token in lowered for token in FORBIDDEN_SPEC_TOKENS):
                return False
            return True
        if isinstance(value, dict):
            if len(value) > 32:
                return False
            kind = str(value.get("kind", "")).strip().lower()
            if kind and kind not in ALLOWED_SPEC_KINDS:
                return False
            for key, item in value.items():
                if str(key).strip().lower() in FORBIDDEN_SPEC_KEYS:
                    return False
                if not self._validate_spec_value(item, depth + 1):
                    return False
            return True
        if isinstance(value, (list, tuple, set)):
            if len(value) > 64:
                return False
            return all(self._validate_spec_value(item, depth + 1) for item in value)
        return False

    def _result_is_safe(self, result: Any, depth: int = 0) -> bool:
        """Begrenzt Ergebnisgroesse und verhindert datenartige Seiteneffekte."""
        if depth > 5:
            return False
        if isinstance(result, (bool, int, float)) or result is None:
            return True
        if isinstance(result, str):
            return len(result) <= 4096 and not self._is_abs_windows_path(result)
        if isinstance(result, dict):
            if len(result) > 64:
                return False
            return all(self._result_is_safe(value, depth + 1) for value in result.values())
        if isinstance(result, (list, tuple, set)):
            if len(result) > 128:
                return False
            return all(self._result_is_safe(item, depth + 1) for item in result)
        return False

    def _quarantine_candidate(self, candidate: AlgorithmCandidate, reason: str) -> None:
        """Nimmt unsichere Kandidaten aus dem aktiven Evolutionspfad."""
        candidate.type = "quarantined"
        candidate.stable = False
        candidate.reproducible = False
        candidate.fitness = 0.0
        candidate.anchor_points = []
        candidate.params["guard_state"] = "QUARANTINED"
        candidate.params["quarantine_reason"] = str(reason)
        candidate.params["vault_posterior_confidence"] = 0.0
        candidate.params["noether_symmetry"] = 0.0
        candidate.params["dual_path_agreement"] = 0.0
        candidate.params["heisenberg_uncertainty"] = 1.0
        self.quarantined_total = int(self.quarantined_total) + 1

    def _candidate_is_safe(self, candidate: AlgorithmCandidate) -> bool:
        """Erlaubt nur whitelist-basierte Specs ohne freie Laufzeitlogik."""
        if candidate.logic is not None:
            self._quarantine_candidate(candidate, "runtime_logic_disabled")
            return False
        if not isinstance(candidate.spec, dict) or not candidate.spec:
            self._quarantine_candidate(candidate, "missing_spec")
            return False
        if not self._validate_spec_value(candidate.spec):
            self._quarantine_candidate(candidate, "unsafe_spec")
            return False
        if not self._validate_spec_value(candidate.params):
            self._quarantine_candidate(candidate, "unsafe_params")
            return False
        return True

    @staticmethod
    def _candidate_signature(candidate: AlgorithmCandidate) -> str:
        return candidate.signature()

    @staticmethod
    def _candidate_score(candidate: AlgorithmCandidate) -> tuple[float, float, float, float, int, int]:
        return (
            float(candidate.fitness),
            float(candidate.params.get("vault_posterior_confidence", 0.0) or 0.0),
            float(candidate.params.get("noether_symmetry", 0.0) or 0.0),
            -float(candidate.params.get("heisenberg_uncertainty", 1.0) or 1.0),
            len(candidate.anchor_points),
            1 if candidate.stable else 0,
        )

    def _project_observation_path(self, value: Any, depth: int = 0) -> Any:
        """Erzeugt einen zweiten, geglaetteten Beobachtungspfad fuer Dual-Path-Tests."""
        if depth >= 3:
            return value
        if isinstance(value, dict):
            projected: dict[str, Any] = {}
            for key, item in list(value.items())[:48]:
                if isinstance(item, bool):
                    projected[str(key)] = bool(item)
                elif isinstance(item, int):
                    projected[str(key)] = int(item)
                elif isinstance(item, float):
                    projected[str(key)] = round(float(item), 4)
                elif isinstance(item, str):
                    projected[str(key)] = " ".join(item.lower().split())[:512]
                elif isinstance(item, list):
                    projected[str(key)] = [self._project_observation_path(entry, depth + 1) for entry in item[:16:2]]
                elif isinstance(item, dict):
                    projected[str(key)] = self._project_observation_path(item, depth + 1)
                else:
                    projected[str(key)] = _json_safe(item)
            return projected
        if isinstance(value, list):
            if not value:
                return []
            return [self._project_observation_path(item, depth + 1) for item in value[:24:2]]
        if isinstance(value, tuple):
            return tuple(self._project_observation_path(item, depth + 1) for item in value[:24:2])
        if isinstance(value, str):
            return " ".join(value.lower().split())[:1024]
        return value

    def _collect_numeric_values(self, value: Any, limit: int = 64) -> list[float]:
        """Extrahiert numerische Werte aus Ergebnissen fuer Guard-Metriken."""
        values: list[float] = []

        def walk(payload: Any) -> None:
            if len(values) >= limit:
                return
            if isinstance(payload, bool):
                values.append(float(int(payload)))
                return
            if isinstance(payload, (int, float)):
                values.append(float(payload))
                return
            if isinstance(payload, dict):
                for item in payload.values():
                    walk(item)
                    if len(values) >= limit:
                        break
                return
            if isinstance(payload, (list, tuple, set)):
                for item in payload:
                    walk(item)
                    if len(values) >= limit:
                        break

        walk(value)
        return values

    def _constant_alignment(self, samples: list[float]) -> float:
        """Misst Naehe eines Zahlenraums zu bekannten Konstanten als weiches Evidenzsignal."""
        if not samples:
            return 0.0
        alignments: list[float] = []
        for sample in list(samples)[:24]:
            best = 0.0
            for constant in KNOWN_CONSTANTS.values():
                best = max(best, max(0.0, 1.0 - (abs(float(sample) - float(constant)) / 1.25)))
            alignments.append(best)
        return float(sum(alignments) / max(1, len(alignments)))

    def _benford_similarity(self, samples: list[float]) -> float | None:
        """Verwendet Benford nur dann, wenn genug numerische Beobachtungen vorliegen."""
        digits = [int(str(abs(sample))[0]) for sample in samples if abs(float(sample)) >= 1.0]
        digits = [digit for digit in digits if 1 <= digit <= 9]
        if len(digits) < 12:
            return None
        counts: dict[int, int] = {}
        for digit in digits:
            counts[digit] = int(counts.get(digit, 0)) + 1
        total = float(len(digits))
        distance = 0.0
        for digit in range(1, 10):
            observed = float(counts.get(digit, 0)) / total
            expected = math.log10(1.0 + (1.0 / float(digit)))
            distance += abs(observed - expected)
        return float(max(0.0, min(1.0, 1.0 - (distance / 2.0))))

    def _result_profile(self, result: Any) -> dict[str, Any]:
        """Reduziert Kandidatenergebnisse auf robuste Strukturinvarianten."""
        numeric = self._collect_numeric_values(result, limit=64)
        kind = type(result).__name__.lower()
        if isinstance(result, (dict, list, tuple, set, str)):
            size = len(result)
        else:
            size = len(str(result))
        scalar = anchor_numeric_value(result)
        numeric_mean = float(sum(numeric) / max(1, len(numeric))) if numeric else float(scalar)
        numeric_spread = float(math.sqrt(sum((value - numeric_mean) ** 2 for value in numeric) / max(1, len(numeric)))) if len(numeric) > 1 else 0.0
        precision = 0.0
        if isinstance(result, float):
            text = f"{float(result):.12f}".rstrip("0").rstrip(".")
            precision = min(1.0, max(0, len(text.split(".")[1]) if "." in text else 0) / 12.0)
        elif isinstance(result, str):
            precision = min(1.0, len(result) / 64.0)
        elif numeric:
            precision = min(1.0, len(numeric) / 24.0)
        shape_bucket = min(8, max(0, int(size // 4)))
        const_align = self._constant_alignment(numeric or [scalar])
        invariant_payload = {
            "kind": str(kind),
            "shape_bucket": int(shape_bucket),
            "size_bucket": int(min(12, max(0, int(size // 8)))),
            "constant_bucket": int(round(const_align * 10.0)),
            "sign": int(math.copysign(1.0, numeric_mean)) if numeric_mean != 0.0 else 0,
        }
        invariant_hash = hashlib.sha256(
            json.dumps(invariant_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "kind": str(kind),
            "shape_bucket": int(shape_bucket),
            "size_norm": float(min(1.0, size / 64.0)),
            "scalar": float(scalar),
            "numeric_mean": float(numeric_mean),
            "numeric_spread": float(min(1.0, numeric_spread / 32.0)),
            "constant_alignment": float(const_align),
            "precision": float(precision),
            "numeric_count": int(len(numeric)),
            "invariant_hash": str(invariant_hash),
            "benford": self._benford_similarity(numeric),
        }

    def _profile_distance(self, left: dict[str, Any], right: dict[str, Any]) -> float:
        """Vergleicht zwei Beobachtungsprofile als weiche Dissonanzmetrik."""
        distance = 0.0
        if str(left.get("kind", "")) != str(right.get("kind", "")):
            distance += 0.35
        if int(left.get("shape_bucket", 0)) != int(right.get("shape_bucket", 0)):
            distance += 0.12
        distance += 0.16 * abs(float(left.get("size_norm", 0.0)) - float(right.get("size_norm", 0.0)))
        distance += 0.16 * abs(float(left.get("constant_alignment", 0.0)) - float(right.get("constant_alignment", 0.0)))
        distance += 0.14 * abs(float(left.get("numeric_spread", 0.0)) - float(right.get("numeric_spread", 0.0)))
        mean_scale = max(1.0, abs(float(left.get("numeric_mean", 0.0))), abs(float(right.get("numeric_mean", 0.0))))
        distance += 0.17 * min(
            1.0,
            abs(float(left.get("numeric_mean", 0.0)) - float(right.get("numeric_mean", 0.0))) / mean_scale,
        )
        scalar_scale = max(1.0, abs(float(left.get("scalar", 0.0))), abs(float(right.get("scalar", 0.0))))
        distance += 0.10 * min(
            1.0,
            abs(float(left.get("scalar", 0.0)) - float(right.get("scalar", 0.0))) / scalar_scale,
        )
        return float(max(0.0, min(1.0, distance)))

    def _govern_candidate(self, candidate: AlgorithmCandidate, primary_result: Any, alternative_result: Any) -> dict[str, float | int | str]:
        """Leitet Governance-Metriken fuer Vault/Subvault aus zwei Beobachtungspfaden ab."""
        primary_profile = self._result_profile(primary_result)
        alternative_profile = self._result_profile(alternative_result)
        profile_distance = self._profile_distance(primary_profile, alternative_profile)
        dual_path_agreement = float(max(0.0, min(1.0, 1.0 - profile_distance)))
        noether_symmetry = float(
            max(
                0.0,
                min(
                    1.0,
                    (0.35 if primary_profile["kind"] == alternative_profile["kind"] else 0.0)
                    + (0.20 if primary_profile["shape_bucket"] == alternative_profile["shape_bucket"] else 0.0)
                    + (0.25 * (1.0 - abs(float(primary_profile["constant_alignment"]) - float(alternative_profile["constant_alignment"]))))
                    + (0.20 * (1.0 - abs(float(primary_profile["size_norm"]) - float(alternative_profile["size_norm"])))),
                ),
            )
        )
        heisenberg_uncertainty = float(
            max(
                0.0,
                min(
                    1.0,
                    profile_distance
                    * (0.70 + (0.60 * max(float(primary_profile["precision"]), float(alternative_profile["precision"])))),
                ),
            )
        )
        usage_count = float(candidate.params.get("usage_count", 0) or 0.0)
        promotion_count = float(candidate.params.get("promotion_count", 0) or 0.0)
        alpha = 1.0 + (0.80 * promotion_count) + (0.40 * min(1.0, usage_count / 24.0)) + (1.10 * noether_symmetry) + (0.95 * dual_path_agreement)
        beta = 1.0 + (1.75 * heisenberg_uncertainty) + max(0.0, 0.65 - noether_symmetry) + max(0.0, 0.60 - dual_path_agreement)
        posterior = float(max(0.0, min(1.0, alpha / max(1e-9, alpha + beta))))
        benford_values = [float(value) for value in self._collect_numeric_values(primary_result, limit=64)]
        benford_values.extend(float(value) for value in self._collect_numeric_values(alternative_result, limit=64))
        benford_score = self._benford_similarity(benford_values)
        if noether_symmetry >= 0.66 and dual_path_agreement >= 0.60 and heisenberg_uncertainty <= 0.34 and posterior >= 0.62:
            guard_state = "MAIN_READY"
        elif noether_symmetry >= 0.34 and dual_path_agreement >= 0.22 and heisenberg_uncertainty <= 0.88:
            guard_state = "SUB_ONLY"
        else:
            guard_state = "REJECTED"
        return {
            "dual_path_agreement": float(dual_path_agreement),
            "noether_symmetry": float(noether_symmetry),
            "heisenberg_uncertainty": float(heisenberg_uncertainty),
            "vault_posterior_confidence": float(posterior),
            "noether_invariant_hash": str(primary_profile["invariant_hash"]) if primary_profile["invariant_hash"] == alternative_profile["invariant_hash"] else "",
            "benford_guard": float(benford_score) if benford_score is not None else -1.0,
            "benford_count": int(len(benford_values)),
            "guard_state": str(guard_state),
        }

    @staticmethod
    def _candidate_ready_for_main(candidate: AlgorithmCandidate) -> bool:
        """Laesst nur strukturell konservierte und hinreichend sichere Kandidaten in den Main-Vault."""
        noether = float(candidate.params.get("noether_symmetry", 0.0) or 0.0)
        dual_path = float(candidate.params.get("dual_path_agreement", 0.0) or 0.0)
        uncertainty = float(candidate.params.get("heisenberg_uncertainty", 1.0) or 1.0)
        posterior = float(candidate.params.get("vault_posterior_confidence", 0.0) or 0.0)
        benford_guard = float(candidate.params.get("benford_guard", -1.0) or -1.0)
        benford_count = int(candidate.params.get("benford_count", 0) or 0)
        benford_ok = True if benford_count < 12 else benford_guard >= 0.35
        return bool(
            noether >= 0.66
            and dual_path >= 0.60
            and uncertainty <= 0.34
            and posterior >= 0.62
            and benford_ok
        )

    def _governance_summary(self, candidates: list[AlgorithmCandidate]) -> dict[str, float | int]:
        """Verdichtet die Kontrollschicht fuer GUI, Vault und Diagnose."""
        if not candidates:
            return {
                "noether_mean": 0.0,
                "heisenberg_mean": 0.0,
                "dual_path_mean": 0.0,
                "posterior_mean": 0.0,
                "benford_mean": 0.0,
                "main_ready": 0,
                "sub_only": 0,
                "rejected": 0,
            }
        noether_values = [float(candidate.params.get("noether_symmetry", 0.0) or 0.0) for candidate in candidates]
        uncertainty_values = [float(candidate.params.get("heisenberg_uncertainty", 1.0) or 1.0) for candidate in candidates]
        dual_values = [float(candidate.params.get("dual_path_agreement", 0.0) or 0.0) for candidate in candidates]
        posterior_values = [float(candidate.params.get("vault_posterior_confidence", 0.0) or 0.0) for candidate in candidates]
        benford_values = [
            float(candidate.params.get("benford_guard", 0.0) or 0.0)
            for candidate in candidates
            if int(candidate.params.get("benford_count", 0) or 0) >= 12 and float(candidate.params.get("benford_guard", -1.0) or -1.0) >= 0.0
        ]
        state_counts = {"MAIN_READY": 0, "SUB_ONLY": 0, "REJECTED": 0}
        for candidate in candidates:
            state = str(candidate.params.get("guard_state", "SUB_ONLY") or "SUB_ONLY")
            if state in state_counts:
                state_counts[state] = int(state_counts[state]) + 1
        return {
            "noether_mean": float(sum(noether_values) / max(1, len(noether_values))),
            "heisenberg_mean": float(sum(uncertainty_values) / max(1, len(uncertainty_values))),
            "dual_path_mean": float(sum(dual_values) / max(1, len(dual_values))),
            "posterior_mean": float(sum(posterior_values) / max(1, len(posterior_values))),
            "benford_mean": float(sum(benford_values) / max(1, len(benford_values))) if benford_values else 0.0,
            "main_ready": int(state_counts["MAIN_READY"]),
            "sub_only": int(state_counts["SUB_ONLY"]),
            "rejected": int(state_counts["REJECTED"]),
            "quarantined_total": int(self.quarantined_total),
        }

    def _prune_sub_vault(self) -> None:
        unique: dict[str, AlgorithmCandidate] = {}
        for candidate in self.sub_vaults:
            signature = self._candidate_signature(candidate)
            existing = unique.get(signature)
            if existing is None or self._candidate_score(candidate) > self._candidate_score(existing):
                unique[signature] = candidate
        ranked = sorted(unique.values(), key=self._candidate_score, reverse=True)
        self.sub_vaults = ranked[: self.max_sub]

    def _prune_main_vault(self) -> None:
        unique: dict[str, AlgorithmCandidate] = {}
        for candidate in self.main_vault:
            signature = self._candidate_signature(candidate)
            existing = unique.get(signature)
            if existing is None or self._candidate_score(candidate) > self._candidate_score(existing):
                unique[signature] = candidate
        ranked = sorted(unique.values(), key=self._candidate_score, reverse=True)
        self.main_vault = ranked[: self.max_main]

    def add_to_sub_vault(self, candidate: AlgorithmCandidate) -> None:
        if not self._candidate_is_safe(candidate):
            return
        candidate.bucket = "sub"
        candidate.params["bucket"] = "sub"
        self.sub_vaults.append(candidate)
        self._prune_sub_vault()

    def promote_to_main_vault(self, candidate: AlgorithmCandidate) -> None:
        if not self._candidate_is_safe(candidate):
            return
        if not self._candidate_ready_for_main(candidate):
            candidate.params["guard_state"] = "SUB_ONLY"
            candidate.params["bucket"] = "sub"
            candidate.bucket = "sub"
            return
        candidate.type = "stable"
        candidate.bucket = "main"
        candidate.params["bucket"] = "main"
        candidate.params["promotion_count"] = int(candidate.params.get("promotion_count", 0) or 0) + 1
        candidate.params["guard_state"] = "MAIN_READY"
        self.main_vault.append(candidate)
        if candidate in self.sub_vaults:
            self.sub_vaults.remove(candidate)
        self._prune_main_vault()
        self._prune_sub_vault()

    def hybridize(self, left: AlgorithmCandidate, right: AlgorithmCandidate) -> AlgorithmCandidate:
        new_params = {**dict(left.params), **dict(right.params)}
        new_params["source_kind"] = "runtime"
        spec = {
            "kind": "sum",
            "left": copy.deepcopy(left.spec),
            "right": copy.deepcopy(right.spec),
        }
        return AlgorithmCandidate(
            logic=None,
            origin=f"hybrid:{left.origin}+{right.origin}",
            params=new_params,
            spec=spec,
        )

    def _mutate_spec(self, spec: dict[str, Any]) -> dict[str, Any]:
        mutated = copy.deepcopy(dict(spec or {}))
        kind = str(mutated.get("kind", "")).strip().lower()
        if kind == "extract_index":
            mutated["index"] = max(0, int(mutated.get("index", 0) or 0) + random.choice([-1, 0, 1]))
        elif kind == "constant":
            mutated["value"] = float(mutated.get("value", 0.0) or 0.0) + random.uniform(-1.0, 1.0)
        elif kind == "sum":
            mutated["left"] = self._mutate_spec(dict(mutated.get("left", {})))
            mutated["right"] = self._mutate_spec(dict(mutated.get("right", {})))
        return mutated

    def mutate(self, candidate: AlgorithmCandidate) -> AlgorithmCandidate:
        mutated = copy.copy(candidate)
        mutated.logic = None
        mutated.params = dict(candidate.params)
        mutated.anchor_points = list(candidate.anchor_points)
        mutated.spec = self._mutate_spec(dict(candidate.spec))
        for key in list(mutated.params):
            value = mutated.params[key]
            if key in {"usage_count", "promotion_count", "last_fitness", "bucket", "source_kind"}:
                continue
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                mutated.params[key] = max(0, int(value + random.choice([-1, 0, 1])))
            elif isinstance(value, float):
                mutated.params[key] = float(value + random.uniform(-1.0, 1.0))
        mutated.origin += "+mut"
        mutated.fitness = 0.0
        mutated.stable = False
        mutated.reproducible = False
        mutated.bucket = "sub"
        mutated.params["bucket"] = "sub"
        return mutated

    def evaluate_fitness(self, candidate: AlgorithmCandidate, data: Any) -> float:
        reproducibility = 0.0
        anchor_detected = 0.0
        governance = {
            "dual_path_agreement": 0.0,
            "noether_symmetry": 0.0,
            "heisenberg_uncertainty": 1.0,
            "vault_posterior_confidence": 0.0,
            "noether_invariant_hash": "",
            "benford_guard": -1.0,
            "benford_count": 0,
            "guard_state": "REJECTED",
        }
        try:
            if not self._candidate_is_safe(candidate):
                return 0.0
            result = candidate.run(data)
            alternative_result = candidate.run(self._project_observation_path(data))
            if not self._result_is_safe(result) or not self._result_is_safe(alternative_result):
                self._quarantine_candidate(candidate, "unsafe_result")
                return 0.0
            if isinstance(result, (int, float)):
                stability = math.log(abs(float(result)) + 1.0)
            else:
                stability = math.log(len(str(result)) + 1.0)
            reproducibility = 1.0 if result == candidate.run(data) else 0.5
            anchor_detected = 1.0 if self.detect_anchor(result) else 0.0
            governance = self._govern_candidate(candidate, result, alternative_result)
            usage_count = float(candidate.params.get("usage_count", 0) or 0.0)
            promotion_count = float(candidate.params.get("promotion_count", 0) or 0.0)
            usage_bonus = min(1.0, usage_count / 32.0) * 0.35
            longevity_bonus = min(1.0, promotion_count / 12.0) * 0.25
            legacy_bonus = 0.0
            if str(candidate.source_kind) == "legacy_dna":
                legacy_bonus = min(
                    0.4,
                    0.1 * float(candidate.params.get("pi_like_constants", 0) or 0.0),
                )
            detector_bonus = 0.0
            if str(candidate.source_kind) == "shanway_detector" and isinstance(result, dict):
                toxicity_score = float(result.get("toxicity_score", 0.0) or 0.0)
                asymmetry_score = float(result.get("asymmetry_score", 0.0) or 0.0)
                noether_symmetry = float(result.get("noether_symmetry", 0.0) or 0.0)
                coherence_proxy = float(result.get("coherence_proxy", 0.0) or 0.0)
                entropy_asymmetry = float(result.get("entropy_asymmetry", 0.0) or 0.0)
                reversibility = float(result.get("reversibility", 0.0) or 0.0)
                sentence_balance = float(result.get("sentence_balance", 0.0) or 0.0)
                anchor_alignment = float(result.get("anchor_alignment", 0.0) or 0.0)
                threat_pressure = min(1.0, float(result.get("threat_terms", 0) or 0.0) / 3.0)
                dehumanization_pressure = min(
                    1.0,
                    float(result.get("dehumanization_terms", 0) or 0.0) / 2.0,
                )
                collective_pressure = min(1.0, float(result.get("collective_terms", 0) or 0.0) / 2.0)
                blacklisted = 1.0 if bool(result.get("blacklisted", False)) else 0.0
                sensitive_guard = 0.45 if bool(result.get("sensitive", False)) else 0.0
                detector_bonus = (
                    (1.05 * max(toxicity_score, asymmetry_score))
                    + (0.40 * noether_symmetry)
                    + (0.25 * coherence_proxy)
                    + (0.18 * entropy_asymmetry)
                    + (0.14 * (1.0 - reversibility))
                    + (0.10 * (1.0 - sentence_balance))
                    + (0.14 * anchor_alignment)
                    + (0.18 * threat_pressure)
                    + (0.14 * dehumanization_pressure)
                    + (0.12 * collective_pressure)
                    + (0.24 * blacklisted)
                    + sensitive_guard
                )
            governance_bonus = (
                (0.36 * float(governance["noether_symmetry"]))
                + (0.28 * float(governance["dual_path_agreement"]))
                + (0.24 * float(governance["vault_posterior_confidence"]))
            )
            uncertainty_penalty = 0.65 * float(governance["heisenberg_uncertainty"])
            benford_bonus = 0.0
            if int(governance["benford_count"]) >= 12 and float(governance["benford_guard"]) >= 0.0:
                benford_bonus = 0.12 * max(0.0, float(governance["benford_guard"]) - 0.5)
            fitness = float(
                stability
                + reproducibility
                + anchor_detected
                + usage_bonus
                + longevity_bonus
                + legacy_bonus
                + detector_bonus
                + governance_bonus
                + benford_bonus
                - uncertainty_penalty
            )
        except Exception:
            fitness = 0.0
            result = None
            governance = dict(governance)
        candidate.params["usage_count"] = int(candidate.params.get("usage_count", 0) or 0) + 1
        candidate.params["last_fitness"] = float(fitness)
        candidate.params.update(governance)
        candidate.fitness = float(fitness)
        candidate.stable = bool(
            fitness > 2.0
            and float(candidate.params.get("noether_symmetry", 0.0) or 0.0) >= 0.34
            and float(candidate.params.get("dual_path_agreement", 0.0) or 0.0) >= 0.22
            and float(candidate.params.get("heisenberg_uncertainty", 1.0) or 1.0) <= 0.88
        )
        candidate.reproducible = bool(reproducibility > 0.8)
        if candidate.stable and anchor_detected and result is not None:
            candidate.anchor_points.append(_json_safe(result))
            if len(candidate.anchor_points) > 8:
                candidate.anchor_points = candidate.anchor_points[-8:]
        return candidate.fitness

    def detect_anchor(self, result: Any) -> bool:
        if isinstance(result, (int, float)):
            return abs(float(result)) < 0.01 or abs(float(result)) > 1000.0
        if isinstance(result, str):
            return len(result) > 5 and result[:3] == result[-3:]
        if isinstance(result, dict):
            return len(result) >= 3
        if isinstance(result, list):
            return len(result) >= 3
        return False

    def evolve(self, data: Any) -> dict[str, Any]:
        self.current_iteration = 0
        self.current_phase = "extract"
        self.last_run_stopped = False
        extracted = self.extract_algorithms(data)[: self.max_sub]
        for algorithm in extracted:
            self._mark_iteration("extract")
            if self._stop_now():
                break
            self.add_to_sub_vault(algorithm)

        working_set = list(self.sub_vaults)[: self.max_sub]
        mutated: list[AlgorithmCandidate] = []
        for algorithm in working_set[: self.max_mutations]:
            self._mark_iteration("mutate")
            if self._stop_now():
                break
            mutated.append(self.mutate(algorithm))
        self.sub_vaults.extend(mutated)

        hybrids: list[AlgorithmCandidate] = []
        base = list(self.sub_vaults)[: min(len(self.sub_vaults), 8)]
        for left_index, left in enumerate(base):
            if self._stop_now():
                break
            for right in base[left_index + 1 :]:
                self._mark_iteration("hybridize")
                if self._stop_now():
                    break
                hybrids.append(self.hybridize(left, right))
                if len(hybrids) >= self.max_hybrids:
                    break
            if len(hybrids) >= self.max_hybrids:
                break
        self.sub_vaults.extend(hybrids)

        for algorithm in self.sub_vaults:
            self._mark_iteration("fitness")
            if self._stop_now():
                break
            self.evaluate_fitness(algorithm, data)

        self._prune_sub_vault()
        for algorithm in list(self.sub_vaults):
            self._mark_iteration("promote")
            if self._stop_now():
                break
            if algorithm.stable and algorithm.anchor_points and self._candidate_ready_for_main(algorithm):
                self.promote_to_main_vault(algorithm)
            elif algorithm.stable and algorithm.anchor_points:
                algorithm.params["guard_state"] = "SUB_ONLY"
        self._prune_main_vault()
        snapshot = self.snapshot(data, limit=12)
        export_path = self._export_anchor_dna(list(snapshot.get("anchors", []) or []))
        if export_path:
            snapshot["dna_export_path"] = str(export_path)
        snapshot["stopped"] = bool(self.last_run_stopped)
        snapshot["iteration"] = int(self.current_iteration)
        snapshot["phase"] = str(self.current_phase)
        self.stop_requested = False
        self.current_phase = "idle"
        return snapshot

    def extract_algorithms(self, data: Any) -> list[AlgorithmCandidate]:
        algorithms: list[AlgorithmCandidate] = []
        if isinstance(data, list):
            for index, _item in enumerate(data[: self.max_sub]):
                algorithms.append(
                    AlgorithmCandidate(
                        logic=None,
                        origin=f"extract_{index}",
                        params={"index": index, "source_kind": "runtime", "bucket": "sub"},
                        spec={"kind": "extract_index", "index": index},
                    )
                )
        elif isinstance(data, dict):
            for key in list(data.keys())[: self.max_sub]:
                algorithms.append(
                    AlgorithmCandidate(
                        logic=None,
                        origin=f"extract_{key}",
                        params={"key": key, "source_kind": "runtime", "bucket": "sub"},
                        spec={"kind": "extract_key", "key": key},
                    )
                )
        elif isinstance(data, str):
            algorithms.append(
                AlgorithmCandidate(
                    logic=None,
                    origin="extract_hash",
                    params={"source_kind": "runtime", "bucket": "sub"},
                    spec={"kind": "hash_text"},
                )
            )
        return algorithms

    def integrate_legacy_dna(self, dna_payload: dict[str, Any], bucket: str = "sub") -> AlgorithmCandidate:
        """Uebernimmt ein altes DNA-Payload als serialisierbaren AELAB-Kandidaten."""
        constants = [float(item) for item in list(dna_payload.get("constants", []))]
        pi_like = [
            float(item)
            for item in constants
            if abs(float(item) - math.pi) <= 0.05
        ]
        params = {
            "legacy_id": str(dna_payload.get("legacy_id", "")),
            "header_metric": int(dna_payload.get("header_metric", 0) or 0),
            "node_count": int(dna_payload.get("node_count", len(list(dna_payload.get("nodes", [])))) or 0),
            "pi_like_constants": int(len(pi_like)),
            "source_hash": str(dna_payload.get("dna_hash", "")),
            "source_kind": "legacy_dna",
            "bucket": str(bucket),
            "usage_count": 0,
            "promotion_count": 0,
        }
        spec = {
            "kind": "legacy_dna",
            "legacy_id": str(dna_payload.get("legacy_id", "")),
            "constants": constants[:24],
            "constant_count": int(dna_payload.get("constant_count", len(constants)) or len(constants)),
            "node_count": int(dna_payload.get("node_count", len(list(dna_payload.get("nodes", [])))) or 0),
            "source_hash": str(dna_payload.get("dna_hash", "")),
        }
        candidate = AlgorithmCandidate(
            logic=None,
            origin=f"legacy_dna:{params['legacy_id'] or params['source_hash'][:12]}",
            params=params,
            spec=spec,
        )
        candidate.type = "legacy"
        preview = {
            "legacy_id": params["legacy_id"],
            "node_count": params["node_count"],
            "pi_like_constants": int(len(pi_like)),
            "bucket": str(bucket),
        }
        candidate.anchor_points = [preview]
        candidate.fitness = 1.0 + (0.2 * float(len(pi_like)))
        candidate.stable = True
        candidate.reproducible = True
        candidate.params.update(
            {
                "dual_path_agreement": 0.82,
                "noether_symmetry": min(0.96, 0.72 + (0.04 * float(len(pi_like)))),
                "heisenberg_uncertainty": max(0.08, 0.28 - (0.02 * float(len(pi_like)))),
                "vault_posterior_confidence": min(0.94, 0.58 + (0.04 * float(len(pi_like)))),
                "noether_invariant_hash": str(spec.get("source_hash", "")),
                "benford_guard": -1.0,
                "benford_count": int(len(constants)),
                "guard_state": "MAIN_READY" if str(bucket) == "main" else "SUB_ONLY",
            }
        )
        if str(bucket) == "main":
            if self._candidate_ready_for_main(candidate):
                self.main_vault.append(candidate)
                self._prune_main_vault()
            else:
                self.add_to_sub_vault(candidate)
        else:
            self.add_to_sub_vault(candidate)
        return candidate

    def integrate_asymmetry_detector(self, detector_payload: dict[str, Any], bucket: str = "sub") -> dict[str, Any]:
        """Uebernimmt einen Shanway-Asymmetriedetektor als AE-Kandidaten und spiegelt ihn als DNA."""
        payload = dict(detector_payload or {})
        params = {
            "classification": str(payload.get("classification", "")),
            "source_kind": "shanway_detector",
            "bucket": str(bucket),
            "usage_count": 0,
            "promotion_count": 0,
            "anchor_constant": str(payload.get("anchor_constant", "")),
        }
        spec = {
            "kind": "asymmetry_detector",
            "classification": str(payload.get("classification", "")),
            "anchor_constant_value": float(payload.get("anchor_constant_value", 0.0) or 0.0),
            "anchor_alignment": float(payload.get("anchor_alignment", 0.0) or 0.0),
        }
        candidate = AlgorithmCandidate(
            logic=None,
            origin=f"shanway_detector:{params['classification'] or 'unknown'}",
            params=params,
            spec=spec,
        )
        candidate.type = "shanway_detector"
        candidate.source_kind = "shanway_detector"
        candidate.bucket = str(bucket)
        candidate.params["bucket"] = str(bucket)
        candidate.anchor_points = [_json_safe(payload)]
        candidate.fitness = float(self.evaluate_fitness(candidate, payload))
        if candidate.stable and candidate.anchor_points:
            self.promote_to_main_vault(candidate)
        else:
            self.add_to_sub_vault(candidate)
        dna_path = self._export_detector_dna(payload)
        return {
            "candidate": candidate,
            "dna_export_path": str(dna_path or ""),
        }

    def export_state(self) -> dict[str, list[dict[str, Any]]]:
        """Exportiert Main- und Sub-Vault serialisierbar fuer Persistenz."""
        return {
            "main": [candidate.to_payload(bucket="main") for candidate in self.main_vault],
            "sub": [candidate.to_payload(bucket="sub") for candidate in self.sub_vaults],
        }

    def load_serialized_state(self, payload: dict[str, Any], clear_existing: bool = False) -> None:
        """Laedt einen zuvor gespeicherten AE-Vault-Zustand wieder ein."""
        if clear_existing:
            self.main_vault = []
            self.sub_vaults = []
        for item in list(payload.get("main", []) or []):
            candidate = AlgorithmCandidate.from_payload(dict(item))
            candidate.bucket = "main"
            candidate.params["bucket"] = "main"
            if self._candidate_is_safe(candidate):
                self.main_vault.append(candidate)
        for item in list(payload.get("sub", []) or []):
            candidate = AlgorithmCandidate.from_payload(dict(item))
            candidate.bucket = "sub"
            candidate.params["bucket"] = "sub"
            if self._candidate_is_safe(candidate):
                self.sub_vaults.append(candidate)
        self._prune_main_vault()
        self._prune_sub_vault()

    def get_main_vault_algorithms(self) -> list[AlgorithmCandidate]:
        return list(self.main_vault)

    def snapshot(self, data: Any, limit: int = 6) -> dict[str, Any]:
        anchors = normalize_anchor_entries(AetherAnchorInterpreter(self).interpret(data, limit=limit))
        type_counts: dict[str, int] = {}
        for anchor in anchors:
            anchor_type = str(anchor.get("type_label", "")).strip()
            if anchor_type:
                type_counts[anchor_type] = int(type_counts.get(anchor_type, 0)) + 1
        top_types = [
            key
            for key, _count in sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
        ]
        return {
            "main_vault_size": int(len(self.main_vault)),
            "sub_vault_size": int(len(self.sub_vaults)),
            "anchor_count": int(len(anchors)),
            "top_anchor_types": top_types,
            "top_origins": [str(item.origin) for item in self.main_vault[: max(1, int(limit))]],
            "anchors": anchors,
            **self._governance_summary(list(self.main_vault) + list(self.sub_vaults)),
            "iteration": int(self.current_iteration),
            "phase": str(self.current_phase),
            "stopped": bool(self.last_run_stopped),
        }

    def export_anchor_snapshot(self, anchors: list[dict[str, Any]] | None = None, data: Any = None) -> str:
        """Exportiert explizit den aktuellen Anchor-Zustand als DNA-Datei."""
        resolved_anchors = list(anchors or [])
        if not resolved_anchors and data is not None:
            resolved_anchors = list(self.snapshot(data, limit=12).get("anchors", []) or [])
        return str(self._export_anchor_dna(resolved_anchors) or "")

    def archive_legacy_dna(self, source_path: str, bucket: str = "sub", legacy_id: str = "") -> str:
        """Kopiert eine alte DNA-Datei in den verwalteten AELAB-Legacy-Bereich."""
        source = Path(source_path)
        if not source.is_file():
            return ""
        bucket_dir = self.legacy_import_dir / str(bucket or "sub")
        bucket_dir.mkdir(parents=True, exist_ok=True)
        stem = str(legacy_id or source.stem or "legacy").strip()
        target = bucket_dir / f"{stem}_{source.name}"
        counter = 1
        while target.exists():
            target = bucket_dir / f"{stem}_{counter}_{source.name}"
            counter += 1
        shutil.copy2(source, target)
        return str(target)

    def _export_anchor_dna(self, anchors: list[dict[str, Any]]) -> str:
        """Spiegelt skalare AE-Anker als einfache DNA-Datei ins lokale Vault-Verzeichnis."""
        exportable = [
            dict(anchor)
            for anchor in list(anchors)
            if abs(float(anchor.get("value", 0.0) or 0.0)) > 1e-12
        ]
        if not exportable:
            self.last_anchor_export_path = ""
            return ""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        file_path = self.export_dir / f"anchors_{timestamp}.dna"
        lines = [f"AETHER_AE_DNA 1 {timestamp} {len(exportable)}"]
        for anchor in exportable:
            lines.append(
                f"{int(anchor.get('index', 0))} "
                f"{float(anchor.get('value', 0.0) or 0.0):.12f} "
                f"{str(anchor.get('type_label', 'EMERGENT'))}"
            )
        file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.last_anchor_export_path = str(file_path)
        return str(file_path)

    def _export_detector_dna(self, detector_payload: dict[str, Any]) -> str:
        """Serialisiert einen Shanway-Asymmetriedetektor als lesbare DNA-Datei."""
        payload = dict(detector_payload or {})
        metrics = [
            ("toxicity_score", float(payload.get("toxicity_score", 0.0) or 0.0)),
            ("asymmetry_score", float(payload.get("asymmetry_score", 0.0) or 0.0)),
            ("noether_symmetry", float(payload.get("noether_symmetry", 0.0) or 0.0)),
            ("coherence_proxy", float(payload.get("coherence_proxy", 0.0) or 0.0)),
            ("entropy_asymmetry", float(payload.get("entropy_asymmetry", 0.0) or 0.0)),
            ("reversibility", float(payload.get("reversibility", 0.0) or 0.0)),
            ("sentence_balance", float(payload.get("sentence_balance", 0.0) or 0.0)),
            ("anchor_alignment", float(payload.get("anchor_alignment", 0.0) or 0.0)),
        ]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        file_path = self.export_dir / f"shanway_detector_{timestamp}.dna"
        lines = [
            f"AETHER_SHANWAY_DNA 1 {timestamp} {str(payload.get('classification', 'unknown')).upper()} {len(metrics)}"
        ]
        for index, (label, value) in enumerate(metrics):
            lines.append(f"{index} {float(value):.12f} {label.upper()}")
        file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(file_path)


class AetherAnchorInterpreter:
    def __init__(self, vault: AEAlgorithmVault):
        self.vault = vault

    def interpret(self, data: Any, limit: int | None = None) -> list[dict[str, Any]]:
        anchors: list[dict[str, Any]] = []
        algorithms = self.vault.get_main_vault_algorithms()
        if limit is not None:
            algorithms = algorithms[: max(1, int(limit))]
        for algorithm in algorithms:
            try:
                result = algorithm.run(data)
            except Exception:
                continue
            anchor_type = self.classify_anchor(result, data)
            if anchor_type:
                anchors.append(
                    {
                        "type": anchor_type,
                        "value": _json_safe(result),
                        "origin": algorithm.origin,
                        "stability": algorithm.stable,
                        "reproducible": algorithm.reproducible,
                        "hash": hashlib.sha256(str(result).encode()).hexdigest(),
                        "noether_symmetry": float(algorithm.params.get("noether_symmetry", 0.0) or 0.0),
                        "dual_path_agreement": float(algorithm.params.get("dual_path_agreement", 0.0) or 0.0),
                        "heisenberg_uncertainty": float(algorithm.params.get("heisenberg_uncertainty", 0.0) or 0.0),
                        "vault_posterior_confidence": float(algorithm.params.get("vault_posterior_confidence", 0.0) or 0.0),
                        "guard_state": str(algorithm.params.get("guard_state", "")),
                    }
                )
        return anchors

    def classify_anchor(self, result: Any, data: Any) -> str:
        if isinstance(result, (int, float)) and (abs(float(result)) < 0.01 or abs(float(result)) > 1000.0):
            return "Raumzeit-Anker"
        if isinstance(result, dict) and "pi_resonance" in result:
            return "Legacy-DNA-Anker"
        if isinstance(result, str) and result in str(data):
            return "Themen-Anker"
        if isinstance(result, str) and len(result) == 64:
            return "Hash-Anker"
        if isinstance(result, (list, dict)) and len(str(result)) > 10:
            return "Struktur-Anker"
        return ""
