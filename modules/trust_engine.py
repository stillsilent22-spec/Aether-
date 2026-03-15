"""Unabhaengige Trust-Pruefung fuer oeffentliche Aether-DNA-Bundles."""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _canonical_json(payload: Any) -> str:
    """Serialisiert Payloads deterministisch fuer lokale Hash-/Trust-Pruefungen."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _clamp(value: Any, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Normalisiert unklare Eingaben robust in einen festen Bereich."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = minimum
    if math.isnan(numeric) or math.isinf(numeric):
        numeric = minimum
    return max(minimum, min(maximum, numeric))


class TrustScoreEngine:
    """Aggregiert nur bereits vorhandene Aether-Metriken zu einem Upload-Trust-Score."""

    def __init__(
        self,
        vault_dir: str = "data/public_anchor_library",
        threshold: float = 0.65,
        log_path: str = "data/public_anchor_library/trust_log.json",
    ) -> None:
        self.vault_dir = Path(vault_dir)
        self.threshold = float(threshold)
        self.log_path = Path(log_path)

    def _collect_pattern_counts(self, current_payload: dict[str, Any] | None = None) -> dict[str, int]:
        """Zaehlt bereits bekannte Anchor-Muster aus oeffentlichen DNA-Bundles."""
        counts: dict[str, int] = {}
        search_roots = [self.vault_dir]
        if current_payload is not None:
            records = list(dict(current_payload.get("dna_share", {}) or {}).get("records", []) or [])
            for record in records:
                pattern_hash = str(dict(record).get("anchor_pattern_hash", "") or "").strip()
                if pattern_hash:
                    counts[pattern_hash] = counts.get(pattern_hash, 0) + 1
        for root in search_roots:
            if not root.exists():
                continue
            for file_path in root.rglob("*.json"):
                try:
                    parsed = json.loads(file_path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                payload = dict(parsed.get("payload", parsed) or {})
                records = list(dict(payload.get("dna_share", {}) or {}).get("records", []) or [])
                for record in records:
                    pattern_hash = str(dict(record).get("anchor_pattern_hash", "") or "").strip()
                    if pattern_hash:
                        counts[pattern_hash] = counts.get(pattern_hash, 0) + 1
        return counts

    def evaluate(
        self,
        anchor_data: dict[str, Any],
        bundle_payload: dict[str, Any] | None = None,
        pattern_counts: dict[str, int] | None = None,
    ) -> tuple[float, bool, dict[str, float], dict[str, bool], list[str]]:
        """Bewertet einen Anchor-Record nur aus vorhandenen Bundle-/Aether-Signalen."""
        record = dict(anchor_data or {})
        trust_inputs = dict(record.get("trust_inputs", {}) or {})
        pattern_counts = dict(pattern_counts or {})
        flags: list[str] = []
        bayes_flags = {
            "bayes_suspicious": False,
            "bayes_stale": False,
            "bayes_inconsistent": False,
        }

        posterior = _clamp(trust_inputs.get("bayes_overall_confidence", 0.0))
        noether_score = _clamp(float(trust_inputs.get("noether_score", 0.0) or 0.0) / 100.0)
        benford_score = _clamp(trust_inputs.get("benford_score", 0.0))
        graph_score = _clamp(trust_inputs.get("graph_confidence_mean", 0.0))
        beauty_score = _clamp(float(trust_inputs.get("beauty_score", 0.0) or 0.0) / 100.0)
        expected_inputs = [value for value in (noether_score, benford_score, graph_score, beauty_score) if value > 0.0]
        expected_range = sum(expected_inputs) / max(1, len(expected_inputs)) if expected_inputs else posterior

        if expected_inputs and abs(posterior - expected_range) > 0.15:
            bayes_flags["bayes_suspicious"] = True
        if not expected_inputs and posterior > 0.0:
            bayes_flags["bayes_stale"] = True
        if posterior >= 0.80 and ((noether_score and noether_score < 0.35) or (benford_score and benford_score < 0.35)):
            bayes_flags["bayes_inconsistent"] = True

        convergence_score = posterior
        if any(bayes_flags.values()):
            convergence_score = min(convergence_score, 0.30)
            flags.extend(flag for flag, active in bayes_flags.items() if active)

        coverage_ratio = _clamp(trust_inputs.get("anchor_coverage_ratio", 0.0))
        unresolved_ratio = _clamp(trust_inputs.get("unresolved_residual_ratio", 1.0))
        coverage_verified = bool(trust_inputs.get("coverage_verified", False))
        coverage_score = _clamp(coverage_ratio - unresolved_ratio)
        if coverage_ratio >= 0.90 and unresolved_ratio <= 0.10 and not coverage_verified:
            flags.append("coverage_unstable")
            coverage_score = max(0.0, coverage_score - 0.20)

        pattern_hash = str(record.get("anchor_pattern_hash", "") or "").strip()
        vault_frequency = max(1, int(pattern_counts.get(pattern_hash, 0) or 0))
        pattern_matches = max(0, int(vault_frequency - 1))
        anchor_weight = 1.0 / math.log(1.0 + float(vault_frequency))
        log_match_score = 0.0
        if pattern_matches > 0:
            log_match_score = math.log(1.0 + float(pattern_matches)) * float(anchor_weight)
        vault_frequency_score = _clamp(log_match_score)
        if pattern_hash and pattern_matches == 0 and convergence_score >= 0.85:
            flags.append("frequency_anomaly")

        reconstruction_verified = bool(trust_inputs.get("reconstruction_verified", False))
        reconstruction_consistency_score = 1.0 if (reconstruction_verified and coverage_verified) else 0.0

        heisenberg_uncertainty = _clamp(trust_inputs.get("heisenberg_uncertainty", 0.0))
        if heisenberg_uncertainty > 0.88:
            flags.append("heisenberg_violation")
            breakdown = {
                "convergence_score": float(convergence_score),
                "coverage_score": float(coverage_score),
                "vault_frequency_score": float(vault_frequency_score),
                "reconstruction_consistency_score": float(reconstruction_consistency_score),
                "physical_plausibility_score": 0.0,
            }
            return 0.0, False, breakdown, bayes_flags, flags
        physical_plausibility_score = _clamp(1.0 - (heisenberg_uncertainty / 0.88))

        if convergence_score >= 0.80 and coverage_score < 0.40:
            flags.append("convergence_coverage_mismatch")
        if coverage_score >= 0.85 and vault_frequency_score < 0.15:
            flags.append("coverage_novel_pattern")

        breakdown = {
            "convergence_score": float(convergence_score),
            "coverage_score": float(coverage_score),
            "vault_frequency_score": float(vault_frequency_score),
            "log_match_score": float(log_match_score),
            "anchor_weight": float(anchor_weight),
            "vault_frequency": float(vault_frequency),
            "match_count": float(pattern_matches),
            "reconstruction_consistency_score": float(reconstruction_consistency_score),
            "physical_plausibility_score": float(physical_plausibility_score),
        }

        final_score = (
            (0.60 * breakdown["vault_frequency_score"])
            + (0.15 * breakdown["convergence_score"])
            + (0.10 * breakdown["coverage_score"])
            + (0.10 * breakdown["reconstruction_consistency_score"])
            + (0.05 * breakdown["physical_plausibility_score"])
        )
        if "convergence_coverage_mismatch" in flags:
            final_score = max(0.0, final_score - 0.10)
        if all(value > 0.95 for value in breakdown.values()):
            flags.append("too_perfect")

        passed = bool(final_score >= self.threshold and "too_perfect" not in flags)
        return float(_clamp(final_score)), passed, breakdown, bayes_flags, flags

    def _append_log(self, reports: list[dict[str, Any]]) -> None:
        """Schreibt lesbare Audit-Eintraege fuer jede Trust-Pruefung."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.is_file():
            try:
                existing = json.loads(self.log_path.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
        else:
            existing = []
        existing.extend(reports)
        self.log_path.write_text(json.dumps(existing[-512:], ensure_ascii=True, indent=2), encoding="utf-8")

    def evaluate_bundle(self, bundle_path: str) -> dict[str, Any]:
        """Prueft ein DNA-Share-Bundle unabhaengig und fail-closed."""
        target = Path(bundle_path)
        if not target.is_file():
            return {"checked": 0, "passed": True, "reason": "bundle_missing"}
        parsed = json.loads(target.read_text(encoding="utf-8"))
        payload = dict(parsed.get("payload", parsed) or {})
        records = list(dict(payload.get("dna_share", {}) or {}).get("records", []) or [])
        if not records:
            return {"checked": 0, "passed": True, "reason": "no_records"}
        pattern_counts = self._collect_pattern_counts(current_payload=payload)
        reports: list[dict[str, Any]] = []
        all_passed = True
        for index, record in enumerate(records):
            score, passed, breakdown, bayes_flags, flags = self.evaluate(
                anchor_data=dict(record),
                bundle_payload=payload,
                pattern_counts=pattern_counts,
            )
            layer_that_blocked = None
            if any(bayes_flags.values()):
                layer_that_blocked = 1
            elif "heisenberg_violation" in flags:
                layer_that_blocked = 2
            elif flags:
                layer_that_blocked = 3 if not passed else 4
            if not passed:
                all_passed = False
            reports.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "anchor_id": str(dict(record).get("dna_record_hash", "") or f"record_{index}"),
                    "file_id": str(payload.get("snapshot_hash", "") or target.stem),
                    "final_score": float(score),
                    "dimension_breakdown": breakdown,
                    "bayes_flags": bayes_flags,
                    "anomaly_flags": flags,
                    "pushed": bool(passed),
                    "layer_that_blocked": layer_that_blocked,
                }
            )
        self._append_log(reports)
        return {
            "checked": int(len(reports)),
            "passed": bool(all_passed),
            "reports": reports,
            "bundle_path": str(target),
        }


def main(argv: list[str] | None = None) -> int:
    """Kommandozeilen-Entry fuer lokale oder CI-gestuetzte Trust-Pruefung."""
    parser = argparse.ArgumentParser(description="Verifiziert oeffentliche Aether-DNA-Bundles unabhaengig.")
    parser.add_argument("--bundle", default="data/public_anchor_library/latest.json", help="Pfad zum DNA-Share-Bundle")
    parser.add_argument("--vault-dir", default="data/public_anchor_library", help="Verzeichnis mit bekannten Bundle-Historien")
    parser.add_argument("--log-path", default="data/public_anchor_library/trust_log.json", help="Zielpfad fuer Audit-Logs")
    parser.add_argument("--min-score", type=float, default=0.65, help="Mindestscore fuer einen erfolgreichen Check")
    args = parser.parse_args(argv)

    engine = TrustScoreEngine(vault_dir=args.vault_dir, threshold=args.min_score, log_path=args.log_path)
    result = engine.evaluate_bundle(args.bundle)
    if result.get("reason") == "bundle_missing":
        print("trust_engine: kein Bundle vorhanden, nichts zu pruefen.")
        return 0
    if result.get("reason") == "no_records":
        print("trust_engine: Bundle enthaelt keine Anchor-Records.")
        return 0
    checked = int(result.get("checked", 0) or 0)
    passed = bool(result.get("passed", False))
    print(f"trust_engine: checked={checked} passed={passed}")
    if not passed:
        for report in list(result.get("reports", []) or []):
            if bool(report.get("pushed", False)):
                continue
            print(
                f"blocked {report.get('anchor_id', 'unknown')} | "
                f"score={float(report.get('final_score', 0.0) or 0.0):.3f} | "
                f"flags={','.join(list(report.get('anomaly_flags', []) or [])) or '-'}"
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
