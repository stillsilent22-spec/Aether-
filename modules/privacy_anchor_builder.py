"""Persist privacy telemetry verdicts into the local DNA vault."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analysis_engine import AetherFingerprint
from .session_engine import SessionContext
from .telemetry_classifier import TelemetryVerdict


def _sanitize_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return cleaned.strip("_") or "entity"


@dataclass
class PrivacyAnchorBuilder:
    vault_path: str = "data/aelab_vault"
    session_engine: SessionContext | None = None

    def __post_init__(self) -> None:
        self._vault_dir = Path(self.vault_path)
        self._vault_dir.mkdir(parents=True, exist_ok=True)

    def verdict_to_fingerprint(self, verdict: TelemetryVerdict, session_id: str) -> AetherFingerprint:
        now = datetime.now(timezone.utc).isoformat()
        return AetherFingerprint(
            session_id=str(session_id),
            file_hash=str(verdict.privacy_anchor_hash),
            file_size=0,
            entropy_blocks=[float(verdict.telemetry_score)],
            entropy_mean=float(verdict.telemetry_score),
            fourier_peaks=[],
            byte_distribution={},
            periodicity=0,
            symmetry_score=float(verdict.log_weight),
            delta=b"",
            delta_ratio=0.0,
            anomaly_coordinates=[],
            verdict=str(verdict.classification),
            timestamp=now,
            source_type="process",
            source_label=str(verdict.entity_name),
            observer_mutual_info=float(verdict.telemetry_score),
            observer_knowledge_ratio=float(verdict.log_weight),
            h_lambda=max(0.0, 1.0 - float(verdict.telemetry_score)),
            integrity_state="PRIVACY_ANCHOR",
            integrity_text=f"Privacy-Anchor: {verdict.classification}",
        )

    def save_to_vault(self, fingerprint: AetherFingerprint) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        file_name = f"privacy_{_sanitize_label(str(fingerprint.source_label))}_{timestamp}.dna"
        file_path = self._vault_dir / file_name
        anchor_lines = [
            f"0 {float(fingerprint.entropy_mean):.12f} TELEMETRY_SCORE",
            f"1 {float(fingerprint.observer_knowledge_ratio):.12f} LOG_WEIGHT",
            f"2 {float(fingerprint.h_lambda):.12f} H_LAMBDA",
        ]
        header = (
            f"AETHER_SHANWAY_DNA 1 {timestamp} "
            f"source_type={fingerprint.source_type} "
            f"source_label={_sanitize_label(str(fingerprint.source_label))} "
            f"file_hash={fingerprint.file_hash}"
        )
        file_path.write_text("\n".join([header] + anchor_lines) + "\n", encoding="utf-8")
        sidecar = file_path.with_suffix(".json")
        sidecar.write_text(
            json.dumps(fingerprint.to_dict(), ensure_ascii=True, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        return str(file_path)

    def build_and_save_all(self, verdicts: list[TelemetryVerdict], session_id: str) -> list[str]:
        saved: list[str] = []
        for verdict in list(verdicts or []):
            if str(getattr(verdict, "classification", "") or "") not in {"CONFIRMED", "SUSPECTED"}:
                continue
            fingerprint = self.verdict_to_fingerprint(verdict, session_id=session_id)
            saved.append(self.save_to_vault(fingerprint))
        return saved
