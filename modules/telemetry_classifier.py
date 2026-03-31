from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any


TELEMETRY_DOMAIN_ANCHORS = {
    "cdn.discordapp.com",
    "telemetry.microsoft.com",
    "update.googleapis.com",
}

TELEMETRY_PROCESS_ANCHORS = {
    "msedge.exe",
    "svchost.exe",
    "discord.exe",
}


@dataclass
class TelemetryVerdict:
    """Kompakter Verdict-Typ fuer Privacy-Telemetrie und aeltere Call-Sites."""

    entity_type: str = "network"
    entity_name: str = ""
    classification: str = "NORMAL"
    telemetry_score: float = 0.0
    log_weight: float = 0.0
    privacy_anchor_hash: str = ""
    reasons: list[str] = field(default_factory=list)
    raw_signal: dict[str, Any] = field(default_factory=dict)

    @property
    def score(self) -> float:
        return float(self.telemetry_score)

    @property
    def label(self) -> str:
        return str(self.classification).lower()


class TelemetryClassifier:
    """Bewertet Prozess- und Netzwerk-Telemetrie anhand lokaler Anker und Struktur."""

    def classify(self, signal: Any) -> TelemetryVerdict:
        return self.classify_domain(signal)

    def classify_domain(self, signal: Any) -> TelemetryVerdict:
        raw = self._signal_to_dict(signal)
        domain = str(raw.get("remote_domain", "")).strip().lower()
        score = self._behavioral_domain_score(signal)
        reasons: list[str] = []
        classification = "NORMAL"

        if domain in TELEMETRY_DOMAIN_ANCHORS:
            score = max(score, 0.95)
            classification = "CONFIRMED"
            reasons.append("domain_anchor_match")
        elif score >= 0.35:
            classification = "SUSPECTED"
            reasons.append(f"behavioral_score={score:.2f}")

        verdict = self._make_verdict(
            entity_type="network",
            entity_name=domain or str(raw.get("process_name", "")).strip(),
            classification=classification,
            telemetry_score=score,
            reasons=reasons,
            raw_signal=raw,
        )
        verdict.log_weight = self.compute_log_weight(verdict, 1)
        return verdict

    def classify_process(self, signal: Any, network_signals: list[Any] | None = None) -> TelemetryVerdict:
        raw = self._signal_to_dict(signal)
        process_name = str(raw.get("name", raw.get("process_name", ""))).strip().lower()
        reasons: list[str] = []
        score = 0.0
        classification = "NORMAL"

        if process_name in TELEMETRY_PROCESS_ANCHORS:
            score += 0.60
            reasons.append("process_anchor_match")

        confirmed_network_hits = 0
        for network_signal in list(network_signals or []):
            network_verdict = self.classify_domain(network_signal)
            if network_verdict.classification == "CONFIRMED":
                confirmed_network_hits += 1

        if confirmed_network_hits:
            score += min(0.40, confirmed_network_hits * 0.20)
            reasons.append(f"confirmed_network_hits={confirmed_network_hits}")

        if score >= 0.80:
            classification = "CONFIRMED"
        elif score >= 0.35:
            classification = "SUSPECTED"

        verdict = self._make_verdict(
            entity_type="process",
            entity_name=process_name,
            classification=classification,
            telemetry_score=min(1.0, score),
            reasons=reasons,
            raw_signal=raw,
        )
        verdict.log_weight = self.compute_log_weight(verdict, max(1, confirmed_network_hits))
        return verdict

    def classify_snapshot(self, snapshot: dict[str, Any]) -> list[TelemetryVerdict]:
        verdicts: list[TelemetryVerdict] = []
        network_signals = list(snapshot.get("network_signals", []) or [])
        process_signals = list(snapshot.get("process_signals", []) or [])

        for signal in network_signals:
            verdict = self.classify_domain(signal)
            if verdict.classification != "NORMAL":
                verdicts.append(verdict)

        for signal in process_signals:
            verdict = self.classify_process(signal, network_signals)
            if verdict.classification != "NORMAL":
                verdicts.append(verdict)

        verdicts.sort(key=lambda item: (float(item.telemetry_score), float(item.log_weight)), reverse=True)
        return verdicts

    def compute_log_weight(self, verdict: TelemetryVerdict, global_hits: int) -> float:
        hits = max(1, int(global_hits or 0))
        base = max(0.0, float(getattr(verdict, "telemetry_score", 0.0) or 0.0))
        return round(base * (1.0 + math.log1p(hits)), 12)

    def is_suspicious(self, signal: Any, threshold: float = 0.35) -> bool:
        return self.classify(signal).score >= threshold

    def _make_verdict(
        self,
        *,
        entity_type: str,
        entity_name: str,
        classification: str,
        telemetry_score: float,
        reasons: list[str],
        raw_signal: dict[str, Any],
    ) -> TelemetryVerdict:
        payload = {
            "entity_type": entity_type,
            "entity_name": entity_name,
            "classification": classification,
            "telemetry_score": round(float(telemetry_score), 12),
            "raw_signal": raw_signal,
        }
        anchor_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return TelemetryVerdict(
            entity_type=entity_type,
            entity_name=entity_name,
            classification=classification,
            telemetry_score=round(float(telemetry_score), 12),
            log_weight=0.0,
            privacy_anchor_hash=anchor_hash,
            reasons=list(reasons),
            raw_signal=dict(raw_signal),
        )

    def _signal_to_dict(self, signal: Any) -> dict[str, Any]:
        if isinstance(signal, dict):
            return dict(signal)
        if hasattr(signal, "to_dict"):
            try:
                payload = signal.to_dict()
                if isinstance(payload, dict):
                    return dict(payload)
            except Exception as e:
                logger.warning(f"[telemetry_classifier] Fehler: {e}")
                pass
        result: dict[str, Any] = {}
        for name in (
            "name",
            "process_name",
            "remote_domain",
            "remote_port",
            "local_port",
            "protocol",
            "pid",
            "packet_size_bucket",
            "connection_count_last_min",
            "interval_regularity",
            "bytes_sent",
            "bytes_received",
            "interval_std",
        ):
            if hasattr(signal, name):
                result[name] = getattr(signal, name)
        return result

    def _behavioral_domain_score(self, signal: Any) -> float:
        score = 0.0
        try:
            raw = self._signal_to_dict(signal)

            def _g(key: str, default: Any) -> Any:
                value = raw.get(key, default)
                return default if value in (None, "") else value

            regularity = float(_g("interval_regularity", 0.0))
            packet_bucket = str(_g("packet_size_bucket", ""))
            conn_count = int(_g("connection_count_last_min", 0))
            remote_port = int(_g("remote_port", 0))
            bytes_sent = int(_g("bytes_sent", 0))
            bytes_recv = int(_g("bytes_received", 0))
            interval_std = float(_g("interval_std", 99.0))
            if regularity > 0.65:
                score += 0.30
            if packet_bucket == "tiny" and conn_count > 2:
                score += 0.25
            if remote_port in {80, 443, 8080, 8443} and regularity > 0.5:
                score += 0.15
            if bytes_sent > 0 and bytes_recv > 0 and bytes_sent > bytes_recv * 3:
                score += 0.20
            if conn_count > 5 and interval_std < 2.0:
                score += 0.10
        except Exception as e:
            logger.warning(f"[telemetry_classifier] Fehler: {e}")
            pass
        return min(1.0, float(score))