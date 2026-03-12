"""Structural telemetry classification without payload inspection."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any


TELEMETRY_DOMAIN_ANCHORS: set[str] = {
    "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "statsfe2.ws.microsoft.com",
    "clients4.google.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "play.googleapis.com",
    "graph.facebook.com",
    "edge-mqtt.facebook.com",
    "lmlicenses.wip4.adobe.com",
    "na2activation.adobe.com",
    "doubleclick.net",
    "googletagmanager.com",
    "analytics.google.com",
    "hotjar.com",
    "mixpanel.com",
    "segment.io",
    "amplitude.com",
    "intercom.io",
    "fullstory.com",
}

TELEMETRY_PROCESS_ANCHORS: set[str] = {
    "DiagTrack",
    "dmwappushservice",
    "WerSvc",
    "WMPNetworkSvc",
    "diagsvc",
    "WdiServiceHost",
    "WdiSystemHost",
    "UsoSvc",
    "WaaSMedicSvc",
}


@dataclass
class TelemetryVerdict:
    entity_name: str
    entity_type: str
    telemetry_score: float
    classification: str
    anchor_matches: list[str]
    behavioral_signals: list[str]
    recommendation: str
    log_weight: float
    privacy_anchor_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_name": str(self.entity_name),
            "entity_type": str(self.entity_type),
            "telemetry_score": float(self.telemetry_score),
            "classification": str(self.classification),
            "anchor_matches": list(self.anchor_matches),
            "behavioral_signals": list(self.behavioral_signals),
            "recommendation": str(self.recommendation),
            "log_weight": float(self.log_weight),
            "privacy_anchor_hash": str(self.privacy_anchor_hash),
        }


class TelemetryClassifier:
    """Scores process and domain telemetry patterns."""

    def classify_process(self, signal: Any, network_signals: list[Any]) -> TelemetryVerdict:
        score = 0.0
        anchor_matches: list[str] = []
        behavioral_signals: list[str] = []
        if str(getattr(signal, "name", "") or "") in TELEMETRY_PROCESS_ANCHORS:
            score += 0.45
            anchor_matches.append(str(getattr(signal, "name", "") or ""))

        matching = [
            item
            for item in list(network_signals or [])
            if int(getattr(item, "pid", -1) or -1) == int(getattr(signal, "pid", -2) or -2)
            and str(getattr(item, "remote_domain", "") or "") in TELEMETRY_DOMAIN_ANCHORS
        ]
        if matching:
            anchor_matches.extend(sorted({str(getattr(item, "remote_domain", "") or "") for item in matching}))
        score += 0.25 * min(1.0, math.log(1.0 + float(len(matching))) / math.log(11.0))

        max_regularity = max(
            (
                float(getattr(item, "interval_regularity", 0.0) or 0.0)
                for item in list(network_signals or [])
                if int(getattr(item, "pid", -1) or -1) == int(getattr(signal, "pid", -2) or -2)
            ),
            default=0.0,
        )
        score += 0.15 * max_regularity
        if max_regularity >= 0.7:
            behavioral_signals.append("fixed_interval")

        if not bool(getattr(signal, "has_window", True)) and int(getattr(signal, "open_connections", 0) or 0) > 0:
            score += 0.10
            behavioral_signals.append("no_ui")

        cpu_percent = float(getattr(signal, "cpu_percent", 0.0) or 0.0)
        if 0.0 < cpu_percent < 3.0 and int(getattr(signal, "open_connections", 0) or 0) > 0:
            score += 0.05
            behavioral_signals.append("idle_network")

        if int(len(matching)) >= 3:
            behavioral_signals.append("high_frequency")
        if any(str(getattr(item, "packet_size_bucket", "") or "") == "tiny" for item in matching):
            behavioral_signals.append("tiny_packets")

        return self._build_verdict(
            entity_name=str(getattr(signal, "name", "") or ""),
            entity_type="process",
            telemetry_score=min(1.0, score),
            anchor_matches=anchor_matches,
            behavioral_signals=behavioral_signals,
        )

    def classify_domain(self, signal: Any) -> TelemetryVerdict:
        score = 0.0
        anchor_matches: list[str] = []
        behavioral_signals: list[str] = []
        domain = str(getattr(signal, "remote_domain", "") or "")
        if domain in TELEMETRY_DOMAIN_ANCHORS:
            score += 0.55
            anchor_matches.append(domain)
        regularity = float(getattr(signal, "interval_regularity", 0.0) or 0.0)
        score += 0.20 * regularity
        if regularity > 0.7:
            behavioral_signals.append("fixed_interval")
        if str(getattr(signal, "packet_size_bucket", "") or "") == "tiny" and int(getattr(signal, "connection_count_last_min", 0) or 0) > 3:
            score += 0.15
            behavioral_signals.extend(["tiny_packets", "high_frequency"])
        if int(getattr(signal, "remote_port", 0) or 0) in {80, 443, 8443} and regularity > 0.7:
            score += 0.10
        return self._build_verdict(
            entity_name=domain,
            entity_type="domain",
            telemetry_score=min(1.0, score),
            anchor_matches=anchor_matches,
            behavioral_signals=behavioral_signals,
        )

    def classify_snapshot(self, snapshot: dict[str, Any]) -> list[TelemetryVerdict]:
        process_signals = list(dict(snapshot or {}).get("process_signals", []) or [])
        network_signals = list(dict(snapshot or {}).get("network_signals", []) or [])
        verdicts: list[TelemetryVerdict] = []
        for signal in process_signals:
            open_connections = int(getattr(signal, "open_connections", signal.get("open_connections", 0)) or 0)
            if open_connections <= 0:
                continue
            verdicts.append(self.classify_process(signal, network_signals))

        best_domains: dict[str, Any] = {}
        for raw_signal in network_signals:
            domain = str(getattr(raw_signal, "remote_domain", raw_signal.get("remote_domain", "")) or "")
            if not domain or domain == "unknown":
                continue
            current = best_domains.get(domain)
            current_reg = float(
                getattr(current, "interval_regularity", current.get("interval_regularity", 0.0))
                if current is not None else 0.0
            )
            candidate_reg = float(
                getattr(raw_signal, "interval_regularity", raw_signal.get("interval_regularity", 0.0)) or 0.0
            )
            if current is None or candidate_reg > current_reg:
                best_domains[domain] = raw_signal
        for signal in best_domains.values():
            verdicts.append(self.classify_domain(signal))

        deduped: dict[tuple[str, str], TelemetryVerdict] = {}
        for verdict in verdicts:
            key = (verdict.entity_type, verdict.entity_name)
            existing = deduped.get(key)
            if existing is None or float(verdict.telemetry_score) > float(existing.telemetry_score):
                deduped[key] = verdict
        ranked = sorted(
            deduped.values(),
            key=lambda item: (-float(item.telemetry_score), str(item.entity_type), str(item.entity_name)),
        )
        return ranked[:50]

    def compute_log_weight(self, verdict: TelemetryVerdict, global_hit_count: int) -> float:
        base = math.log(1.0 + (float(verdict.telemetry_score) * 10.0)) / math.log(11.0)
        global_f = math.log(1.0 + float(max(0, int(global_hit_count)))) / math.log(1.0 + 1000.0)
        return min(1.0, base * (1.0 + global_f))

    def _build_verdict(
        self,
        entity_name: str,
        entity_type: str,
        telemetry_score: float,
        anchor_matches: list[str],
        behavioral_signals: list[str],
    ) -> TelemetryVerdict:
        score = max(0.0, min(1.0, float(telemetry_score)))
        if score >= 0.75:
            classification = "CONFIRMED"
        elif score >= 0.45:
            classification = "SUSPECTED"
        elif score >= 0.20:
            classification = "NEUTRAL"
        else:
            classification = "CLEAN"
        payload = {
            "process_anchor": str(entity_name) if entity_type == "process" else "",
            "domain_anchors": sorted(str(item) for item in anchor_matches),
            "classification": classification,
            "behavioral_signals": sorted(set(str(item) for item in behavioral_signals)),
        }
        anchor_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
        ).hexdigest()
        verdict = TelemetryVerdict(
            entity_name=str(entity_name),
            entity_type=str(entity_type),
            telemetry_score=score,
            classification=classification,
            anchor_matches=sorted(set(str(item) for item in anchor_matches)),
            behavioral_signals=sorted(set(str(item) for item in behavioral_signals)),
            recommendation=self._recommendation(classification, entity_type, entity_name),
            log_weight=0.0,
            privacy_anchor_hash=anchor_hash,
        )
        verdict.log_weight = float(self.compute_log_weight(verdict, len(verdict.anchor_matches)))
        return verdict

    @staticmethod
    def _recommendation(classification: str, entity_type: str, entity_name: str) -> str:
        if classification == "CONFIRMED":
            return f"{entity_type} {entity_name} nur mit expliziter Zustimmung blockieren oder deaktivieren"
        if classification == "SUSPECTED":
            return f"{entity_type} {entity_name} weiter lokal beobachten und bei Bestaetigung haerten"
        if classification == "NEUTRAL":
            return f"{entity_type} {entity_name} beobachten, aber noch nicht eingreifen"
        return f"{entity_type} {entity_name} aktuell unauffaellig"
