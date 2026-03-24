from typing import Any as _tc_Any
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TelemetryVerdict:
    """Ergebnis einer Telemetrie-Klassifikation."""
    score: float = 0.0
    label: str = "unknown"
    reasons: list = field(default_factory=list)
    raw_signal: dict = field(default_factory=dict)


class TelemetryClassifier:
    """Bewertet Netzwerk-Telemetriesignale strukturell ohne Domainnamen."""

    LABEL_THRESHOLDS = {
        "beacon":  0.70,
        "exfil":   0.55,
        "suspect": 0.35,
        "normal":  0.0,
    }

    def classify(self, signal: Any) -> TelemetryVerdict:
        """Hauptmethode: gibt TelemetryVerdict fuer ein Signal zurueck."""
        score = self._behavioral_domain_score(signal)
        label = "normal"
        for lbl, threshold in self.LABEL_THRESHOLDS.items():
            if score >= threshold:
                label = lbl
                break
        reasons = []
        if score >= 0.30:
            reasons.append(f"behavioral_score={score:.2f}")
        return TelemetryVerdict(
            score=score,
            label=label,
            reasons=reasons,
            raw_signal=signal if isinstance(signal, dict) else {},
        )

    def is_suspicious(self, signal: Any, threshold: float = 0.35) -> bool:
        """True wenn der behavioral score >= threshold."""
        return self.classify(signal).score >= threshold


def _behavioral_domain_score(self, signal: _tc_Any) -> float:
    """Bewertet Telemetrie-Verhalten strukturell — ohne Domainnamen."""
    score = 0.0
    try:
        def _g(s, k, d):
            return getattr(s, k, s.get(k, d) if isinstance(s, dict) else d) or d
        regularity = float(_g(signal, "interval_regularity", 0.0))
        packet_bucket = str(_g(signal, "packet_size_bucket", ""))
        conn_count = int(_g(signal, "connection_count_last_min", 0))
        remote_port = int(_g(signal, "remote_port", 0))
        bytes_sent = int(_g(signal, "bytes_sent", 0))
        bytes_recv = int(_g(signal, "bytes_received", 0))
        interval_std = float(_g(signal, "interval_std", 99.0))
        if regularity > 0.65: score += 0.30
        if packet_bucket == "tiny" and conn_count > 2: score += 0.25
        if remote_port in {80,443,8080,8443} and regularity > 0.5: score += 0.15
        if bytes_sent > 0 and bytes_recv > 0 and bytes_sent > bytes_recv * 3: score += 0.20
        if conn_count > 5 and interval_std < 2.0: score += 0.10
    except Exception:
        pass
    return min(1.0, float(score))

TelemetryClassifier._behavioral_domain_score = _behavioral_domain_score