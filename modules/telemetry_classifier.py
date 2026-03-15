from typing import Any as _tc_Any

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