from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""metalayer_assistant.py — MetaLayer OS Phase D: Assistant-gefilterte Befunde.

Übersetzt MetaLayer-OS-Erkenntnisse in das Assistant-Konsensformat.
Alle Ausgaben durchlaufen die Assistant-Pipeline (h_lambda-Gate, Trust-Score).
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Any

# ── Assistant-Konstanten (aus assistant_pipeline.py) ──────────────────────────────

TRUST_THRESHOLD   = 0.45
CONFIDENCE_MIN    = 0.65
H_LAMBDA_MAX      = 5.5   # >5.5 → Ausgabe unterdrücken


# ── Enums ─────────────────────────────────────────────────────────────────────

class MetaLayerFindingType(str, Enum):
    REDUNDANT_PROCESS    = "redundant_process"
    BEHAVIORAL_TWIN      = "behavioral_twin"
    COORD_ANOMALY        = "coord_anomaly"
    PATH_OPTIMIZATION    = "path_optimization"
    VAULT_ANCHOR         = "vault_anchor"
    THINNING_APPLIED     = "thinning_applied"
    SYSTEM_STATUS        = "system_status"


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class MetaLayerFinding:
    """Ein struktureller Befund des MetaLayer OS."""
    finding_type: MetaLayerFindingType
    title: str
    body: str
    confidence: float           # [0, 1]
    h_lambda: float             # Beobachter-Restunsicherheit
    trust_score: float          # Gesamtscore aus Assistant-Pipeline
    pid: Optional[int] = None
    process_name: Optional[str] = None
    payload: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def is_publishable(self) -> bool:
        """True wenn Befund Assistant-Qualitätsgates passiert."""
        return (
            self.h_lambda <= H_LAMBDA_MAX
            and self.confidence >= CONFIDENCE_MIN
            and self.trust_score >= TRUST_THRESHOLD
        )

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type.value,
            "title":        self.title,
            "body":         self.body,
            "confidence":   round(self.confidence, 4),
            "h_lambda":     round(self.h_lambda, 4),
            "trust_score":  round(self.trust_score, 4),
            "is_publishable": self.is_publishable,
            "pid":          self.pid,
            "process_name": self.process_name,
            "payload":      self.payload,
            "timestamp":    self.timestamp,
        }


# ── Assistant-Filter-Wrapper ────────────────────────────────────────────────────

def format_finding(finding: MetaLayerFinding) -> str:
    """
    Formatiert einen MetaLayerFinding als Assistant-gefilterter Textbefund.
    Gibt leeren String zurück wenn Qualitätsgates nicht bestanden.
    """
    if not finding.is_publishable:
        return ""
    lines = [
        f"[MetaLayer/{finding.finding_type.value}] {finding.title}",
        f"  {finding.body}",
        f"  Confidence={round(finding.confidence, 3)} | "
        f"H_λ={round(finding.h_lambda, 3)} | "
        f"Trust={round(finding.trust_score, 3)}",
    ]
    if finding.pid is not None:
        lines.append(f"  PID={finding.pid} Prozess='{finding.process_name}'")
    return "\n".join(lines)


class MetaLayerAssistantBridge:
    """
    Verbindet MetaLayer-OS-Ergebnisse mit der Assistant-Pipeline.

    Wenn keine Assistant-Pipeline übergeben wird, werden strukturelle
    Heuristiken für h_lambda und trust_score verwendet.
    """

    def __init__(self, assistant_pipeline: Optional[Any] = None) -> None:
        self._pipeline = assistant_pipeline

    def create_finding(
        self,
        finding_type: MetaLayerFindingType,
        title: str,
        body: str,
        confidence: float,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        payload: Optional[dict] = None,
    ) -> MetaLayerFinding:
        """Erstellt einen MetaLayerFinding und misst Assistant-Parameter."""
        h_lambda, trust_score = self._measure(title, body, confidence)
        return MetaLayerFinding(
            finding_type  = finding_type,
            title         = title,
            body          = body,
            confidence    = min(1.0, max(0.0, confidence)),
            h_lambda      = h_lambda,
            trust_score   = trust_score,
            pid           = pid,
            process_name  = process_name,
            payload       = payload or {},
        )

    def findings_from_thinning_proposals(self, proposals: list) -> list[MetaLayerFinding]:
        findings = []
        for p in proposals:
            entry = getattr(p, "entry", None)
            if entry is None:
                continue
            body = (
                f"RAM-Gewinn: ~{round(getattr(p,'expected_ram_gain_mb',0),1)}MB | "
                f"CPU-Gewinn: ~{round(getattr(p,'expected_cpu_gain_pct',0),1)}% | "
                f"Aktion: {getattr(p,'action','?')}"
            )
            reasons = getattr(entry, "reasons", [])
            if reasons:
                body += " | Gründe: " + ", ".join(reasons[:3])
            f = self.create_finding(
                finding_type  = MetaLayerFindingType.REDUNDANT_PROCESS,
                title         = f"Redundanter Prozess: '{entry.process_name}'",
                body          = body,
                confidence    = float(getattr(p, "confidence", 0.5)),
                pid           = entry.pid,
                process_name  = entry.process_name,
                payload       = getattr(p, "to_dict", lambda: {})(),
            )
            findings.append(f)
        return findings

    def findings_from_anomalies(self, anomalies: list) -> list[MetaLayerFinding]:
        findings = []
        for a in anomalies:
            f = self.create_finding(
                finding_type  = MetaLayerFindingType.COORD_ANOMALY,
                title         = f"Koordinaten-Anomalie: {a.anomaly_type}",
                body          = (
                    f"Beobachtet={round(a.observed,2)} | "
                    f"Baseline={round(a.baseline,2)} | "
                    f"Abweichung={round(a.deviation_pct,1)}%"
                ),
                confidence    = min(0.95, a.deviation_pct / 100.0 + 0.5),
                pid           = a.pid,
                process_name  = a.process_name,
                payload       = a.to_dict(),
            )
            findings.append(f)
        return findings

    def publish_all(self, findings: list[MetaLayerFinding]) -> list[str]:
        """Formatiert und filtert alle publishable Befunde."""
        return [
            formatted
            for f in findings
            if (formatted := format_finding(f))
        ]

    # ── Interne Messung ───────────────────────────────────────────────────────

    def _measure(
        self, title: str, body: str, confidence: float
    ) -> tuple[float, float]:
        """
        Bestimmt h_lambda und Trust-Score via Assistant-Pipeline oder Heuristik.
        """
        if self._pipeline is not None:
            try:
                text = f"{title}\n{body}"
                measure = getattr(self._pipeline, "measure_consensus", None)
                if callable(measure):
                    result = measure(text, [])
                    h_lam  = float(getattr(result, "h_lambda", 3.0))
                    trust  = float(getattr(result, "trust_score", confidence))
                    return h_lam, trust
            except Exception as e:
                logger.warning(f"[metalayer_assistant] Fehler: {e}")
                pass
        # Heuristik: h_lambda aus Textlänge + confidence
        text_len = len(title) + len(body)
        h_lambda = max(0.5, min(5.0, 8.0 - confidence * 4.0 - text_len / 200.0))
        trust    = min(1.0, confidence * 0.85 + 0.1)
        return round(h_lambda, 4), round(trust, 4)
