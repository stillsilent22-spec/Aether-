"""
telemetry_classifier.py — Klassifizierungs-Verdikt für Privacy-Telemetrie.

TelemetryVerdict klassifiziert einen beobachteten Telemetrie-Eintrag als:
  - SAFE:     unbedenklich, darf im Privacy-Vault gespeichert werden
  - REDACT:   muss vor Speicherung anonymisiert werden
  - BLOCK:    darf nicht gespeichert werden (z.B. Passwort-Felder, Keystrokes)

Wird von privacy_anchor_builder.py genutzt um Entscheidungen über
Local-Vault-Einträge zu treffen.

Privacy-Garantie: Klassifizierung erfolgt rein strukturell (Metadaten),
niemals auf Basis von Inhalten.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict


class TelemetryClass(str, Enum):
    SAFE   = "safe"
    REDACT = "redact"
    BLOCK  = "block"


@dataclass
class TelemetryVerdict:
    """Klassifizierungs-Ergebnis für einen Telemetrie-Eintrag.

    label:      TelemetryClass — was soll mit dem Eintrag passieren?
    confidence: Wie sicher ist die Klassifizierung? 0.0–1.0
    reason:     Kurze Begründung (für Logging, kein Inhalt)
    source:     Welches Modul hat das Verdikt erzeugt?
    """
    label:      TelemetryClass
    confidence: float = 1.0
    reason:     str = ""
    source:     str = "telemetry_classifier"

    def is_safe(self) -> bool:
        return self.label == TelemetryClass.SAFE

    def should_block(self) -> bool:
        return self.label == TelemetryClass.BLOCK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label":      self.label.value,
            "confidence": round(self.confidence, 4),
            "reason":     self.reason,
            "source":     self.source,
        }


def classify_telemetry_entry(
    entry_type: str,
    metadata: Dict[str, Any],
) -> TelemetryVerdict:
    """Klassifiziert einen Telemetrie-Eintrag strukturell (kein Inhalt).

    Geblockte Typen (hardcoded — kein Override möglich):
      - keystroke, input_event, mouse_click, clipboard, password, auth_token

    Redact-Typen:
      - file_path (wird gekürzt), process_name (nur Name, kein Pfad)

    Alles andere: SAFE
    """
    entry_type_lower = str(entry_type).lower().strip()

    _BLOCK_PATTERNS = {
        "keystroke", "keypress", "input_event", "mouse_click",
        "clipboard", "password", "auth_token", "secret", "credential",
    }
    _REDACT_PATTERNS = {
        "file_path", "file_open", "process_name", "window_title",
    }

    for pattern in _BLOCK_PATTERNS:
        if pattern in entry_type_lower:
            return TelemetryVerdict(
                label=TelemetryClass.BLOCK,
                confidence=1.0,
                reason=f"Typ '{entry_type}' ist explizit gesperrt (Privacy-Policy)",
            )

    for pattern in _REDACT_PATTERNS:
        if pattern in entry_type_lower:
            return TelemetryVerdict(
                label=TelemetryClass.REDACT,
                confidence=0.9,
                reason=f"Typ '{entry_type}' erfordert Anonymisierung vor Speicherung",
            )

    return TelemetryVerdict(
        label=TelemetryClass.SAFE,
        confidence=0.8,
        reason=f"Typ '{entry_type}' strukturell unbedenklich",
    )
