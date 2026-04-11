"""screen_vision_engine — Datenschutzfilter für Screen-/Render-Kontexte.

Stellt fest, ob ein Screen-Kontext als privat eingestuft werden muss.
Private Kontexte (Passwörter, E-Mails, Chats etc.) werden von der
Analyse-Pipeline ausgeschlossen.

Keine passive Beobachtung — dieser Filter wird nur aufgerufen,
wenn der Nutzer aktiv einen Render-/Runtime-Kontext zur Analyse freigibt.
"""

from __future__ import annotations

import re

# Kontextschlüssel, die immer als privat gelten
_PRIVATE_CONTEXT_KEYS: frozenset[str] = frozenset([
    "whatsapp_chat", "telegram_chat", "signal_chat",
    "chat", "message", "inbox", "email_inbox", "mail",
    "password", "passwort", "credentials", "login", "auth",
    "banking", "paypal", "credit_card", "health", "medical",
    "private", "personal",
])

# Regex-Muster, die im Payload-Text auf private Daten hinweisen
_PRIVATE_PAYLOAD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"password\s*=", re.IGNORECASE),
    re.compile(r"passwort\s*=", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),  # e-mail
    re.compile(r"\b(?:token|secret|api_key|apikey)\s*[=:]\s*\S+", re.IGNORECASE),
)


def is_private_context(context_key: str, payload_text: str) -> bool:
    """Gibt True zurück, wenn der Kontext oder Payload als privat eingestuft wird.

    Args:
        context_key:  Bezeichner des Screen-/Render-Kontexts (z.B. "whatsapp_chat").
        payload_text: Sichtbarer Text oder Metadaten aus dem Kontext.

    Returns:
        True  → privater Kontext, nicht analysieren.
        False → kein privater Hinweis gefunden.
    """
    key_lower = str(context_key or "").lower()
    for private_key in _PRIVATE_CONTEXT_KEYS:
        if private_key in key_lower:
            return True

    text = str(payload_text or "")
    for pattern in _PRIVATE_PAYLOAD_PATTERNS:
        if pattern.search(text):
            return True

    return False
