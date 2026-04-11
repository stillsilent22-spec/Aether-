"""AgentLoopEngine — plant lokale Folgeaktionen nach Analyse-Assessments.

Alle Aktionen bleiben lokal-deskriptiv. Externe Anfragen oder Browser-Navigationen
werden nur als Direktive zurückgegeben, nicht automatisch ausgeführt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentDirective:
    """Geplante Folgeaktion nach einem Analyse-Assessment."""

    should_execute: bool
    action: str
    action_payload: dict[str, Any] = field(default_factory=dict)
    loop_iteration: int = 1
    reason: str = ""


class AgentLoopEngine:
    """Plant deterministische Folgedirektiven basierend auf Analysezustand.

    Kein autonomes Ausführen — alle Direktiven werden gemeldet und müssen
    vom Aufrufer bestätigt werden.
    """

    _MAX_LOOP_ITERATIONS = 3

    def __init__(self) -> None:
        self._navigation_history: dict[str, list[str]] = {}

    def plan_browser_followup(
        self,
        source_key: str,
        source_label: str,
        file_type: str,
        h_lambda: float,
        observer_state: str,
        assessment_payload: dict[str, Any],
        browser_enabled: bool = False,
        browser_available: bool = False,
        current_url: str = "",
    ) -> AgentDirective:
        """Gibt eine Direktive für eine optionale Browser-Suche zurück.

        Wenn der Observer-Zustand offen ist und browser_enabled/available gesetzt sind,
        wird eine lokale Suchdirekive für passende strukturverwandte Dateitypen erzeugt.
        Die Direktive wird *nicht* automatisch ausgeführt.
        """
        history = self._navigation_history.get(source_key, [])
        iteration = len(history) + 1

        if iteration > self._MAX_LOOP_ITERATIONS:
            return AgentDirective(
                should_execute=False,
                action="none",
                reason="Max loop iterations reached",
                loop_iteration=iteration,
            )

        is_open = str(observer_state or "").upper() in ("OFFEN", "OPEN", "UNCERTAIN", "STRUCTURAL_HYPOTHESIS")
        if not (browser_enabled and browser_available and is_open):
            return AgentDirective(
                should_execute=False,
                action="none",
                reason="Browser not enabled/available or state not open",
                loop_iteration=iteration,
            )

        label = str(source_label or "")
        ext = str(file_type or "").lstrip(".").lower()
        if not ext and "." in label:
            ext = label.rsplit(".", 1)[-1].lower()

        # Build a local search query from file type and label
        query_parts = []
        if ext:
            query_parts.append(ext)
        # Add a domain hint based on known extensions
        domain_hints: dict[str, str] = {
            "ttf": "font", "otf": "font", "woff": "font", "woff2": "font",
            "mp3": "audio", "wav": "audio", "flac": "audio", "ogg": "audio",
            "mp4": "video", "mov": "video", "avi": "video",
            "jpg": "image", "jpeg": "image", "png": "image", "gif": "image",
            "pdf": "document", "docx": "document", "txt": "text",
            "zip": "archive", "tar": "archive", "gz": "archive",
            "py": "code", "js": "code", "ts": "code", "rs": "code",
        }
        if ext in domain_hints:
            query_parts.append(domain_hints[ext])
        if label:
            query_parts.append(label)

        query = " ".join(dict.fromkeys(query_parts))  # deduplicate, preserve order

        return AgentDirective(
            should_execute=True,
            action="browser_search",
            action_payload={"query": query, "source_key": source_key},
            loop_iteration=iteration,
            reason=f"Open assessment state with h_lambda={h_lambda:.2f}; local search suggested",
        )

    def note_browser_navigation(self, source_key: str, url: str) -> None:
        """Protokolliert eine Navigation für einen source_key (für Loop-Tracking)."""
        if source_key not in self._navigation_history:
            self._navigation_history[source_key] = []
        self._navigation_history[source_key].append(str(url))
