"""Log- und Screenshot-System fuer Aether."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from matplotlib.figure import Figure

from .analysis_engine import AetherFingerprint


class LogSystem:
    """Speichert Analyseprotokolle und Visualisierungs-Screenshots dauerhaft."""

    def __init__(self, log_dir: str, screenshot_dir: str) -> None:
        """
        Initialisiert das Logsystem und erzeugt die Zielordner.

        Args:
            log_dir: Verzeichnis fuer JSON-Logs.
            screenshot_dir: Verzeichnis fuer PNG-Screenshots.
        """
        self.log_dir = Path(log_dir)
        self.screenshot_dir = Path(screenshot_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    def _verdict_comment(self, verdict: str) -> str:
        """Erzeugt einen lesbaren deutschen Kommentar passend zum Urteil."""
        if verdict == "CRITICAL":
            return "Kritischer Befund: starke Unregelmaessigkeiten, sofortige Pruefung empfohlen."
        if verdict == "SUSPICIOUS":
            return "Auffaelliger Befund: lokale Verwerfungen erkannt, vertiefte Analyse sinnvoll."
        return "Unauffaelliger Befund: Feldstruktur wirkt konsistent und stabil."

    def write_analysis_log(self, fingerprint: AetherFingerprint) -> Path:
        """
        Schreibt einen Analyseeintrag als JSON-Datei.

        Args:
            fingerprint: Analyseergebnis als AetherFingerprint.

        Returns:
            Pfad zur geschriebenen Logdatei.
        """
        payload = fingerprint.to_dict()
        payload["comment_de"] = self._verdict_comment(fingerprint.verdict)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        target = self.log_dir / f"{stamp}.json"
        try:
            target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Logdatei konnte nicht geschrieben werden: {exc}") from exc
        return target

    def save_screenshot(self, figure: Figure) -> Path:
        """
        Speichert eine Matplotlib-Figure als PNG.

        Args:
            figure: Zu speichernde Visualisierung.

        Returns:
            Pfad zur Screenshot-Datei.
        """
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        target = self.screenshot_dir / f"{stamp}.png"
        try:
            figure.savefig(target, dpi=140, facecolor=figure.get_facecolor(), bbox_inches="tight")
        except OSError as exc:
            raise RuntimeError(f"Screenshot konnte nicht gespeichert werden: {exc}") from exc
        return target

    def get_recent_logs(self) -> list[dict[str, Any]]:
        """Liest die zehn neuesten Logeintraege als Dictionary-Liste ein."""
        items: list[dict[str, Any]] = []
        files = sorted(self.log_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:10]
        for file_path in files:
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                data["_file"] = file_path.name
                items.append(data)
            except (OSError, json.JSONDecodeError):
                continue
        return items
