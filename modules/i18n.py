"""
Aether Internationalisierung (i18n) — Deutsch / English.

Verwendung:
    from modules.i18n import t, set_language, get_language

    set_language("de")   # oder "en"
    print(t("welcome"))  # -> "Willkommen bei Aether"

Sprache wird in data/settings.json gespeichert und beim naechsten
Start automatisch geladen.
"""

from __future__ import annotations

import json
from pathlib import Path

_LANG: str = "de"
_SETTINGS_FILE: Path | None = None

# ---------------------------------------------------------------------------
# Übersetzungstabelle
# ---------------------------------------------------------------------------
_STRINGS: dict[str, dict[str, str]] = {
    # --- Allgemein ---
    "welcome": {
        "de": "Willkommen bei Aether",
        "en": "Welcome to Aether",
    },
    "language": {
        "de": "Sprache",
        "en": "Language",
    },
    "settings": {
        "de": "Einstellungen",
        "en": "Settings",
    },
    "cancel": {
        "de": "Abbrechen",
        "en": "Cancel",
    },
    "ok": {
        "de": "OK",
        "en": "OK",
    },
    "yes": {
        "de": "Ja",
        "en": "Yes",
    },
    "no": {
        "de": "Nein",
        "en": "No",
    },
    "error": {
        "de": "Fehler",
        "en": "Error",
    },
    "warning": {
        "de": "Warnung",
        "en": "Warning",
    },
    "info": {
        "de": "Info",
        "en": "Info",
    },
    "save": {
        "de": "Speichern",
        "en": "Save",
    },
    "close": {
        "de": "Schließen",
        "en": "Close",
    },
    "start": {
        "de": "Starten",
        "en": "Start",
    },
    "stop": {
        "de": "Stoppen",
        "en": "Stop",
    },
    "status": {
        "de": "Status",
        "en": "Status",
    },
    # --- Monitor ---
    "monitor_start": {
        "de": "Hintergrundüberwachung gestartet",
        "en": "Background monitoring started",
    },
    "monitor_stop": {
        "de": "Hintergrundüberwachung beendet",
        "en": "Background monitoring stopped",
    },
    "monitor_interval": {
        "de": "Überwachungsintervall (Sekunden)",
        "en": "Monitoring interval (seconds)",
    },
    "monitor_running": {
        "de": "Überwachung läuft",
        "en": "Monitoring active",
    },
    "monitor_stopped": {
        "de": "Überwachung gestoppt",
        "en": "Monitoring stopped",
    },
    "snapshots_stored": {
        "de": "Snapshots gespeichert",
        "en": "Snapshots stored",
    },
    # --- Optimierung ---
    "optimize_run": {
        "de": "Optimierung wird ausgeführt…",
        "en": "Running optimization…",
    },
    "optimize_done": {
        "de": "Optimierung abgeschlossen",
        "en": "Optimization complete",
    },
    "optimize_rollback": {
        "de": "Änderungen rückgängig gemacht",
        "en": "Changes rolled back",
    },
    "optimize_consent": {
        "de": "Soll Aether diese Optimierung automatisch anwenden?",
        "en": "Should Aether apply this optimization automatically?",
    },
    "optimize_no_issues": {
        "de": "Keine Optimierungsmöglichkeiten gefunden.",
        "en": "No optimization opportunities found.",
    },
    "autopilot_on": {
        "de": "Autopilot aktiviert",
        "en": "Autopilot enabled",
    },
    "autopilot_off": {
        "de": "Autopilot deaktiviert",
        "en": "Autopilot disabled",
    },
    "autopilot_consent": {
        "de": "Autopilot einmalig aktivieren? Wiederkehrende Optimierungen werden selbstständig angewendet.",
        "en": "Enable autopilot once? Recurring optimizations will be applied automatically.",
    },
    "rollback_available": {
        "de": "Rollback verfügbar",
        "en": "Rollback available",
    },
    # --- Hardware ---
    "hw_old_detected": {
        "de": "Ältere Hardware erkannt – Aether wechselt in den ressourcenschonenden Modus.",
        "en": "Older hardware detected – Aether switches to resource-efficient mode.",
    },
    "hw_cpu": {
        "de": "Prozessor",
        "en": "Processor",
    },
    "hw_ram": {
        "de": "Arbeitsspeicher",
        "en": "RAM",
    },
    "hw_disk": {
        "de": "Festplatte",
        "en": "Drive",
    },
    "hw_gpu": {
        "de": "Grafikkarte",
        "en": "GPU",
    },
    # --- Shanway Vorschläge ---
    "suggestion_disable_services": {
        "de": "Ich habe {n} Dienste gefunden, die Speicher belegen, aber nicht benötigt werden. Soll ich sie deaktivieren?",
        "en": "I found {n} services consuming memory but not needed. Should I disable them?",
    },
    "suggestion_hdd_thrashing": {
        "de": "Dieses Programm verursacht ständige Festplattenzugriffe – das bremst deinen Rechner aus. Empfehlung: Nutze eine alternative Software.",
        "en": "This program causes constant disk activity – slowing your system down. Recommendation: use an alternative.",
    },
    "suggestion_high_cpu": {
        "de": "Prozess '{name}' belegt dauerhaft {cpu:.0f}% CPU. Soll ich die Priorität senken?",
        "en": "Process '{name}' is constantly using {cpu:.0f}% CPU. Should I lower its priority?",
    },
    "suggestion_memory_fragmentation": {
        "de": "Hohe Speicherfragmentierung erkannt. Empfehlung: Weniger Programme gleichzeitig öffnen.",
        "en": "High memory fragmentation detected. Recommendation: open fewer programs at once.",
    },
    "suggestion_aero": {
        "de": "Visuelle Effekte (Transparenz/Aero) belasten alte Hardware stark. Soll ich sie deaktivieren?",
        "en": "Visual effects (transparency/Aero) put heavy load on older hardware. Should I disable them?",
    },
    # --- Ethics / Analyse ---
    "ethics_clean": {
        "de": "Strukturell unauffällig",
        "en": "Structurally unremarkable",
    },
    "ethics_obfuscated": {
        "de": "Mögliche Verschleierung erkannt (hohe Entropieabweichung, Zipf-Verletzung)",
        "en": "Possible obfuscation detected (high entropy deviation, Zipf violation)",
    },
    "ethics_malware_pattern": {
        "de": "Strukturelle Ähnlichkeit zu bekannten Anomalie-Mustern",
        "en": "Structural similarity to known anomaly patterns",
    },
    # --- Report ---
    "report_heading": {
        "de": "Aether System-Bericht",
        "en": "Aether System Report",
    },
    "report_meta_anchors": {
        "de": "Meta-Anker (erkannte Muster)",
        "en": "Meta-anchors (detected patterns)",
    },
    "report_suggestions": {
        "de": "Optimierungsvorschläge",
        "en": "Optimization suggestions",
    },
    "report_no_anchors": {
        "de": "Noch keine Meta-Anker – weitere Beobachtung nötig.",
        "en": "No meta-anchors yet – more observation needed.",
    },
    # --- GUI ---
    "gui_title": {
        "de": "Aether – Strukturanalyse",
        "en": "Aether – Structural Analysis",
    },
    "gui_tab_monitor": {
        "de": "Überwachung",
        "en": "Monitor",
    },
    "gui_tab_optimize": {
        "de": "Optimierung",
        "en": "Optimize",
    },
    "gui_tab_report": {
        "de": "Bericht",
        "en": "Report",
    },
    "gui_tab_settings": {
        "de": "Einstellungen",
        "en": "Settings",
    },
    "gui_cpu_label": {
        "de": "CPU",
        "en": "CPU",
    },
    "gui_ram_label": {
        "de": "RAM",
        "en": "RAM",
    },
    "gui_processes": {
        "de": "Prozesse",
        "en": "Processes",
    },
    "language_choose": {
        "de": "Sprache wählen / Choose language",
        "en": "Choose language / Sprache wählen",
    },
    "language_restart_hint": {
        "de": "Sprachänderung wird beim nächsten Neustart vollständig wirksam.",
        "en": "Language change takes full effect on next restart.",
    },
}


def _load_settings(settings_file: Path) -> dict:
    if settings_file.exists():
        try:
            return json.loads(settings_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_settings(settings_file: Path, data: dict) -> None:
    try:
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def init(settings_dir: Path | str | None = None) -> None:
    """
    Initialisiert i18n und laedt die gespeicherte Spracheinstellung.
    Muss vor dem ersten Aufruf von t() aufgerufen werden wenn
    persistente Sprache gewuenscht ist.
    """
    global _SETTINGS_FILE, _LANG
    if settings_dir is None:
        settings_dir = Path(__file__).resolve().parent.parent / "data"
    _SETTINGS_FILE = Path(settings_dir) / "settings.json"
    data = _load_settings(_SETTINGS_FILE)
    lang = str(data.get("language", "de")).lower().strip()
    if lang in ("en", "de"):
        _LANG = lang


def set_language(lang: str, persist: bool = True) -> None:
    """Setzt die aktive Sprache ('de' oder 'en')."""
    global _LANG
    lang = lang.lower().strip()
    if lang not in ("de", "en"):
        return
    _LANG = lang
    if persist and _SETTINGS_FILE is not None:
        data = _load_settings(_SETTINGS_FILE)
        data["language"] = lang
        _save_settings(_SETTINGS_FILE, data)


def get_language() -> str:
    """Gibt die aktive Sprache zurueck ('de' oder 'en')."""
    return _LANG


def t(key: str, **kwargs: object) -> str:
    """
    Gibt die Uebersetzung fuer *key* in der aktiven Sprache zurueck.
    Unbekannte Schluessel werden als Fallback mit dem Key selbst zurueckgegeben.
    Format-Platzhalter werden via str.format(**kwargs) aufgeloest.
    """
    entry = _STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(_LANG) or entry.get("de") or key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return text


def choose_language_cli() -> str:
    """
    Interaktive Sprachauswahl in der Konsole.
    Gibt 'de' oder 'en' zurueck.
    """
    print("\n" + t("language_choose"))
    print("  [1] Deutsch")
    print("  [2] English")
    choice = input("  > ").strip()
    lang = "en" if choice == "2" else "de"
    set_language(lang)
    return lang


def choose_language_tk(parent=None) -> str:
    """
    Sprachauswahl via Tkinter-Dialog.
    Gibt 'de' oder 'en' zurueck.
    """
    try:
        import tkinter as tk
        from tkinter import ttk

        root = parent or tk.Tk()
        if parent is None:
            root.withdraw()

        dialog = tk.Toplevel(root)
        dialog.title(t("language_choose"))
        dialog.resizable(False, False)
        dialog.grab_set()

        tk.Label(dialog, text=t("language_choose"), font=("Helvetica", 12, "bold"),
                 pady=12, padx=20).pack()

        selected = tk.StringVar(value=_LANG)
        frame = tk.Frame(dialog, padx=20, pady=8)
        frame.pack()
        tk.Radiobutton(frame, text="Deutsch", variable=selected, value="de").pack(anchor="w")
        tk.Radiobutton(frame, text="English", variable=selected, value="en").pack(anchor="w")

        result: list[str] = [_LANG]

        def _ok() -> None:
            result[0] = selected.get()
            dialog.destroy()

        tk.Button(dialog, text="OK", command=_ok, width=10,
                  pady=4).pack(pady=(8, 16))
        dialog.wait_window()

        lang = result[0]
        set_language(lang)
        return lang
    except Exception:
        return _LANG
