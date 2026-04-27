"""Windows-Autostart-Verwaltung fuer den Aether-Hintergrundprozess.

Registriert einen HKCU-Registry-Run-Eintrag damit start.py beim
Windows-Benutzerlogin automatisch gestartet wird.

Benoetigt keine Administrator-Rechte (wirkt nur fuer aktuellen Benutzer).

Einstellungsschalter:
    data/settings.json -> "ae_autostart": true / false

Auf Nicht-Windows-Systemen sind alle Funktionen sichere No-Ops.
"""
from __future__ import annotations

import sys
from pathlib import Path

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "AetherDeltaEngine"
_ROOT = Path(__file__).resolve().parent.parent


def _get_launch_command() -> str:
    """Baut den Windows-Startbefehl: pythonw start.py (kein Konsolenfenster)."""
    python_exe = Path(sys.executable)
    # Bevorzugt pythonw.exe — oeffnet kein schwarzes Konsolenfenster
    pythonw = python_exe.parent / "pythonw.exe"
    if not pythonw.is_file():
        pythonw = python_exe
    script = _ROOT / "start.py"
    return f'"{pythonw}" "{script}"'


def is_registered() -> bool:
    """Gibt True zurueck wenn der Autostart-Eintrag bereits existiert."""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, _VALUE_NAME)
            return True
    except OSError:
        return False
    except Exception:
        return False


def register() -> bool:
    """Schreibt den Autostart-Eintrag in HKCU Run.

    Primaer: Windows-Registry HKCU Run.
    Fallback: .bat-Datei im Windows-Startup-Ordner.
    Gibt True bei Erfolg zurueck.
    """
    if sys.platform != "win32":
        return False
    cmd = _get_launch_command()
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, _VALUE_NAME, 0, winreg.REG_SZ, cmd)
        return True
    except Exception:
        return _register_startup_folder(cmd)


def _register_startup_folder(cmd: str) -> bool:
    """Fallback: erstellt eine .bat-Datei im Windows-Startup-Ordner."""
    try:
        import os
        startup = (
            Path(os.environ.get("APPDATA", ""))
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup"
        )
        if not startup.is_dir():
            return False
        bat = startup / "AetherDeltaEngine.bat"
        bat.write_text(
            f"@echo off\nstart \"\" {cmd}\n",
            encoding="utf-8",
        )
        return True
    except Exception:
        return False


def unregister() -> bool:
    """Entfernt den Autostart-Eintrag. Gibt True bei Erfolg zurueck."""
    if sys.platform != "win32":
        return False
    removed = False
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, _VALUE_NAME)
        removed = True
    except FileNotFoundError:
        removed = True
    except Exception:
        pass

    # Auch Startup-Ordner-Fallback bereinigen
    try:
        import os
        startup = (
            Path(os.environ.get("APPDATA", ""))
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup"
        )
        bat = startup / "AetherDeltaEngine.bat"
        if bat.is_file():
            bat.unlink()
    except Exception:
        pass

    return removed
