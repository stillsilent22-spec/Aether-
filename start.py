"""Einziger Einstiegspunkt fuer Aether."""

from __future__ import annotations

import importlib
import importlib.util
import multiprocessing as mp
import os
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# i18n frühzeitig initialisieren (vor allen anderen Importen)
# ---------------------------------------------------------------------------
try:
    from modules.i18n import init as _i18n_init, t, get_language, set_language
    _I18N_OK = True
except Exception:
    _I18N_OK = False
    def t(key: str, **kwargs) -> str:  # type: ignore[misc]
        return key

try:
    import winshell
except Exception:  # pragma: no cover - optionale Packaging-Abhaengigkeit
    winshell = None

try:
    from win32com.client import Dispatch
except Exception:  # pragma: no cover - optionale Packaging-Abhaengigkeit
    Dispatch = None


if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent

if not (PROJECT_ROOT / "keys" / "node_secret.key").exists():
    print("[AETHER] Kein Node initialisiert. Ausfuehren: python node_init.py")
    sys.exit(1)

REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"
MIN_PYTHON = (3, 10)
REQUIRED_IMPORTS = {
    "numpy": "numpy",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "psutil": "psutil",
    "sounddevice": "sounddevice",
    "SpeechRecognition": "speech_recognition",
    "pyinstaller": "PyInstaller",
    "tkinterdnd2": "tkinterdnd2",
    "opencv-python": "cv2",
    "pillow": "PIL",
    "pywebview": "webview",
    "cryptography": "cryptography",
    "winshell": "winshell",
    "pywin32": "win32com.client",
}


def check_python_version() -> None:
    """Prueft, ob mindestens Python 3.10 verwendet wird."""
    if sys.version_info < MIN_PYTHON:
        major, minor = MIN_PYTHON
        raise RuntimeError(
            f"Python {major}.{minor} oder neuer wird benoetigt. "
            f"Gefunden: {sys.version_info.major}.{sys.version_info.minor}."
        )


def _python_version_tuple(executable: Path) -> tuple[int, int] | None:
    """Liest die Major-/Minor-Version eines Kandidaten robust aus."""
    try:
        output = subprocess.check_output(
            [str(executable), "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        major_text, minor_text = output.split(".", 1)
        return int(major_text), int(minor_text)
    except Exception:
        return None


def find_supported_python() -> Path | None:
    """Sucht lokal nach einer installierten Python-Version >= Mindestversion."""
    current = Path(sys.executable).resolve()
    roots = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python",
        Path(os.environ.get("ProgramFiles", "")),
        Path(os.environ.get("ProgramFiles(x86)", "")),
    ]
    candidates: list[Path] = []
    for root in roots:
        if not str(root).strip() or not root.exists():
            continue
        try:
            for candidate in root.rglob("python.exe"):
                resolved = candidate.resolve()
                if resolved == current:
                    continue
                candidates.append(resolved)
        except Exception:
            continue
    seen: set[str] = set()
    for candidate in sorted(candidates, reverse=True):
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        version = _python_version_tuple(candidate)
        if version is not None and version >= MIN_PYTHON:
            return candidate
    return None


def ensure_supported_python() -> None:
    """Wechselt nach Moeglichkeit automatisch auf eine passende Python-Installation."""
    if sys.version_info >= MIN_PYTHON:
        return
    candidate = find_supported_python()
    if candidate is None:
        check_python_version()
        return
    print(f"Wechsle automatisch auf {candidate} ...")
    os.execv(str(candidate), [str(candidate), str(PROJECT_ROOT / "start.py")])


def find_missing_dependencies() -> list[str]:
    """Ermittelt fehlende Abhaengigkeiten ueber direkte Importtests."""
    missing: list[str] = []
    for package_name, import_name in REQUIRED_IMPORTS.items():
        try:
            importlib.import_module(import_name)
        except Exception:
            missing.append(package_name)
    return missing


def install_requirements() -> None:
    """Installiert alle Abhaengigkeiten aus requirements.txt."""
    if not REQUIREMENTS_FILE.exists():
        raise RuntimeError("requirements.txt wurde nicht gefunden.")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)])


def restart_application() -> None:
    """Startet das Programm nach erfolgreicher Installation neu."""
    os.execv(sys.executable, [sys.executable, str(PROJECT_ROOT / "start.py")])


def restart_application_with_args(args: list[str] | None = None) -> None:
    """Startet das Programm nach erfolgreicher Installation mit erhaltenen CLI-Flags neu."""
    argv = [sys.executable, str(PROJECT_ROOT / "start.py")]
    if args:
        argv.extend([str(item) for item in list(args) if str(item).strip()])
    os.execv(sys.executable, argv)


def _desktop_dir() -> Path | None:
    """Ermittelt den Desktop-Pfad plattformunabhaengig."""
    # Windows: winshell oder Fallback
    if sys.platform.startswith("win"):
        if winshell is not None:
            try:
                d = Path(str(winshell.desktop())).expanduser()
                if d.exists():
                    return d
            except Exception:
                pass
        fallback = Path.home() / "Desktop"
        return fallback if fallback.exists() else None
    # macOS
    if sys.platform == "darwin":
        d = Path.home() / "Desktop"
        return d if d.exists() else None
    # Linux/XDG
    import os
    xdg = os.environ.get("XDG_DESKTOP_DIR", "")
    if xdg:
        d = Path(xdg)
        if d.exists():
            return d
    d = Path.home() / "Desktop"
    return d if d.exists() else None


def _desktop_shortcut_path() -> Path | None:
    """Gibt den Pfad fuer den plattformspezifischen Shortcut zurueck."""
    d = _desktop_dir()
    if d is None:
        return None
    if sys.platform.startswith("win"):
        return d / "Aether.lnk"
    if sys.platform == "darwin":
        return d / "Aether.command"
    return d / "aether.desktop"


def ensure_desktop_shortcut() -> None:
    """
    Erstellt beim ersten Start einen Desktop-Shortcut — plattformunabhaengig.
    Windows: .lnk via pywin32
    macOS:   .command Shell-Script
    Linux:   .desktop XDG-Eintrag
    """
    if not getattr(sys, "frozen", False):
        return
    shortcut_path = _desktop_shortcut_path()
    if shortcut_path is None:
        append_startup_trace("shortcut_skip desktop_unavailable")
        return
    if shortcut_path.exists():
        return
    exe_path = Path(sys.executable).resolve()
    try:
        shortcut_path.parent.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            if winshell is None or Dispatch is None:
                append_startup_trace("shortcut_skip missing winshell/pywin32")
                return
            shell = Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(str(shortcut_path))
            shortcut.Targetpath = str(exe_path)
            shortcut.WorkingDirectory = str(exe_path.parent)
            shortcut.IconLocation = f"{exe_path},0"
            shortcut.Description = "Aether"
            shortcut.save()
        elif sys.platform == "darwin":
            shortcut_path.write_text(
                f"#!/bin/bash\ncd '{exe_path.parent}'\nexec '{exe_path}'\n",
                encoding="utf-8",
            )
            shortcut_path.chmod(0o755)
        else:
            shortcut_path.write_text(
                "[Desktop Entry]\n"
                "Version=1.0\n"
                "Type=Application\n"
                "Name=Aether\n"
                f"Exec={exe_path}\n"
                f"Path={exe_path.parent}\n"
                "Terminal=false\n"
                "Categories=Utility;\n",
                encoding="utf-8",
            )
            shortcut_path.chmod(0o755)
        append_startup_trace(f"shortcut_created {shortcut_path}")
    except Exception as exc:
        append_startup_trace(f"shortcut_error {type(exc).__name__}: {exc}")


def append_startup_trace(message: str) -> None:
    """Schreibt einen knappen Frozen-Startverlauf fuer spaetere Diagnose mit."""
    try:
        data_dir = PROJECT_ROOT / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        with (data_dir / "startup_trace.log").open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} {message}\n")
    except Exception:
        pass


def report_startup_error(exc: Exception) -> None:
    """Macht Frozen-Startfehler sichtbar und schreibt sie lokal weg."""
    error_text = (
        f"[{Path(sys.executable if getattr(sys, 'frozen', False) else __file__).name}] {type(exc).__name__}: {exc}\n\n"
        f"{traceback.format_exc()}"
    )
    append_startup_trace(f"startup_error {type(exc).__name__}: {exc}")
    try:
        data_dir = PROJECT_ROOT / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "startup_error.log").write_text(error_text, encoding="utf-8")
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                0,
                "Aether konnte nicht gestartet werden.\n\n"
                f"{type(exc).__name__}: {exc}\n\n"
                f"Details: {str(PROJECT_ROOT / 'data' / 'startup_error.log')}",
                "Aether Startfehler",
                0x10,
            )
        except Exception:
            pass


def report_security_lock(summary: str) -> None:
    """Zeigt einen klaren Sperrdialog bei Manipulation des Sicherheitskerns."""
    message = (
        "Aether Sicherheits-Lock\n\n"
        "Manipulation an Kernschutz oder Integritaetsbasis erkannt.\n"
        "Der Hauptstart wird im PROD-Modus blockiert.\n\n"
        f"{summary}\n\n"
        f"Pruefe: {PROJECT_ROOT / 'data' / 'registry.db'}\n"
        f"Audit: {PROJECT_ROOT / 'data' / 'startup_trace.log'}"
    )
    append_startup_trace("security_lock " + summary)
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, message, "Aether Sicherheits-Lock", 0x10)
    except Exception:
        pass


def confirm_local_update_rebaseline(summary: str) -> bool:
    """Fragt bei rein lokalem Node-Update nach einer kontrollierten Uebernahme als neue Basis."""
    message = (
        "Aether Sicherheitspruefung\n\n"
        "Die aktuelle Installation weicht vom gespeicherten Basiszustand ab.\n"
        "Wenn du dieses Update selbst ausgefuehrt hast, kannst du den aktuellen Stand als neue lokale Basis uebernehmen.\n\n"
        f"{summary}\n\n"
        "Nur fuer eigene, vertrauenswuerdige Updates bestaetigen."
    )
    try:
        import ctypes

        result = ctypes.windll.user32.MessageBoxW(
            0,
            message,
            "Aether Lokales Update bestaetigen",
            0x00000004 | 0x00000020,
        )
        return int(result) == 6
    except Exception:
        return False


def _show_first_start_welcome_cli() -> None:
    """
    Gibt Shanways Erststart-Hinweis in der Konsole aus (keine GUI nötig).
    Markiert den ersten Start als gesehen, damit der Text nicht wiederholt wird.
    """
    try:
        from modules.i18n import t as _t, get_language
        lang = get_language()
        title = _t("first_start_title")
        body = _t("first_start_body")
        ack = _t("first_start_ack")
        border = "=" * 64
        print(f"\n{border}")
        print(f"  Shanway: {title}")
        print(border)
        for line in body.splitlines():
            print(f"  {line}")
        print(border)
        input(f"\n  [{ack}]  → Enter drücken / Press Enter\n")
        # Merke, dass der Hinweis gezeigt wurde
        settings_path = PROJECT_ROOT / "data" / "settings.json"
        import json as _json
        data: dict = {}
        if settings_path.exists():
            try:
                data = _json.loads(settings_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        data["first_start_shown"] = True
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass  # Erststart-Hinweis ist nicht kritisch


def show_first_start_welcome_tk(parent=None) -> None:
    """
    Zeigt Shanways Erststart-Hinweis als modalen Tkinter-Dialog.
    Wird von der GUI beim ersten Öffnen aufgerufen.
    """
    try:
        import tkinter as tk
        from tkinter import ttk
        from modules.i18n import t as _t, get_language

        root_or_parent = parent
        win = tk.Toplevel(root_or_parent) if root_or_parent else tk.Tk()
        win.title(_t("first_start_title"))
        win.configure(bg="#081120")
        win.resizable(False, False)
        try:
            win.grab_set()
        except Exception:
            pass

        BG, FG, ACCENT = "#081120", "#E7F4FF", "#7DE8A7"

        tk.Label(win, text=f"  Shanway: {_t('first_start_title')}",
                 bg=BG, fg=ACCENT, font=("Segoe UI", 13, "bold"),
                 anchor="w").pack(fill="x", padx=16, pady=(16, 4))
        tk.Frame(win, bg="#2A3A7A", height=1).pack(fill="x", padx=8)

        txt = tk.Text(win, width=62, height=16,
                      bg="#0C172B", fg=FG, font=("Segoe UI", 10),
                      relief="flat", padx=12, pady=10, wrap="word",
                      state="normal", cursor="arrow")
        txt.insert("1.0", _t("first_start_body"))
        txt.configure(state="disabled")
        txt.pack(padx=16, pady=12)

        def _ack() -> None:
            # Merke, dass der Hinweis gezeigt wurde
            try:
                import json as _json
                settings_path = PROJECT_ROOT / "data" / "settings.json"
                data: dict = {}
                if settings_path.exists():
                    data = _json.loads(settings_path.read_text(encoding="utf-8"))
                data["first_start_shown"] = True
                settings_path.parent.mkdir(parents=True, exist_ok=True)
                settings_path.write_text(_json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            win.destroy()

        tk.Button(win, text=f"✓  {_t('first_start_ack')}",
                  command=_ack, bg="#1E3A6A", fg=ACCENT,
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  padx=16, pady=8).pack(pady=(0, 16))

        if root_or_parent:
            win.wait_window()
        else:
            win.mainloop()
    except Exception:
        pass  # Dialog ist nicht kritisch


def bootstrap(shanway_raster_insight: bool = False) -> None:
    """Initialisiert alle Kernmodule in der vorgegebenen Reihenfolge und startet die GUI."""
    os.chdir(PROJECT_ROOT)
    append_startup_trace("bootstrap_begin")

    from modules.registry import AetherRegistry
    from modules.security_engine import SecurityManager

    registry = AetherRegistry(str(PROJECT_ROOT / "data" / "registry.db"))
    append_startup_trace("registry_ready")
    security_manager = SecurityManager(registry)
    append_startup_trace("login_prompt_open")
    security_session = security_manager.prompt_login()
    append_startup_trace(f"login_ok user={security_session.username}")

    from modules.analysis_engine import AnalysisEngine
    from modules.audio_engine import AudioEngine
    from modules.blockchain_interface import AetherChain
    from modules.gui import VeiraGUI
    from modules.log_system import LogSystem
    from modules.security_monitor import AetherSecurityMonitor
    from modules.session_engine import SessionContext
    from modules.scene_renderer import AetherSceneRenderer
    from modules.ae_evolution_core import AEAlgorithmVault, AetherAnchorInterpreter

    session_context = SessionContext(security_session=security_session)
    try:
        from modules.swarm_sync import discover_nodes, pull_anchors

        new_packs = pull_anchors()
        nodes = discover_nodes()
        print(f"[SWARM] {len(nodes)} Node(s) | {len(new_packs)} neue Pack(s)")
    except Exception as err:
        print(f"[SWARM WARN] Sync uebersprungen: {err}")
    security_monitor = AetherSecurityMonitor(PROJECT_ROOT, registry)
    security_snapshot = security_monitor.run_integrity_check(
        session_context=session_context,
        mode=str(getattr(session_context, "security_mode", "PROD")),
    )
    if bool(dict(getattr(security_snapshot, "policy", {}) or {}).get("fail_closed_lock", False)):
        if security_monitor.can_adopt_current_node(security_snapshot, session_context) and confirm_local_update_rebaseline(
            str(getattr(security_snapshot, "summary", "Security lock active."))
        ):
            security_snapshot = security_monitor.adopt_current_node_as_baseline(
                session_context=session_context,
                mode=str(getattr(session_context, "security_mode", "PROD")),
            )
        if bool(dict(getattr(security_snapshot, "policy", {}) or {}).get("fail_closed_lock", False)):
            report_security_lock(str(getattr(security_snapshot, "summary", "Security lock active.")))
            return
    log_system = LogSystem(str(PROJECT_ROOT / "data" / "logs"), str(PROJECT_ROOT / "data" / "screenshots"))
    renderer = AetherSceneRenderer()
    audio_engine = AudioEngine()
    chain = AetherChain(
        endpoint="local://aether-fingerprint-chain",
        ledger_path=PROJECT_ROOT / "data" / "fingerprint_chain.jsonl",
        registry=registry,
    )
    analysis_engine = AnalysisEngine(session_context=session_context, chain=chain, registry=registry)
    ae_vault = AEAlgorithmVault(export_dir=PROJECT_ROOT / "data" / "aelab_vault")
    ae_state = registry.load_ae_vault_state(user_id=int(getattr(session_context, "user_id", 0) or 0))
    if ae_state.get("main") or ae_state.get("sub"):
        ae_vault.load_serialized_state(ae_state, clear_existing=True)
    ae_interpreter = AetherAnchorInterpreter(ae_vault)
    session_context.user_settings["shanway_raster_insight"] = bool(shanway_raster_insight)
    gui = VeiraGUI(
        session_context=session_context,
        registry=registry,
        log_system=log_system,
        renderer=renderer,
        audio_engine=audio_engine,
        analysis_engine=analysis_engine,
        security_monitor=security_monitor,
        ae_vault=ae_vault,
        ae_interpreter=ae_interpreter,
    )
    append_startup_trace("gui_run_begin")
    # Ersten-Start-Hinweis anzeigen, falls noch nicht bestätigt
    try:
        import json as _json
        _sp = PROJECT_ROOT / "data" / "settings.json"
        _data = _json.loads(_sp.read_text(encoding="utf-8")) if _sp.exists() else {}
        if not _data.get("first_start_shown"):
            show_first_start_welcome_tk(parent=getattr(gui, "root", None))
    except Exception:
        pass
    gui.run()


def run_roundtrip_smoke_trigger() -> int:
    """Laedt den lokalen Roundtrip-Selbsttest und fuehrt ihn ohne GUI-Start aus."""
    test_path = PROJECT_ROOT / "tests" / "test_lossless_roundtrip.py"
    if not test_path.exists():
        raise RuntimeError(f"Roundtrip-Test nicht gefunden: {test_path}")
    spec = importlib.util.spec_from_file_location("aether_roundtrip_test", str(test_path))
    if spec is None or spec.loader is None:
        raise RuntimeError("Roundtrip-Testmodul konnte nicht geladen werden.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    runner = getattr(module, "run_roundtrip_smoke_test", None)
    if not callable(runner):
        raise RuntimeError("run_roundtrip_smoke_test() fehlt im Roundtrip-Testmodul.")
    result = dict(runner())
    verification = dict(result.get("reconstruction_verification", {}) or {})
    verdict = str(result.get("verdict_reconstruction", "") or "")
    gain = max(
        0.0,
        min(100.0, (1.0 - float(verification.get("compression_ratio", 1.0) or 1.0)) * 100.0),
    )
    if verdict != "CONFIRMED" or not bool(verification.get("verified", False)):
        reason = str(verification.get("reason", "") or result.get("response", "") or "Roundtrip nicht bestaetigt.")
        print(f"Roundtrip fehlgeschlagen: {verdict or 'FAILED'} | {reason}")
        return 1
    print(f"Roundtrip erfolgreich: {verdict}, {gain:.1f}% Gewinn")
    return 0


def main(argv: list[str] | None = None) -> None:
    """Fuehrt Vorpruefungen aus und startet anschliessend Aether."""
    cli_args = list(sys.argv[1:] if argv is None else argv)

    # -- i18n: Sprache laden und ggf. interaktiv waehlen -------------------
    if _I18N_OK:
        _i18n_init(settings_dir=PROJECT_ROOT / "data")
        # --lang de / --lang en als CLI-Flag
        for flag in cli_args:
            if flag.startswith("--lang="):
                set_language(flag.split("=", 1)[1].strip())
            elif flag == "--lang" and cli_args.index(flag) + 1 < len(cli_args):
                set_language(cli_args[cli_args.index(flag) + 1])
        # Beim allerersten Start (keine gespeicherte Einstellung) fragen
        import json as _json
        _settings_path = PROJECT_ROOT / "data" / "settings.json"
        _is_first_start = not _settings_path.exists()
        if _is_first_start and "--no-lang-prompt" not in cli_args:
            from modules.i18n import choose_language_cli
            choose_language_cli()
        # Shanway-Begrüßung beim ersten Start (CLI)
        if _is_first_start and "--no-lang-prompt" not in cli_args:
            _show_first_start_welcome_cli()

    # --- Modus-Flags analysieren ------------------------------------------
    test_roundtrip = "--test-roundtrip" in cli_args
    shanway_raster_insight = "--shanway-raster-insight" in cli_args
    run_monitor = "--monitor" in cli_args
    run_optimize = "--optimize" in cli_args
    run_report = "--report" in cli_args

    try:
        append_startup_trace("main_begin")
        mp.freeze_support()
        ensure_supported_python()
        check_python_version()
        if not getattr(sys, "frozen", False):
            missing = find_missing_dependencies()
            if missing:
                names = ", ".join(missing)
                print(f"{t('warning')}: {names}")
                print("Installation startet automatisch ...")
                install_requirements()
                print("Installation erfolgreich. Anwendung wird neu gestartet ...")
                restart_application_with_args(cli_args)
                return

        # --- --test-roundtrip ------------------------------------------------
        if test_roundtrip:
            append_startup_trace("main_roundtrip_test")
            exit_code = run_roundtrip_smoke_trigger()
            if exit_code != 0:
                raise RuntimeError("Roundtrip-Selbsttest fehlgeschlagen.")
            return

        # --- --monitor -------------------------------------------------------
        if run_monitor:
            _cmd_monitor(cli_args)
            return

        # --- --optimize ------------------------------------------------------
        if run_optimize:
            _cmd_optimize(cli_args)
            return

        # --- --report --------------------------------------------------------
        if run_report:
            _cmd_report(cli_args)
            return

        # --- Normaler GUI-Start ----------------------------------------------
        ensure_desktop_shortcut()
        append_startup_trace("main_bootstrap")
        bootstrap(shanway_raster_insight=shanway_raster_insight)

    except KeyboardInterrupt:
        print("\nProgramm beendet. Auf Wiedersehen.")
    except subprocess.CalledProcessError:
        print("Fehler: Abhaengigkeiten konnten nicht automatisch installiert werden.")
    except Exception as exc:
        report_startup_error(exc)
        print(f"Fehler: {exc}")
        print("Die Anwendung konnte nicht gestartet werden. Bitte Konfiguration und Berechtigungen pruefen.")


# ---------------------------------------------------------------------------
# CLI-Kommandos
# ---------------------------------------------------------------------------

def _cmd_monitor(cli_args: list[str]) -> None:
    """Startet Hintergrundüberwachung im Vordergrund (blockierend)."""
    import signal
    import time as _time

    interval = 30.0
    for a in cli_args:
        if a.startswith("--interval="):
            try:
                interval = float(a.split("=", 1)[1])
            except ValueError:
                pass

    db_path = PROJECT_ROOT / "data" / "process_anchors.db"
    print(t("monitor_start"))
    print(f"  Intervall: {interval:.0f}s | DB: {db_path}")

    from modules.background_monitor import BackgroundMonitor

    def _on_batch(n: int) -> None:
        print(f"  [monitor] {n} {t('snapshots_stored')}", flush=True)

    monitor = BackgroundMonitor(
        db_path=db_path,
        interval=interval,
        on_snapshot_batch=_on_batch,
    )
    monitor.start()

    def _shutdown(signum, frame):  # type: ignore[type-arg]
        print(f"\n{t('monitor_stop')}")
        monitor.stop()
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        while True:
            _time.sleep(60)
    except KeyboardInterrupt:
        print(f"\n{t('monitor_stop')}")
        monitor.stop()


def _cmd_optimize(cli_args: list[str]) -> None:
    """Einmalige Optimierungsanalyse mit optionalem --apply."""
    auto_apply = "--apply" in cli_args

    print(t("optimize_run"))
    from modules.hardware_profiler import HardwareProfiler, HardwareOptimizer
    from modules.process_anchor_store import ProcessAnchorStore
    from modules.autopilot_engine import AutopilotEngine

    hw = HardwareProfiler().profile()
    lang = get_language() if _I18N_OK else "de"
    if hw.is_old_hardware:
        print(t("hw_old_detected"))
    print(f"  CPU: {hw.cpu_name or '?'} | RAM: {hw.ram_total_mb} MB | Disk: {hw.disk_type}")

    optimizer = HardwareOptimizer()
    suggestions = optimizer.analyze()

    if not suggestions:
        print(t("optimize_no_issues"))
        return

    print(f"\n{t('report_suggestions')}:")
    for i, sug in enumerate(suggestions, 1):
        sev_marker = {"high": "(!)", "medium": "(*)", "low": "(i)"}[sug.severity]
        print(f"  {i}. {sev_marker} {sug.title(lang)}")

    if auto_apply:
        store = ProcessAnchorStore(PROJECT_ROOT / "data" / "process_anchors.db")
        engine = AutopilotEngine(store, autopilot=False)
        results = engine.apply(
            [s for s in suggestions if s.auto_applicable],
            user_consented=True,
        )
        for r in results:
            status = "OK" if r["success"] else "SKIP"
            print(f"  [{status}] {r['action_type']} -> {r['target']}: {r['message']}")
        rb = store.get_pending_rollbacks()
        if rb:
            print(f"\n{t('rollback_available')}: {len(rb)} {t('optimize_rollback')}")
    else:
        print(f"\n  Tipp: Mit --apply automatisch anwendbare Optimierungen ausfuehren.")

    print(t("optimize_done"))


def _cmd_report(cli_args: list[str]) -> None:
    """Gibt Meta-Anker und Optimierungsvorschlaege als Text-Bericht aus."""
    from modules.process_anchor_store import ProcessAnchorStore
    from modules.hardware_profiler import HardwareProfiler, HardwareOptimizer

    db_path = PROJECT_ROOT / "data" / "process_anchors.db"
    lang = get_language() if _I18N_OK else "de"
    store = ProcessAnchorStore(db_path)

    print(f"\n=== {t('report_heading')} ===\n")

    # Meta-Anker
    meta = store.get_meta_anchors(limit=20)
    print(f"--- {t('report_meta_anchors')} ({len(meta)}) ---")
    if not meta:
        print(f"  {t('report_no_anchors')}")
    else:
        for a in meta:
            print(f"  [{a['trigger_name']} -> {a['effect_name']}] corr={a['correlation']:.2f}")
            print(f"    {a['observation']}")

    # Konsens-Anker
    consensus = store.get_consensus_anchors(limit=10)
    print(f"\n--- Konsens-Anker ({len(consensus)}) ---")
    for c in consensus:
        print(f"  {c['process_name']}: CPU={c['avg_cpu']:.1f}% RAM={c['avg_memory_rss']//1024//1024}MB n={c['sample_count']}")

    # Optimierungsvorschläge
    print(f"\n--- {t('report_suggestions')} ---")
    suggestions = HardwareOptimizer().analyze()
    if not suggestions:
        print(f"  {t('optimize_no_issues')}")
    else:
        for sug in suggestions:
            sev_marker = {"high": "(!)", "medium": "(*)", "low": "(i)"}[sug.severity]
            print(f"  {sev_marker} {sug.title(lang)}")

    # Snapshot-Statistik
    count = store.count_snapshots()
    rb_count = len(store.get_pending_rollbacks())
    print(f"\n--- Stats ---")
    print(f"  {t('snapshots_stored')}: {count}")
    if rb_count:
        print(f"  {t('rollback_available')}: {rb_count}")


if __name__ == "__main__":
    main()
