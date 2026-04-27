"""Permanenter AE-Evolutions-Hintergrundthread.

Wird von start.py als Daemon-Thread gestartet. Prueft alle 60 Sekunden
die aktuelle Systemlast (CPU, RAM) und triggert AELab-Evolution wenn
die Bedingungen erfuellt sind (delta_ratio > Setpoint oder
bits_per_joule < 70% des Referenzwerts).

Einstellungsschalter:
    data/settings.json -> "ae_learning_enabled": true / false
    Wird live gelesen — kein Neustart noetig zum Ein/Ausschalten.

Status-Datei (fuer GUI/Debug):
    data/interbus/evolution_status.json
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CYCLE_INTERVAL_S: int = 60          # Pause zwischen Zyklen in Sekunden
_CPU_WINDOW_SIZE: int = 10           # Anzahl CPU-Samples fuer gleitenden Mittelwert
_BPJ_REFERENCE: float = 1000.0      # Bits-per-Joule Referenz-Baseline

_ROOT = Path(__file__).resolve().parent.parent
_SETTINGS_PATH = _ROOT / "data" / "settings.json"
_STATUS_PATH = _ROOT / "data" / "interbus" / "evolution_status.json"
_VAULT_DIR = _ROOT / "data" / "aelab_vault"

_stop_event = threading.Event()
_thread: threading.Thread | None = None


def _read_settings() -> dict[str, Any]:
    try:
        return json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def is_enabled() -> bool:
    """Prueft ob AE-Hintergrundlernen in den Einstellungen aktiv ist."""
    return bool(_read_settings().get("ae_learning_enabled", True))


def _write_status(payload: dict[str, Any]) -> None:
    try:
        _STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATUS_PATH.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


def _run_one_cycle(cpu_history: list[float]) -> dict[str, Any]:
    """Fuehrt einen einzelnen Mess- und Evolutions-Zyklus aus.

    Gibt ein Status-Dict zurueck das in evolution_status.json gespeichert wird.
    Wirft keine Exceptions — Fehler werden im Rueckgabe-Dict vermerkt.
    """
    from modules.efficiency_monitor import EfficiencyMonitor
    from modules.ae_evolution_core import (
        AEAlgorithmVault,
        should_trigger_ae_evolution,
    )

    monitor = EfficiencyMonitor()
    sample = monitor.sample("orchestrator_cycle")

    # Rollendes CPU-Fenster fuer delta_ratio
    cpu_history.append(sample.cpu_percent)
    if len(cpu_history) > _CPU_WINDOW_SIZE:
        cpu_history.pop(0)

    # delta_ratio: normalisierte Abweichung des letzten CPU-Werts vom Fenstermittel
    if len(cpu_history) >= 2:
        avg = sum(cpu_history) / len(cpu_history)
        delta_ratio = abs(cpu_history[-1] - avg) / max(avg, 1.0)
    else:
        delta_ratio = 0.0

    # Einfache BPJ-Schaetzung: hoher RAM-Druck reduziert effektive Effizienz
    bpj = max(1.0, _BPJ_REFERENCE * (1.0 - sample.ram_percent / 100.0))

    triggered, reason = should_trigger_ae_evolution(
        delta_ratio=delta_ratio,
        bits_per_joule=bpj,
        bpj_reference=_BPJ_REFERENCE,
    )

    evolution_result: dict[str, Any] = {}
    evolution_ran = False
    evolution_error = ""

    if triggered:
        try:
            vault = AEAlgorithmVault(export_dir=_VAULT_DIR)
            data_input: dict[str, Any] = {
                "entropy_mean": delta_ratio * 8.0,
                "h_lambda": bpj / _BPJ_REFERENCE * 4.0,
                "cpu_percent": sample.cpu_percent,
                "ram_percent": sample.ram_percent,
                "threads": sample.threads,
            }
            evolution_result = vault.evolve(data_input)
            evolution_ran = True
        except Exception as exc:
            evolution_error = str(exc)
            logger.warning("[ORCH] AE-Evolution fehlgeschlagen: %s", exc)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "enabled": True,
        "cpu_percent": round(sample.cpu_percent, 2),
        "ram_percent": round(sample.ram_percent, 2),
        "threads": sample.threads,
        "delta_ratio": round(delta_ratio, 6),
        "bpj": round(bpj, 2),
        "triggered": triggered,
        "trigger_reason": reason,
        "evolution_ran": evolution_ran,
        "evolution_error": evolution_error,
        "main_vault_size": int(evolution_result.get("main_vault_size", 0)) if evolution_ran else 0,
        "sub_vault_size": int(evolution_result.get("sub_vault_size", 0)) if evolution_ran else 0,
        "anchor_count": int(evolution_result.get("anchor_count", 0)) if evolution_ran else 0,
    }


def _loop() -> None:
    """Haupt-Schleife des Orchestrator-Daemon-Threads."""
    cpu_history: list[float] = []
    logger.info("[ORCH] AE-Evolutions-Orchestrator gestartet (Intervall: %ds).", _CYCLE_INTERVAL_S)

    while not _stop_event.is_set():
        if is_enabled():
            try:
                status = _run_one_cycle(cpu_history)
                _write_status(status)
                if status.get("triggered"):
                    logger.info(
                        "[ORCH] Evolution ausgefuehrt: main=%d sub=%d grund=%s",
                        status["main_vault_size"],
                        status["sub_vault_size"],
                        status["trigger_reason"],
                    )
            except Exception as exc:
                logger.warning("[ORCH] Zyklus-Fehler: %s", exc)
                _write_status({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "enabled": True,
                    "error": str(exc),
                })
        else:
            _write_status({
                "ts": datetime.now(timezone.utc).isoformat(),
                "enabled": False,
                "status": "deaktiviert_via_einstellungen",
            })

        _stop_event.wait(timeout=_CYCLE_INTERVAL_S)

    logger.info("[ORCH] AE-Evolutions-Orchestrator gestoppt.")


def start() -> threading.Thread:
    """Startet den Orchestrator als Hintergrund-Daemon-Thread. Non-blocking."""
    global _thread, _stop_event
    if _thread is not None and _thread.is_alive():
        return _thread
    _stop_event.clear()
    _thread = threading.Thread(target=_loop, name="AEOrchestrator", daemon=True)
    _thread.start()
    return _thread


def stop() -> None:
    """Stoppt den Orchestrator-Thread sauber (wartet max. 5s)."""
    _stop_event.set()
    if _thread is not None:
        _thread.join(timeout=5.0)
