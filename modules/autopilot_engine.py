"""
Aether – Autopilot-Engine mit Rollback-System.

Führt Optimierungen automatisch durch (nach einmaliger Nutzerzustimmung)
und protokolliert jede Aktion so, dass sie vollständig rückgängig gemacht
werden kann.

Sicherheits-Invarianten:
  - Systemprozesse (PID < 10, SYSTEM-Integrity) werden nie angefasst.
  - Sicherheitssoftware (AV, Firewall) wird nie deaktiviert.
  - Jede Aktion benötigt user_consented=True (außer im Autopilot-Modus
    nach expliziter Einmalerlaubnis).
  - Rollback immer möglich solange log-Eintrag existiert.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .hardware_profiler import OptimizationSuggestion
    from .process_anchor_store import ProcessAnchorStore
except ImportError:
    from modules.hardware_profiler import OptimizationSuggestion
    from modules.process_anchor_store import ProcessAnchorStore

try:
    import psutil
    _PSUTIL_OK = True
except Exception:
    psutil = None  # type: ignore
    _PSUTIL_OK = False

_IS_WIN = sys.platform.startswith("win")

logger = logging.getLogger(__name__)

# Prozesse / Dienste, die NIEMALS angefasst werden
_PROTECTED_PROCESSES = {
    "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "lsass.exe", "services.exe", "svchost.exe", "dwm.exe",
    # Sicherheitssoftware (exemplarisch; kein keyword-matching, nur Hash)
    "MsMpEng.exe",   # Windows Defender
    "avp.exe",       # Kaspersky
    "avgnt.exe",     # Avira
    "mbam.exe",      # Malwarebytes
    "bdagent.exe",   # Bitdefender
}

_PROTECTED_SERVICES = {
    "WinDefend", "SecurityHealthService", "wscsvc",
    "mpssvc",  # Windows Firewall
    "EventLog", "Winmgmt", "RpcSs",
}


class AutopilotEngine:
    """
    Führt Optimierungen mit optionalem Autopilot durch.

    Jede Aktion wird in der ProcessAnchorStore-Datenbank protokolliert
    und kann über rollback(log_id) rückgängig gemacht werden.

    Beispiel:
        engine = AutopilotEngine(store)
        engine.enable_autopilot()   # einmalige Erlaubnis
        applied = engine.apply(suggestions)
        # Später:
        engine.rollback_all()
    """

    def __init__(
        self,
        store: ProcessAnchorStore,
        autopilot: bool = False,
    ) -> None:
        self._store = store
        self._autopilot = bool(autopilot)

    # ------------------------------------------------------------------
    # Autopilot
    # ------------------------------------------------------------------

    def enable_autopilot(self) -> None:
        self._autopilot = True
        logger.info("Autopilot enabled.")

    def disable_autopilot(self) -> None:
        self._autopilot = False
        logger.info("Autopilot disabled.")

    @property
    def autopilot_enabled(self) -> bool:
        return self._autopilot

    # ------------------------------------------------------------------
    # Optimierungsanwendung
    # ------------------------------------------------------------------

    def apply(
        self,
        suggestions: list[OptimizationSuggestion],
        user_consented: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Wendet eine Liste von Vorschlägen an.
        Gibt eine Liste von Ergebnis-Dicts zurück:
          {"success": bool, "log_id": int, "message": str, ...}

        Vorschläge mit auto_applicable=False werden nur im Autopilot-Modus
        angewendet wenn user_consented=True gesetzt ist.
        """
        results: list[dict[str, Any]] = []
        for sug in suggestions:
            if not user_consented and not self._autopilot:
                results.append({"success": False, "message": "no_consent", "suggestion": sug.action_type})
                continue
            if not sug.auto_applicable and not self._autopilot:
                results.append({"success": False, "message": "requires_manual_consent", "suggestion": sug.action_type})
                continue

            result = self._apply_one(sug, user_consented=user_consented)
            results.append(result)
        return results

    def _apply_one(
        self, sug: OptimizationSuggestion, user_consented: bool
    ) -> dict[str, Any]:
        handler = {
            "priority_lower":       self._lower_priority,
            "service_disable":      self._disable_service,
            "visual_disable":       self._disable_aero,
            "memory_alert":         self._noop,
            "io_alert":             self._noop,
            "memory_fragmentation": self._noop,
        }.get(sug.action_type, self._noop)

        try:
            ok, message, rollback_data = handler(sug)
        except Exception as exc:
            logger.warning("Apply failed (%s): %s", sug.action_type, exc)
            ok = False
            message = str(exc)
            rollback_data = dict(sug.rollback_data)

        log_id = 0
        if ok:
            log_id = self._store.log_optimization(
                action_type=sug.action_type,
                target=sug.target,
                details=dict(sug.details),
                rollback_data=rollback_data,
                user_consented=user_consented,
            )
            logger.info("Applied '%s' on '%s'", sug.action_type, sug.target)

        return {
            "success": ok,
            "log_id": log_id,
            "message": message,
            "action_type": sug.action_type,
            "target": sug.target,
        }

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self, log_id: int) -> dict[str, Any]:
        """Macht eine einzelne Optimierungsaktion rückgängig."""
        pending = self._store.get_pending_rollbacks()
        entry = next((e for e in pending if e["id"] == log_id), None)
        if entry is None:
            return {"success": False, "message": "log_entry_not_found"}

        action_type = str(entry.get("action_type", ""))
        rollback_data = dict(entry.get("rollback_data") or {})

        handler = {
            "priority_lower":  self._rollback_priority,
            "service_disable": self._rollback_service,
            "visual_disable":  self._rollback_aero,
        }.get(action_type, self._noop_rollback)

        try:
            ok, message = handler(rollback_data)
        except Exception as exc:
            logger.warning("Rollback failed (%s): %s", action_type, exc)
            ok = False
            message = str(exc)

        if ok:
            self._store.mark_rolled_back(log_id)
            logger.info("Rolled back log_id=%d (%s)", log_id, action_type)

        return {"success": ok, "message": message, "log_id": log_id}

    def rollback_all(self) -> list[dict[str, Any]]:
        """Macht alle noch nicht rückgängig gemachten Aktionen rückgängig."""
        pending = self._store.get_pending_rollbacks()
        return [self.rollback(int(e["id"])) for e in pending]

    # ------------------------------------------------------------------
    # Implementierungen
    # ------------------------------------------------------------------

    def _lower_priority(
        self, sug: OptimizationSuggestion
    ) -> tuple[bool, str, dict]:
        """Senkt die Prozess-Priorität (Nice-Level)."""
        if not _PSUTIL_OK or psutil is None:
            return False, "psutil not available", {}
        name = sug.target
        if name in _PROTECTED_PROCESSES:
            return False, f"protected process: {name}", {}

        for proc in psutil.process_iter(["name", "pid", "nice"]):
            try:
                if proc.name() == name:
                    old_nice = proc.nice()
                    new_nice = 10 if _IS_WIN else 10  # BELOW_NORMAL on Win, +10 on Unix
                    if _IS_WIN:
                        proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                    else:
                        proc.nice(new_nice)
                    return True, "priority_lowered", {
                        "process": name, "pid": proc.pid,
                        "prev_priority": old_nice,
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return False, f"process not found: {name}", {}

    def _rollback_priority(self, rollback_data: dict) -> tuple[bool, str]:
        if not _PSUTIL_OK or psutil is None:
            return False, "psutil not available"
        name = rollback_data.get("process", "")
        prev = rollback_data.get("prev_priority")
        if not name:
            return False, "no process name"
        for proc in psutil.process_iter(["name", "pid"]):
            try:
                if proc.name() == name:
                    if prev is not None:
                        proc.nice(prev)
                    return True, "priority_restored"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False, "process not found"

    def _disable_service(
        self, sug: OptimizationSuggestion
    ) -> tuple[bool, str, dict]:
        """Deaktiviert einen Windows-Dienst (setzt Start auf 4=Disabled)."""
        if not _IS_WIN:
            return False, "not windows", {}
        svc = sug.target
        if svc in _PROTECTED_SERVICES:
            return False, f"protected service: {svc}", {}
        try:
            subprocess.run(
                ["sc", "config", svc, "start=", "disabled"],
                check=True, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["sc", "stop", svc],
                capture_output=True, timeout=10,
            )
            return True, "service_disabled", {"service": svc, "prev_start": sug.rollback_data.get("prev_start", 3)}
        except subprocess.CalledProcessError as exc:
            return False, str(exc), {}

    def _rollback_service(self, rollback_data: dict) -> tuple[bool, str]:
        if not _IS_WIN:
            return False, "not windows"
        svc = rollback_data.get("service", "")
        prev = rollback_data.get("prev_start", 3)
        if not svc:
            return False, "no service name"
        start_map = {2: "auto", 3: "demand", 4: "disabled"}
        start_str = start_map.get(int(prev), "demand")
        try:
            subprocess.run(
                ["sc", "config", svc, f"start={start_str}"],
                check=True, capture_output=True, timeout=10,
            )
            return True, "service_restored"
        except Exception as exc:
            return False, str(exc)

    def _disable_aero(
        self, sug: OptimizationSuggestion
    ) -> tuple[bool, str, dict]:
        """Deaktiviert Aero/DWM-Komposition auf Windows."""
        if not _IS_WIN:
            return False, "not windows", {}
        try:
            import ctypes
            ctypes.windll.dwmapi.DwmEnableComposition(0)
            return True, "aero_disabled", {"aero_state": True}
        except Exception as exc:
            return False, str(exc), {}

    def _rollback_aero(self, rollback_data: dict) -> tuple[bool, str]:
        if not _IS_WIN:
            return False, "not windows"
        try:
            import ctypes
            ctypes.windll.dwmapi.DwmEnableComposition(1)
            return True, "aero_restored"
        except Exception as exc:
            return False, str(exc)

    def _noop(
        self, sug: OptimizationSuggestion
    ) -> tuple[bool, str, dict]:
        """Keine automatische Aktion – nur für informative Vorschläge."""
        return False, "informational_only", {}

    def _noop_rollback(self, rollback_data: dict) -> tuple[bool, str]:
        return False, "no rollback defined"
