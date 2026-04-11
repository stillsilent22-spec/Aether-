"""
runtime_loop.py — Deterministische Run-Loop für Aether CLI.

Implementiert run_loop() und simple_delta_provider() die von modules/cli.py
genutzt werden wenn kein spezifischer Befehl gegeben wird (Default-Pfad).

Der Loop:
  1. Läuft max_ticks Iterationen (oder unbegrenzt wenn max_ticks=0)
  2. Holt pro Tick ein Delta vom delta_provider (callable → dict)
  3. Wendet runtime_step() an → akkumuliert Zustand + History
  4. Inkrementiert tick-Zähler

Für die echte Produktion wird dieser Loop von der Rust-Shell getriggert
(deterministischer Pipeline-Trigger via IPC). Diese Python-Implementierung
ist der Fallback für Legacy-Knoten und CLI-Tests.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

from modules.runtime_core import runtime_step, runtime_set_running


def simple_delta_provider() -> Dict[str, Any]:
    """Einfacher Test-Delta-Provider: konstante Null-Deltas.

    Für Produktionsnutzung als Platzhalter — echte Deltas kommen
    aus dem Cascade-Pipeline-Output via aether_pipeline.py.
    """
    return {"signal": 0.0, "ts": time.time()}


def run_loop(
    runtime: Dict[str, Any],
    *,
    max_ticks: int = 10,
    delta_provider: Optional[Callable[[], Dict[str, Any]]] = None,
    tick_interval_ms: float = 0.0,
) -> Dict[str, Any]:
    """Führt den Runtime-Loop für max_ticks Iterationen aus.

    Args:
        runtime:         Initialisierter Runtime-State (aus init_runtime()).
        max_ticks:       Maximale Ticks. 0 = unbegrenzt (läuft bis running=False).
        delta_provider:  Callable → delta dict. Standard: simple_delta_provider.
        tick_interval_ms: Pause zwischen Ticks in ms (0 = kein Sleep).

    Rückgabe: Finaler Runtime-State nach allen Ticks.
    """
    if delta_provider is None:
        delta_provider = simple_delta_provider

    runtime = runtime_set_running(runtime, True)
    tick = 0

    try:
        while runtime.get("running", False):
            if max_ticks > 0 and tick >= max_ticks:
                break
            try:
                delta = delta_provider()
            except Exception as exc:
                logger.debug(f"[runtime_loop] delta_provider fehlgeschlagen: {exc}")
                delta = {"signal": 0.0, "ts": time.time()}

            runtime = runtime_step(runtime, delta)
            tick += 1

            if tick_interval_ms > 0:
                time.sleep(tick_interval_ms / 1000.0)
    except KeyboardInterrupt:
        logger.info("[runtime_loop] Abbruch durch Benutzer.")
    finally:
        runtime = runtime_set_running(runtime, False)

    logger.debug(f"[runtime_loop] Fertig nach {tick} Ticks.")
    return runtime
