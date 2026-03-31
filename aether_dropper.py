"""Compatibility shim — AetherDropper wurde durch modules/unified_cascade.py ersetzt.
Diese Datei existiert nur damit:
  - tests/test_aether_dropper.py importiert werden kann
  - launcher_dashboard.rs aether_dropper.py als subprocess starten kann
"""
from __future__ import annotations
import hashlib
import math
from pathlib import Path

MATH_CONSTANTS = {
    "phi":   0.6180339887,
    "pi":    0.3141592653,
    "e":     0.2718281828,
    "sqrt2": 0.4142135623,
}

def _detect_anchor(value: float, tolerance: float = 0.02) -> str | None:
    """Erkennt ob ein Entropiewert nahe einer mathematischen Konstante liegt."""
    for name, const in MATH_CONSTANTS.items():
        if abs(value - const) <= tolerance:
            return name
        if abs(value - (1.0 - const)) <= tolerance:
            return name
    return None

def _safe_child_path(base: Path, relative: str) -> Path:
    """Verhindert Path-Traversal-Angriffe aus Archiven."""
    resolved = (base / relative).resolve()
    if not str(resolved).startswith(str(base.resolve())):
        raise ValueError(f"Path traversal attempt: {relative!r}")
    return resolved

class AetherDropper:
    """Legacy-Klasse. Neue Implementierung: modules/unified_cascade.run_full_pipeline()"""
    def run(self) -> None:
        from modules.unified_cascade import run_full_pipeline
        print("[DROPPER] Weiterleitung an unified_cascade.")

if __name__ == "__main__":
    print("[DROPPER] Shim aktiv. Nutze start.py fuer den vollen Start.")
