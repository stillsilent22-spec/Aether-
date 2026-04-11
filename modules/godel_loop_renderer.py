"""
godel_loop_renderer.py — Gödelsche Selbstreferenz-Renderer
===========================================================

Das zentrale Paradox nach Kurt Gödel:
  Ein System kann sich selbst nicht vollständig beschreiben ohne
  auf Aussagen zu stoßen die es weder beweisen noch widerlegen kann.

Übersetzung auf Signalverarbeitung:
  1. Analysiere ein Signal → erzeuge strukturelle Metrik
  2. Verwende die Metrik als Input für die nächste Analyse-Iteration
  3. Prüfe ob das System zu einem Fixpunkt konvergiert (Gödel-Rest → 0)
  4. Wenn ja: Gödelstop — weiteres Iterieren liefert kein neues Wissen mehr
  5. Wenn nein nach MAX_DEPTH Iterationen: Gödelstop — erzwungen (unvollständig)

Konvergenz = System beschreibt sich stabil selbst (keine Information im Rest-Term).
Nicht-Konvergenz = Es gibt strukturelle Wahrheiten die das System nicht intern darstellen kann.

Beide Fälle enden deterministische — Gödel zeigt immer eine Grenze.

Verwendung:
  from modules.godel_loop_renderer import GoedelLoopRenderer
  renderer = GoedelLoopRenderer()
  result = renderer.render_with_self_reference("beliebiger Input", max_depth=3)
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from typing import Any, Dict, List, Optional

from modules.math_utils import _shannon_entropy as _shannon_entropy_impl

from modules.math_utils import _shannon_entropy as _shannon_entropy_impl


# ── Konvergenz-Schwellen ────────────────────────────────────────────────────

DELTA_CONVERGENCE_THRESHOLD  = 1.0   # %, < 1% = Fixpunkt erreicht
DEFAULT_MAX_DEPTH             = 3     # Maximale Rekursionstiefe
STOP_REASON_CONVERGENCE       = "KOHAERENZ_ERREICHT"
STOP_REASON_FIXPOINT          = "FIXPUNKT_ERREICHT"
STOP_REASON_MAX_DEPTH         = "GOEDEL_STOP_MAXTIEFE"
GOEDEL_STOP_MESSAGE           = "Goedel-Stop erreicht"


# ── Hilfsfunktionen (deterministisch, keine I/O) ───────────────────────────

def _shannon_entropy(data: bytes) -> float:
    """Shannon-Entropie normiert auf [0, 1] (max 8 bit/byte)."""
    return float(min(1.0, _shannon_entropy_impl(data) / 8.0))


def _periodicity(data: bytes) -> float:
    """Periodizitätslevel in [0, 1] — 1.0 = perfekte Periodizität."""
    total, coincide = 0, 0
    for i in range(len(data) - 1):
        total += 1
        if data[i] == data[i + 1]:
            coincide += 1
    return float(coincide / max(1, total))


def _content_hash(data: bytes) -> str:
    """SHA-256 des Inhalts (deterministisch, truncated für Payload-Effizienz)."""
    return hashlib.sha256(data).hexdigest()[:32]


def _delta_percent(a: Dict[str, float], b: Dict[str, float]) -> float:
    """Relative Änderung zwischen zwei Metrik-Dicts in Prozent."""
    total_rel = 0.0
    count = 0
    for key in ("entropy", "periodicity"):
        va = a.get(key, 0.0)
        vb = b.get(key, 0.0)
        denom = max(abs(va), 1e-6)
        total_rel += abs(vb - va) / denom
        count += 1
    # Größe-Änderung relativ
    sa = a.get("size", 0.0)
    sb = b.get("size", 0.0)
    total_rel += abs(sb - sa) / max(sa, 1.0)
    count += 1
    return float(total_rel / count * 100.0)


# ── GoedelLoopRenderer ─────────────────────────────────────────────────────

class GoedelLoopRenderer:
    """Iterativer Gödel-Selbstreferenz-Loop.

    Das Objekt ist zustandslos — alle Ergebnisse sind deterministisch:
    gleicher Input → gleiches Output bei allen Aufrufen.
    """

    def render_with_self_reference(
        self,
        input_signal: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Dict[str, Any]:
        """Führt den Gödelschen Selbstreferenz-Loop durch.

        Ablauf:
          Level 0: Input → Metriken berechnen
          Level 1: JSON(Metriken Level 0) → Metriken berechnen
          Level N: JSON(Metriken Level N-1) → Metriken berechnen
          Stop wenn: delta < 1% OR hash-Fixpunkt OR max_depth erreicht

        Returns:
          {
            "deterministic": True,       # immer True — kein Zufall im Pfad
            "stop_reached": bool,        # True wenn konvergiert oder max_depth
            "stop_reason": str,          # KOHAERENZ_ERREICHT / FIXPUNKT / GOEDEL_STOP
            "stop_message": str,         # Menschenlesbar, enthält "Goedel-Stop erreicht"
            "depth_reached": int,        # Wie viele Level durchlaufen?
            "godel_rest": float,         # Restliche Selbst-Unvollständigkeit [0,1]
            "coherence": float,          # 1 - godel_rest
            "levels": [                  # Details je Level
              {"level": 0, "entropy": ..., "periodicity": ..., "size": ...,
               "fingerprint": ..., "delta_pct": ...},
            ],
          }
        """
        signal: bytes
        if isinstance(input_signal, str):
            signal = input_signal.encode("utf-8")
        elif isinstance(input_signal, bytes):
            signal = input_signal
        else:
            signal = str(input_signal).encode("utf-8")

        levels: List[Dict[str, Any]] = []
        prev_metrics: Optional[Dict[str, float]] = None
        prev_hash = ""

        for depth in range(max_depth + 1):
            fingerprint = _content_hash(signal)
            entropy      = _shannon_entropy(signal)
            periodicity  = _periodicity_score(signal)
            size         = float(len(signal))

            current_metrics: Dict[str, float] = {
                "entropy":     entropy,
                "periodicity": periodicity,
                "size":        size,
            }

            delta_pct = 0.0
            if prev_metrics is not None:
                delta_pct = _delta_percent(prev_metrics, current_metrics)

            level_entry: Dict[str, Any] = {
                "level":       depth,
                "entropy":     round(entropy, 6),
                "periodicity": round(periodicity, 6),
                "size":        int(size),
                "fingerprint": fingerprint,
                "delta_pct":   round(delta_pct, 4),
            }
            levels.append(level_entry)

            # Konvergenz-Prüfung (nach erstem Level, da prev fehlt bei Level 0)
            if prev_metrics is not None:
                if fingerprint == prev_hash:
                    # Echter Hash-Fixpunkt — Signal ist stabil, keine neue Information
                    godel_rest = max(0.0, 1.0 - entropy)
                    return {
                        "deterministic": True,
                        "stop_reached":  True,
                        "stop_reason":   STOP_REASON_FIXPOINT,
                        "stop_message":  f"{GOEDEL_STOP_MESSAGE}: Fixpunkt bei Level {depth} (hash identisch)",
                        "depth_reached": depth,
                        "godel_rest":    round(godel_rest, 6),
                        "coherence":     round(1.0 - godel_rest, 6),
                        "levels":        levels,
                    }
                if delta_pct < DELTA_CONVERGENCE_THRESHOLD:
                    # Metriken konvergiert — weniger als 1% Änderung
                    godel_rest = max(0.0, 1.0 - entropy)
                    return {
                        "deterministic": True,
                        "stop_reached":  True,
                        "stop_reason":   STOP_REASON_CONVERGENCE,
                        "stop_message":  (
                            f"{GOEDEL_STOP_MESSAGE}: Kohärenz erreicht bei Level {depth} "
                            f"(delta={delta_pct:.3f}%)"
                        ),
                        "depth_reached": depth,
                        "godel_rest":    round(godel_rest, 6),
                        "coherence":     round(1.0 - godel_rest, 6),
                        "levels":        levels,
                    }

            # Max-Depth erreicht
            if depth >= max_depth:
                godel_rest = max(0.0, 1.0 - entropy)
                return {
                    "deterministic": True,
                    "stop_reached":  True,
                    "stop_reason":   STOP_REASON_MAX_DEPTH,
                    "stop_message":  (
                        f"{GOEDEL_STOP_MESSAGE}: maximale Tiefe {max_depth} erreicht "
                        f"— System bleibt unvollständig (Gödel-Rest={godel_rest:.4f})"
                    ),
                    "depth_reached": depth,
                    "godel_rest":    round(godel_rest, 6),
                    "coherence":     round(1.0 - godel_rest, 6),
                    "levels":        levels,
                }

            # Nächste Iteration: Signal = JSON-Beschreibung der aktuellen Metriken
            next_signal_dict: Dict[str, Any] = {
                "entropy":     round(entropy, 8),
                "periodicity": round(periodicity, 8),
                "size":        int(size),
                "fingerprint": fingerprint,
            }
            signal = json.dumps(next_signal_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

            prev_metrics = current_metrics
            prev_hash    = fingerprint

        # Fallback (sollte nicht erreichbar sein)
        godel_rest = max(0.0, 1.0 - _shannon_entropy(signal))
        return {
            "deterministic": True,
            "stop_reached":  True,
            "stop_reason":   STOP_REASON_MAX_DEPTH,
            "stop_message":  f"{GOEDEL_STOP_MESSAGE}: max_depth={max_depth}",
            "depth_reached": max_depth,
            "godel_rest":    round(godel_rest, 6),
            "coherence":     round(1.0 - godel_rest, 6),
            "levels":        levels,
        }

    def run_on_bytes(
        self,
        data: bytes,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Dict[str, Any]:
        """Komfort-Methode für Byte-Input (z.B. aus capture_live_render_frame)."""
        # Für Bytes: direkt übergeben
        result = self.render_with_self_reference(
            input_signal=data.decode("latin-1"),
            max_depth=max_depth,
        )
        return result
