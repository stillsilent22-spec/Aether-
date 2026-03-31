import logging
logger = logging.getLogger(__name__)
"""
attractor_engine.py
Kanonische Implementierung der Permutation-Entropy-Metrik für Aether.

Permutation Entropy (Bandt & Pompe, 2002) misst die strukturelle Komplexität
eines Byte-Stroms über die Häufigkeitsverteilung von Ordnungsmustern in
gleitenden Fenstern. Sie ist orthogonal zur Shannon-Entropie (die die
Byte-Verteilung misst) und misst stattdessen die Ordnungsstruktur.

Ergebnis ∈ [0, 1]:
  1.0 = maximal geordnet (alle Fenster zeigen dasselbe Ordnungsmuster)
  0.0 = maximal komplex (alle Ordnungsmuster gleichverteilt)

Kein Lyapunov-Exponent. Keine Wiederkehrzählung.
Formel: PE = 1 - H_perm / log2(order!)
"""

from __future__ import annotations
import math
from itertools import permutations as _iter_perms


def perm_entropy(data: bytes, order: int = 3, step: int = 1) -> float:
    """
    Berechnet die normalisierte Permutation Entropy eines Byte-Stroms.

    Algorithmus (Bandt & Pompe):
      1. Zerlege den Stream in gleitende Fenster der Länge `order`.
      2. Ermittle für jedes Fenster das Ordnungsmuster (Ranking der Werte).
      3. Zähle die Häufigkeit jedes Ordnungsmusters.
      4. Berechne die Shannon-Entropie über diese Häufigkeiten.
      5. Normalisiere auf [0, 1] via Division durch log2(order!).
      6. Invertiere: hohe Geordnetheit → hoher Rückgabewert.

    Args:
        data:  Eingabe-Bytes (wird auf max. 4096 Bytes gekürzt für Performance).
        order: Fenstergröße. 3 ist der Standard für Byte-Streams.
               Größere Werte (4, 5) erhöhen die Sensitivität, aber auch den
               Rechenaufwand exponentiell (order! mögliche Muster).
        step:  Schrittweite des gleitenden Fensters. 1 = überlappend.

    Returns:
        float ∈ [0.0, 1.0].
        1.0 = alle Fenster haben dasselbe Ordnungsmuster (maximal strukturiert).
        0.0 = alle Ordnungsmuster gleichverteilt (weißes Rauschen / Verschlüsselung).
        0.5 = Rückgabewert wenn Berechnung nicht möglich (zu wenig Daten).
    """
    arr = list(data[:4096])
    n = len(arr)
    if n < order:
        return 0.5

    patterns: dict[tuple[int, ...], int] = {}
    for i in range(0, n - order + 1, step):
        window = arr[i : i + order]
        # Ordnungsmuster: Rang-Tupel der Werte im Fenster
        key = tuple(sorted(range(order), key=lambda j: window[j]))
        patterns[key] = patterns.get(key, 0) + 1

    total = sum(patterns.values())
    if total == 0:
        return 0.5

    # Shannon-Entropie über Ordnungsmuster
    h = -sum(
        (count / total) * math.log2(count / total)
        for count in patterns.values()
        if count > 0
    )
    max_h = math.log2(math.factorial(order))
    if max_h == 0:
        return 0.5

    # Invertiert: 1.0 = geordnet, 0.0 = chaotisch
    return max(0.0, min(1.0, 1.0 - h / max_h))


# ---------------------------------------------------------------------------
# Legacy-Kompatibilität: attractor_track und attractor_signature bleiben
# erhalten damit bestehende Importe nicht brechen. Sie werden nicht mehr
# in der Cascade-Pipeline verwendet.
# ---------------------------------------------------------------------------

def attractor_signature(state_hash: str) -> str:
    """Legacy. Gibt die ersten 12 Zeichen des Hash zurück."""
    return state_hash[:12]


def attractor_track(history: list[str]) -> dict:
    """
    Legacy. Wird nicht mehr in unified_cascade.py verwendet.
    Verbleibt für externe Module die es noch direkt importieren.
    """
    counts: dict[str, int] = {}
    for h in history:
        counts[h] = counts.get(h, 0) + 1
    attractors = [k for k, v in counts.items() if v > 1]
    return {"attractors": attractors, "counts": counts}
