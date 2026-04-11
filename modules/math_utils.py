"""
math_utils.py — Kanonische Math-Hilfsfunktionen für Aether-Module.

EINMALIGE Definitionen statt 5–8 Kopien quer durch das Repo.

Verwendung:
    from modules.math_utils import _clamp, _shannon_entropy, log_scale_fitness, \
        legacy_tier_from_score, _symmetry, _resonance
"""
from __future__ import annotations

import math
from typing import Union

# ---------------------------------------------------------------------------
# Weber-Fechner Konstanten — logarithmisches Empfindlichkeitsmodell
# ---------------------------------------------------------------------------
# fitness → tier: floor(log2(fitness * _LOG_SCALE + 1))
#   fitness 0.00 → tier 0  (Basis-Daemon)
#   fitness 0.12 → tier 1  (Minimal Node)
#   fitness 0.37 → tier 2  (Standard)
#   fitness 0.75 → tier 3  (Aether OS)
#   fitness 1.00 → tier 3  (gesättigter Bereich)
_LOG_SCALE = 8.0
_LOG_NORM  = math.log1p(_LOG_SCALE)  # = log1p(8) ≈ 2.197


def _clamp(value: Union[int, float], low: float = 0.0, high: float = 1.0) -> float:
    """Klemmt einen Wert auf [low, high]. Sicher für int/float/Any-Eingaben."""
    try:
        v = float(value)
        if not math.isfinite(v):
            return float(low)
        return max(float(low), min(float(high), v))
    except Exception:
        return float(low)


def _shannon_entropy(data: bytes) -> float:
    """Shannon-Entropie in Bits pro Symbol für beliebige Byte-Sequenz.

    Rückgabe: [0.0, 8.0]  (0 = nur ein Symbol, 8 = maximale Gleichverteilung über 256)
    Zeitkomplexität: O(n)
    """
    if not data:
        return 0.0
    counts: list[int] = [0] * 256
    for byte_val in data:
        counts[byte_val] += 1
    n = float(len(data))
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _symmetry(data: bytes) -> float:
    """Verteilungs-Symmetrie der Byte-Werte: 1.0 = perfekt gleichverteilt, 0.0 = maximal schief.

    Misst die mittlere Abweichung der Byte-Häufigkeiten von ihrem Erwartungswert.
    Kanonische Implementierung — identisch in analysis_capsule + render_coordinator.
    """
    if not data:
        return 1.0
    counts: list[int] = [0] * 256
    for byte_val in data:
        counts[byte_val] += 1
    non_zero = [c for c in counts if c > 0]
    if not non_zero:
        return 1.0
    mean = float(sum(non_zero)) / float(len(non_zero))
    deviation = sum(abs(float(c) - mean) for c in non_zero) / float(len(non_zero))
    return _clamp(1.0 - deviation / max(mean, 1.0))


def _resonance(data: bytes) -> float:
    """Resonanz: wie nah ist die Byte-Verteilung an einem harmonischen Profil?

    1.0 = harmonisch (std ≈ 0), 0.0 = chaotisch (std >> mean).
    """
    if not data:
        return 0.0
    n = len(data)
    mean = float(sum(data)) / n
    variance = sum((b - mean) ** 2 for b in data) / n
    std = math.sqrt(variance)
    return _clamp(1.0 - std / max(1.0, mean))


# ---------------------------------------------------------------------------
# Logarithmische Capability-/Fitness-Skalierung
# ---------------------------------------------------------------------------

def log_scale_fitness(fitness: float, hardware_tier: int = 2) -> float:
    """Logarithmisch skalierter Fitness-Wert [0, 1].

    Motivation (Weber-Fechner-Gesetz):
      Auf Legacy-Hardware (hardware_tier=0/1) ist ein fitness von 0.3 eine
      ENORME Leistung — linear würde es schlecht aussehen im Vergleich zu 0.9.
      Log-Skalierung gibt den unteren Fitness-Bereichen proportional mehr Gewicht.

    hardware_tier:
      0 → Basis-Daemon      kleiner boost (+0.30)
      1 → Minimal Node      mittlerer boost (+0.20)
      2 → Standard          kleiner boost (+0.10)
      3 → Aether OS         kein boost
      4+ → Genesis          kein boost

    Beispiele (tier=0):
      fitness 0.10 → normalized 0.71 (ohne tier) × 1.30 → 0.92 (log-boost)
      fitness 0.30 → normalized 0.84 × 1.30 → 1.00
      fitness 0.90 → 0.98 × 1.30 → 1.00 (kein Unterschied oben)
    """
    fitness = _clamp(fitness)
    base = math.log1p(fitness * _LOG_SCALE) / _LOG_NORM
    tier_boost = max(0.0, 3 - hardware_tier) * 0.10
    return _clamp(base + tier_boost)


def legacy_tier_from_capability_score(score_pct: float) -> int:
    """Ordnet einen Capability-Score (0–100) einem Integer-Tier 0–4 zu.

    score_pct  0– 24 → 0  (Basis-Daemon)
    score_pct 25– 49 → 1  (Minimal Node)
    score_pct 50– 74 → 2  (Standard)
    score_pct 75– 99 → 3  (Aether OS)
    score_pct   100  → 4  (Aether OS [Aktiv])

    Logarithmische Grenzenwahl: tier k bricht erst bei score ≥ 25·k.
    Das ist bewusst linear damit kleine Schritte immer belohnt werden —
    die *Bewertung* innerhalb eines Tiers ist logarithmisch (log_scale_fitness).
    """
    score = int(_clamp(score_pct, 0.0, 100.0))
    if score >= 100:
        return 4
    return min(3, score // 25)


def tier_from_fitness(fitness: float) -> int:
    """Token-Fitness → empfohlener Mindest-Tier für sinnvollen Einsatz.

    fitness < 0.12 → tier 0 (auch aufsteigende Legacy-Knoten können es nutzen)
    fitness < 0.37 → tier 1
    fitness < 0.75 → tier 2
    fitness ≥ 0.75  → tier 3
    """
    f = _clamp(fitness)
    raw = int(math.log1p(f * _LOG_SCALE))
    return min(3, max(0, raw))


def log_delta_gate(
    new_entropy: float,
    last_entropy: float,
    idle_threshold: float = 0.05,
    active_threshold: float = 0.25,
) -> str:
    """Event-Classification für delta-basiertes Compute-Gating.

    Rückgabe:
      "skip"   — Entropie-Delta klein genug → Cascade überspringen, gecachten Token nutzen
      "token"  — Mittleres Delta → Token-Lookup reicht, kein vollständiger Cascade
      "full"   — Großes Delta (Nutzerinteraktion, Szenenänderung) → voller Cascade

    Logarithmische Skala: log1p(|delta| * 8) / log1p(8)
    Damit erscheinen kleine Deltas auf schwacher Hardware genauso skaliert wie
    große Deltas auf starker Hardware — derselbe Schwellwert funktioniert überall.
    """
    if not (math.isfinite(new_entropy) and math.isfinite(last_entropy)):
        return "full"
    abs_delta = abs(new_entropy - last_entropy)
    log_delta = math.log1p(abs_delta * _LOG_SCALE) / _LOG_NORM
    if log_delta < idle_threshold:
        return "skip"
    if log_delta < active_threshold:
        return "token"
    return "full"
