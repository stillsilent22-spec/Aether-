from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""
Aether - optionaler Rust-Kern-Wrapper.

Das Repository baut derzeit standardmaessig keine PyO3-Extension mehr.
Wenn lokal bereits ein kompatibles Modul `aether_core_rs` installiert ist,
wird es verwendet; ansonsten bleibt der Python-Pfad der kanonische Standard.
"""


import math as _math
from collections import Counter as _Counter
from typing import Sequence

# Optionale historische Rust-Extension laden, falls lokal vorhanden.
try:
    import aether_core_rs as _rs  # type: ignore
    _RUST_OK = True
except ImportError as e:
    _rs = None
    _RUST_OK = False


def byte_entropy(data: bytes) -> float:
    """
    Shannon-Entropie über alle Byte-Werte.

    H(X) = -Σ p(x) · log₂ p(x)   mit x ∈ {0..255}

    Rückgabe: 0.0 (uniformes Byte) … 8.0 (Gleichverteilung).

    Rust-Implementierung wird bevorzugt (ca. 8× schneller).
    """
    if _RUST_OK:
        return float(_rs.byte_entropy(data))
    # Pure-Python Fallback
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * _math.log2(c / n) for c in counts if c
    )


def token_entropy(tokens: Sequence[str]) -> float:
    """
    Shannon-Entropie über eine Token-Verteilung.

    H(T) = -Σ p(t) · log₂ p(t)   mit t ∈ Vokabular

    Rust-Implementierung wird bevorzugt.
    """
    if _RUST_OK:
        return float(_rs.token_entropy(list(tokens)))
    if not tokens:
        return 0.0
    counts = _Counter(tokens)
    n = len(tokens)
    return -sum(
        (c / n) * _math.log2(c / n) for c in counts.values() if c
    )


def zipf_score(word_counts: list[int]) -> float:
    """
    Zipf-Conformance-Score.

    Misst, wie gut rangierte Worthäufigkeiten dem Zipfschen Gesetz folgen:
      f(r) ∝ r^{−α},   ideales α ≈ 1

    Das Verfahren fittet α via linearer Regression auf log-Rang vs. log-Häufigkeit:
      log f(r) = α · log r + const

    Score = max(0, 1 − |α − 1| / 0.8)

    0.0 = stark abweichend (z. B. Obfuscation-Code)
    1.0 = perfektes Zipf-Gesetz (natürlicher Text)

    Rust-Implementierung wird bevorzugt.
    """
    if _RUST_OK:
        return float(_rs.zipf_score([int(c) for c in word_counts]))
    # Pure-Python Fallback
    ranked = sorted(word_counts, reverse=True)[:50]
    n = len(ranked)
    if n < 5:
        return 0.7
    xs = [_math.log(i) for i in range(1, n + 1)]
    ys = [_math.log(max(1, f)) for f in ranked]
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if abs(den) < 1e-12:
        return 0.7
    slope = num / den
    return max(0.0, min(1.0, 1.0 - abs(abs(slope) - 1.0) / 0.8))


def noether_score(words_start: dict[str, float], words_end: dict[str, float]) -> float:
    """
    Noether-Score: thematische Konsistenz.

    Misst, ob Anfang und Ende eines Textes dem gleichen Thema angehören.
    Verwendet Kosinus-Ähnlichkeit der Wortfrequenzvektoren:

      N(T) = clamp(cos(v_Anfang, v_Ende) × 2, 0, 1)

      cos(a, b) = (a · b) / (‖a‖ · ‖b‖)

    Interpretation:
      1.0 — thematisch stabil (Noether-Symmetrie: konservierte Größe)
      0.0 — starker Themenwechsel (Symmetriebruch)

    Rust-Implementierung wird bevorzugt.
    """
    if _RUST_OK:
        return float(_rs.noether_score(words_start, words_end))
    # Pure-Python Fallback
    all_words = set(words_start) | set(words_end)
    if not all_words:
        return 0.6
    dot = sum(words_start.get(w, 0.0) * words_end.get(w, 0.0) for w in all_words)
    norm_a = sum(v * v for v in words_start.values()) ** 0.5
    norm_b = sum(v * v for v in words_end.values()) ** 0.5
    if norm_a < 1e-12 or norm_b < 1e-12:
        return 0.6
    return min(1.0, max(0.0, dot / (norm_a * norm_b) * 2.0))


def is_rust_available() -> bool:
    """Gibt True zurück wenn das kompilierte Rust-Modul geladen wurde."""
    return _RUST_OK


def build_info() -> str:
    """Informationsstring über die aktive Backend-Implementierung."""
    if _RUST_OK:
        return "aether_core_rs (Rust/PyO3) — optimiert"
    return "Pure-Python Fallback (Rust-Modul nicht kompiliert)"
