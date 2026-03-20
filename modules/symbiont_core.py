"""symbiont_core.py — Aether Symbiont: Signal-agnostischer Meta-Ockham Kern.

Verarbeitet beliebige Signaltypen (Code, Text, AST, Binär) als strukturelle
Einheiten — ohne semantische Annahmen. Berechnet StructuralProfile und Delta.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Union, List

try:
    import numpy as np
    _NUMPY = True
except ImportError:
    _NUMPY = False


# ── Signal-Typen ──────────────────────────────────────────────────────────────

# Ein Signal ist ein beliebiges, handhabbares Datenobjekt.
#   str   → Quelltext, Dokument, Prompt
#   bytes → Binärblob, AST-Serialisierung, Token-Sequenz
#   dict  → Strukturiertes Objekt (JSON-AST, Konfiguration)
Signal = Union[str, bytes, dict]


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class StructuralProfile:
    """
    Invariante strukturelle Merkmale eines Signals.
    Alle Werte sind dimensionslos und signaltyp-unabhängig.
    """
    signal_id: str                  # SHA-256[:16] des Signals
    timestamp: float
    byte_length: int
    entropy: float                  # Shannon H(X) in [0, 8]
    compression_ratio: float        # Schätzwert: 1-H/8
    token_count: int                # Simple Whitespace-Token für Text, Höhe für bytes
    unique_token_ratio: float       # Lexikalische Diversität [0, 1]
    structural_depth: int           # Schachtelungstiefe (für dicts)
    symmetry: float                 # Palindrom-ähnliche Achsensymmetrie [0, 1]
    signal_type: str                # "text" | "bytes" | "dict"

    def to_dict(self) -> dict:
        return {
            "signal_id":          self.signal_id,
            "timestamp":          self.timestamp,
            "byte_length":        self.byte_length,
            "entropy":            round(self.entropy, 5),
            "compression_ratio":  round(self.compression_ratio, 4),
            "token_count":        self.token_count,
            "unique_token_ratio": round(self.unique_token_ratio, 4),
            "structural_depth":   self.structural_depth,
            "symmetry":           round(self.symmetry, 4),
            "signal_type":        self.signal_type,
        }


@dataclass
class StructuralDelta:
    """Differenz zwischen zwei StructuralProfiles."""
    signal_id_a: str
    signal_id_b: str
    timestamp: float
    entropy_delta:          float
    compression_delta:      float
    token_count_delta:      int
    unique_ratio_delta:     float
    symmetry_delta:         float
    structural_depth_delta: int
    similarity_score:       float    # [0, 1] — 1 = identisch

    def to_dict(self) -> dict:
        return {
            "signal_id_a":           self.signal_id_a,
            "signal_id_b":           self.signal_id_b,
            "timestamp":             self.timestamp,
            "entropy_delta":         round(self.entropy_delta, 5),
            "compression_delta":     round(self.compression_delta, 4),
            "token_count_delta":     self.token_count_delta,
            "unique_ratio_delta":    round(self.unique_ratio_delta, 4),
            "symmetry_delta":        round(self.symmetry_delta, 4),
            "structural_depth_delta":self.structural_depth_delta,
            "similarity_score":      round(self.similarity_score, 4),
        }


@dataclass
class OckhamProposal:
    """
    Ein Ockham-Vereinfachungsvorschlag: zwei äquivalente Signale +
    die einfachere Variante (geringere strukturelle Komplexität).
    """
    candidate_a_id: str
    candidate_b_id: str
    preferred_id: str           # ID des strukturell einfacheren Signals
    rationale: str              # Begründung auf Basis struktureller Metriken
    complexity_reduction: float # Schätzung der Reduktion [0, 1]
    confidence: float           # [0, 1]

    def to_dict(self) -> dict:
        return {
            "candidate_a_id":     self.candidate_a_id,
            "candidate_b_id":     self.candidate_b_id,
            "preferred_id":       self.preferred_id,
            "rationale":          self.rationale,
            "complexity_reduction": round(self.complexity_reduction, 4),
            "confidence":         round(self.confidence, 4),
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class AetherSymbiont:
    """
    Signal-agnostischer Strukturanalyse-Kern des Aether Symbiont.

    Verarbeitet Signale ohne Interpretation ihres Inhalts — nur strukturelle
    Metriken werden extrahiert: Entropie, Symmetrie, Komprimierbarkeit, Tiefe.
    """

    MAX_CACHE = 512

    def __init__(self) -> None:
        self._profiles: Dict[str, StructuralProfile] = {}

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def profile(self, signal: Signal) -> StructuralProfile:
        """
        Berechnet das StructuralProfile eines Signals.
        Ergebnisse werden gecacht (LRU-Strategie).
        """
        raw = _to_bytes(signal)
        sig_id = hashlib.sha256(raw).hexdigest()[:16]
        if sig_id in self._profiles:
            return self._profiles[sig_id]

        p = self._compute_profile(signal, raw, sig_id)

        # LRU-Cache eviction
        if len(self._profiles) >= self.MAX_CACHE:
            oldest = next(iter(self._profiles))
            del self._profiles[oldest]
        self._profiles[sig_id] = p
        return p

    def delta(self, signal_a: Signal, signal_b: Signal) -> StructuralDelta:
        """Berechnet das StructuralDelta zwischen zwei Signalen."""
        pa = self.profile(signal_a)
        pb = self.profile(signal_b)
        return self._compute_delta(pa, pb)

    def propose_ockham(
        self, signal_a: Signal, signal_b: Signal
    ) -> Optional[OckhamProposal]:
        """
        Gibt einen Ockham-Vorschlag zurück wenn eines der Signale strukturell
        einfacher ist als das andere (strikt — gleiche Komplexität → None).
        """
        pa = self.profile(signal_a)
        pb = self.profile(signal_b)
        delta = self._compute_delta(pa, pb)

        complexity_a = self._complexity(pa)
        complexity_b = self._complexity(pb)

        if abs(complexity_a - complexity_b) < 0.02:
            return None     # Kein struktureller Unterschied

        preferred_id, preferred_p, other_p = (
            (pa.signal_id, pa, pb) if complexity_a < complexity_b
            else (pb.signal_id, pb, pa)
        )
        reduction = abs(complexity_a - complexity_b) / max(complexity_a, complexity_b, 1e-9)
        rationale = (
            f"Signal '{preferred_id}' hat geringere strukturelle Komplexität "
            f"(entropy={round(preferred_p.entropy,3)}, "
            f"token_count={preferred_p.token_count}, "
            f"depth={preferred_p.structural_depth}) "
            f"gegenüber '{other_p.signal_id}'."
        )
        return OckhamProposal(
            candidate_a_id      = pa.signal_id,
            candidate_b_id      = pb.signal_id,
            preferred_id        = preferred_id,
            rationale           = rationale,
            complexity_reduction= round(reduction, 4),
            confidence          = round(delta.similarity_score * 0.8 + 0.1, 4),
        )

    # ── Berechnungen ──────────────────────────────────────────────────────────

    def _compute_profile(
        self, signal: Signal, raw: bytes, sig_id: str
    ) -> StructuralProfile:
        sig_type = (
            "text"  if isinstance(signal, str)
            else "dict"  if isinstance(signal, dict)
            else "bytes"
        )
        entropy = _shannon_entropy(raw)
        compression_ratio = max(0.0, 1.0 - entropy / 8.0)
        tokens, unique_ratio = _tokenize(signal)
        depth = _dict_depth(signal) if isinstance(signal, dict) else 0
        symmetry = _symmetry(raw)

        return StructuralProfile(
            signal_id          = sig_id,
            timestamp          = time.time(),
            byte_length        = len(raw),
            entropy            = entropy,
            compression_ratio  = compression_ratio,
            token_count        = tokens,
            unique_token_ratio = unique_ratio,
            structural_depth   = depth,
            symmetry           = symmetry,
            signal_type        = sig_type,
        )

    @staticmethod
    def _compute_delta(pa: StructuralProfile, pb: StructuralProfile) -> StructuralDelta:
        feature_diffs = [
            abs(pa.entropy           - pb.entropy)          / 8.0,
            abs(pa.compression_ratio - pb.compression_ratio),
            abs(pa.unique_token_ratio - pb.unique_token_ratio),
            abs(pa.symmetry          - pb.symmetry),
        ]
        similarity = 1.0 - (sum(feature_diffs) / len(feature_diffs))
        return StructuralDelta(
            signal_id_a          = pa.signal_id,
            signal_id_b          = pb.signal_id,
            timestamp            = time.time(),
            entropy_delta        = abs(pa.entropy - pb.entropy),
            compression_delta    = abs(pa.compression_ratio - pb.compression_ratio),
            token_count_delta    = abs(pa.token_count - pb.token_count),
            unique_ratio_delta   = abs(pa.unique_token_ratio - pb.unique_token_ratio),
            symmetry_delta       = abs(pa.symmetry - pb.symmetry),
            structural_depth_delta = abs(pa.structural_depth - pb.structural_depth),
            similarity_score     = round(max(0.0, min(1.0, similarity)), 4),
        )

    @staticmethod
    def _complexity(p: StructuralProfile) -> float:
        """Normiertes Komplexitätsmaß eines Profils [0, 1]."""
        return (
            p.entropy / 8.0 * 0.4
            + min(1.0, p.token_count / 1000) * 0.3
            + p.structural_depth / max(1, p.structural_depth + 5) * 0.2
            + (1.0 - p.unique_token_ratio) * 0.1
        )


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _to_bytes(signal: Signal) -> bytes:
    if isinstance(signal, bytes):
        return signal
    if isinstance(signal, str):
        return signal.encode("utf-8", errors="replace")
    import json
    return json.dumps(signal, sort_keys=True, default=str).encode("utf-8")


def _shannon_entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    if _NUMPY:
        import numpy as np
        arr = np.frombuffer(raw, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        total = float(arr.size)
        probs = counts[counts > 0] / total
        return float(-np.sum(probs * np.log2(probs)))
    # Pure Python fallback
    from collections import Counter
    total = len(raw)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in Counter(raw).values()
        if c > 0
    )


def _tokenize(signal: Signal) -> tuple[int, float]:
    """Gibt (token_count, unique_ratio) zurück."""
    if isinstance(signal, str):
        tokens = signal.split()
        if not tokens:
            return 0, 0.0
        unique = len(set(tokens))
        return len(tokens), round(unique / len(tokens), 4)
    if isinstance(signal, bytes):
        return len(signal), 1.0
    if isinstance(signal, dict):
        import json
        text = json.dumps(signal, default=str)
        tokens = text.split()
        if not tokens:
            return 0, 0.0
        return len(tokens), round(len(set(tokens)) / len(tokens), 4)
    return 0, 0.0


def _dict_depth(d: Any, level: int = 0) -> int:
    if not isinstance(d, dict):
        return level
    if not d:
        return level + 1
    return max(_dict_depth(v, level + 1) for v in d.values())


def _symmetry(raw: bytes) -> float:
    if len(raw) < 2:
        return 1.0
    half = len(raw) // 2
    matches = sum(1 for a, b in zip(raw[:half], reversed(raw[-half:])) if a == b)
    return round(matches / half, 4)
