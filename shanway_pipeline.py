"""shanway_pipeline.py — Vollständige Aether-Pipeline für Web-Quellen.

Schichten (aus Whitepaper Abschnitte 7–13, identisch zur Hauptpipeline):

  [0] SECURITY      deny by default — verbotene Inhalte sofort verwerfen
  [1] SHANNON       klassische Entropie H(X)
  [2] H_LAMBDA      beobachterrelative Restunsicherheit H_lambda(X,t)
  [3] ANCHOR        pi / phi / sqrt2 / e Detektion per Block
  [4] SYMMETRY      normalisierte Verteilungsungleichheit
  [5] DELTA         XOR-Transformation gegen Session-Seed
  [6] PERIODICITY   Autokorrelation über Block-Entropie-Sequenz
  [7] BEAUTY        diagnostische Signatur (kombiniert)
  [8] BAYES         Posterior-Update über Anchor-Coverage
  [9] TRUST         Gesamtscore aus allen Schichten
  [10] CONSENSUS    Cross-Source Konsens-Messung

Keine neuen Abhängigkeiten außer collections und random.
Bestehende Aether-Pipeline bleibt vollständig unberührt.
"""
from __future__ import annotations

import hashlib
import math
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── Mathematische Konstanten (identisch zu aether_dropper.py) ────────────────
PI_ANCHOR    = 3.14159265358979
PHI_ANCHOR   = 1.61803398874989
SQRT2_ANCHOR = 1.41421356237310
E_ANCHOR     = 2.71828182845904
ANCHORS      = [PI_ANCHOR, PHI_ANCHOR, SQRT2_ANCHOR, E_ANCHOR]
ANCHOR_NAMES = ["pi", "phi", "sqrt2", "e"]

# Observer-Wissen Basisrate (wächst mit Vault-Größe, hier konservativ)
OBSERVER_KNOWLEDGE_RATIO = 0.15

# ── Schwellwerte ──────────────────────────────────────────────────────────────
TRUST_THRESHOLD       = 0.45
CONSENSUS_MIN_SOURCES = 2
DELTA_MIN_SOURCES     = 1

# ── Safety: verbotene Kategorien — deny by default ───────────────────────────
_DENY_PATTERNS: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"\b(bomb|explosiv|sprengstoff|waffe[n]?|weapon|kill\s+instruction|anleitung.{0,20}(t.ten|mord))\b",
    r"\b(hate\s*speech|racial\s*slur|rassist|volksverhetz|n.gger|k[i1]ke|ch[i1]nk)\b",
    r"\b(child\s*(porn|abuse|exploit)|kinderporno|missbrauch.{0,10}kind)\b",
    r"\b(deepfake\s*tutorial|fake\s*news\s*generat|disinfo\s*toolkit)\b",
    r"\b(synthes[ie]s\s*of\s*(meth|fentanyl|heroin)|drug\s*recipe|drogenherstellung)\b",
]]

ANCHOR_MEANING: dict[str, str] = {
    "pi":    "periodische oder zyklische Struktur",
    "phi":   "selbstähnliche, proportional stabile Struktur",
    "sqrt2": "dimensionaler Übergang oder Transformation",
    "e":     "Wachstums- oder Zerfallsmuster",
}


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class SourceProfile:
    url: str
    title: Optional[str]
    sha256: str
    # Schicht 1: Shannon
    entropy_mean: float
    # Schicht 2: H_lambda
    h_lambda: float
    observer_mutual_info: float
    # Schicht 3: Anchor
    anchors_found: dict[str, int]
    anchor_coverage: float
    # Schicht 4: Symmetry
    symmetry_score: float
    # Schicht 5: Delta
    delta_score: float
    # Schicht 6: Periodicity
    periodicity_score: float
    # Schicht 7: Beauty
    beauty_score: float
    # Schicht 8: Bayes
    bayes_posterior: float
    # Schicht 9: Trust
    trust_score: float
    # Verdict
    verdict: str                    # "CONFIRMED" | "FAILED" | "DENIED"
    deny_reason: Optional[str] = None


@dataclass
class ConsensusResult:
    query: str
    status: str                      # "ANKER" | "DELTA" | "UNRESOLVED"
    confirmed_anchors: list[str]
    delta_anchors: list[str]
    sources_analyzed: int
    sources_confirmed: int
    mean_trust: float
    mean_h_lambda: float             # Restunsicherheit über alle Quellen
    mean_beauty: float               # Beauty-Signatur Konsens
    profiles: list[SourceProfile] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(datetime.timezone.utc
            if hasattr(datetime, 'timezone') else None
        ).strftime("%Y%m%dT%H%M%SZ")
        if False else "",
    )

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


# ── Schicht 0: Security ───────────────────────────────────────────────────────

def _is_denied(raw: bytes) -> Optional[str]:
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    for pat in _DENY_PATTERNS:
        if pat.search(text):
            return f"deny:{pat.pattern[:40]}"
    return None


# ── Schicht 1: Shannon-Entropie ───────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    h = 0.0
    for c in freq:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


# ── Schicht 2: H_lambda — beobachterrelative Restunsicherheit ────────────────
# H_lambda(X,t) = max(0, H(X) - observer_mutual_info)
# observer_mutual_info ~= entropy_mean * observer_knowledge_ratio

def _h_lambda(entropy_mean: float,
              knowledge_ratio: float = OBSERVER_KNOWLEDGE_RATIO) -> tuple[float, float]:
    mutual_info = entropy_mean * knowledge_ratio
    h_lam = max(0.0, entropy_mean - mutual_info)
    return round(h_lam, 4), round(mutual_info, 4)


# ── Schicht 3: Anchor-Detektion ───────────────────────────────────────────────

def _normalize_block(block: bytes) -> float:
    if not block:
        return 0.0
    return sum(block) / float(len(block) * 255.0)


def _detect_anchor(value: float, tolerance: float = 0.02) -> Optional[str]:
    for anchor, name in zip(ANCHORS, ANCHOR_NAMES):
        frac = anchor - int(anchor)
        if abs(value - frac) < tolerance:
            return name
    return None


# ── Schicht 4: Symmetrie ──────────────────────────────────────────────────────
# Normalisierte Verteilungsungleichheit über Block-Entropien

def _symmetry(entropy_values: list[float]) -> float:
    if len(entropy_values) < 2:
        return 0.0
    mean = sum(entropy_values) / len(entropy_values)
    if mean == 0:
        return 0.0
    variance = sum((e - mean) ** 2 for e in entropy_values) / len(entropy_values)
    # Niedrige Varianz relativ zum Mittelwert = hohe Symmetrie
    cv = math.sqrt(variance) / mean if mean > 0 else 1.0
    return round(max(0.0, 1.0 - min(1.0, cv)), 4)


# ── Schicht 5: Delta-Transformation ──────────────────────────────────────────
# XOR gegen session_seed → misst strukturelle Stabilität

def _delta_score(blocks: list[bytes], session_seed: int) -> float:
    if not blocks:
        return 0.0
    rng = random.Random(session_seed)
    scores: list[float] = []
    for block in blocks:
        noise = bytes(rng.randint(0, 255) for _ in range(len(block)))
        xored = bytes(a ^ b for a, b in zip(block, noise))
        original_e = _entropy(block)
        delta_e = _entropy(xored)
        # Wenn Delta-Entropie >> Original → Struktur ist real, nicht zufällig
        if original_e > 0:
            scores.append(min(1.0, delta_e / 8.0))
    return round(sum(scores) / len(scores), 4) if scores else 0.0


# ── Schicht 6: Periodizität ───────────────────────────────────────────────────
# Autokorrelation der Block-Entropie-Sequenz

def _periodicity(entropy_values: list[float]) -> float:
    n = len(entropy_values)
    if n < 4:
        return 0.0
    mean = sum(entropy_values) / n
    centered = [e - mean for e in entropy_values]
    # Lag-1 Autokorrelation
    denom = sum(c ** 2 for c in centered)
    if denom == 0:
        return 0.0
    numer = sum(centered[i] * centered[i + 1] for i in range(n - 1))
    autocorr = numer / denom
    # Hohe positive Autokorrelation → periodische Struktur
    return round(max(0.0, autocorr), 4)


# ── Schicht 7: Beauty-Signatur ────────────────────────────────────────────────
# Diagnostische Kombination — kein Wahrheitsbeweis, nur strukturelle Diagnose

def _beauty(entropy_mean: float, symmetry: float,
            anchor_coverage: float, periodicity: float) -> float:
    # Gewichtete Kombination der Strukturmetriken
    b = (
        0.30 * min(1.0, entropy_mean / 8.0) +
        0.25 * symmetry +
        0.25 * min(1.0, anchor_coverage * 4.0) +
        0.20 * periodicity
    )
    return round(b, 4)


# ── Schicht 8: Bayes-Posterior ────────────────────────────────────────────────
# Prior: anchor_coverage als Likelihood, Posterior-Update über Trust

def _bayes_posterior(anchor_coverage: float, trust_prior: float = 0.5) -> float:
    # P(anchor | data) ∝ P(data | anchor) * P(anchor)
    # Vereinfacht: Likelihood = coverage, Prior = 0.5
    likelihood = min(1.0, anchor_coverage * 2.0)
    posterior = (likelihood * trust_prior) / (
        likelihood * trust_prior + (1 - likelihood) * (1 - trust_prior) + 1e-9
    )
    return round(posterior, 4)


# ── Schicht 9: Trust-Score ────────────────────────────────────────────────────
# Identisch zu aether_dropper.py, erweitert um neue Schichten

def _trust(coverage: float, entropy_mean: float, n_anchors: int,
           symmetry: float, beauty: float, bayes: float) -> float:
    base = (
        min(1.0, coverage * 4.0)
        + coverage
        + min(1.0, entropy_mean / 8.0)
        + min(1.0, n_anchors / 4.0)
        + (1.0 if entropy_mean < 7.9 else 0.0)
    ) / 5.0
    # Aether-Erweiterung: Symmetry + Beauty + Bayes gewichtet einmischen
    extended = base * 0.6 + symmetry * 0.15 + beauty * 0.15 + bayes * 0.10
    return round(min(1.0, extended), 4)


# ── Vollständige Source-Profilerstellung ──────────────────────────────────────

def _profile_source(url: str, title: Optional[str],
                    raw: bytes, session_seed: int = 0xA37E) -> SourceProfile:
    """Alle 10 Schichten der Aether-Pipeline auf eine Quelle anwenden."""

    # [0] Security — deny by default
    deny = _is_denied(raw)
    if deny:
        return SourceProfile(
            url=url, title=title,
            sha256=hashlib.sha256(raw).hexdigest(),
            entropy_mean=0.0, h_lambda=0.0, observer_mutual_info=0.0,
            anchors_found={}, anchor_coverage=0.0,
            symmetry_score=0.0, delta_score=0.0, periodicity_score=0.0,
            beauty_score=0.0, bayes_posterior=0.0, trust_score=0.0,
            verdict="DENIED", deny_reason=deny,
        )

    # Block-Segmentierung
    size = len(raw)
    block_size = max(512, size // 64) if size else 512
    blocks = [raw[i: i + block_size] for i in range(0, size, block_size)] or [b""]

    # [1] Shannon
    entropy_values = [_entropy(b) for b in blocks]
    entropy_mean = sum(entropy_values) / len(entropy_values)

    # [2] H_lambda
    h_lam, mutual_info = _h_lambda(entropy_mean)

    # [3] Anchor
    anchors_found: dict[str, int] = {}
    for block in blocks:
        name = _detect_anchor(_normalize_block(block))
        if name:
            anchors_found[name] = anchors_found.get(name, 0) + 1
    coverage = sum(anchors_found.values()) / float(len(blocks))

    # [4] Symmetry
    sym = _symmetry(entropy_values)

    # [5] Delta
    delta = _delta_score(blocks, session_seed)

    # [6] Periodicity
    period = _periodicity(entropy_values)

    # [7] Beauty
    beauty = _beauty(entropy_mean, sym, coverage, period)

    # [8] Bayes
    bayes = _bayes_posterior(coverage)

    # [9] Trust
    trust = _trust(coverage, entropy_mean, len(anchors_found), sym, beauty, bayes)

    verdict = "CONFIRMED" if coverage > 0.0 and trust >= TRUST_THRESHOLD else "FAILED"

    return SourceProfile(
        url=url, title=title,
        sha256=hashlib.sha256(raw).hexdigest(),
        entropy_mean=round(entropy_mean, 4),
        h_lambda=h_lam,
        observer_mutual_info=mutual_info,
        anchors_found=anchors_found,
        anchor_coverage=round(coverage, 6),
        symmetry_score=sym,
        delta_score=delta,
        periodicity_score=period,
        beauty_score=beauty,
        bayes_posterior=bayes,
        trust_score=trust,
        verdict=verdict,
    )


# ── Schicht 10: Konsens-Engine ────────────────────────────────────────────────

def measure_consensus(query: str, sources: list,
                      session_seed: int = 0xA37E) -> ConsensusResult:
    """Vollständige Aether-Pipeline über alle Quellen → ConsensusResult."""

    profiles = [
        _profile_source(src.url, src.title, src.raw_bytes, session_seed)
        for src in sources
    ]

    confirmed = [p for p in profiles if p.verdict == "CONFIRMED"]

    if not confirmed:
        return ConsensusResult(
            query=query, status="UNRESOLVED",
            confirmed_anchors=[], delta_anchors=[],
            sources_analyzed=len(profiles), sources_confirmed=0,
            mean_trust=0.0, mean_h_lambda=0.0, mean_beauty=0.0,
            profiles=profiles,
        )

    # Cross-Source Anker-Konsens
    anchor_source_count: dict[str, int] = defaultdict(int)
    for p in confirmed:
        for a in p.anchors_found:
            anchor_source_count[a] += 1

    consensus_anchors = [a for a, c in anchor_source_count.items()
                         if c >= CONSENSUS_MIN_SOURCES]
    delta_anchors     = [a for a, c in anchor_source_count.items()
                         if c == DELTA_MIN_SOURCES]

    mean_trust   = sum(p.trust_score for p in confirmed) / len(confirmed)
    mean_h_lam   = sum(p.h_lambda    for p in confirmed) / len(confirmed)
    mean_beauty  = sum(p.beauty_score for p in confirmed) / len(confirmed)

    status = ("ANKER" if consensus_anchors
              else "DELTA" if delta_anchors
              else "UNRESOLVED")

    return ConsensusResult(
        query=query, status=status,
        confirmed_anchors=consensus_anchors,
        delta_anchors=delta_anchors,
        sources_analyzed=len(profiles),
        sources_confirmed=len(confirmed),
        mean_trust=round(mean_trust, 4),
        mean_h_lambda=round(mean_h_lam, 4),
        mean_beauty=round(mean_beauty, 4),
        profiles=profiles,
    )
