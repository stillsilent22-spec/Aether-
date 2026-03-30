"""modules/text_utils.py — Structural text normalisation and feature extraction.

Public API:
    text_normalize(text)         → normalised string (NFKC, lowercase, no umlauts)
    text_reduce(text)            → structural feature dict (entropy, anchors, …)
    interference_score(a, b)     → float [0,1] — structural divergence between two texts
"""
from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_GERMAN_HINTS = {"und", "oder", "nicht", "ist", "mit", "fuer", "der", "die", "das"}
_ENGLISH_HINTS = {"and", "or", "not", "is", "with", "the", "this", "that", "for"}
_STOPWORDS = {
    "and", "are", "aus", "bei", "das", "der", "die", "ein", "eine", "for", "ist", "mit",
    "nicht", "oder", "the", "und", "von", "with",
}


def text_normalize(text: str) -> str:
    value = " ".join(str(text or "").split())
    value = "".join(char for char in value if char.isprintable())
    value = unicodedata.normalize("NFKC", value).lower()
    replacements = {
        "ä": "ae",
        "ö": "oe",
        "ü": "ue",
        "ß": "ss",
    }
    for source, target in replacements.items():
        value = value.replace(source, target)
    return value


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text_normalize(text))


def _entropy_bytes(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = Counter(payload)
    total = float(len(payload))
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def _token_entropy(tokens: list[str]) -> float:
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    total = float(len(tokens))
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def _bigrams(tokens: list[str]) -> list[str]:
    return [f"{left}->{right}" for left, right in zip(tokens, tokens[1:])]


def _jaccard_score(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return 1.0
    return float(len(left & right) / len(union))


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _reference_model() -> dict[str, Any]:
    root = _project_root()
    corpus_dir = root / "data" / "text_corpus"
    fallback_paths = [
        root / "README.md",
        root / "README_EN.md",
        root / "WHITEPAPER.md",
        root / "WHITEPAPER_EN.md",
        root / "core_axioms.md",
        root / "contracts" / "aether_event_schema_v1.json",
        root / "contracts" / "aether_kpi_contract_v1.json",
        root / "data" / "aether_event_schema_v1.json",
        root / "data" / "aether_kpi_contract_v1.json",
    ]
    paths: list[Path] = []
    for language_dir in (corpus_dir / "de", corpus_dir / "en"):
        if language_dir.is_dir():
            paths.extend(sorted(path for path in language_dir.iterdir() if path.suffix.lower() == ".txt"))
    if not paths:
        paths = [path for path in fallback_paths if path.is_file()]

    documents: list[dict[str, Any]] = []
    token_freq: Counter[str] = Counter()
    bigram_freq: Counter[str] = Counter()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        try:
            raw_text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        normalized = text_normalize(raw_text)[:200000]
        tokens = _tokenize(normalized)
        bigrams = _bigrams(tokens)
        documents.append(
            {
                "path": path.relative_to(root).as_posix(),
                "tokens": Counter(tokens),
                "token_set": set(tokens),
                "bigram_set": set(bigrams),
                "signature": hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16],
            }
        )
        token_freq.update(token for token in tokens if len(token) >= 4 and token not in _STOPWORDS)
        bigram_freq.update(bigrams)

    anchor_terms = [token for token, _ in token_freq.most_common(96)]
    return {
        "documents": documents,
        "token_freq": token_freq,
        "bigram_set": set(bigram_freq.keys()),
        "anchor_terms": anchor_terms,
    }


def _language_hint(tokens: list[str]) -> str:
    token_set = set(tokens)
    german_hits = len(token_set & _GERMAN_HINTS)
    english_hits = len(token_set & _ENGLISH_HINTS)
    if german_hits > english_hits:
        return "de"
    if english_hits > german_hits:
        return "en"
    return "mixed"


def interference_score(a: str, b: str) -> float:
    """Structural divergence between two texts. Returns float in [0, 1]."""
    left_norm = text_normalize(a)
    right_norm = text_normalize(b)
    if not left_norm and not right_norm:
        return 0.0

    left_bytes = left_norm.encode("utf-8")
    right_bytes = right_norm.encode("utf-8")
    prefix_len = min(len(left_bytes), len(right_bytes))
    xor_drift = 0.0
    if prefix_len > 0:
        xor_drift = sum((left_bytes[index] ^ right_bytes[index]) / 255.0 for index in range(prefix_len)) / prefix_len
    length_drift = abs(len(left_bytes) - len(right_bytes)) / max(len(left_bytes), len(right_bytes), 1)
    token_distance = 1.0 - _jaccard_score(set(_tokenize(left_norm)), set(_tokenize(right_norm)))
    sequence_distance = 1.0 - SequenceMatcher(a=left_norm, b=right_norm).ratio()
    return float(min(1.0, max(0.0, xor_drift * 0.35 + token_distance * 0.30 + sequence_distance * 0.25 + length_drift * 0.10)))


def text_reduce(text: str) -> dict[str, Any]:
    """Extract structural features from text for Aether analysis pipeline."""
    normalized = text_normalize(text)
    payload = normalized.encode("utf-8")
    tokens = _tokenize(normalized)
    token_set = set(tokens)
    bigram_set = set(_bigrams(tokens))
    reference = _reference_model()

    token_entropy = _token_entropy(tokens)
    byte_entropy = _entropy_bytes(payload)
    unique_token_ratio = float(len(token_set) / max(len(tokens), 1))
    anchor_hits = sorted(token for token in token_set if token in set(reference["anchor_terms"]))[:12]
    reference_alignment = _jaccard_score(token_set, set(reference["anchor_terms"]))
    markov_coherence = float(len(bigram_set & set(reference["bigram_set"])) / max(len(bigram_set), 1))

    candidates: list[dict[str, Any]] = []
    for document in reference["documents"]:
        token_overlap = _jaccard_score(token_set, set(document["token_set"]))
        bigram_overlap = _jaccard_score(bigram_set, set(document["bigram_set"]))
        score = token_overlap * 0.6 + bigram_overlap * 0.4
        if score > 0.0:
            candidates.append(
                {
                    "path": document["path"],
                    "score": float(round(score, 6)),
                    "signature": document["signature"],
                }
            )
    candidates.sort(key=lambda item: (-float(item["score"]), str(item["path"])))

    structure_score = float(
        min(
            1.0,
            max(
                0.0,
                reference_alignment * 0.40
                + markov_coherence * 0.35
                + (1.0 - unique_token_ratio) * 0.10
                + min(token_entropy / 6.0, 1.0) * 0.15,
            ),
        )
    )

    return {
        "length": len(payload),
        "entropy": byte_entropy,
        "signature": hashlib.sha256(payload).hexdigest(),
        "normalized": normalized,
        "language_hint": _language_hint(tokens),
        "token_count": len(tokens),
        "unique_token_ratio": unique_token_ratio,
        "token_entropy": token_entropy,
        "anchor_count": len(anchor_hits),
        "anchor_hits": anchor_hits,
        "reference_alignment": reference_alignment,
        "markov_coherence": markov_coherence,
        "structure_score": structure_score,
        "reference_candidates": candidates[:3],
        "corpus_ready": bool(reference["documents"]),
    }
