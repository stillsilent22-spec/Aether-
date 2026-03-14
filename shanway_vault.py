"""shanway_vault.py — Anker-Speicher.
Nur verifizierter Konsens landet hier.
Format kompatibel mit bestehendem aelab_vault.
"""
from __future__ import annotations

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from shanway_pipeline import ConsensusResult, ANCHOR_MEANING, TRUST_THRESHOLD

VAULT_DIR = Path(__file__).resolve().parent / "data" / "shanway_vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

# Minimaler Trust für Vault-Eintrag
VAULT_TRUST_MIN = 0.50





class VaultAnchor:
    __slots__ = ("query", "anchors", "mean_trust", "sources",
                 "summary", "timestamp", "anchor_id")

    def __init__(self, query: str, anchors: list[str], mean_trust: float,
                 sources: int, summary: str, timestamp: str):
        self.query      = query
        self.anchors    = anchors
        self.mean_trust = mean_trust
        self.sources    = sources
        self.summary    = summary
        self.timestamp  = timestamp
        self.anchor_id  = hashlib.sha256(
            f"{query}:{timestamp}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "anchor_id":  self.anchor_id,
            "query":      self.query,
            "anchors":    self.anchors,
            "mean_trust": self.mean_trust,
            "sources":    self.sources,
            "summary":    self.summary,
            "timestamp":  self.timestamp,
        }


def _make_summary(result: ConsensusResult) -> str:
    """Kompakte menschlich lesbare Zusammenfassung des Konsens."""
    parts = []
    for a in result.confirmed_anchors:
        meaning = ANCHOR_MEANING.get(a, a)
        parts.append(meaning)
    src_titles = [p.title for p in result.profiles
                  if p.verdict == "CONFIRMED" and p.title][:3]
    title_hint = "; ".join(src_titles) if src_titles else "mehrere Quellen"
    anchors_str = ", ".join(result.confirmed_anchors)
    return (f"Konsens [{anchors_str}] aus {result.sources_confirmed} Quellen "
            f"({title_hint}). Struktur: {', '.join(parts)}.")


def save_to_vault(result: ConsensusResult) -> Optional[VaultAnchor]:
    """Speichert Konsens-Ergebnis wenn würdig. Gibt VaultAnchor zurück oder None."""
    if result.status != "ANKER":
        return None
    if result.mean_trust < VAULT_TRUST_MIN:
        return None

    summary  = _make_summary(result)
    anchor   = VaultAnchor(
        query      = result.query,
        anchors    = result.confirmed_anchors,
        mean_trust = result.mean_trust,
        sources    = result.sources_confirmed,
        summary    = summary,
        timestamp  = result.timestamp,
    )

    path = VAULT_DIR / f"shanway_{result.timestamp}_{anchor.anchor_id}.json"
    path.write_text(json.dumps(anchor.to_dict(), ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return anchor


def load_vault() -> list[VaultAnchor]:
    """Lädt alle gespeicherten Anker."""
    anchors: list[VaultAnchor] = []
    for f in sorted(VAULT_DIR.glob("shanway_*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            anchors.append(VaultAnchor(
                query      = d["query"],
                anchors    = d["anchors"],
                mean_trust = d["mean_trust"],
                sources    = d["sources"],
                summary    = d["summary"],
                timestamp  = d["timestamp"],
            ))
        except Exception:
            continue
    return anchors


def find_in_vault(query: str, threshold: float = 0.3) -> Optional[VaultAnchor]:
    """Einfache Ähnlichkeitssuche — Wort-Overlap.
    Kein externes Modell, kein Embedding.
    """
    query_words = set(query.lower().split())
    best: Optional[VaultAnchor] = None
    best_score = 0.0

    for anchor in load_vault():
        vault_words = set(anchor.query.lower().split())
        if not vault_words:
            continue
        overlap = len(query_words & vault_words) / len(query_words | vault_words)
        if overlap > best_score and overlap >= threshold:
            best_score = overlap
            best = anchor

    return best
