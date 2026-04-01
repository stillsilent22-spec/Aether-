from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""completion_filter.py — Aether Symbiont: Ockham-gefilterter Completion-Ranker.

Nimmt eine Liste von KI-Completion-Kandidaten entgegen, berechnet für jeden
einen strukturellen OckhamScore und sortiert nach dem Razor-Prinzip:
niedrigster Razor-Score (strukturell einfachste + kohärenteste Antwort) gewinnt.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional

from modules.symbiont_core import AetherSymbiont, Signal
from modules.meta_ockham   import MetaOckhamEngine, OckhamScore

# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class FilteredCompletion:
    """Eine einzelne, bewertete Completion."""
    completion_id: str
    text: str
    ockham_score: OckhamScore
    rank: int                   # 1 = bester
    accepted: bool              # True = unterhalb Razor-Schwelle

    def to_dict(self) -> dict:
        return {
            "completion_id": self.completion_id,
            "text_preview":  self.text[:120],
            "ockham_score":  self.ockham_score.to_dict(),
            "rank":          self.rank,
            "accepted":      self.accepted,
        }


@dataclass
class RankedCompletion:
    """Vollständiges Ranking-Ergebnis für eine Completion-Anfrage."""
    query_preview: str
    candidates:  List[FilteredCompletion] = field(default_factory=list)
    best:        Optional[FilteredCompletion] = None
    razor_threshold: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "query_preview":   self.query_preview,
            "candidates":      [c.to_dict() for c in self.candidates],
            "best_id":         self.best.completion_id if self.best else None,
            "razor_threshold": round(self.razor_threshold, 4),
            "timestamp":       self.timestamp,
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class SymbiontCompletionFilter:
    """
    Filtert und rankt KI-Completions nach dem Ockham-Razor-Prinzip.

    Niedrigster Razor-Score = strukturell einfachste + kohärenteste Antwort
    → wird als Kandidat bevorzugt.

    Razor-Schwelle: Completions mit Score > threshold werden als "rejected"
    markiert, aber immer noch zurückgegeben (für Transparenz/Debugging).
    """

    DEFAULT_RAZOR_THRESHOLD = 1.5

    def __init__(
        self,
        razor_threshold: float = DEFAULT_RAZOR_THRESHOLD,
    ) -> None:
        self._engine   = MetaOckhamEngine()
        self._threshold = razor_threshold

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def rank(
        self,
        query: str,
        completions: List[str],
    ) -> RankedCompletion:
        """
        Rankt eine Liste von Text-Completions per Ockham-Score.

        Parameters
        ----------
        query:
            Ursprüngliche Anfrage (nur für Vorschau/Logging).
        completions:
            Liste der Completion-Texte (Strings).

        Returns
        -------
        RankedCompletion mit sortierten Kandidaten (Rang 1 = bester).
        """
        if not completions:
            return RankedCompletion(
                query_preview=query[:80],
                razor_threshold=self._threshold,
            )

        scored: list[tuple[str, OckhamScore]] = []
        for i, text in enumerate(completions):
            comp_id = f"c{i:03d}"
            score   = self._engine.score_signal(text)
            scored.append((comp_id, text, score))

        # Sortierung: niedrigster Razor-Score zuerst
        scored.sort(key=lambda x: x[2].razor_score)

        filtered: list[FilteredCompletion] = []
        for rank, (comp_id, text, score) in enumerate(scored, start=1):
            accepted = score.razor_score <= self._threshold
            filtered.append(FilteredCompletion(
                completion_id = comp_id,
                text          = text,
                ockham_score  = score,
                rank          = rank,
                accepted      = accepted,
            ))

        best = filtered[0] if filtered else None
        return RankedCompletion(
            query_preview    = query[:80],
            candidates       = filtered,
            best             = best,
            razor_threshold  = self._threshold,
        )

    def rank_structured(
        self,
        query: str,
        completions: List[Signal],
    ) -> RankedCompletion:
        """
        Wie rank(), akzeptiert aber beliebige Signal-Typen (str, bytes, dict).
        """
        texts = [
            c if isinstance(c, str)
            else (c.decode("utf-8", errors="replace") if isinstance(c, bytes)
                  else str(c))
            for c in completions
        ]
        return self.rank(query, texts)

    def best_completion(self, query: str, completions: List[str]) -> Optional[str]:
        """Gibt direkt den Text der best-gerankten Completion zurück (oder None)."""
        result = self.rank(query, completions)
        return result.best.text if result.best else None

    def set_threshold(self, threshold: float) -> None:
        """Setzt den Razor-Threshold (kann zur Laufzeit geändert werden)."""
        self._threshold = float(threshold)
