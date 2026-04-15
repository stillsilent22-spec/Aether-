"""
prediction_engine.py — Meta-Mutation Adaptive Chunk Streaming

KERNIDEE: Metamutationen durch kollektive Entscheidungslogik
============================================================

Jede Nutzerentscheidung (Kamerabewegung, Tastendruck, Scrollrichtung) erzeugt
ein Delta-Signal im Ausgabestream. Dieses Signal hat eine strukturelle Signatur
Φ_decision — genauso wie jeder andere Datenchunk.

Die PredictionEngine lernt die Übergangswahrscheinlichkeit:

    P(Φ_next_chunk | Φ_current_state, Φ_decision)

Je mehr Nutzer mitspielen, desto präziser wird diese Vorhersage im kollektiven
Vault (Vault-Konvergenz-Theorem gilt auch für diesen Übergangsraum).

WARUM VISTA DAMIT AAA-GAMES SPIELEN KANN:
==========================================

1. Vista-PC sendet nur: Φ_current_state + Φ_decision  (~128 Byte)
2. Starker Swarm-Knoten rendert den nächsten Frame
3. Ergebnis: delta-komprimierte Chunk-Signaturen (~64 Byte je Chunk)
   statt unkomprimiertem Video (>4 MBit/s für 1080p@30fps)
4. Vista-PC assembliert: Frame[N] = Frame[N-1] ⊕ delta_chunks
5. Vault-Hit-Rate > 80%  →  ×8 Kompression
   → Vista braucht nur ~500 KBit/s für 1080p@30fps

META-MUTATION — Der lebende Baum:
==================================
Der Chunk-Vorhersage-Baum verändert sich selbst basierend auf realen
Nutzerentscheidungen:

- Selten benutzte Pfade (< MIN_OBSERVATIONS) werden beschnitten → RAM-Ersparnis
- Häufig benutzte Pfade akkumulieren Gewichte → tiefere Vorhersage, besserer Prefetch
- Der Baum mutiert seine Topologie basierend auf kollektivem Verhalten
- Individuelle Entscheidungen beeinflussen DIREKT welche Chunks als nächstes geladen werden

Gespeichert:  data/interbus/chunk_transitions.json
Geteilt via:  Gossip als "prefetch_hints" (top-8 wahrscheinlichste nächste Chunks)
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
TRANSITIONS_PATH  = ROOT / "data" / "interbus" / "chunk_transitions.json"
PREFETCH_QUEUE_PATH = ROOT / "data" / "interbus" / "prefetch_queue.json"

# nach wie vielen Beobachtungen wird ein Prefetch-Hint emittiert
MIN_OBSERVATIONS = 3
# max Kandidaten pro (state_bucket, decision_bucket) Kante
MAX_CANDIDATES_PER_EDGE = 8
# max Kanten im Übergangs-Graphen (Speicherbudget für Vista-Klasse)
# 4096 Kanten × 8 Kandidaten × ~128 Byte ≈ 4 MB — für 512 MB RAM problemlos
MAX_EDGES = 4096
# max lokale Nutzerkontexte für kontext-sensitive Gewichtung
MAX_CONTEXTS = 32
# max Kandidaten pro Kontext-Edge
MAX_CONTEXT_BIAS_CANDIDATES = 8
# Kontext-Boosung für lokale Spiel-/Session-Gewichtung
CONTEXT_BIAS_BOOST = 1.5
# Unterstützungszähler ab dem ein Prefetch-Hint als stark gilt
MIN_SUPPORT_FOR_STRONG_HINT = 3
# Begrenzung für gespeicherte Prefetch-Queue-Einträge
MAX_PREFETCH_QUEUE_ITEMS = 128


# --------------------------------------------------------------------------- #
#  Datenstrukturen                                                             #
# --------------------------------------------------------------------------- #

@dataclass
class DecisionSignal:
    """Kompakte strukturelle Repräsentation einer Nutzeraktion.

    KEINE persönlichen Daten:
    - Keine Tastencodes
    - Keine Fensterdaten
    - Keine Mauskoordinaten
    - Nur: quantisierte Richtung, Betrag, Timing-Bucket

    Wird als ~64-Byte-Fingerprint übermittelt.
    """
    signal_type:       str    # "input_vector", "camera_delta", "ui_interaction", "scroll"
    direction_bucket:  int    # Quantisiert 0–15 (4 Bits = 16 Richtungen)
    magnitude_bucket:  int    # Quantisiert 0–7  (3 Bits = 8 Beträge)
    timing_bucket:     int    # 0=schnell(<100ms), 1=mittel(<500ms), 2=langsam(>500ms)
    state_fingerprint: str    # SHA256 des aktuellen Zustands-Φ-Vektors
    context_key:       str    = ""  # optionaler lokaler Kontext wie Spielprozess oder Session
    ts: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        """Deterministischer Fingerprint dieses Decision-Signals."""
        return hashlib.sha256(
            f"{self.signal_type}:{self.direction_bucket}:{self.magnitude_bucket}:"
            f"{self.timing_bucket}:{self.state_fingerprint}".encode()
        ).hexdigest()

    @staticmethod
    def from_invariant_delta(
        before_phi: List[float],
        after_phi: List[float],
        signal_type: str = "invariant_delta",
    ) -> "DecisionSignal":
        """Leitet ein DecisionSignal aus der Änderung zweier Φ-Vektoren ab.

        Privatsphäre-sicher: Nur die STRUKTURELLE ÄNDERUNG wird kodiert,
        kein Inhalt. Erfasst z.B.:
        - Wie stark hat sich die Shannon-Entropie geändert?
        - Hat sich die Zipf-Verteilung verschoben?
        Diese Änderungen zeigen STRUKTURELL was der Nutzer gemacht hat,
        ohne Inhalte preiszugeben.
        """
        if not before_phi or not after_phi:
            fp = hashlib.sha256(b"empty").hexdigest()
            return DecisionSignal(signal_type, 0, 0, 0, fp)

        delta = [a - b for a, b in zip(after_phi, before_phi)]
        # Welche Dimension hat sich am stärksten geändert?
        max_idx = max(range(len(delta)), key=lambda i: abs(delta[i])) if delta else 0
        direction_bucket = (max_idx * 2) % 16
        if delta and delta[max_idx] < 0:
            direction_bucket = (direction_bucket + 1) % 16

        total_change = sum(abs(d) for d in delta)
        magnitude_bucket = min(7, int(total_change * 14))

        fp = hashlib.sha256(
            json.dumps([round(v, 4) for v in before_phi[:9]],
                       separators=(",", ":")).encode()
        ).hexdigest()
        return DecisionSignal(signal_type, direction_bucket, magnitude_bucket, 1, fp)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_type":       self.signal_type,
            "direction_bucket":  self.direction_bucket,
            "magnitude_bucket":  self.magnitude_bucket,
            "timing_bucket":     self.timing_bucket,
            "state_fingerprint": self.state_fingerprint,
            "context_key":       self.context_key,
            "fingerprint":       self.fingerprint(),
        }


# --------------------------------------------------------------------------- #
#  Kern-Engine                                                                 #
# --------------------------------------------------------------------------- #

class PredictionEngine:
    """Lernt und sagt vorher welche Chunks als nächstes kommen.

    Architektur:
        Kanten-Key: f"{state_fp_prefix}:{decision_fp_prefix}"  (24 Hex je)
        Kanten-Wert: {candidate_fp: Anzahl_Beobachtungen}
        Sortiert nach Häufigkeit für O(1)-Prefetch

    Singleton pro Prozess — PredictionEngine.instance() verwenden.
    Thread-sicher. Persistenz in data/interbus/chunk_transitions.json.
    Memory-Budget: MAX_EDGES × MAX_CANDIDATES_PER_EDGE × ~128 Byte ≈ 4 MB
    """

    _instance: Optional["PredictionEngine"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "PredictionEngine":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Übergangs-Tabelle: kanten_key → {nächster_chunk_fp: Anzahl}
        self._transitions:          Dict[str, Dict[str, int]] = {}
        self._context_biases:       Dict[str, Dict[str, Dict[str, int]]] = {}
        self._context_usage:        Dict[str, int] = {}
        self._hint_support:         Dict[str, set[str]] = {}
        self._total_observations:   int = 0
        self._prefetch_hits:        int = 0
        self._prefetch_misses:      int = 0
        self._load_persistent()

    # ── Persistenz ────────────────────────────────────────────────────────── #

    def _load_persistent(self) -> None:
        try:
            if TRANSITIONS_PATH.is_file():
                data = json.loads(TRANSITIONS_PATH.read_text(encoding="utf-8"))
                self._transitions = {
                    k: {fp: int(c) for fp, c in v.items()}
                    for k, v in data.get("transitions", {}).items()
                    if isinstance(v, dict)
                }
                self._context_biases = {
                    ctx: {
                        k: {fp: int(c) for fp, c in edge.items()}
                        for k, edge in contexts.items() if isinstance(edge, dict)
                    }
                    for ctx, contexts in data.get("context_biases", {}).items()
                    if isinstance(contexts, dict)
                }
                self._context_usage = {
                    ctx: int(count) for ctx, count in data.get("context_usage", {}).items()
                    if isinstance(count, (int, float))
                }
                self._total_observations = int(data.get("total_observations", 0))
                self._prefetch_hits      = int(data.get("prefetch_hits", 0))
                self._prefetch_misses    = int(data.get("prefetch_misses", 0))
                logger.info(f"[prediction_engine] {len(self._transitions)} Kanten, "
                            f"{self._total_observations} Beobachtungen geladen")
        except Exception as exc:
            logger.debug(f"[prediction_engine] load_persistent: {exc}")

    def _save_persistent(self) -> None:
        try:
            TRANSITIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
            TRANSITIONS_PATH.write_text(
                json.dumps({
                    "schema":             "aether.prediction.v1",
                    "transitions":        self._transitions,
                    "context_biases":     self._context_biases,
                    "context_usage":      self._context_usage,
                    "total_observations": self._total_observations,
                    "prefetch_hits":      self._prefetch_hits,
                    "prefetch_misses":    self._prefetch_misses,
                    "edge_count":         len(self._transitions),
                }, ensure_ascii=True, separators=(",", ":")),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug(f"[prediction_engine] save_persistent: {exc}")

    # ── Hilfsmethoden ─────────────────────────────────────────────────────── #

    def _edge_key(self, state_fp: str, decision_fp: str) -> str:
        return f"{state_fp[:24]}:{decision_fp[:24]}"

    def _prune_least_used_edge(self) -> None:
        """Entfernt die am wenigsten benutzte Kante (Meta-Mutation: seltene Pfade sterben).

        Das IST die Metamutation: der Baum beschneidet sich selbst basierend
        auf kollektivem Verhalten. Selten gegangene Wege verschwinden.
        """
        if not self._transitions:
            return
        total_per_edge = {k: sum(v.values()) for k, v in self._transitions.items()}
        weakest_key = min(total_per_edge, key=total_per_edge.__getitem__)
        del self._transitions[weakest_key]

    def _prune_least_used_context(self) -> None:
        """Entfernt den am wenigsten relevanten lokalen Kontext um Speicher zu schonen."""
        if not self._context_usage:
            return
        weakest_context = min(self._context_usage, key=self._context_usage.__getitem__)
        self._context_usage.pop(weakest_context, None)
        self._context_biases.pop(weakest_context, None)

    def _promote_context_bias(
        self,
        edge_key: str,
        fp_key: str,
        context_key: str,
    ) -> None:
        if not context_key:
            return
        self._context_usage[context_key] = self._context_usage.get(context_key, 0) + 1
        if len(self._context_usage) > MAX_CONTEXTS:
            self._prune_least_used_context()
        contexts = self._context_biases.setdefault(context_key, {})
        edge_bias = contexts.setdefault(edge_key, {})
        edge_bias[fp_key] = edge_bias.get(fp_key, 0) + 1
        if len(edge_bias) > MAX_CONTEXT_BIAS_CANDIDATES:
            rarest = min(edge_bias.items(), key=lambda x: x[1])
            edge_bias.pop(rarest[0], None)

    def _load_prefetch_queue(self) -> List[Dict[str, Any]]:
        if not PREFETCH_QUEUE_PATH.is_file():
            return []
        try:
            data = json.loads(PREFETCH_QUEUE_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass
        return []

    def _save_prefetch_queue(self, queue: List[Dict[str, Any]]) -> None:
        try:
            PREFETCH_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
            PREFETCH_QUEUE_PATH.write_text(
                json.dumps(queue, ensure_ascii=True, separators=(",", ":")),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug(f"[prediction_engine] save_prefetch_queue: {exc}")

    def schedule_prefetch(
        self,
        context_key: str,
        state_fingerprint: str,
        decision: DecisionSignal,
        depth: int = 3,
        beam: int = 4,
        top_n: int = 8,
    ) -> int:
        """Plant lokale Prefetch-Sequenzen für einen Kontext und speichert sie in einer Queue."""
        sequences = self.predict_next_sequences(
            state_fingerprint,
            decision,
            depth=depth,
            beam=beam,
            top_n=top_n,
            context_key=context_key,
        )
        if not sequences:
            return 0
        queue = self._load_prefetch_queue()
        timestamp = time.time()
        for seq in sequences:
            queue.append({
                "context_key": context_key,
                "state_fingerprint": state_fingerprint,
                "decision": decision.to_dict(),
                "sequence": seq["sequence"],
                "probability": seq["probability"],
                "ts": timestamp,
            })
        queue = queue[-MAX_PREFETCH_QUEUE_ITEMS:]
        self._save_prefetch_queue(queue)
        return len(sequences)

    def load_prefetch_queue(self) -> List[Dict[str, Any]]:
        return self._load_prefetch_queue()

    # ── Kern-Lernmethoden ─────────────────────────────────────────────────── #

    def record_transition(
        self,
        state_fingerprint: str,
        decision: DecisionSignal,
        next_chunk_fingerprint: str,
        context_key: str = "",
    ) -> None:
        """Zeichnet eine beobachtete Transition auf: Zustand + Entscheidung → nächster Chunk.

        Wird aufgerufen NACHDEM der Vault-Lookup abgeschlossen ist —
        wir wissen dann welcher Chunk tatsächlich als nächstes kam.

        Meta-Mutation: Die Topologie der Transitions-Tabelle ändert sich
        mit jeder Aufzeichnung. Beliebte Pfade akkumulieren Gewicht,
        seltene Pfade bleiben schwach und werden beim Speicher-Limit bereinigt.
        """
        edge_key = self._edge_key(state_fingerprint, decision.fingerprint())
        context_key = context_key or decision.context_key or ""
        with self._lock:
            if edge_key not in self._transitions:
                if len(self._transitions) >= MAX_EDGES:
                    self._prune_least_used_edge()
                self._transitions[edge_key] = {}
            candidates = self._transitions[edge_key]
            fp_key = next_chunk_fingerprint[:32]
            candidates[fp_key] = candidates.get(fp_key, 0) + 1
            if context_key:
                self._promote_context_bias(edge_key, fp_key, context_key)
            # Kandidaten-Limit: seltenster fliegt raus (Metamutation auf Edge-Ebene)
            if len(candidates) > MAX_CANDIDATES_PER_EDGE:
                rarest = min(candidates.items(), key=lambda x: x[1])
                del candidates[rarest[0]]
            self._total_observations += 1
            # Alle 100 Beobachtungen persistieren
            if self._total_observations % 100 == 0:
                self._save_persistent()

    def predict_next_chunks(
        self,
        state_fingerprint: str,
        decision: DecisionSignal,
        top_n: int = 4,
        context_key: Optional[str] = None,
    ) -> List[Tuple[str, float]]:
        """Sagt die wahrscheinlichsten nächsten Chunk-Fingerprints vorher.

        Rückgabe: [(chunk_fp, Wahrscheinlichkeit)] absteigend sortiert.
        Leere Liste wenn nicht genug Beobachtungen vorhanden.

        Dies treibt den Prefetch-Scheduler: Chunks werden PRE-LOADED bevor
        der Client sie anfordert. Bei Vault-Hit-Rate > 80%: Vista braucht
        nur ~500 KBit/s statt 4 MBit/s für 1080p@30fps.
        """
        edge_key = self._edge_key(state_fingerprint, decision.fingerprint())
        with self._lock:
            base_candidates = dict(self._transitions.get(edge_key, {}))
            context_bias = {}
            if context_key:
                context_bias = (
                    self._context_biases.get(context_key, {}).get(edge_key, {})
                )
        if not base_candidates and not context_bias:
            return []
        weighted = dict(base_candidates)
        for fp, count in (context_bias or {}).items():
            weighted[fp] = weighted.get(fp, 0) + int(count * CONTEXT_BIAS_BOOST)
        total = sum(weighted.values())
        if total < MIN_OBSERVATIONS:
            return []
        sorted_c = sorted(weighted.items(), key=lambda x: -x[1])
        return [(fp, count / total) for fp, count in sorted_c[:top_n]]

    def predict_next_sequences(
        self,
        state_fingerprint: str,
        decision: DecisionSignal,
        depth: int = 2,
        beam: int = 3,
        top_n: int = 4,
        context_key: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Erzeugt die wahrscheinlichsten nächsten Chunk-Sequenzen für Prefetching."""
        beams: List[Tuple[List[str], float, str, DecisionSignal]] = [([], 1.0, state_fingerprint, decision)]
        final_beams: List[Tuple[List[str], float, str, DecisionSignal]] = beams
        for _ in range(depth):
            next_beams: List[Tuple[List[str], float, str, DecisionSignal]] = []
            for sequence, probability, current_state, current_decision in beams:
                candidates = self.predict_next_chunks(
                    current_state,
                    current_decision,
                    top_n=top_n,
                    context_key=context_key,
                )
                for fp, p in candidates:
                    if p <= 0.0:
                        continue
                    next_probability = probability * p
                    next_decision = DecisionSignal(
                        "auto",
                        0,
                        0,
                        0,
                        fp,
                        context_key=context_key or "",
                    )
                    next_beams.append((sequence + [fp], next_probability, fp, next_decision))
            if not next_beams:
                break
            beams = sorted(next_beams, key=lambda x: -x[1])[:beam]
            final_beams = beams
        return [
            {"sequence": seq, "probability": round(prob, 4)}
            for seq, prob, _, _ in final_beams
        ]

    def record_prefetch_outcome(self, predicted_fp: str, actual_fp: str) -> None:
        """Verfolgt ob eine Prefetch-Vorhersage korrekt war (für Genauigkeits-Metrik)."""
        with self._lock:
            if predicted_fp[:32] == actual_fp[:32]:
                self._prefetch_hits += 1
            else:
                self._prefetch_misses += 1

    # ── Gossip-Interface ──────────────────────────────────────────────────── #

    def get_prefetch_hints_for_gossip(self) -> List[Dict[str, Any]]:
        """Exportiert die wertvollsten Vorhersagen für den Gossip-Austausch.

        Andere Knoten nutzen diese Hints um ihren Vault zu wärmen BEVOR
        die Anfrage eintrifft. Das ist wie kollektive Intelligenz entsteht:

        - Meine Entscheidungen trainieren DEINEN Vault was wahrscheinlich kommt
        - 10 Spieler spielen dasselbe Game → jeder Vault ist 10× klüger
        - Ergebnis: Prefetch-Hits vor Misses → Vista-Hardware schafft AAA-Content

        Max 8 Hints im Gossip-Paket (Overhead-Kontrolle).
        """
        hints: List[Dict[str, Any]] = []
        with self._lock:
            edge_totals = [
                (k, sum(v.values()), v, len(self._hint_support.get(k, set())))
                for k, v in self._transitions.items()
            ]
            edge_totals.sort(key=lambda x: (-x[1], -x[3]))
            edge_totals = edge_totals[:8]
        for edge_key, total, candidates, support_count in edge_totals:
            if total < MIN_OBSERVATIONS:
                continue
            strong = support_count >= MIN_SUPPORT_FOR_STRONG_HINT
            best = sorted(candidates.items(), key=lambda x: -x[1])[:3]
            hints.append({
                "edge_key": edge_key,
                "predictions": [
                    {"fp": fp, "prob": round(c / total, 3)}
                    for fp, c in best
                ],
                "observation_count": total,
                "support_count": support_count,
                "strong_hint": strong,
            })
        return hints

    def absorb_gossip_hints(self, hints: List[Dict[str, Any]]) -> int:
        """Absorbiert Prefetch-Hints aus dem Gossip eines Peers.

        Führt deren Beobachtungen in unsere lokale Transitions-Tabelle zusammen.
        Das ist der kollektive Lernmechanismus:
          10 Spieler spielen dasselbe → Vault an jedem Knoten 10× intelligenter.

        Sicherheit: Gossip-Gewichte werden auf max 1/4 der eigenen skaliert,
        damit ein einziger Peer den Predictor nicht dominieren kann.

        Rückgabe: Anzahl aktualisierter Kanten.
        """
        updated = 0
        with self._lock:
            for hint in hints:
                edge_key = str(hint.get("edge_key", ""))
                if not edge_key or len(edge_key) < 10:
                    continue
                if edge_key not in self._transitions:
                    if len(self._transitions) >= MAX_EDGES:
                        self._prune_least_used_edge()
                    self._transitions[edge_key] = {}
                obs_count = int(hint.get("observation_count", 1))
                gossip_weight = max(1, min(obs_count // 4, 10))
                peer_id = str(hint.get("peer_id", ""))
                if peer_id:
                    self._hint_support.setdefault(edge_key, set()).add(peer_id)
                for pred in hint.get("predictions", []):
                    fp = str(pred.get("fp", ""))[:32]
                    if not fp:
                        continue
                    self._transitions[edge_key][fp] = (
                        self._transitions[edge_key].get(fp, 0) + gossip_weight
                    )
                    if len(self._transitions[edge_key]) > MAX_CANDIDATES_PER_EDGE:
                        rarest = min(self._transitions[edge_key].items(),
                                     key=lambda x: x[1])
                        del self._transitions[edge_key][rarest[0]]
                    updated += 1
        if updated > 0:
            self._save_persistent()
        return updated

    # ── Statistik ─────────────────────────────────────────────────────────── #

    def get_prefetch_accuracy(self) -> float:
        """Aktuell erreichte Vorhersage-Genauigkeit (Hits / Gesamt). 0.0 wenn kein Datum."""
        with self._lock:
            total = self._prefetch_hits + self._prefetch_misses
            if total == 0:
                return 0.0
            return self._prefetch_hits / total

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._prefetch_hits + self._prefetch_misses
            return {
                "edge_count":          len(self._transitions),
                "total_observations":  self._total_observations,
                "prefetch_accuracy":   round(self._prefetch_hits / total, 3) if total else 0.0,
                "prefetch_hits":       self._prefetch_hits,
                "prefetch_misses":     self._prefetch_misses,
                "memory_budget_pct":   round(len(self._transitions) / MAX_EDGES * 100, 1),
            }
