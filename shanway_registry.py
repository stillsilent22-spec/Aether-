"""shanway_registry.py — Universelles Ankerregister.

Shanways Gedächtnis. Ein wachsender Strukturgraph.

Alle Kanäle schreiben in dasselbe Register:
  - Web-Quellen        (shanway_web)
  - Lokale Dateien     (aether_dropper)
  - Browser-Rendering  (zukünftig)
  - Prozessdynamik     (zukünftig)

Jeder Anker der durch alle Pipeline-Filter kommt wird eingetragen.
Über die Graphschicht entstehen Verbindungen zwischen Ankern.
Aus diesen Verbindungen entsteht kontextuelle Semantik — bottom up.

Keine neuen Abhängigkeiten außer collections und random.
Bestehende Pipeline bleibt vollständig unberührt.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from shanway_pipeline import (
    ANCHOR_NAMES, ANCHOR_MEANING,
    _entropy, _normalize_block, _detect_anchor,
    _h_lambda, _symmetry, _periodicity, _beauty, _bayes_posterior, _trust,
    _is_denied, TRUST_THRESHOLD,
    ConsensusResult,
)

# ── Pfade ─────────────────────────────────────────────────────────────────────
REGISTRY_DIR  = Path(__file__).resolve().parent / "data" / "shanway_registry"
REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
REGISTRY_FILE = REGISTRY_DIR / "anchors.jsonl"   # append-only, nie überschreiben
GRAPH_FILE    = REGISTRY_DIR / "graph.json"

# ── Eingangskanäle ────────────────────────────────────────────────────────────
CHANNEL_WEB     = "web"
CHANNEL_FILE    = "file"
CHANNEL_RENDER  = "render"
CHANNEL_PROCESS = "process"
CHANNEL_TEXT    = "text"

# ── Schwellwerte ──────────────────────────────────────────────────────────────
REGISTRY_TRUST_MIN     = 0.45
INTERFERENCE_THRESHOLD = 0.35   # Minimum für [ANKER]
DELTA_THRESHOLD        = 0.15   # Minimum für [DELTA]
GRAPH_EDGE_MIN_TRUST   = 0.50   # Minimum Trust für Graphkante


# ── RegistryAnchor ────────────────────────────────────────────────────────────

class RegistryAnchor:
    """Ein verifizierter Anker. Enthält volles Strukturprofil.
    Kanal-agnostisch — Web, Datei, Render, Prozess, alles gleich.
    """
    __slots__ = (
        "anchor_id", "channel", "label",
        "signature",
        "entropy_mean", "h_lambda", "symmetry",
        "periodicity", "beauty", "bayes", "trust",
        "raw_hash", "timestamp", "summary",
    )

    def __init__(self, channel: str, label: str, raw: bytes,
                 entropy_mean: float, h_lambda: float, symmetry: float,
                 periodicity: float, beauty: float, bayes: float,
                 trust: float, anchors_found: dict[str, int], summary: str):
        self.channel      = channel
        self.label        = label
        self.entropy_mean = round(entropy_mean, 4)
        self.h_lambda     = round(h_lambda, 4)
        self.symmetry     = round(symmetry, 4)
        self.periodicity  = round(periodicity, 4)
        self.beauty       = round(beauty, 4)
        self.bayes        = round(bayes, 4)
        self.trust        = round(trust, 4)
        self.signature    = frozenset(anchors_found.keys())
        self.raw_hash     = hashlib.sha256(raw).hexdigest()
        self.timestamp    = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        self.summary      = summary
        self.anchor_id    = hashlib.sha256(
            f"{channel}:{label}:{self.timestamp}:{self.raw_hash}".encode()
        ).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "anchor_id":    self.anchor_id,
            "channel":      self.channel,
            "label":        self.label,
            "signature":    sorted(self.signature),
            "entropy_mean": self.entropy_mean,
            "h_lambda":     self.h_lambda,
            "symmetry":     self.symmetry,
            "periodicity":  self.periodicity,
            "beauty":       self.beauty,
            "bayes":        self.bayes,
            "trust":        self.trust,
            "raw_hash":     self.raw_hash,
            "timestamp":    self.timestamp,
            "summary":      self.summary,
        }

    @staticmethod
    def from_dict(d: dict) -> "RegistryAnchor":
        a = object.__new__(RegistryAnchor)
        for k in RegistryAnchor.__slots__:
            setattr(a, k, d.get(k, None))
        a.signature = frozenset(d.get("signature", []))
        return a

    def vector(self) -> dict[str, float]:
        """Strukturvektor für Interferenzmessung."""
        return {
            "entropy":     self.entropy_mean / 8.0,
            "h_lambda":    self.h_lambda / 8.0,
            "symmetry":    self.symmetry,
            "periodicity": self.periodicity,
            "beauty":      self.beauty,
            "bayes":       self.bayes,
            "has_pi":      1.0 if "pi"    in self.signature else 0.0,
            "has_phi":     1.0 if "phi"   in self.signature else 0.0,
            "has_sqrt2":   1.0 if "sqrt2" in self.signature else 0.0,
            "has_e":       1.0 if "e"     in self.signature else 0.0,
        }


# ── Graphschicht ──────────────────────────────────────────────────────────────

class AnchorGraph:
    """Verbindungen zwischen Ankern = emergente Semantik.

    Kante entsteht wenn zwei Anker:
    - dieselben Struktursignaturen teilen
    - aus ähnlichen Kanälen kommen
    - hohen kombinierten Trust haben

    Über Zeit bilden sich Cluster:
    - Rezept-Cluster: e + niedrige Entropie + hohe Symmetrie
    - Wissenschaft-Cluster: pi + hohe Periodizität
    - Prozess-Cluster: sqrt2 + hohe Delta-Werte
    Das ist Shanways emergente Semantik — nicht trainiert, gemessen.
    """

    def __init__(self):
        # edges[id_a][id_b] = Kantengewicht (kombinierter Trust)
        self.edges: dict[str, dict[str, float]] = defaultdict(dict)
        # Nachschlagetabelle id → Anker
        self.nodes: dict[str, RegistryAnchor] = {}

    def add_anchor(self, anchor: RegistryAnchor) -> None:
        """Anker eintragen und Kanten zu ähnlichen Ankern ziehen."""
        self.nodes[anchor.anchor_id] = anchor
        for existing_id, existing in self.nodes.items():
            if existing_id == anchor.anchor_id:
                continue
            weight = self._edge_weight(anchor, existing)
            if weight >= GRAPH_EDGE_MIN_TRUST:
                self.edges[anchor.anchor_id][existing_id] = round(weight, 4)
                self.edges[existing_id][anchor.anchor_id] = round(weight, 4)

    def _edge_weight(self, a: RegistryAnchor, b: RegistryAnchor) -> float:
        """Kantengewicht = Strukturähnlichkeit × kombinierter Trust."""
        sig_overlap = len(a.signature & b.signature) / max(
            len(a.signature | b.signature), 1
        )
        vec_sim = _cosine_similarity(a.vector(), b.vector())
        combined_trust = (a.trust + b.trust) / 2.0
        return sig_overlap * 0.4 + vec_sim * 0.4 + combined_trust * 0.2

    def neighbors(self, anchor_id: str,
                  min_weight: float = 0.5) -> list[tuple[RegistryAnchor, float]]:
        """Nachbarn eines Ankerns sortiert nach Kantengewicht."""
        result = []
        for nid, weight in self.edges.get(anchor_id, {}).items():
            if weight >= min_weight and nid in self.nodes:
                result.append((self.nodes[nid], weight))
        return sorted(result, key=lambda x: x[1], reverse=True)

    def cluster_summary(self, anchor_id: str, depth: int = 2) -> str:
        """Fasst den semantischen Cluster um einen Anker zusammen."""
        if anchor_id not in self.nodes:
            return ""
        visited = {anchor_id}
        queue = [anchor_id]
        summaries: list[str] = []
        for _ in range(depth):
            next_queue = []
            for nid in queue:
                for neighbor, weight in self.neighbors(nid, min_weight=0.4):
                    if neighbor.anchor_id not in visited:
                        visited.add(neighbor.anchor_id)
                        next_queue.append(neighbor.anchor_id)
                        summaries.append(neighbor.summary)
            queue = next_queue
            if not queue:
                break
        return " | ".join(summaries[:5]) if summaries else ""

    def to_dict(self) -> dict:
        return {
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": {k: dict(v) for k, v in self.edges.items()},
        }

    @staticmethod
    def from_dict(d: dict) -> "AnchorGraph":
        g = AnchorGraph()
        for aid, adict in d.get("nodes", {}).items():
            g.nodes[aid] = RegistryAnchor.from_dict(adict)
        for aid, edges in d.get("edges", {}).items():
            g.edges[aid] = dict(edges)
        return g

    def save(self) -> None:
        GRAPH_FILE.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    @staticmethod
    def load() -> "AnchorGraph":
        if not GRAPH_FILE.exists():
            return AnchorGraph()
        try:
            return AnchorGraph.from_dict(
                json.loads(GRAPH_FILE.read_text(encoding="utf-8"))
            )
        except Exception:
            return AnchorGraph()


# ── Interferenzmessung ────────────────────────────────────────────────────────

def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    keys = set(a) | set(b)
    dot  = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in keys)
    na   = math.sqrt(sum(v ** 2 for v in a.values()))
    nb   = math.sqrt(sum(v ** 2 for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _raw_to_vector(raw: bytes,
                   session_seed: int = 0xA37E) -> Optional[dict[str, float]]:
    """Rohdaten → Strukturvektor. None wenn DENIED oder zu klein."""
    if _is_denied(raw):
        return None
    if len(raw) < 64:
        return None

    size = len(raw)
    block_size = max(512, size // 64)
    blocks = [raw[i: i + block_size] for i in range(0, size, block_size)] or [b""]

    entropy_values = [_entropy(b) for b in blocks]
    entropy_mean   = sum(entropy_values) / len(entropy_values)

    anchors_found: dict[str, int] = {}
    for block in blocks:
        name = _detect_anchor(_normalize_block(block))
        if name:
            anchors_found[name] = anchors_found.get(name, 0) + 1

    coverage = sum(anchors_found.values()) / float(len(blocks))
    h_lam, _ = _h_lambda(entropy_mean)
    sym      = _symmetry(entropy_values)
    period   = _periodicity(entropy_values)
    beauty   = _beauty(entropy_mean, sym, coverage, period)
    bayes    = _bayes_posterior(coverage)

    return {
        "entropy":     entropy_mean / 8.0,
        "h_lambda":    h_lam / 8.0,
        "symmetry":    sym,
        "periodicity": period,
        "beauty":      beauty,
        "bayes":       bayes,
        "has_pi":      1.0 if "pi"    in anchors_found else 0.0,
        "has_phi":     1.0 if "phi"   in anchors_found else 0.0,
        "has_sqrt2":   1.0 if "sqrt2" in anchors_found else 0.0,
        "has_e":       1.0 if "e"     in anchors_found else 0.0,
    }


class InterferenceResult:
    """Ergebnis der Interferenzmessung."""
    __slots__ = ("status", "best_anchor", "best_score",
                 "cluster_summary", "label")

    def __init__(self, status: str, best_anchor: Optional[RegistryAnchor],
                 best_score: float, cluster_summary: str):
        self.status          = status           # "ANKER" | "DELTA" | "UNRESOLVED"
        self.best_anchor     = best_anchor
        self.best_score      = round(best_score, 4)
        self.cluster_summary = cluster_summary
        self.label = (
            f"[{status}:{best_anchor.anchor_id if best_anchor else '—'}]"
        )


# ── Registry-Hauptklasse ──────────────────────────────────────────────────────

class ShanwayRegistry:
    """Das universelle Ankerregister.

    Einziger Eintrittspunkt für alle Kanäle.
    Alle Schreiboperationen gehen durch die Pipeline.
    Alle Leseoperationen laufen über Interferenzmessung + Graph.
    """

    def __init__(self, session_seed: int = 0xA37E):
        self.session_seed = session_seed
        self.graph        = AnchorGraph.load()
        self._rng         = random.Random(session_seed)

    # ── Schreiben ─────────────────────────────────────────────────────────────

    def register_from_consensus(self, result: ConsensusResult,
                                 channel: str = CHANNEL_WEB) -> Optional[RegistryAnchor]:
        """Consensus-Ergebnis aus Web-Pipeline ins Register eintragen."""
        if result.status not in ("ANKER", "DELTA"):
            return None
        if result.mean_trust < REGISTRY_TRUST_MIN:
            return None

        # Zusammenfassung aus bestätigten Quellen
        titles = [p.title for p in result.profiles
                  if p.verdict == "CONFIRMED" and p.title][:3]
        meanings = [ANCHOR_MEANING.get(a, a) for a in result.confirmed_anchors]
        summary = (
            f"{', '.join(meanings)} — "
            f"{result.sources_confirmed} Quellen"
            + (f" ({'; '.join(titles)})" if titles else "")
        )

        # Strukturprofil aus dem stärksten bestätigten Profil
        confirmed = [p for p in result.profiles if p.verdict == "CONFIRMED"]
        if not confirmed:
            return None
        best = max(confirmed, key=lambda p: p.trust_score)

        anchors_found = {a: 1 for a in result.confirmed_anchors}
        # Dummy-Raw für Hash (echter Hash aus Quellprofil)
        raw_proxy = best.sha256.encode()

        anchor = RegistryAnchor(
            channel      = channel,
            label        = result.query,
            raw          = raw_proxy,
            entropy_mean = best.entropy_mean,
            h_lambda     = best.h_lambda,
            symmetry     = best.symmetry_score,
            periodicity  = best.periodicity_score,
            beauty       = best.beauty_score,
            bayes        = best.bayes_posterior,
            trust        = result.mean_trust,
            anchors_found= anchors_found,
            summary      = summary,
        )
        # raw_hash überschreiben mit echtem Quell-Hash
        object.__setattr__(anchor, "raw_hash", best.sha256) \
            if hasattr(anchor, "__setattr__") else None
        anchor.raw_hash = best.sha256

        self._write(anchor)
        return anchor

    def register_from_raw(self, raw: bytes, label: str,
                          channel: str = CHANNEL_FILE) -> Optional[RegistryAnchor]:
        """Rohdaten direkt ins Register — für Datei-Drop und andere Kanäle."""
        if _is_denied(raw):
            return None

        size = len(raw)
        block_size = max(512, size // 64) if size else 512
        blocks = [raw[i: i + block_size] for i in range(0, size, block_size)] or [b""]

        entropy_values = [_entropy(b) for b in blocks]
        entropy_mean   = sum(entropy_values) / len(entropy_values)

        anchors_found: dict[str, int] = {}
        for block in blocks:
            name = _detect_anchor(_normalize_block(block))
            if name:
                anchors_found[name] = anchors_found.get(name, 0) + 1

        if not anchors_found:
            return None

        coverage = sum(anchors_found.values()) / float(len(blocks))
        h_lam, _ = _h_lambda(entropy_mean)
        sym      = _symmetry(entropy_values)
        period   = _periodicity(entropy_values)
        beauty   = _beauty(entropy_mean, sym, coverage, period)
        bayes    = _bayes_posterior(coverage)
        trust    = _trust(coverage, entropy_mean, len(anchors_found),
                          sym, beauty, bayes)

        if trust < REGISTRY_TRUST_MIN:
            return None

        meanings = [ANCHOR_MEANING.get(a, a) for a in anchors_found]
        summary  = f"{label} [{channel}]: {', '.join(meanings)}"

        anchor = RegistryAnchor(
            channel=channel, label=label, raw=raw,
            entropy_mean=entropy_mean, h_lambda=h_lam,
            symmetry=sym, periodicity=period,
            beauty=beauty, bayes=bayes, trust=trust,
            anchors_found=anchors_found, summary=summary,
        )
        self._write(anchor)
        return anchor

    def _write(self, anchor: RegistryAnchor) -> None:
        """Append-only Schreiben + Graphupdate."""
        # 1. Append-only ins JSONL
        with REGISTRY_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(anchor.to_dict(), ensure_ascii=False) + "\n")
        # 2. Graph aktualisieren
        self.graph.add_anchor(anchor)
        self.graph.save()

    # ── Lesen / Interferenz ───────────────────────────────────────────────────

    def measure_interference(self, raw: bytes) -> InterferenceResult:
        """Misst Interferenz von Rohdaten gegen alle Anker im Register.
        Gibt [ANKER] [DELTA] oder [UNRESOLVED] zurück.
        """
        query_vec = _raw_to_vector(raw, self.session_seed)

        if query_vec is None or not self.graph.nodes:
            return InterferenceResult("UNRESOLVED", None, 0.0, "")

        best_anchor: Optional[RegistryAnchor] = None
        best_score = 0.0

        for anchor in self.graph.nodes.values():
            score = _cosine_similarity(query_vec, anchor.vector())
            if score > best_score:
                best_score = score
                best_anchor = anchor

        if best_score >= INTERFERENCE_THRESHOLD and best_anchor:
            cluster = self.graph.cluster_summary(best_anchor.anchor_id)
            return InterferenceResult("ANKER", best_anchor, best_score, cluster)

        if best_score >= DELTA_THRESHOLD and best_anchor:
            return InterferenceResult("DELTA", best_anchor, best_score, "")

        return InterferenceResult("UNRESOLVED", None, best_score, "")

    def measure_interference_text(self, text: str) -> InterferenceResult:
        """Textbasierte Interferenzmessung — für Chat-Input."""
        return self.measure_interference(text.encode("utf-8"))

    # ── Abfragen ──────────────────────────────────────────────────────────────

    def load_all(self) -> list[RegistryAnchor]:
        """Alle Anker laden."""
        if not REGISTRY_FILE.exists():
            return []
        anchors = []
        for line in REGISTRY_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                anchors.append(RegistryAnchor.from_dict(json.loads(line)))
            except Exception:
                continue
        return anchors

    def stats(self) -> dict:
        """Registry-Statistik."""
        all_anchors = self.load_all()
        channels: dict[str, int] = defaultdict(int)
        sigs: dict[str, int] = defaultdict(int)
        for a in all_anchors:
            channels[a.channel] += 1
            for s in a.signature:
                sigs[s] += 1
        return {
            "total_anchors": len(all_anchors),
            "graph_nodes":   len(self.graph.nodes),
            "graph_edges":   sum(len(v) for v in self.graph.edges.values()) // 2,
            "channels":      dict(channels),
            "signatures":    dict(sigs),
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_registry: Optional[ShanwayRegistry] = None


def get_registry(session_seed: int = 0xA37E) -> ShanwayRegistry:
    global _registry
    if _registry is None:
        _registry = ShanwayRegistry(session_seed=session_seed)
    return _registry
