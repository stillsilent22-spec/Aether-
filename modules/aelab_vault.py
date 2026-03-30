"""
aelab_vault.py
Deterministischer, auditierbarer Vault für den AELab Motor.

Struktur:
    vault/
        main/          – aktive, bewährte Bäume
        sub_vault/
            recovered/ – reaktivierte Bäume
            inactive/  – ruhende Bäume
        vault_index.tsv – vollständiges Audit-Log

Jeder Eintrag ist deterministisch auditierbar:
    - Signatur: SHA256 über den serialisierten Baum (kein Zufall)
    - Alle Scores sind reproduzierbar aus gespeicherten Feldern
    - TSV-Format: menschlich lesbar, versionierbar mit git

Verwendung:
    from modules.aelab_vault import AEVault
    from modules.aelab_motor import AEEvolver, node_copy

    vault = AEVault("vault")
    evolver = AEEvolver(data=...)
    tree, fit = evolver.run()

    entry = vault.store(tree, fitness=fit, lossless=evolver.best_lossless,
                        generation=0, label="block_0042")
    seed = vault.best_seed(top_n=5)   # bester Baum als GA-Seed
    vault.tick()                       # Decay + Lifecycle
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict

from .aelab_motor import (
    Node, node_copy, node_size, node_depth,
    has_anchor, first_anchor, anchor_mask_for,
    N_SEQUENCE, N_BRIDGE, N_XOR, N_INTERFERE,
    N_LSHIFT, N_RSHIFT, N_ZETA, N_LIOUVILLE,
    N_GF_MUL, N_HAMMING, N_ZIPF, N_LOG,
    N_CONST, NF_ANCHOR,
)

# ---------------------------------------------------------------------------
# Baum → deterministischer Hash (auditierbar)
# ---------------------------------------------------------------------------
def tree_signature(n: Optional[Node]) -> str:
    """SHA256 über kanonische JSON-Serialisierung des Baums."""
    def serialize(nd):
        if nd is None:
            return None
        return {
            "t":  nd.t,
            "iv": nd.iv,
            "v":  round(nd.v, 12),
            "f":  nd.f,
            "a":  serialize(nd.a),
            "b":  serialize(nd.b),
            "c":  serialize(nd.c),
        }
    raw = json.dumps(serialize(n), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw.encode()).hexdigest()

def tree_to_json(n: Optional[Node]) -> str:
    """Legacy — wird intern für tree_signature() gebraucht. Nicht für Persistenz verwenden."""
    def serialize(nd):
        if nd is None: return None
        return {"t":nd.t,"iv":nd.iv,"v":round(nd.v,12),"f":nd.f,
                "a":serialize(nd.a),"b":serialize(nd.b),"c":serialize(nd.c)}
    return json.dumps(serialize(n), separators=(',',':'))

def tree_from_json(s: str) -> Optional[Node]:
    """Legacy — nur für Migration alter .json-Vault-Dateien."""
    def deserialize(d):
        if d is None: return None
        n = Node(d["t"], d["iv"], d["v"], d["f"])
        n.a = deserialize(d["a"])
        n.b = deserialize(d["b"])
        n.c = deserialize(d["c"])
        return n
    return deserialize(json.loads(s))

# ---------------------------------------------------------------------------
# DNA-Format — flat-indexed, OS-agnostisch, git-freundlich
# ---------------------------------------------------------------------------
# Format:
#   # AETHER.DNA v1
#   # nodes:N
#   0 t=TYPE iv=IV v=VALUE f=FLAGS a=A_IDX b=B_IDX c=C_IDX
#   ...
#
# Pre-order Traversal. Kinder durch Index referenziert, -1 = None.
# tree_signature() bleibt JSON-basiert (Kompatibilität mit bestehenden Signaturen).
# ---------------------------------------------------------------------------
_DNA_HEADER = "# AETHER.DNA v1"


def tree_to_dna(n: Optional[Node]) -> str:
    """
    Serialisiert einen Baum als flach-indiziertes DNA-Format.

    Eigenschaften:
    - Kein JSON, kein Windows-Pfadproblem, kein BOM
    - Menschenlesbar und git-freundlich (line-diff funktioniert)
    - OS-agnostisch: nur ASCII-Zeichen
    - Deterministisch: gleicher Baum → gleicher Output
    - order=pre-order; Kindknoten durch integer index referenziert
    """
    if n is None:
        return _DNA_HEADER + "\n# nodes:0\n"

    # Pre-order: index zuweisen und Adjazenzliste aufbauen
    order: list[Node] = []
    idx_of: dict[int, int] = {}  # id(node) -> index

    def visit(nd: Optional[Node]) -> int:
        if nd is None:
            return -1
        obj_id = id(nd)
        if obj_id in idx_of:
            return idx_of[obj_id]
        i = len(order)
        idx_of[obj_id] = i
        order.append(nd)
        # Kinder besuchen NACH der Index-Zuweisung (Pre-order, keine Zyklen)
        nd._dna_a = visit(nd.a)
        nd._dna_b = visit(nd.b)
        nd._dna_c = visit(nd.c)
        return i

    visit(n)

    lines = [_DNA_HEADER, f"# nodes:{len(order)}"]
    for i, nd in enumerate(order):
        lines.append(
            f"{i} t={nd.t} iv={nd.iv} v={nd.v:.12f} f={nd.f}"
            f" a={nd._dna_a} b={nd._dna_b} c={nd._dna_c}"
        )
        # Temp-Attribute aufräumen
        del nd._dna_a, nd._dna_b, nd._dna_c

    return "\n".join(lines) + "\n"


def tree_from_dna(s: str) -> Optional[Node]:
    """
    Deserialisiert einen Baum aus dem DNA-Format.

    Robust gegenüber Leerzeilen, unbekannten Kommentaren und
    Zahlen-Formaten (inf, nan → 0.0 als Fallback).
    Gibt None zurück wenn das Format nicht erkannt wird.
    """
    raw: dict[int, tuple] = {}  # idx → (t, iv, v, f, a_idx, b_idx, c_idx)

    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = line.split()
            if len(parts) < 8:
                continue
            idx = int(parts[0])
            kv: dict[str, str] = {}
            for part in parts[1:]:
                k, _, v = part.partition("=")
                kv[k] = v
            v_raw = float(kv["v"])
            if not isinstance(v_raw, float) or not (v_raw == v_raw):  # NaN guard
                v_raw = 0.0
            import math as _math
            if _math.isinf(v_raw):
                v_raw = 0.0
            raw[idx] = (
                int(kv["t"]),
                int(kv["iv"]),
                v_raw,
                int(kv["f"]),
                int(kv["a"]),
                int(kv["b"]),
                int(kv["c"]),
            )
        except (KeyError, ValueError, IndexError):
            continue

    if not raw:
        return None

    cache: dict[int, Optional[Node]] = {}

    def build(idx: int) -> Optional[Node]:
        if idx < 0:
            return None
        if idx in cache:
            return cache[idx]
        if idx not in raw:
            return None
        t, iv, v, f, a_i, b_i, c_i = raw[idx]
        nd = Node(t, iv, v, f)
        cache[idx] = nd  # vor Rekursion eintragen (Sicherheit gegen Zyklen)
        nd.a = build(a_i)
        nd.b = build(b_i)
        nd.c = build(c_i)
        return nd

    return build(0)

# ---------------------------------------------------------------------------
# Baum-Metrik-Extraktion (deterministisch, keine Zufallskomponente)
# ---------------------------------------------------------------------------
def _has_type(n, t):
    if n is None: return False
    if n.t == t: return True
    return _has_type(n.a, t) or _has_type(n.b, t) or _has_type(n.c, t)

def count_anchors(n):
    if n is None: return 0
    return (1 if (n.f & NF_ANCHOR and n.t == N_CONST) else 0) + \
           count_anchors(n.a) + count_anchors(n.b) + count_anchors(n.c)

def _count_nodes_of_type(n, t):
    if n is None: return 0
    return (1 if n.t == t else 0) + \
           _count_nodes_of_type(n.a, t) + \
           _count_nodes_of_type(n.b, t) + \
           _count_nodes_of_type(n.c, t)

def extract_metrics(tree: Optional[Node], fitness: float, lossless: float) -> dict:
    """Alle Metriken deterministisch aus Baum und Fitnesswerten."""
    if tree is None:
        return {}
    sz = node_size(tree)
    dp = node_depth(tree)
    anc = count_anchors(tree)

    op_types = set()
    def collect_ops(n):
        if n is None: return
        if n.t not in (0,1,2,3,4,5,6): op_types.add(n.t)
        collect_ops(n.a); collect_ops(n.b); collect_ops(n.c)
    collect_ops(tree)
    diversity = len(op_types) / 37.0

    stability    = min(1.0, lossless * 0.70 + min(anc, 4)/4.0 * 0.30)
    novelty      = min(1.0, fitness / (1.0 + sz * 0.05))
    coherence    = min(1.0, diversity * 0.60 + lossless * 0.40)

    coupling = 0.0
    if _has_type(tree, N_SEQUENCE):  coupling += 0.20
    if _has_type(tree, N_BRIDGE):    coupling += 0.16
    if _has_type(tree, N_XOR):       coupling += 0.16
    if _has_type(tree, N_INTERFERE): coupling += 0.16
    if _has_type(tree, N_LSHIFT) or _has_type(tree, N_RSHIFT): coupling += 0.10
    if _has_type(tree, N_ZETA) or _has_type(tree, N_LIOUVILLE): coupling += 0.08
    if anc > 0:                      coupling += 0.08
    coupling = min(1.0, coupling)

    mem_ops = (1 if _has_type(tree, N_SEQUENCE) else 0) + \
              (1 if _has_type(tree, N_BRIDGE) else 0)
    adaptability = min(1.0, dp / 16.0 * 0.50 + mem_ops * 0.25 + diversity * 0.25)

    anchor_mask = 0
    if has_anchor(tree):
        a = first_anchor(tree)
        if a: anchor_mask = anchor_mask_for(a.v)

    return {
        "nodes":        sz,
        "depth":        dp,
        "anchors":      anc,
        "anchor_mask":  anchor_mask,
        "stability":    round(stability, 6),
        "novelty":      round(novelty, 6),
        "coherence":    round(coherence, 6),
        "coupling":     round(coupling, 6),
        "adaptability": round(adaptability, 6),
        "has_sequence": int(_has_type(tree, N_SEQUENCE)),
        "has_bridge":   int(_has_type(tree, N_BRIDGE)),
        "has_xor":      int(_has_type(tree, N_XOR)),
        "has_interfere":int(_has_type(tree, N_INTERFERE)),
        "has_shift":    int(_has_type(tree, N_LSHIFT) or _has_type(tree, N_RSHIFT)),
        "has_log":      int(_has_type(tree, N_LOG)),
        "has_prime":    int(_has_type(tree, N_ZETA) or _has_type(tree, N_LIOUVILLE)),
    }

# ---------------------------------------------------------------------------
# VaultEntry
# ---------------------------------------------------------------------------
@dataclass
class VaultEntry:
    # Identität
    sig:          str   = ""
    label:        str   = ""
    bucket:       str   = "main"

    # Fitness
    fitness:      float = 0.0
    lossless:     float = 0.0

    # Struktur
    nodes:        int   = 0
    depth:        int   = 0
    anchors:      int   = 0
    anchor_mask:  int   = 0

    # Scores (deterministisch berechnet)
    stability:    float = 0.0
    novelty:      float = 0.0
    coherence:    float = 0.0
    coupling:     float = 0.0
    adaptability: float = 0.0

    # Lifecycle
    utility_score:      float = 0.0
    decay_rate:         float = 0.003
    generation_created: int   = 0
    times_used:         int   = 0
    times_recovered:    int   = 0
    times_influenced_best: int = 0
    inactive_ticks:     int   = 0
    active:             bool  = True
    reactivated:        bool  = False
    access_seq:         int   = 0      # monotoner Vault-Zähler, kein Timestamp

    # Operator-Flags
    has_sequence:  int = 0
    has_bridge:    int = 0
    has_xor:       int = 0
    has_interfere: int = 0
    has_shift:     int = 0
    has_log:       int = 0
    has_prime:     int = 0

    def init_lifecycle(self):
        """Initiale utility_score und decay_rate deterministisch berechnen."""
        base = min(1.0, max(0.02,
            self.stability    * 0.30 +
            self.novelty      * 0.15 +
            self.coherence    * 0.14 +
            self.coupling     * 0.16 +
            self.adaptability * 0.15 +
            min(self.anchors / 4.0, 1.0) * 0.10
        ))
        if self.utility_score <= 0.0:
            self.utility_score = base
        if self.decay_rate <= 0.0:
            self.decay_rate = max(0.0003, min(0.0040,
                0.0027 - self.stability * 0.0011
                       - self.coupling  * 0.0006
                       - self.adaptability * 0.0004
            ))

    def adjusted_score(self, total_ticks: int = 1) -> float:
        """Score aus gespeicherten Feldern – 100% deterministisch, kein Echtzeit-Zugriff."""
        recency = self.access_seq / max(1, total_ticks)

        def log_norm(v, gain=6.0):
            x = max(0.0, min(1.0, v))
            g = max(1e-6, gain)
            den = math.log1p(g)
            return max(0.0, min(1.0, math.log1p(x*g)/den)) if den > 1e-12 else x

        experience = 1.0 - math.exp(-(
            0.18 * self.times_used +
            0.28 * self.times_recovered +
            0.38 * self.times_influenced_best
        ))
        base         = log_norm(self.utility_score, 9.0)
        recency_log  = log_norm(recency, 6.0)
        coherence_l  = log_norm(self.coherence, 6.0)
        coupling_l   = log_norm(self.coupling, 6.0)
        adapt_l      = log_norm(self.adaptability, 6.0)
        active_bias  = 0.12 if self.active else (0.04 if self.reactivated else -0.03)

        return (base * (0.52 + 0.48 * recency_log)
                + experience * 0.18
                + coherence_l * 0.05
                + coupling_l  * 0.09
                + adapt_l     * 0.07
                + active_bias)

    def tick_decay(self):
        """Ein Zeitschritt: utility_score verfällt, inactive_ticks steigen."""
        if self.active:
            self.inactive_ticks = 0
        else:
            self.inactive_ticks += 1
        self.utility_score = max(0.0,
            self.utility_score - self.decay_rate * (1.0 if self.active else 1.8)
        )

    def mark_used(self, influenced_best: bool = False, vault_tick: int = 0):
        self.times_used += 1
        self.access_seq = vault_tick
        bonus = 0.035 if self.active else 0.060
        self.utility_score = min(1.0, self.utility_score + bonus)
        if influenced_best:
            self.times_influenced_best += 1

# ---------------------------------------------------------------------------
# TSV-Schema
# ---------------------------------------------------------------------------
TSV_FIELDS = [
    "sig","label","bucket","fitness","lossless",
    "nodes","depth","anchors","anchor_mask",
    "stability","novelty","coherence","coupling","adaptability",
    "utility_score","decay_rate","generation_created",
    "times_used","times_recovered","times_influenced_best","inactive_ticks",
    "active","reactivated","access_seq",
    "has_sequence","has_bridge","has_xor","has_interfere",
    "has_shift","has_log","has_prime",
]

# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------
class AEVault:
    def __init__(self, root: str = "vault", max_main: int = 256,
                 max_sub: int = 512):
        self.root     = Path(root)
        self.max_main = max_main
        self.max_sub  = max_sub
        self._entries: Dict[str, VaultEntry] = {}
        self._trees:   Dict[str, Node]       = {}
        self._tick:    int                   = 0   # montoner Zugriffszähler
        self._chunk_index: Dict[str, str]    = {}

        for d in ["main", "sub_vault/inactive", "sub_vault/recovered"]:
            (self.root / d).mkdir(parents=True, exist_ok=True)
        (self.root / "raw_chunks").mkdir(parents=True, exist_ok=True)

        self._load()

    # ------------------------------------------------------------------
    # Speichern
    # ------------------------------------------------------------------
    def store(self, tree: Node, fitness: float, lossless: float,
              generation: int = 0, label: str = "") -> Optional[VaultEntry]:
        """
        Baum in Vault aufnehmen.
        Gibt None zurück wenn bereits vorhanden (selbe Signatur).
        """
        sig = tree_signature(tree)

        if sig in self._entries:
            e = self._entries[sig]
            if fitness > e.fitness:
                e.fitness  = round(fitness, 8)
                e.lossless = round(lossless, 8)
                self._tick += 1
                e.mark_used(influenced_best=True, vault_tick=self._tick)
                self._save_tree(sig, tree)
                self._write_index()
            return e

        metrics = extract_metrics(tree, fitness, lossless)
        e = VaultEntry(
            sig          = sig,
            label        = label or sig[:12],
            bucket       = "main",
            fitness      = round(fitness, 8),
            lossless     = round(lossless, 8),
            generation_created = generation,
            **{k: metrics[k] for k in metrics},
        )
        e.init_lifecycle()

        self._entries[sig] = e
        self._trees[sig]   = node_copy(tree)
        self._save_tree(sig, tree)
        self._enforce_limits()
        self._write_index()
        return e

    def store_for_chunk(self, chunk_key: str, tree: Node,
                        fitness: float, lossless: float,
                        generation: int = 0) -> Optional["VaultEntry"]:
        entry = self.store(tree, fitness, lossless, generation,
                           label=f"chunk_{chunk_key[:8]}")
        if entry is not None:
            self._chunk_index[chunk_key] = entry.sig
            self._save_chunk_index()
            self.refresh_chunk_resolution(chunk_key)
        # Wenn neuer Baum besser ist als gespeicherter -> chunk_index
        # bleibt gleich, VaultEntry wird automatisch upgedated durch store().
        # Beim nächsten encode_frame() wird entry.lossless >= 1.0 geprüft
        # -> DNA ersetzt automatisch rohe Bytes ohne manuellen Eingriff.
        return entry

    def remember_chunk_bytes(self, chunk_key: str, chunk: bytes) -> None:
        path = self._raw_chunk_path(chunk_key)
        if not path.exists():
            path.write_bytes(bytes(chunk))

    def get_raw_chunk(self, chunk_key: str) -> Optional[bytes]:
        path = self._raw_chunk_path(chunk_key)
        if not path.exists():
            return None
        try:
            return path.read_bytes()
        except Exception:
            return None

    def refresh_chunk_resolution(self, chunk_key: str) -> bool:
        tree_sig = self._chunk_index.get(chunk_key)
        if not tree_sig:
            return False
        tree = self._trees.get(tree_sig)
        raw_chunk = self.get_raw_chunk(chunk_key)
        if tree is None or raw_chunk is None:
            return False

        from modules.aelab_motor import AEEvolver

        evolver = AEEvolver(data=raw_chunk)
        if evolver.decode(tree) != raw_chunk:
            return False

        entry = self._entries.get(tree_sig)
        if entry is not None and entry.lossless < 1.0:
            entry.lossless = 1.0
            self._write_index()
        self._delete_raw_chunk(chunk_key)
        self._save_chunk_index()
        return True

    def refresh_all_chunk_resolutions(self, limit: Optional[int] = None) -> int:
        upgraded = 0
        for index, chunk_key in enumerate(list(self._chunk_index.keys())):
            if limit is not None and index >= limit:
                break
            if self.refresh_chunk_resolution(chunk_key):
                upgraded += 1
        return upgraded

    def chunk_packet(self, chunk_key: str, raw_chunk: Optional[bytes] = None) -> Optional[dict[str, str]]:
        if raw_chunk is not None:
            self.remember_chunk_bytes(chunk_key, raw_chunk)
        if self.refresh_chunk_resolution(chunk_key):
            return {"type": "dna", "sig": chunk_key}

        tree_sig = self._chunk_index.get(chunk_key)
        entry = self._entries.get(tree_sig) if tree_sig else None
        if entry is not None and entry.lossless >= 1.0:
            return {"type": "dna", "sig": chunk_key}

        raw = raw_chunk if raw_chunk is not None else self.get_raw_chunk(chunk_key)
        if raw is None:
            return None
        return {"type": "raw", "data": raw.hex()}

    # ------------------------------------------------------------------
    # Abrufen
    # ------------------------------------------------------------------
    def best_seed(self, top_n: int = 5,
                  min_lossless: float = 0.0) -> Optional[Node]:
        """Bester aktiver Baum als GA-Seed."""
        candidates = [
            e for e in self._entries.values()
            if e.active and e.lossless >= min_lossless
        ]
        if not candidates:
            candidates = list(self._entries.values())
        if not candidates:
            return None
        candidates.sort(key=lambda e: e.adjusted_score(self._tick), reverse=True)
        best = candidates[0]
        self._tick += 1
        best.mark_used(vault_tick=self._tick)
        self._write_index()
        tree = self._trees.get(best.sig)
        return node_copy(tree) if tree else None

    def top_entries(self, n: int = 10) -> List[VaultEntry]:
        entries = sorted(self._entries.values(),
                         key=lambda e: e.adjusted_score(self._tick), reverse=True)
        return entries[:n]

    def get_tree(self, sig: str) -> Optional[Node]:
        tree = self._trees.get(sig)
        if tree:
            self._tick += 1
            self._entries[sig].mark_used(vault_tick=self._tick)
            self._write_index()
        return node_copy(tree) if tree else None

    def get_tree_dna(self, sig: str) -> Optional[str]:
        tree = self._trees.get(sig)
        if tree is None:
            tree_sig = self._chunk_index.get(sig)
            if tree_sig:
                tree = self._trees.get(tree_sig)
                if tree is not None and tree_sig in self._entries:
                    self._tick += 1
                    self._entries[tree_sig].mark_used(vault_tick=self._tick)
                    self._write_index()
        elif sig in self._entries:
            self._tick += 1
            self._entries[sig].mark_used(vault_tick=self._tick)
            self._write_index()
        if tree is None:
            return None
        return tree_to_dna(tree)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def tick(self, best_fit: float = 0.0):
        """
        Einen Zeitschritt ausführen:
        - Decay auf alle Einträge
        - Inaktive in sub_vault verschieben
        - Reaktivierung wenn utility wieder steigt
        """
        self._tick += 1
        to_deactivate = []
        to_reactivate = []

        for sig, e in self._entries.items():
            e.tick_decay()

            if e.active and e.inactive_ticks > 50 and e.utility_score < 0.10:
                to_deactivate.append(sig)
            elif not e.active and e.utility_score > 0.35:
                to_reactivate.append(sig)

            if best_fit > 0 and e.fitness >= best_fit * 0.98:
                e.times_influenced_best += 1

        for sig in to_deactivate:
            e = self._entries[sig]
            e.active = False
            e.bucket = "sub_vault/inactive"
            self._move_tree(sig, "sub_vault/inactive")

        for sig in to_reactivate:
            e = self._entries[sig]
            e.active = True
            e.reactivated = True
            e.times_recovered += 1
            e.bucket = "sub_vault/recovered"
            self._move_tree(sig, "sub_vault/recovered")

        self._write_index()

    def promote_to_main(self, sig: str):
        """Eintrag in main-Vault hochstufen."""
        if sig not in self._entries: return
        e = self._entries[sig]
        e.active = True
        e.bucket = "main"
        self._move_tree(sig, "main")
        self._write_index()

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def audit(self) -> str:
        """Vollständige, auditierbare Zusammenfassung."""
        lines = [
            "=" * 60,
            f"AELab Vault Audit  –  {len(self._entries)} Einträge",
            f"Root: {self.root.resolve()}",
            "=" * 60,
        ]
        main  = [e for e in self._entries.values() if e.bucket == "main"]
        inact = [e for e in self._entries.values() if "inactive" in e.bucket]
        recov = [e for e in self._entries.values() if "recovered" in e.bucket]

        lines.append(f"  main:              {len(main):4d}")
        lines.append(f"  sub_vault/inactive:{len(inact):4d}")
        lines.append(f"  sub_vault/recovered:{len(recov):3d}")
        lines.append("")

        top = self.top_entries(10)
        lines.append("Top 10 (nach adjusted_score):")
        lines.append(f"  {'label':<16} {'fit':>8} {'lr':>6} {'nodes':>5} {'anc':>4} {'score':>7} {'bucket'}")
        lines.append("  " + "-"*62)
        for e in top:
            lines.append(
                f"  {e.label:<16} {e.fitness:8.4f} {e.lossless*100:5.1f}%"
                f" {e.nodes:5d} {e.anchors:4d}"
                f" {e.adjusted_score(self._tick):7.4f}  {e.bucket}"
            )
        lines.append("=" * 60)
        return "\n".join(lines)

    def verify_integrity(self) -> List[str]:
        """
        Prüft ob gespeicherte Signaturen mit Baum-Inhalt übereinstimmen.
        Gibt Liste von Fehlern zurück (leer = alles ok).
        """
        errors = []
        for sig, tree in self._trees.items():
            computed = tree_signature(tree)
            if computed != sig:
                errors.append(f"INTEGRITY FAIL: {sig[:12]}... → computed {computed[:12]}...")
            e = self._entries.get(sig)
            if e is None:
                errors.append(f"ORPHAN TREE: {sig[:12]}... (kein Index-Eintrag)")
        for sig, e in self._entries.items():
            if sig not in self._trees:
                errors.append(f"MISSING TREE: {sig[:12]}... (Index ohne Datei)")
        return errors

    # ------------------------------------------------------------------
    # I/O (deterministisch, kein Zufall)
    # ------------------------------------------------------------------
    def _tree_path(self, sig: str, bucket: str) -> Path:
        return self.root / bucket / f"{sig[:16]}.dna"

    def _raw_chunk_path(self, chunk_key: str) -> Path:
        return self.root / "raw_chunks" / f"{chunk_key}.raw"

    def _save_tree(self, sig: str, tree: Node):
        e = self._entries.get(sig)
        bucket = e.bucket if e else "main"
        path = self._tree_path(sig, bucket)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(tree_to_dna(tree), encoding="utf-8")

    def _move_tree(self, sig: str, new_bucket: str):
        e = self._entries[sig]
        old_path = self._tree_path(sig, e.bucket)
        new_path = self._tree_path(sig, new_bucket)
        new_path.parent.mkdir(parents=True, exist_ok=True)
        if old_path.exists():
            old_path.rename(new_path)
        e.bucket = new_bucket

    def _delete_raw_chunk(self, chunk_key: str) -> None:
        path = self._raw_chunk_path(chunk_key)
        if path.exists():
            path.unlink(missing_ok=True)

    def _save_chunk_index(self) -> None:
        path = self.root / "chunk_index.tsv"
        lines = ["chunk_key\ttree_sig"]
        for ck, ts in sorted(self._chunk_index.items()):
            lines.append(f"{ck}\t{ts}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _load(self):
        """Lädt alle Bäume und den Index."""
        chunk_index_path = self.root / "chunk_index.tsv"
        self._chunk_index = {}
        if chunk_index_path.exists():
            for line in chunk_index_path.read_text(
                    encoding="utf-8").splitlines()[1:]:
                parts = line.strip().split("\t")
                if len(parts) == 2:
                    self._chunk_index[parts[0]] = parts[1]

        index_path = self.root / "vault_index.tsv"
        index: Dict[str, VaultEntry] = {}

        if index_path.exists():
            with open(index_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f, delimiter="\t")
                for row in reader:
                    try:
                        e = VaultEntry(
                            sig          = row["sig"],
                            label        = row.get("label",""),
                            bucket       = row.get("bucket","main"),
                            fitness      = float(row.get("fitness",0)),
                            lossless     = float(row.get("lossless",0)),
                            nodes        = int(row.get("nodes",0)),
                            depth        = int(row.get("depth",0)),
                            anchors      = int(row.get("anchors",0)),
                            anchor_mask  = int(row.get("anchor_mask",0)),
                            stability    = float(row.get("stability",0)),
                            novelty      = float(row.get("novelty",0)),
                            coherence    = float(row.get("coherence",0)),
                            coupling     = float(row.get("coupling",0)),
                            adaptability = float(row.get("adaptability",0)),
                            utility_score= float(row.get("utility_score",0)),
                            decay_rate   = float(row.get("decay_rate",0.003)),
                            generation_created=int(row.get("generation_created",0)),
                            times_used   = int(row.get("times_used",0)),
                            times_recovered=int(row.get("times_recovered",0)),
                            times_influenced_best=int(row.get("times_influenced_best",0)),
                            inactive_ticks=int(row.get("inactive_ticks",0)),
                            active       = row.get("active","1") == "1",
                            reactivated  = row.get("reactivated","0") == "1",
                            access_seq   = int(float(row.get("access_seq", row.get("last_used_ts", 0)))),
                            has_sequence = int(row.get("has_sequence",0)),
                            has_bridge   = int(row.get("has_bridge",0)),
                            has_xor      = int(row.get("has_xor",0)),
                            has_interfere= int(row.get("has_interfere",0)),
                            has_shift    = int(row.get("has_shift",0)),
                            has_log      = int(row.get("has_log",0)),
                            has_prime    = int(row.get("has_prime",0)),
                        )
                        index[e.sig] = e
                    except (KeyError, ValueError):
                        continue

        for bucket in ["main", "sub_vault/inactive", "sub_vault/recovered"]:
            bucket_path = self.root / bucket
            if not bucket_path.exists():
                continue

            # Neue DNA-Dateien laden
            for dna_file in bucket_path.glob("*.dna"):
                try:
                    tree = tree_from_dna(dna_file.read_text(encoding="utf-8"))
                    if tree is None:
                        continue
                    sig = tree_signature(tree)
                    self._trees[sig] = tree
                    if sig not in index:
                        e = VaultEntry(sig=sig, label=sig[:12], bucket=bucket)
                        e.init_lifecycle()
                        index[sig] = e
                    else:
                        index[sig].bucket = bucket
                except Exception:
                    continue

            # Legacy: .json migrieren → sofort als .dna neu schreiben, .json löschen
            for json_file in bucket_path.glob("*.json"):
                try:
                    tree = tree_from_json(json_file.read_text(encoding="utf-8"))
                    if tree is None:
                        continue
                    sig = tree_signature(tree)
                    if sig in self._trees:
                        json_file.unlink(missing_ok=True)
                        continue
                    self._trees[sig] = tree
                    if sig not in index:
                        e = VaultEntry(sig=sig, label=sig[:12], bucket=bucket)
                        e.init_lifecycle()
                        index[sig] = e
                    else:
                        index[sig].bucket = bucket
                    # Migration: als DNA speichern, alte JSON-Datei entfernen
                    dna_path = json_file.with_suffix(".dna")
                    dna_path.write_text(tree_to_dna(tree), encoding="utf-8")
                    json_file.unlink(missing_ok=True)
                except Exception:
                    continue

        self._entries = index
        self._chunk_index = {
            chunk_key: tree_sig
            for chunk_key, tree_sig in self._chunk_index.items()
            if tree_sig in self._entries and tree_sig in self._trees
        }
        if self._entries:
            self._tick = max(e.access_seq for e in self._entries.values())

    def _write_index(self):
        """Schreibt vault_index.tsv deterministisch (nach sig sortiert)."""
        index_path = self.root / "vault_index.tsv"
        rows = sorted(self._entries.values(), key=lambda e: e.sig)
        with open(index_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=TSV_FIELDS,
                                    delimiter="\t", extrasaction="ignore")
            writer.writeheader()
            for e in rows:
                row = {
                    "sig":          e.sig,
                    "label":        e.label,
                    "bucket":       e.bucket,
                    "fitness":      e.fitness,
                    "lossless":     e.lossless,
                    "nodes":        e.nodes,
                    "depth":        e.depth,
                    "anchors":      e.anchors,
                    "anchor_mask":  e.anchor_mask,
                    "stability":    e.stability,
                    "novelty":      e.novelty,
                    "coherence":    e.coherence,
                    "coupling":     e.coupling,
                    "adaptability": e.adaptability,
                    "utility_score":round(e.utility_score, 6),
                    "decay_rate":   round(e.decay_rate, 6),
                    "generation_created": e.generation_created,
                    "times_used":   e.times_used,
                    "times_recovered": e.times_recovered,
                    "times_influenced_best": e.times_influenced_best,
                    "inactive_ticks": e.inactive_ticks,
                    "active":       "1" if e.active else "0",
                    "reactivated":  "1" if e.reactivated else "0",
                    "access_seq":   e.access_seq,
                    "has_sequence": e.has_sequence,
                    "has_bridge":   e.has_bridge,
                    "has_xor":      e.has_xor,
                    "has_interfere":e.has_interfere,
                    "has_shift":    e.has_shift,
                    "has_log":      e.has_log,
                    "has_prime":    e.has_prime,
                }
                writer.writerow(row)

    def _enforce_limits(self):
        """Überlaufschutz: schwächste Einträge in sub_vault verschieben."""
        main_entries = sorted(
            [e for e in self._entries.values() if e.bucket == "main"],
            key=lambda e: e.adjusted_score(self._tick)
        )
        while len(main_entries) > self.max_main:
            weakest = main_entries.pop(0)
            weakest.active = False
            weakest.bucket = "sub_vault/inactive"
            self._move_tree(weakest.sig, "sub_vault/inactive")

        all_entries = sorted(
            self._entries.values(),
            key=lambda e: e.adjusted_score(self._tick)
        )
        while len(all_entries) > self.max_main + self.max_sub:
            drop = all_entries.pop(0)
            path = self._tree_path(drop.sig, drop.bucket)
            if path.exists():
                path.unlink()
            del self._entries[drop.sig]
            self._trees.pop(drop.sig, None)
            self._chunk_index = {
                chunk_key: tree_sig
                for chunk_key, tree_sig in self._chunk_index.items()
                if tree_sig != drop.sig
            }
            all_entries = [e for e in all_entries if e.sig != drop.sig]
        self._save_chunk_index()


# ---------------------------------------------------------------------------
# Selbsttest  (python -m modules.aelab_vault)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import shutil
    import math
    import tempfile
    from .aelab_motor import AEEvolver

    print("AELab Vault – Selbsttest")
    test_dir = tempfile.mkdtemp(prefix="aelab_vault_test_")

    vault = AEVault(test_dir, max_main=10, max_sub=20)
    data  = bytes([int(128 + 127*math.sin(i/8.0)) & 0xFF for i in range(256)])

    for run in range(3):
        evolver = AEEvolver(data=data, seed=run*100)
        tree, fit = evolver.run(pop=60, gens=40)
        e = vault.store(tree, fit, evolver.best_lossless,
                        generation=run, label=f"run_{run:03d}")
        print(f"  Run {run}: fit={fit:.4f}  lr={evolver.best_lossless*100:.1f}%"
              f"  sig={e.sig[:12]}...  score={e.adjusted_score(vault._tick):.4f}")

    vault.tick(best_fit=vault.top_entries(1)[0].fitness)

    print()
    print(vault.audit())

    errors = vault.verify_integrity()
    if errors:
        print("INTEGRITY ERRORS:")
        for err in errors: print(" ", err)
    else:
        print("Integrity: OK – alle Signaturen verifiziert")

    seed = vault.best_seed()
    print(f"\nBester Seed: {'gefunden' if seed else 'keiner'}")
    if seed:
        from .aelab_motor import node_size, node_depth
        print(f"  Größe: {node_size(seed)} Nodes, Tiefe: {node_depth(seed)}")

    shutil.rmtree(test_dir, ignore_errors=True)
