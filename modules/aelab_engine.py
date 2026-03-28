"""
aelab_engine.py
Brücke zwischen AELab-Motor/Vault und der Aether-Pipeline.

Exponiert zwei Eintrittspunkte für aether_pipeline.py:

    initialize(vault_path)  – Vault öffnen oder anlegen
    analyze(raw)            – Algorithmus-strukturelle Datenanalyse

`analyze()` bewertet, wie gut ein GP-Baum die Byte-Sequenz approximieren kann.
Das Ergebnis ergänzt Entropie, Symmetrie und Invarianten mit einem
"algorithmischen Kompressibilitäts"-Score.

Bei bekannten Datenstrukturen (Vault-Seed vorhanden) ist der Aufruf schnell
(O(N × Baumgröße)). Bei unbekannten Strukturen wird eine Kurzevolution
(pop=20, gens=10) gestartet – der beste Baum wird im Vault gespeichert.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .aelab_motor import (
    AEEvolver, Node, fitness_drop,
    node_size, node_depth, has_anchor,
)
from .aelab_vault import AEVault, tree_signature

# ---------------------------------------------------------------------------
# Globaler Vault (lazy-init, thread-safe für sequenzielle Pipeline-Aufrufe)
# ---------------------------------------------------------------------------
_vault: Optional[AEVault] = None
_vault_lock = threading.Lock()

# Maximale Byte-Länge die pro analyze()-Aufruf verarbeitet wird.
# Längere Daten werden auf dieses Fenster gekürzt – schnell genug für die Pipeline.
_MAX_SAMPLE = 512


def initialize(vault_path: str = "data/aelab_vault") -> None:
    """
    Initialisiert den globalen Tree-Vault (idempotent).
    Wird von aether_pipeline.py beim Start aufgerufen.
    """
    global _vault
    with _vault_lock:
        if _vault is None:
            Path(vault_path).mkdir(parents=True, exist_ok=True)
            _vault = AEVault(root=vault_path, max_main=128, max_sub=256)


def analyze(raw: bytes) -> dict:
    """
    Algorithmisch-strukturelle Analyse eines Byte-Blocks.

    Rückgabe-Dict:
        fitness    – wie gut lässt sich `raw` durch einen GP-Baum modellieren [0, ∞)
        lossless   – Anteil exakt getroffener Bytes [0, 1]
        nodes      – Baumgröße des verwendeten Baums
        depth      – Baumtiefe
        has_anchor – Baum enthält math. Ankerpunkte (π, e, 2^k, …)
        evolved    – True wenn in diesem Aufruf eine neue Evolution lief
    """
    if not raw:
        return _empty_result()

    sample = raw[:_MAX_SAMPLE]

    try:
        _ensure_initialized()

        with _vault_lock:
            seed = _vault.best_seed() if _vault else None

        evolved = False
        score: float = 0.0
        lr: float = 0.0
        best_tree: Optional[Node] = None
        selected_entry: Optional[Dict[str, Any]] = None
        vault_state: Dict[str, Any] = {}

        if seed is not None:
            # Schnell: bestehenden Baum gegen neue Daten auswerten
            score, lr, _ = fitness_drop(seed, sample)
            best_tree = seed
            if score < 0.05:
                # Seed passt kaum – kurze Evolution starten
                best_tree, score, lr = _quick_evolve(sample)
                evolved = True
        else:
            # Noch kein Seed im Vault – Minimalevolution
            best_tree, score, lr = _quick_evolve(sample)
            evolved = True

        # Verbesserten Baum in Vault schreiben
        if evolved and best_tree is not None and _vault is not None:
            with _vault_lock:
                stored = _vault.store(
                    best_tree,
                    fitness=score,
                    lossless=lr,
                    generation=0,
                    label=f"pipe_{len(raw)}b_{_short_hash(raw)}",
                )
                selected_entry = _entry_payload(stored)
                vault_state = _vault_status_locked()
        elif best_tree is not None and _vault is not None:
            with _vault_lock:
                sig = tree_signature(best_tree)
                selected_entry = _entry_payload(_vault._entries.get(sig))
                vault_state = _vault_status_locked()

        return {
            "fitness":    round(score, 6),
            "lossless":   round(lr, 4),
            "nodes":      node_size(best_tree) if best_tree else 0,
            "depth":      node_depth(best_tree) if best_tree else 0,
            "has_anchor": has_anchor(best_tree) if best_tree else False,
            "evolved":    evolved,
            "signature":  tree_signature(best_tree) if best_tree else "",
            "selected_seed": selected_entry or {},
            "vault": vault_state,
        }

    except Exception as exc:
        return {**_empty_result(), "error": str(exc)}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _ensure_initialized() -> None:
    global _vault
    if _vault is None:
        initialize()


def _quick_evolve(data: bytes) -> Tuple[Optional[Node], float, float]:
    """Kurze Evolution (pop=20, gens=10) für den Pipeline-Kontext."""
    seed_val = int(_short_hash(data), 16)
    ev = AEEvolver(data=data, seed=seed_val)
    tree, fit = ev.run(pop=20, gens=10, seed_depth=3, max_depth=6)
    return tree, fit, ev.best_lossless


def _short_hash(data: bytes) -> str:
    """8-stelliger deterministischer Hash über die ersten 64 Bytes."""
    return hashlib.sha256(data[:64]).hexdigest()[:8]


def _empty_result() -> dict:
    return {
        "fitness":    0.0,
        "lossless":   0.0,
        "nodes":      0,
        "depth":      0,
        "has_anchor": False,
        "evolved":    False,
        "signature":  "",
        "selected_seed": {},
        "vault": {},
    }


def _entry_payload(entry: Any) -> Optional[Dict[str, Any]]:
    if entry is None:
        return None
    return {
        "label": getattr(entry, "label", ""),
        "signature": getattr(entry, "sig", ""),
        "bucket": getattr(entry, "bucket", ""),
        "fitness": round(float(getattr(entry, "fitness", 0.0)), 6),
        "lossless": round(float(getattr(entry, "lossless", 0.0)), 6),
        "nodes": int(getattr(entry, "nodes", 0)),
        "depth": int(getattr(entry, "depth", 0)),
        "anchors": int(getattr(entry, "anchors", 0)),
        "coherence": round(float(getattr(entry, "coherence", 0.0)), 6),
        "coupling": round(float(getattr(entry, "coupling", 0.0)), 6),
        "adaptability": round(float(getattr(entry, "adaptability", 0.0)), 6),
        "utility_score": round(float(getattr(entry, "utility_score", 0.0)), 6),
        "times_used": int(getattr(entry, "times_used", 0)),
        "has_sequence": bool(getattr(entry, "has_sequence", 0)),
        "has_bridge": bool(getattr(entry, "has_bridge", 0)),
        "has_xor": bool(getattr(entry, "has_xor", 0)),
        "has_interfere": bool(getattr(entry, "has_interfere", 0)),
    }


def _vault_status_locked() -> Dict[str, Any]:
    if _vault is None:
        return {}
    integrity_errors = _vault.verify_integrity()
    entries = list(_vault._entries.values())
    main_entries = sum(1 for entry in entries if entry.bucket == "main")
    inactive_entries = sum(1 for entry in entries if "inactive" in entry.bucket)
    recovered_entries = sum(1 for entry in entries if "recovered" in entry.bucket)
    top_entries = [_entry_payload(entry) for entry in _vault.top_entries(3)]
    return {
        "root": str(_vault.root),
        "total_entries": len(entries),
        "main_entries": main_entries,
        "inactive_entries": inactive_entries,
        "recovered_entries": recovered_entries,
        "integrity_ok": not integrity_errors,
        "integrity_errors": integrity_errors[:3],
        "top_entries": [entry for entry in top_entries if entry],
    }
