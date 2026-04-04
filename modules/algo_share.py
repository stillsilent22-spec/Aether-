"""
algo_share.py
Teilt Expression Trees als strukturelle Algorithmen — nie Daten, nie Deltas.

Anwendungsfälle:
  - Swarm-Nodes tauschen effektive Trees für bestimmte Datenklassen
  - Gaming: Spieler teilen Kompressions-Algorithmen als handelbare Assets
  - Forschung: reproduzierbare strukturelle Beschreibungen ohne Inhalte

Ein AlgoToken ist:
  - tree_signature: SHA256 des Trees (Fingerprint)
  - invariant_profile: welche mathematischen Invarianten der Tree nutzt
  - fitness_score: wie gut der Tree Strukturen beschreibt (lossless-Rate)
  - domain_hint: für welche Datenklasse der Tree optimiert wurde
  - NIEMALS: Rohdaten, Delta, session_key, persönliche Dateien
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AlgoToken:
    """
    Handelbares/teilbares Strukturbeschreibungs-Token.
    Enthält nur den Algorithmus, nie die Daten.
    """
    token_id: str              # SHA256(tree_signature + domain_hint)
    tree_signature: str        # SHA256 des Expression Trees
    invariant_profile: List[str]  # welche Invarianten genutzt werden (z.B. ["pi", "phi", "2^k"])
    fitness_score: float       # lossless-Rate des Trees [0,1]
    domain_hint: str           # "text", "binary", "audio", "generic"
    cascade_version: str
    node_count: int
    depth: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "tree_signature": self.tree_signature,
            "invariant_profile": self.invariant_profile,
            "fitness_score": round(self.fitness_score, 4),
            "domain_hint": self.domain_hint,
            "cascade_version": self.cascade_version,
            "node_count": self.node_count,
            "depth": self.depth,
        }

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True,
                          sort_keys=True, separators=(",", ":"))


def build_algo_token(aelab_result: Dict[str, Any], domain_hint: str = "generic") -> Optional[AlgoToken]:
    """
    Baut einen AlgoToken aus einem aelab_engine.analyze()-Ergebnis.
    Gibt None zurück wenn commit_allowed=False (Tree nicht gut genug zum Teilen).
    """
    from modules.unified_cascade import CASCADE_VERSION

    if not aelab_result.get("commit_allowed", False):
        return None

    tree_sig = str(aelab_result.get("signature", ""))
    if not tree_sig:
        return None

    # Invarianten-Profil aus has_anchor und Signatur ableiten
    invariant_profile: List[str] = []
    if aelab_result.get("has_anchor", False):
        invariant_profile = ["mathematical_anchor"]

    token_id = hashlib.sha256(
        f"{tree_sig}|{domain_hint}".encode()
    ).hexdigest()

    return AlgoToken(
        token_id=token_id,
        tree_signature=tree_sig,
        invariant_profile=invariant_profile,
        fitness_score=float(aelab_result.get("lossless", 0.0)),
        domain_hint=domain_hint,
        cascade_version=CASCADE_VERSION,
        node_count=int(aelab_result.get("nodes", 0)),
        depth=int(aelab_result.get("depth", 0)),
    )


def verify_algo_token(token: AlgoToken) -> bool:
    """
    Prüft ob ein empfangener AlgoToken strukturell valide ist.
    Kein Inhalt, keine Daten — nur Struktur-Integrität.
    """
    expected_id = hashlib.sha256(
        f"{token.tree_signature}|{token.domain_hint}".encode()
    ).hexdigest()
    return (
        token.token_id == expected_id
        and 0.0 <= token.fitness_score <= 1.0
        and len(token.tree_signature) == 64  # SHA256 hex
        and bool(token.cascade_version)
    )
