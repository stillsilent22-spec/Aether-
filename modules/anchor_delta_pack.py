"""
AnchorDeltaPack: Das lokale Speicherformat von Aether.

Datei = AnchorPack (öffentlich, SHA256) + DeltaPack (lokal, verschlüsselt)

AnchorPack:
  - Liste von Anker-Hashes (SHA256 der Chunks die durch Invarianten beschreibbar sind)
  - Invarianten-Signaturen (mathematische Strukturbeschreibung, kein Inhalt)
  - Optional: tree_signature des Expression Trees (teilbar, kein Inhalt)
  - Nie: Rohdaten, nie Delta, nie session_key

DeltaPack:
  - XOR-verschlüsselt mit _DeltaSession RAM-Key (AES-256-GCM)
  - Enthält: was die Datei von der universellen Struktur unterscheidet
  - Verlässt das Gerät niemals
  - Wird gelöscht wenn Session endet (sofern kein Vault-Commit)
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional


@dataclass
class AnchorEntry:
    offset: int          # Byte-Offset im Original
    length: int          # Chunk-Länge
    anchor_hash: str     # SHA256(chunk) — öffentlich
    invariant_sig: str   # SHA256(invariant_description) — öffentlich


@dataclass
class AnchorPack:
    """Öffentlich teilbarer Teil. Enthält keine Rohdaten."""
    source_hash: str       # SHA256(original) — Referenz, kein Inhalt
    anchor_count: int
    anchors: List[AnchorEntry]
    coverage_ratio: float  # Anteil der Bytes die durch Anker beschrieben sind
    tree_signature: str    # SHA256(expression_tree) — algo-fingerprint, kein Inhalt
    invariant_hash: str    # SHA256(invariants_json) — strukturelle Beschreibung
    cascade_version: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True,
                          sort_keys=True, separators=(",", ":"))

    def public_id(self) -> str:
        """Eindeutiger öffentlicher Identifier — SHA256 des Packs selbst."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


@dataclass
class DeltaPack:
    """
    Lokaler, verschlüsselter Rest.
    Verlässt das Gerät nie. Wird nur mit RAM-Session-Key entschlüsselt.
    """
    source_hash: str                      # Referenz zum zugehörigen AnchorPack
    delta_entries: List[Dict[str, Any]]   # verschlüsselte Chunks (op=add)
    delta_hash: str                       # SHA256(raw_delta_before_encryption)
    session_id: str                       # Welcher RAM-Session-Key wurde verwendet
    byte_length: int                      # Original-Größe (für Rekonstruktion)


def build_anchor_delta_pack(
    raw: bytes,
    delta_log: List[Dict[str, Any]],
    tree_sig: str,
    invariant_hash: str,
    session_encrypt_fn: Callable[[bytes], bytes],
    session_id: str,
    cascade_version: str,
) -> tuple[AnchorPack, DeltaPack]:
    """
    Nimmt den delta_log aus reconstruction_engine.build_delta_log()
    und teilt ihn sauber in öffentlichen AnchorPack und lokalen DeltaPack.

    op=ref → AnchorPack (Anker-Hash bekannt, kein Inhalt nötig)
    op=add → DeltaPack (unbekannter Chunk, bleibt lokal, verschlüsselt)
    """
    source_hash = hashlib.sha256(raw).hexdigest()
    anchor_entries: List[AnchorEntry] = []
    delta_entries: List[Dict[str, Any]] = []
    ref_bytes = 0
    total_bytes = len(raw)

    for entry in delta_log:
        op = entry.get("op")
        if op == "ref":
            anchor_entries.append(AnchorEntry(
                offset=int(entry["offset"]),
                length=int(entry["length"]),
                anchor_hash=str(entry["anchor_hash"]),
                invariant_sig=hashlib.sha256(str(entry["anchor_hash"]).encode()).hexdigest(),
            ))
            ref_bytes += int(entry["length"])
        elif op == "add":
            # Chunk-Daten verschlüsseln bevor sie lokal gespeichert werden
            raw_chunk = bytes.fromhex(str(entry.get("data", "")))
            encrypted_chunk = session_encrypt_fn(raw_chunk)
            delta_entries.append({
                "offset": int(entry["offset"]),
                "length": int(entry["length"]),
                "anchor_hash": str(entry["anchor_hash"]),
                "encrypted_data": encrypted_chunk.hex(),
            })

    coverage_ratio = float(ref_bytes / max(1, total_bytes))

    # Delta-Hash: SHA256 aller unverschlüsselten Delta-Chunks (vor Encryption)
    raw_delta_concat = b"".join(
        bytes.fromhex(str(e.get("data", "")))
        for e in delta_log if e.get("op") == "add"
    )
    delta_hash = hashlib.sha256(raw_delta_concat).hexdigest()

    anchor_pack = AnchorPack(
        source_hash=source_hash,
        anchor_count=len(anchor_entries),
        anchors=anchor_entries,
        coverage_ratio=round(coverage_ratio, 6),
        tree_signature=tree_sig,
        invariant_hash=invariant_hash,
        cascade_version=cascade_version,
    )
    delta_pack = DeltaPack(
        source_hash=source_hash,
        delta_entries=delta_entries,
        delta_hash=delta_hash,
        session_id=session_id,
        byte_length=total_bytes,
    )
    return anchor_pack, delta_pack
