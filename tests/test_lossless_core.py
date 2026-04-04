"""tests/test_lossless_core.py — Lossless Roundtrip-Tests fuer LosslessReconstructionEngine.

Adressiert die E-Mail-Anfrage von Kevin Hannemann:
  - @dataclass fuer Snapshot und Residuum (Punkt 3)
  - assert original == reconstructed (Punkt 4)
  - pytest-kompatibel, kein Netzwerk, kein LLM noetig (Punkt 5)

Ausfuehren:
    python -m pytest tests/test_lossless_core.py -v

Erwartetes Ergebnis: alle Tests gruen (passed).
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Pfad-Setup
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.reconstruction_engine import (
    AnchorExtractor,
    GoedelLoopTerminator,
    LosslessReconstructionEngine,
    StructuralAnchor,
    VaultMissError,
)


# ---------------------------------------------------------------------------
# @dataclass-Modelle (Antwort auf Kevins Punkt 3)
# ---------------------------------------------------------------------------

@dataclass
class Snapshot:
    """Unveraenderlicher Zustand: Invarianten + SHA-256 Fingerprint der Originaldaten."""
    invariants: dict                 # Strukturmetriken (Entropy, Symmetrie, Resonanz, ...)
    original_hash: str               # SHA-256 des Originals — dient als Lossless-Pruefsum
    data: bytes = field(default=b"", repr=False)  # Originaldaten (optional fuer reinen Verifier)


@dataclass
class Residuum:
    """Delta zwischen zwei Snapshots — XOR-basiertes Differenzobjekt."""
    delta: bytes                     # XOR-Differenz der Originaldaten
    patch_meta: dict = field(default_factory=dict)  # optionale Metadaten

    def apply_to(self, base: bytes) -> bytes:
        """Rekonstruiert Originaldaten: D(Snapshot, Residuum) = Original."""
        if not self.delta:
            return base
        # XOR-Rekonstruktion: O = base XOR delta
        # Padding falls Laengen unterschiedlich (sollte in Praxis gleich sein)
        max_len = max(len(base), len(self.delta))
        base_padded  = base.ljust(max_len, b"\x00")
        delta_padded = self.delta.ljust(max_len, b"\x00")
        return bytes(a ^ b for a, b in zip(base_padded, delta_padded))


# ---------------------------------------------------------------------------
# Lokaler ReconstructionEngine (minimal, fuer Kevins Punkt 3+4)
# ---------------------------------------------------------------------------

class SimpleReconstructionEngine:
    """
    Minimal-Implementierung: O = D(Snapshot, Residuum).
    Lossless wird durch SHA-256-Vergleich verifiziert.
    """

    @staticmethod
    def snapshot(data: bytes) -> Snapshot:
        """Erstellt einen Snapshot aus Rohdaten."""
        inv = {
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": _shannon_entropy(data),
        }
        return Snapshot(invariants=inv, original_hash=inv["sha256"], data=data)

    @staticmethod
    def make_residuum(original: bytes, modified: bytes) -> Residuum:
        """Berechnet das Delta zwischen Original und modifizierten Bytes."""
        max_len = max(len(original), len(modified))
        base_p  = original.ljust(max_len, b"\x00")
        mod_p   = modified.ljust(max_len, b"\x00")
        delta   = bytes(a ^ b for a, b in zip(base_p, mod_p))
        return Residuum(delta=delta, patch_meta={"original_len": len(original)})

    def reconstruct(self, snap: Snapshot, residuum: Residuum) -> bytes:
        """Rekonstruiert: D(Snapshot, Residuum) = Original."""
        reconstructed = residuum.apply_to(snap.data)
        # Auf Originallaenge zuschneiden (falls Padding vorhanden)
        orig_len = residuum.patch_meta.get("original_len", len(reconstructed))
        return reconstructed[:orig_len]

    def verify_lossless(self, original: bytes, reconstructed: bytes) -> bool:
        """assert original == reconstructed — True = vollstaendig verlustfrei."""
        return hashlib.sha256(original).hexdigest() == hashlib.sha256(reconstructed).hexdigest()


def _shannon_entropy(data: bytes) -> float:
    import math
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_DATA = (
    b"Aether lossless roundtrip test\n"
    b"observer-relative information remains local\n"
    b"session seeds must survive reloads\n"
) * 8


# ===========================================================================
# 1. @dataclass Lossless Roundtrip (Kevins Punkt 3+4)
# ===========================================================================

class TestSimpleReconstructionEngine:
    """Minimale lossless D(Snapshot, Residuum) = Original Tests."""

    def test_snapshot_has_correct_hash(self):
        engine = SimpleReconstructionEngine()
        snap = engine.snapshot(SAMPLE_DATA)
        assert snap.original_hash == hashlib.sha256(SAMPLE_DATA).hexdigest()

    def test_snapshot_dataclass_fields(self):
        snap = Snapshot(
            invariants={"length": 3, "entropy": 1.5},
            original_hash="abc",
            data=b"xyz",
        )
        assert snap.invariants["length"] == 3
        assert snap.original_hash == "abc"
        assert snap.data == b"xyz"

    def test_residuum_dataclass_fields(self):
        res = Residuum(delta=b"\x01\x02", patch_meta={"original_len": 2})
        assert res.delta == b"\x01\x02"
        assert res.patch_meta["original_len"] == 2

    def test_lossless_roundtrip_identical_data(self):
        """Wenn original == modified, muss Residuum.delta alles Nullbytes sein."""
        engine = SimpleReconstructionEngine()
        snap = engine.snapshot(SAMPLE_DATA)
        residuum = engine.make_residuum(SAMPLE_DATA, SAMPLE_DATA)
        reconstructed = engine.reconstruct(snap, residuum)
        # Kernassertion: Original == Rekonstruiert (Kevins Punkt 4)
        assert reconstructed == SAMPLE_DATA
        assert engine.verify_lossless(SAMPLE_DATA, reconstructed)

    def test_lossless_roundtrip_modified_then_delta_back(self):
        """XOR-Delta rueckgaengig machen: Original wiederherstellen."""
        engine = SimpleReconstructionEngine()
        original = b"Hallo Aether Welt!"
        modified = b"Hallo Aether Well!"   # letztes Zeichen geaendert
        snap      = engine.snapshot(original)
        residuum  = engine.make_residuum(original, modified)
        # Rekonstruktion: apply_to(modified) mit delta(original, modified) = original
        reconstructed = residuum.apply_to(modified)[:len(original)]
        assert reconstructed == original, f"Lossless fehlgeschlagen: {reconstructed!r} != {original!r}"

    def test_verify_lossless_success(self):
        engine = SimpleReconstructionEngine()
        assert engine.verify_lossless(b"test", b"test") is True

    def test_verify_lossless_failure(self):
        engine = SimpleReconstructionEngine()
        assert engine.verify_lossless(b"test", b"XXXX") is False

    def test_empty_data_roundtrip(self):
        engine = SimpleReconstructionEngine()
        snap = engine.snapshot(b"")
        residuum = engine.make_residuum(b"", b"")
        reconstructed = engine.reconstruct(snap, residuum)
        assert reconstructed == b""
        assert engine.verify_lossless(b"", reconstructed)

    def test_large_data_roundtrip(self):
        engine = SimpleReconstructionEngine()
        data = bytes(range(256)) * 200   # 51200 bytes
        snap = engine.snapshot(data)
        residuum = engine.make_residuum(data, data)
        reconstructed = engine.reconstruct(snap, residuum)
        assert reconstructed == data


# ===========================================================================
# 2. LosslessReconstructionEngine (echter Engine aus reconstruction_engine.py)
# ===========================================================================

class TestLosslessReconstructionEngine:
    """Tests fuer den echten LosslessReconstructionEngine mit In-Memory-Vault."""

    def _engine(self) -> LosslessReconstructionEngine:
        return LosslessReconstructionEngine(chunk_size=64, vault_db_path=":memory:")

    def test_build_delta_log_returns_list(self):
        engine = self._engine()
        log = engine.build_delta_log(SAMPLE_DATA)
        assert isinstance(log, list)
        assert len(log) > 0

    def test_delta_log_entries_have_required_keys(self):
        engine = self._engine()
        log = engine.build_delta_log(SAMPLE_DATA)
        for entry in log:
            assert "anchor_hash" in entry
            assert "chunk_offset" in entry

    def test_reconstruct_from_delta_log(self):
        """Kerntest: Original-Bytes nach Build+Reconstruct identisch."""
        engine = self._engine()
        original = SAMPLE_DATA
        log = engine.build_delta_log(original)
        reconstructed = engine.replay(log)
        # assert original == reconstructed  (Kevins Punkt 4 — echter Engine)
        assert reconstructed == original, (
            f"Lossless-Roundtrip fehlgeschlagen!\n"
            f"  Original SHA-256:       {hashlib.sha256(original).hexdigest()[:16]}...\n"
            f"  Rekonstruiert SHA-256:  {hashlib.sha256(reconstructed).hexdigest()[:16]}..."
        )

    def test_verify_lossless_true_for_identical(self):
        engine = self._engine()
        result = engine.verify_lossless(SAMPLE_DATA, SAMPLE_DATA)
        assert result.get("verified") is True

    def test_verify_lossless_false_for_different(self):
        engine = self._engine()
        result = engine.verify_lossless(SAMPLE_DATA, b"manipuliert")
        assert result.get("verified") is False

    def test_coherence_index_bounded(self):
        engine = self._engine()
        log = engine.build_delta_log(SAMPLE_DATA)
        ci = engine.coherence_index(log)
        assert 0.0 <= ci <= 1.0, f"Coherence-Index ausserhalb [0,1]: {ci}"

    def test_vault_report(self):
        engine = self._engine()
        engine.build_delta_log(SAMPLE_DATA)
        report = engine.vault_report()
        assert "total_anchors" in report
        assert report["total_anchors"] > 0

    def test_empty_bytes_roundtrip(self):
        engine = self._engine()
        log = engine.build_delta_log(b"")
        reconstructed = engine.replay(log)
        assert reconstructed == b""

    def test_single_byte_roundtrip(self):
        engine = self._engine()
        data = b"\x42"
        log = engine.build_delta_log(data)
        reconstructed = engine.replay(log)
        assert reconstructed == data


# ===========================================================================
# 3. AnchorExtractor (StructuralAnchor @dataclass)
# ===========================================================================

class TestAnchorExtractor:
    """StructuralAnchor ist ein @dataclass — teste Extraktion."""

    def test_extracts_anchors_from_sample(self):
        extractor = AnchorExtractor()
        anchors = extractor.extract_anchors(SAMPLE_DATA)
        assert len(anchors) > 0
        assert all(isinstance(a, StructuralAnchor) for a in anchors)

    def test_anchor_hash_is_deterministic(self):
        """Gleiche Daten → gleiche Anchor-Hashes (content-addressed)."""
        extractor = AnchorExtractor()
        a1 = extractor.extract_anchors(SAMPLE_DATA)
        a2 = extractor.extract_anchors(SAMPLE_DATA)
        assert [a.anchor_hash for a in a1] == [a.anchor_hash for a in a2]

    def test_anchor_hash_differs_for_different_data(self):
        extractor = AnchorExtractor()
        a1 = extractor.extract_anchors(b"Aether")
        a2 = extractor.extract_anchors(b"aether")
        assert a1[0].anchor_hash != a2[0].anchor_hash

    def test_anchor_signature_dict_has_entropy(self):
        extractor = AnchorExtractor()
        anchors = extractor.extract_anchors(SAMPLE_DATA)
        sig = anchors[0].signature_dict()
        assert "entropy" in sig
        assert isinstance(sig["entropy"], float)

    def test_empty_bytes_returns_one_anchor(self):
        extractor = AnchorExtractor()
        anchors = extractor.extract_anchors(b"")
        assert len(anchors) == 1


# ===========================================================================
# 4. GoedelLoopTerminator
# ===========================================================================

class TestGoedelLoopTerminator:

    def test_terminates_at_max_depth(self):
        terminator = GoedelLoopTerminator()
        engine = LosslessReconstructionEngine(chunk_size=64, vault_db_path=":memory:")
        result = terminator.run_loop(SAMPLE_DATA, engine)
        assert result["terminated"] is True
        assert result["depth"] <= GoedelLoopTerminator.MAX_RECURSION_DEPTH

    def test_coherence_in_result(self):
        terminator = GoedelLoopTerminator()
        engine = LosslessReconstructionEngine(chunk_size=64, vault_db_path=":memory:")
        result = terminator.run_loop(SAMPLE_DATA, engine)
        assert "coherence" in result
        assert 0.0 <= result["coherence"] <= 1.0

    def test_goedel_rest_bounded(self):
        terminator = GoedelLoopTerminator()
        engine = LosslessReconstructionEngine(chunk_size=64, vault_db_path=":memory:")
        result = terminator.run_loop(SAMPLE_DATA, engine)
        assert 0.0 <= result["goedel_rest"] <= 1.0

    def test_should_terminate_on_high_coherence(self):
        t = GoedelLoopTerminator()
        ok, reason = t.should_terminate(coherence=0.99, depth=1, delta_change=0.1)
        assert ok is True
        assert "KOHAERENZ" in reason

    def test_should_terminate_on_max_depth(self):
        t = GoedelLoopTerminator()
        ok, reason = t.should_terminate(
            coherence=0.1, depth=GoedelLoopTerminator.MAX_RECURSION_DEPTH, delta_change=0.5
        )
        assert ok is True
        assert "GOEDEL" in reason

    def test_should_not_terminate_mid_loop(self):
        t = GoedelLoopTerminator()
        ok, reason = t.should_terminate(coherence=0.5, depth=2, delta_change=0.5)
        assert ok is False
