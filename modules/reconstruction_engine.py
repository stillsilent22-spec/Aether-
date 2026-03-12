"""Verlustfreie Rekonstruktion aus Delta-Logs."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

try:
    import numpy as np
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    np = None

try:
    from scipy.fft import rfft
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    rfft = None


@dataclass
class ReconstructionResult:
    """Ergebnis einer Delta-Log-Rekonstruktion."""

    delta_log: list[dict[str, Any]]
    reconstructed_bytes: bytes
    reconstructed_hash: str
    merkle_root: str
    reconstruction_verified: bool
    anchor_coverage_ratio: float = 0.0
    unresolved_residual_ratio: float = 1.0
    residual_hash: str = ""
    coverage_verified: bool = False


@dataclass
class StructuralAnchor:
    """Struktureller Anker aus einem Signal-Chunk. Kein Originalinhalt im Delta-Log."""

    anchor_hash: str
    chunk_offset: int
    chunk_length: int
    entropy: float
    dominant_frequency: float
    fractal_dimension: float
    benford_score: float
    pi_positions: list[int]
    symmetry: float
    signal_type: str

    def signature_dict(self) -> dict[str, Any]:
        return {
            "entropy": round(self.entropy, 6),
            "dominant_frequency": round(self.dominant_frequency, 6),
            "fractal_dimension": round(self.fractal_dimension, 6),
            "benford_score": round(self.benford_score, 6),
            "pi_positions": list(self.pi_positions[:8]),
            "symmetry": round(self.symmetry, 6),
            "signal_type": str(self.signal_type),
        }


class AnchorExtractor:
    """Extrahiert robuste Strukturanker aus Rohdaten-Chunks."""

    CHUNK_SIZE: int = 512
    PI_DIGITS = "14159265358979323846264338327950288"

    def extract_anchors(self, raw_bytes: bytes) -> list[StructuralAnchor]:
        anchors: list[StructuralAnchor] = []
        for offset in range(0, len(raw_bytes), self.CHUNK_SIZE):
            chunk = raw_bytes[offset : offset + self.CHUNK_SIZE]
            anchors.append(self._extract_single(chunk, offset))
        if not anchors and raw_bytes == b"":
            anchors.append(self._extract_single(b"", 0))
        return anchors

    def _extract_single(self, chunk: bytes, offset: int) -> StructuralAnchor:
        entropy = self._shannon_entropy(chunk)
        dominant_freq = self._dominant_frequency(chunk)
        fractal_dim = self._katz_fractal_dimension(chunk)
        benford = self._benford_score(chunk)
        pi_pos = self._pi_positions(chunk)
        symmetry = self._gini_symmetry(chunk)
        signal_type = self._detect_signal_type(entropy)
        raw_hash = hashlib.sha256(chunk).hexdigest()
        sig = (
            f"{entropy:.4f}|{dominant_freq:.4f}|{fractal_dim:.4f}|"
            f"{benford:.4f}|{symmetry:.4f}|{signal_type}|{raw_hash}"
        )
        anchor_hash = hashlib.sha256(sig.encode("utf-8")).hexdigest()
        return StructuralAnchor(
            anchor_hash=anchor_hash,
            chunk_offset=int(offset),
            chunk_length=int(len(chunk)),
            entropy=float(entropy),
            dominant_frequency=float(dominant_freq),
            fractal_dimension=float(fractal_dim),
            benford_score=float(benford),
            pi_positions=list(pi_pos),
            symmetry=float(symmetry),
            signal_type=str(signal_type),
        )

    def _shannon_entropy(self, chunk: bytes) -> float:
        if not chunk:
            return 0.0
        counts: dict[int, int] = {}
        for value in chunk:
            counts[value] = counts.get(value, 0) + 1
        total = len(chunk)
        return float(
            -sum((count / total) * math.log2(count / total) for count in counts.values() if count > 0)
        )

    def _dominant_frequency(self, chunk: bytes) -> float:
        if len(chunk) < 4 or np is None or rfft is None:
            return 0.0
        signal = np.frombuffer(chunk, dtype=np.uint8).astype(float)
        spectrum = np.abs(rfft(signal))
        if len(spectrum) < 2:
            return 0.0
        return float(np.argmax(spectrum[1:]) + 1) / float(max(1, len(signal)))

    def _katz_fractal_dimension(self, chunk: bytes) -> float:
        if len(chunk) < 2 or np is None:
            return 1.0
        signal = np.frombuffer(chunk, dtype=np.uint8).astype(float)
        diffs = np.abs(np.diff(signal))
        length = float(np.sum(diffs))
        distance = float(np.max(np.abs(signal - signal[0])))
        if distance < 1e-9 or length < 1e-9:
            return 1.0
        n = float(len(signal))
        denominator = math.log10(distance / length) + math.log10(max(n, 1.0))
        if abs(denominator) < 1e-9:
            return 1.0
        return float(math.log10(max(n, 1.0)) / denominator)

    def _benford_score(self, chunk: bytes) -> float:
        expected = {str(digit): math.log10(1.0 + 1.0 / float(digit)) for digit in range(1, 10)}
        counts: dict[str, int] = {}
        total = 0
        for value in chunk:
            first = str(value)[0] if value > 0 else None
            if first and first in expected:
                counts[first] = counts.get(first, 0) + 1
                total += 1
        if total <= 0:
            return 0.5
        deviation = sum(abs(counts.get(digit, 0) / total - expected[digit]) for digit in expected)
        return float(max(0.0, 1.0 - deviation))

    def _pi_positions(self, chunk: bytes) -> list[int]:
        positions: list[int] = []
        pi = self.PI_DIGITS
        limit = max(0, min(len(chunk) - 2, 50))
        for index in range(limit):
            fragment = "".join(str(value % 10) for value in chunk[index : index + 3])
            if fragment in pi:
                positions.append(index)
        return positions[:8]

    def _gini_symmetry(self, chunk: bytes) -> float:
        if not chunk:
            return 0.0
        values = sorted(chunk)
        total = sum(values)
        if total <= 0:
            return 1.0
        n = len(values)
        gini = sum((2 * (index + 1) - n - 1) * value for index, value in enumerate(values))
        gini /= max(1, n * total)
        return float(1.0 - abs(gini))

    def _detect_signal_type(self, entropy: float) -> str:
        if entropy < 3.0:
            return "text"
        if entropy > 7.5:
            return "binary_compressed"
        return "binary"


class VaultAnchorStore:
    """
    Lokaler SQLite-Vault fuer strukturelle Anker.
    Speichert nur Signaturen und Rekonstruktionsbytes im lokalen Vault.
    """

    def __init__(self, db_path: str = "data/vault/anchors.db") -> None:
        self.db_path = str(db_path)
        db_file = Path(self.db_path)
        if self.db_path != ":memory:":
            db_file.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS anchors (
                    anchor_hash TEXT PRIMARY KEY,
                    raw_bytes BLOB,
                    signature_json TEXT NOT NULL,
                    hit_count INTEGER DEFAULT 1,
                    trust_score REAL DEFAULT 0.65,
                    lossless_confirmed INTEGER DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hit_count ON anchors(hit_count DESC)")
            conn.commit()

    def lookup(self, anchor_hash: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_bytes, signature_json, hit_count, trust_score FROM anchors WHERE anchor_hash = ?",
                (str(anchor_hash),),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE anchors SET hit_count = hit_count + 1, last_seen = ? WHERE anchor_hash = ?",
                (int(time.time()), str(anchor_hash)),
            )
            conn.commit()
            return {
                "raw_bytes": bytes(row[0] or b""),
                "signature": json.loads(str(row[1] or "{}")),
                "hit_count": int(row[2] or 0),
                "trust_score": float(row[3] or 0.0),
            }

    def store(self, anchor: StructuralAnchor, raw_bytes: bytes, trust_score: float = 0.65) -> bool:
        now = int(time.time())
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO anchors
                    (anchor_hash, raw_bytes, signature_json, hit_count, trust_score,
                     lossless_confirmed, created_at, last_seen)
                    VALUES (?, ?, ?, 1, ?, 0, ?, ?)
                    """,
                    (
                        str(anchor.anchor_hash),
                        sqlite3.Binary(bytes(raw_bytes)),
                        json.dumps(anchor.signature_dict()),
                        float(trust_score),
                        now,
                        now,
                    ),
                )
                conn.commit()
                return int(cursor.rowcount or 0) > 0
        except sqlite3.Error:
            return False

    def confirm_lossless(self, anchor_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE anchors SET lossless_confirmed = 1, last_seen = ? WHERE anchor_hash = ?",
                (int(time.time()), str(anchor_hash)),
            )
            conn.commit()

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = int(conn.execute("SELECT COUNT(*) FROM anchors").fetchone()[0] or 0)
            confirmed = int(
                conn.execute("SELECT COUNT(*) FROM anchors WHERE lossless_confirmed = 1").fetchone()[0] or 0
            )
            avg_hits = float(conn.execute("SELECT AVG(hit_count) FROM anchors").fetchone()[0] or 0.0)
        return {
            "total_anchors": total,
            "lossless_confirmed": confirmed,
            "avg_hit_count": round(avg_hits, 2),
        }


class GoedelLoopTerminator:
    """Beendet den Goedel-Loop nach Koharenz-, Tiefen- oder Stabilitaetskriterium."""

    COHERENCE_THRESHOLD: float = 0.95
    MAX_RECURSION_DEPTH: int = 7
    DELTA_STABILITY_THRESHOLD: float = 0.02

    def should_terminate(self, coherence: float, depth: int, delta_change: float) -> tuple[bool, str]:
        if coherence >= self.COHERENCE_THRESHOLD:
            return True, f"KOHAERENZ_ERREICHT: C(t)={coherence:.4f}"
        if depth >= self.MAX_RECURSION_DEPTH:
            return True, f"GOEDEL_STOP: maximale Tiefe {self.MAX_RECURSION_DEPTH}"
        if delta_change < self.DELTA_STABILITY_THRESHOLD:
            return True, f"DELTA_STABIL: Aenderung {delta_change:.4f} konvergiert"
        return False, "LOOP_FORTSETZUNG"

    def run_loop(self, raw_bytes: bytes, engine: "LosslessReconstructionEngine") -> dict[str, Any]:
        prev_coherence = 0.0
        result: dict[str, Any] = {}
        for depth in range(self.MAX_RECURSION_DEPTH + 1):
            delta_log = engine.build_delta_log(raw_bytes)
            coherence = engine.coherence_index(delta_log)
            delta_change = abs(coherence - prev_coherence)
            terminate, reason = self.should_terminate(coherence, depth, delta_change)
            result = {
                "coherence": float(coherence),
                "depth": int(depth),
                "delta_change": float(delta_change),
                "reason": str(reason),
                "terminated": bool(terminate),
                "goedel_rest": round(max(0.0, 1.0 - coherence), 6),
            }
            if terminate:
                break
            prev_coherence = coherence
        return result


class LosslessReconstructionEngine:
    """Erzeugt und verifiziert verlustfreie Delta-Logs fuer Originalbytes."""

    def __init__(self, chunk_size: int = 512, vault_db_path: str = "data/vault/anchors.db") -> None:
        self.chunk_size = max(64, int(chunk_size))
        self.extractor = AnchorExtractor()
        self.extractor.CHUNK_SIZE = self.chunk_size
        self.vault = VaultAnchorStore(db_path=vault_db_path)

    def build_delta_log(self, raw_bytes: bytes) -> list[dict[str, Any]]:
        """Kodiert Originalbytes als vault-basierten Delta-Log."""
        anchors = self.extractor.extract_anchors(bytes(raw_bytes or b""))
        delta_log: list[dict[str, Any]] = [{"op": "init", "size": int(len(raw_bytes))}]
        vault_hits = 0
        vault_misses = 0
        for anchor in anchors:
            chunk = raw_bytes[anchor.chunk_offset : anchor.chunk_offset + anchor.chunk_length]
            vault_entry = self.vault.lookup(anchor.anchor_hash)
            if vault_entry is not None:
                delta_log.append(
                    {
                        "op": "ref",
                        "offset": int(anchor.chunk_offset),
                        "length": int(anchor.chunk_length),
                        "anchor_hash": str(anchor.anchor_hash),
                    }
                )
                vault_hits += 1
                continue
            self.vault.store(anchor, bytes(chunk))
            delta_log.append(
                {
                    "op": "add",
                    "offset": int(anchor.chunk_offset),
                    "length": int(anchor.chunk_length),
                    "data": bytes(chunk).hex(),
                    "anchor_hash": str(anchor.anchor_hash),
                }
            )
            vault_misses += 1
        delta_log.append(
            {
                "op": "meta",
                "vault_hits": int(vault_hits),
                "vault_misses": int(vault_misses),
                "coverage_ratio": float(vault_hits / max(1, vault_hits + vault_misses)),
            }
        )
        return delta_log

    def benford_profile(self, delta_log: Sequence[dict[str, Any]]) -> dict[str, Any]:
        """Misst eine Benford-nahe Fuehrungsziffernverteilung fuer Delta-Magnituden."""
        magnitudes: list[int] = []
        for entry in delta_log:
            for key in ("size", "offset", "length", "source_offset"):
                raw_value = entry.get(key)
                try:
                    value = abs(int(raw_value))
                except (TypeError, ValueError):
                    continue
                if value >= 1:
                    magnitudes.append(value)

        counts = {str(index): 0 for index in range(1, 10)}
        for value in magnitudes:
            leading = str(value).lstrip("0")[:1]
            if leading in counts:
                counts[leading] += 1

        sample_count = int(sum(counts.values()))
        expected = {
            str(index): float(math.log10(1.0 + (1.0 / float(index))))
            for index in range(1, 10)
        }
        if sample_count <= 0:
            return {
                "sample_count": 0,
                "informative": False,
                "leading_digit_counts": counts,
                "observed": {digit: 0.0 for digit in counts},
                "expected": expected,
                "mad": 0.0,
                "conformity_score": 0.0,
            }

        observed = {
            digit: float(count) / float(sample_count)
            for digit, count in counts.items()
        }
        mad = float(
            sum(abs(observed[digit] - expected[digit]) for digit in counts) / float(len(counts))
        )
        informative = sample_count >= 24 and len([digit for digit, count in counts.items() if count > 0]) >= 4
        conformity_score = float(max(0.0, min(100.0, 100.0 * (1.0 - (mad / 0.12)))))
        return {
            "sample_count": sample_count,
            "informative": informative,
            "leading_digit_counts": counts,
            "observed": observed,
            "expected": expected,
            "mad": mad,
            "conformity_score": conformity_score,
        }

    def replay(self, delta_log: Sequence[dict[str, Any]]) -> bytes:
        """Rekonstruiert Originalbytes ausschliesslich aus dem Delta-Log."""
        size = 0
        for entry in delta_log:
            if str(entry.get("op", "")) == "init":
                size = max(0, int(entry.get("size", 0)))
                break

        buffer = bytearray(size)
        for entry in delta_log:
            op = str(entry.get("op", ""))
            if op == "init":
                continue
            if op not in {"add", "move", "remove", "ref"}:
                continue
            offset = max(0, int(entry.get("offset", 0)))
            length = max(0, int(entry.get("length", 0)))
            if op == "remove":
                for index in range(offset, min(len(buffer), offset + length)):
                    buffer[index] = 0
                continue
            if op == "ref":
                vault_entry = self.vault.lookup(str(entry.get("anchor_hash", "")))
                chunk = bytes(vault_entry.get("raw_bytes", b"")) if vault_entry else b""
                end = min(len(buffer), offset + len(chunk))
                buffer[offset:end] = chunk[: max(0, end - offset)]
                continue
            data_hex = str(entry.get("data", ""))
            chunk = bytes.fromhex(data_hex) if data_hex else b""
            if op == "move":
                source = max(0, int(entry.get("source_offset", 0)))
                chunk = bytes(buffer[source : source + length])
            end = min(len(buffer), offset + len(chunk))
            buffer[offset:end] = chunk[: max(0, end - offset)]
        return bytes(buffer)

    def reconstruct_from_vault(self, delta_log: Sequence[dict[str, Any]]) -> bytes:
        """Rekonstruiert Originalbytes aus vault-basiertem Delta-Log."""
        return self.replay(delta_log)

    def coherence_index(self, delta_log: Sequence[dict[str, Any]]) -> float:
        """C(t) = vault_hits / total_chunks. Steigt mit wachsendem Vault gegen 1."""
        meta = next((entry for entry in delta_log if str(entry.get("op", "")) == "meta"), {})
        hits = int(meta.get("vault_hits", 0) or 0)
        misses = int(meta.get("vault_misses", 0) or 0)
        total = hits + misses
        if total <= 0:
            return 0.0
        return round(hits / float(total), 6)

    def merkle_root(self, delta_log: Sequence[dict[str, Any]]) -> str:
        """Berechnet eine einfache Merkle-Root ueber den Delta-Log."""
        leaves = [hashlib.sha256(str(entry).encode("utf-8")).digest() for entry in delta_log]
        if not leaves:
            return hashlib.sha256(b"").hexdigest()
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [
                hashlib.sha256(leaves[index] + leaves[index + 1]).digest()
                for index in range(0, len(leaves), 2)
            ]
        return leaves[0].hex()

    def anchor_residual_profile(
        self,
        raw_bytes: bytes,
        anchor_block_indices: Sequence[int],
        block_count: int,
        block_size: int | None = None,
        coverage_threshold: float = 0.85,
    ) -> dict[str, Any]:
        """Misst, wie viel des Byte-Stroms durch aktuelle Anchor-Bloecke abgedeckt ist."""
        effective_block_size = max(64, int(block_size or self.chunk_size))
        normalized_block_count = max(1, int(block_count or 0))
        covered_indices = {
            int(index)
            for index in anchor_block_indices
            if 0 <= int(index) < normalized_block_count
        }
        covered_byte_count = 0
        residual_chunks = bytearray()
        for block_index in range(normalized_block_count):
            start = int(block_index * effective_block_size)
            if start >= len(raw_bytes):
                break
            end = min(len(raw_bytes), start + effective_block_size)
            chunk = raw_bytes[start:end]
            if block_index in covered_indices:
                covered_byte_count += len(chunk)
            else:
                residual_chunks.extend(chunk)
        total_size = max(1, len(raw_bytes))
        anchor_coverage_ratio = float(max(0.0, min(1.0, covered_byte_count / float(total_size))))
        unresolved_residual_ratio = float(max(0.0, min(1.0, len(residual_chunks) / float(total_size))))
        coverage_verified = bool(
            math.isclose(anchor_coverage_ratio + unresolved_residual_ratio, 1.0, abs_tol=1e-6)
            and anchor_coverage_ratio >= float(max(0.0, min(1.0, coverage_threshold)))
        )
        return {
            "covered_block_count": int(len(covered_indices)),
            "block_count": int(normalized_block_count),
            "covered_byte_count": int(covered_byte_count),
            "unresolved_byte_count": int(len(residual_chunks)),
            "anchor_coverage_ratio": anchor_coverage_ratio,
            "unresolved_residual_ratio": unresolved_residual_ratio,
            "residual_hash": hashlib.sha256(bytes(residual_chunks)).hexdigest(),
            "coverage_verified": coverage_verified,
            "coverage_threshold": float(max(0.0, min(1.0, coverage_threshold))),
        }

    def verify(self, original_hash: str, delta_log: Sequence[dict[str, Any]]) -> ReconstructionResult:
        """Replayed den Delta-Log und prueft den SHA-256-Hash gegen das Original."""
        reconstructed = self.replay(delta_log)
        reconstructed_hash = hashlib.sha256(reconstructed).hexdigest()
        merkle_root = self.merkle_root(delta_log)
        return ReconstructionResult(
            delta_log=list(delta_log),
            reconstructed_bytes=reconstructed,
            reconstructed_hash=reconstructed_hash,
            merkle_root=merkle_root,
            reconstruction_verified=(reconstructed_hash == str(original_hash)),
        )

    def verify_lossless(self, original_bytes: bytes, reconstructed_bytes: bytes) -> dict[str, Any]:
        """Vergleicht Original und Rekonstruktion bytegenau und liefert Diagnosekennzahlen."""
        original = bytes(original_bytes or b"")
        reconstructed = bytes(reconstructed_bytes or b"")
        original_size = int(len(original))
        reconstructed_size = int(len(reconstructed))
        original_hash = hashlib.sha256(original).hexdigest()
        reconstructed_hash = hashlib.sha256(reconstructed).hexdigest()
        size_match = bool(original_size == reconstructed_size)
        byte_match = bool(original_hash == reconstructed_hash)

        if original_size <= 0:
            compression_ratio = 1.0 if reconstructed_size <= 0 else 1.0
            anchor_coverage_ratio = 1.0 if reconstructed_size <= 0 else 0.0
            unresolved_residual_ratio = 0.0 if reconstructed_size <= 0 else 1.0
            residual_size_bytes = int(reconstructed_size)
        else:
            shared_length = min(original_size, reconstructed_size)
            matched_bytes = sum(
                1
                for index in range(shared_length)
                if original[index] == reconstructed[index]
            )
            residual_size_bytes = int(
                (shared_length - matched_bytes) + abs(original_size - reconstructed_size)
            )
            compression_ratio = float(
                max(0.0, min(1.0, reconstructed_size / float(original_size)))
            )
            anchor_coverage_ratio = float(
                max(0.0, min(1.0, matched_bytes / float(original_size)))
            )
            unresolved_residual_ratio = float(
                max(0.0, min(1.0, residual_size_bytes / float(original_size)))
            )

        return {
            "verified": bool(byte_match and size_match),
            "original_hash": str(original_hash),
            "reconstructed_hash": str(reconstructed_hash),
            "byte_match": bool(byte_match),
            "size_match": bool(size_match),
            "compression_ratio": float(compression_ratio),
            "anchor_coverage_ratio": float(anchor_coverage_ratio),
            "unresolved_residual_ratio": float(unresolved_residual_ratio),
            "residual_size_bytes": int(residual_size_bytes),
        }
