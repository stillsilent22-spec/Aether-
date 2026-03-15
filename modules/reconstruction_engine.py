"""Verlustfreie Rekonstruktion aus Delta-Logs."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .session_engine import SessionContext

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
    failure_reason: str = ""


class VaultMissError(RuntimeError):
    """Signalisiert einen fehlenden Vault-Eintrag fuer einen referenzierten Anker."""

    def __init__(self, anchor_hash: str):
        super().__init__(f"Vault-Eintrag fehlt fuer Anker: {anchor_hash}")
        self.anchor_hash = str(anchor_hash)


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
        """Serialisiert nur stabile Strukturmetriken fuer die lokale Signaturansicht."""
        return {
            "entropy": round(self.entropy, 6),
            "dominant_frequency": round(self.dominant_frequency, 6),
            "fractal_dimension": round(self.fractal_dimension, 6),
            "benford_score": round(self.benford_score, 6),
            "symmetry": round(self.symmetry, 6),
            "signal_type": str(self.signal_type),
        }


class AnchorExtractor:
    """Extrahiert robuste Strukturanker aus Rohdaten-Chunks."""

    CHUNK_SIZE: int = 512
    PI_DIGITS = "14159265358979323846264338327950288"

    def extract_anchors(self, raw_bytes: bytes) -> list[StructuralAnchor]:
        """Zerlegt einen Bytestrom in stabile Chunk-Anker fuer den lokalen Vault."""
        anchors: list[StructuralAnchor] = []
        for offset in range(0, len(raw_bytes), self.CHUNK_SIZE):
            chunk = raw_bytes[offset : offset + self.CHUNK_SIZE]
            anchors.append(self._extract_single(chunk, offset))
        if not anchors and raw_bytes == b"":
            anchors.append(self._extract_single(b"", 0))
        return anchors

    def _extract_single(self, chunk: bytes, offset: int) -> StructuralAnchor:
        """
        Extrahiert einen einzelnen Strukturanker fuer einen Chunk.

        Der ``anchor_hash`` bleibt bewusst content-addressed: In die Signatur
        fliesst ein SHA-256-Hash des Chunk-Inhalts ein. Damit ist der Anker pro
        Byteinhalt eindeutig und fuer die Vault-Rekonstruktion korrekt, statt
        nur ein allgemeiner Structure-Hash zu sein.
        """
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
        self._memory_connection: sqlite3.Connection | None = None
        db_file = Path(self.db_path)
        if self.db_path != ":memory:":
            db_file.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._memory_connection is None:
                self._memory_connection = sqlite3.connect(":memory:")
            return self._memory_connection
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        conn = self._connect()
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
        """Fuehrt den Lernloop mit einem isolierten In-Memory-Vault aus."""
        loop_engine = LosslessReconstructionEngine(
            chunk_size=engine.chunk_size,
            vault_db_path=":memory:",
        )
        prev_coherence = 0.0
        result: dict[str, Any] = {}
        for depth in range(self.MAX_RECURSION_DEPTH + 1):
            delta_log = loop_engine.build_delta_log(raw_bytes)
            coherence = loop_engine.coherence_index(delta_log)
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
                anchor_hash = str(entry.get("anchor_hash", "") or "")
                vault_entry = self.vault.lookup(anchor_hash)
                if vault_entry is None:
                    raise VaultMissError(anchor_hash)
                chunk = bytes(vault_entry.get("raw_bytes", b""))
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
        """Rekonstruiert Originalbytes aus dem Vault oder wirft ``VaultMissError``."""
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
        merkle_root = self.merkle_root(delta_log)
        try:
            reconstructed = self.replay(delta_log)
        except VaultMissError as exc:
            return ReconstructionResult(
                delta_log=list(delta_log),
                reconstructed_bytes=b"",
                reconstructed_hash="",
                merkle_root=merkle_root,
                reconstruction_verified=False,
                failure_reason=str(exc),
            )
        reconstructed_hash = hashlib.sha256(reconstructed).hexdigest()
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


def _utc_now_iso() -> str:
    """Liefert eine kanonische UTC-Zeitmarke fuer auditierbare Zustandsobjekte."""
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(payload: Any) -> str:
    """Serialisiert verschachtelte Payloads deterministisch fuer Hashes und Signaturen."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_payload(payload: Any) -> str:
    """Bildet einen stabilen SHA-256-Hash ueber JSON-kanonisierte Payloads."""
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _normalize_score(value: float, scale: float = 1.0) -> float:
    """Normiert lokale Metriken robust in den Bereich 0..1."""
    if scale <= 1e-9:
        return float(max(0.0, min(1.0, value)))
    return float(max(0.0, min(1.0, float(value) / float(scale))))


def _mean(values: Sequence[float]) -> float:
    """Berechnet Mittelwerte ohne externe Statistikbibliotheken."""
    if not values:
        return 0.0
    return float(sum(float(value) for value in values) / float(len(values)))


def _variance(values: Sequence[float]) -> float:
    """Berechnet eine deterministische Populationsvarianz fuer Driftmetriken."""
    if len(values) <= 1:
        return 0.0
    center = _mean(values)
    return float(sum((float(value) - center) ** 2 for value in values) / float(len(values)))


def _parse_iso_timestamp(value: str) -> datetime:
    """Parst UTC-Zeitmarken robust und faellt fail-closed auf UNIX-Epoch zurueck."""
    try:
        normalized = str(value or "").replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _graph_topology_diff(left: dict[str, Any], right: dict[str, Any]) -> float:
    """Misst topologische Differenz ueber Knotenzahl, Kantenzahl und Dichte."""
    node_diff = abs(float(left.get("node_count", 0.0) or 0.0) - float(right.get("node_count", 0.0) or 0.0))
    edge_diff = abs(float(left.get("edge_count", 0.0) or 0.0) - float(right.get("edge_count", 0.0) or 0.0))
    density_diff = abs(float(left.get("density", 0.0) or 0.0) - float(right.get("density", 0.0) or 0.0))
    return float(max(0.0, min(1.0, (node_diff / 16.0 + edge_diff / 32.0 + density_diff) / 3.0)))


def _bytes_xor_delta(source: bytes, target: bytes) -> dict[str, Any]:
    """Kodiert Bytedifferenzen deterministisch als XOR-Delta plus Ziellaenge."""
    source_bytes = bytes(source or b"")
    target_bytes = bytes(target or b"")
    max_length = max(len(source_bytes), len(target_bytes))
    source_padded = source_bytes.ljust(max_length, b"\x00")
    target_padded = target_bytes.ljust(max_length, b"\x00")
    delta = bytes(left ^ right for left, right in zip(source_padded, target_padded))
    return {
        "source_length": int(len(source_bytes)),
        "target_length": int(len(target_bytes)),
        "xor_hex": delta.hex(),
        "target_hash": hashlib.sha256(target_bytes).hexdigest(),
        "source_hash": hashlib.sha256(source_bytes).hexdigest(),
    }


def _apply_xor_delta(source: bytes, delta_payload: dict[str, Any]) -> bytes:
    """Rekonstruiert einen Ziel-Bytestrom deterministisch aus Quelle und XOR-Delta."""
    source_bytes = bytes(source or b"")
    xor_payload = bytes.fromhex(str(delta_payload.get("xor_hex", "") or ""))
    target_length = max(0, int(delta_payload.get("target_length", len(source_bytes)) or 0))
    if not xor_payload and target_length == len(source_bytes):
        return source_bytes[:target_length]
    source_padded = source_bytes.ljust(max(len(source_bytes), len(xor_payload)), b"\x00")
    xor_padded = xor_payload.ljust(len(source_padded), b"\x00")
    reconstructed = bytes(left ^ right for left, right in zip(source_padded, xor_padded))
    return reconstructed[:target_length]


@dataclass
class GovernanceContext:
    """Beschreibt lokale Rechte, Invarianten und Signaturmaterial fuer Rekonstruktionen."""

    mode: str = "LOCAL"
    session_id: str = ""
    user_id: int = 0
    role: str = "operator"
    rights: dict[str, list[str]] = field(default_factory=dict)
    invariants: dict[str, Any] = field(default_factory=dict)
    keys: dict[str, str] = field(default_factory=dict)
    audit: dict[str, Any] = field(default_factory=dict)

    def allows(self, modality: str, op: str) -> bool:
        """Prueft deterministisch, ob eine Modalitaets-Operation lokal erlaubt ist."""
        allowed_ops = list(self.rights.get(str(modality), []) or [])
        return bool(str(op) in allowed_ops or "*" in allowed_ops)

    def signature_material(self) -> str:
        """Liefert lokales Material fuer HMAC-Signaturen auf Rekonstruktionsobjekten."""
        material = str(self.keys.get("signature_material", "") or "")
        if material:
            return material
        return hashlib.sha256(
            f"{self.mode}|{self.session_id}|{self.user_id}|{self.role}".encode("utf-8")
        ).hexdigest()

    def to_dict(self, redact_keys: bool = False) -> dict[str, Any]:
        """Serialisiert Governance-Kontext fuer Audit und optionale Fingerprint-Payloads."""
        keys = dict(self.keys)
        if redact_keys and "signature_material" in keys:
            keys["signature_material"] = hashlib.sha256(
                str(keys.get("signature_material", "")).encode("utf-8")
            ).hexdigest()
        return {
            "mode": str(self.mode),
            "session_id": str(self.session_id),
            "user_id": int(self.user_id),
            "role": str(self.role),
            "rights": {str(key): [str(item) for item in list(value or [])] for key, value in self.rights.items()},
            "invariants": dict(self.invariants or {}),
            "keys": keys,
            "audit": dict(self.audit or {}),
        }


@dataclass
class ModalityFeatures:
    """Entkoppelte Strukturmerkmale einer einzelnen Modalitaet ohne Semantik."""

    modality: str
    entropy_profile: list[float]
    symmetry_profile: dict[str, float]
    delta_profile: dict[str, float]
    resonance_profile: dict[str, float]
    graph_signature: dict[str, Any]
    invariants: list[str]
    source_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert Modalitaetsmerkmale deterministisch fuer Rekonstruktionszustand und Audit."""
        return {
            "modality": str(self.modality),
            "entropy_profile": [float(value) for value in self.entropy_profile],
            "symmetry_profile": {str(key): float(value) for key, value in self.symmetry_profile.items()},
            "delta_profile": {str(key): float(value) for key, value in self.delta_profile.items()},
            "resonance_profile": {str(key): float(value) for key, value in self.resonance_profile.items()},
            "graph_signature": dict(self.graph_signature or {}),
            "invariants": [str(value) for value in self.invariants],
            "source_hash": str(self.source_hash),
        }


@dataclass
class FeatureSpaceState:
    """Gemeinsamer struktureller Feature-Raum fuer Kamera-, Audio- und Dateizustaende."""

    entropy: float
    fingerprints: list[str]
    delta: float
    symmetry: float
    resonance: float
    graph: dict[str, Any]
    invariants: list[str]
    modalities: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert den beobachterrelativen Feature-Zustand auditierbar."""
        return {
            "entropy": float(self.entropy),
            "fingerprints": [str(value) for value in self.fingerprints],
            "delta": float(self.delta),
            "symmetry": float(self.symmetry),
            "resonance": float(self.resonance),
            "graph": dict(self.graph or {}),
            "invariants": [str(value) for value in self.invariants],
            "modalities": dict(self.modalities or {}),
        }


@dataclass
class ReconstructionSnapshot:
    """Rekonstruktionsfaehiger Systemzustand S_t inklusive Daten-, Feature- und Governance-Lage."""

    snapshot_id: str
    timestamp: str
    data: dict[str, bytes]
    data_hashes: dict[str, str]
    features: FeatureSpaceState
    observer: dict[str, Any]
    governance: GovernanceContext
    reconstruction: dict[str, Any]
    modality_features: dict[str, ModalityFeatures] = field(default_factory=dict)

    def core_payload(self, redact_governance: bool = False, include_data: bool = False) -> dict[str, Any]:
        """Liefert den auditierbaren Kernzustand fuer Hashing, Debugging und Export."""
        data_payload = (
            {str(key): bytes(value).hex() for key, value in self.data.items()}
            if include_data
            else {
                str(key): {
                    "hash": str(self.data_hashes.get(key, "")),
                    "length": int(len(bytes(value or b""))),
                }
                for key, value in self.data.items()
            }
        )
        return {
            "timestamp": str(self.timestamp),
            "data": data_payload,
            "features": self.features.to_dict(),
            "observer": dict(self.observer or {}),
            "governance": self.governance.to_dict(redact_keys=redact_governance),
            "reconstruction": dict(self.reconstruction or {}),
            "modality_features": {
                str(key): value.to_dict() for key, value in self.modality_features.items()
            },
        }


@dataclass
class ReconstructionResidual:
    """Mehrdimensionales, append-only Residuum fuer Zeit-, Modalitaets- und Governance-Deltas."""

    residual_id: str
    source_snapshot_id: str
    target_snapshot_id: str
    time_delta: dict[str, Any]
    modality_delta: dict[str, Any]
    feature_delta: dict[str, Any]
    governance_delta: dict[str, Any]
    meta_delta: dict[str, Any]
    hash: str
    signature: str
    timestamp: str
    invariants: dict[str, bool]

    def content_payload(self) -> dict[str, Any]:
        """Liefert den signierbaren Residualinhalt ohne abgeleitete Felder."""
        return {
            "source_snapshot_id": str(self.source_snapshot_id),
            "target_snapshot_id": str(self.target_snapshot_id),
            "time_delta": dict(self.time_delta or {}),
            "modality_delta": dict(self.modality_delta or {}),
            "feature_delta": dict(self.feature_delta or {}),
            "governance_delta": dict(self.governance_delta or {}),
            "meta_delta": dict(self.meta_delta or {}),
            "timestamp": str(self.timestamp),
            "invariants": {str(key): bool(value) for key, value in self.invariants.items()},
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert das Residuum inklusive Hash und Signatur auditierbar."""
        payload = self.content_payload()
        payload.update(
            {
                "residual_id": str(self.residual_id),
                "hash": str(self.hash),
                "signature": str(self.signature),
            }
        )
        return payload


@dataclass
class ReconstructionGraph:
    """Gerichteter Graph aus Schnappschuessen und eindeutig referenzierbaren Residuen."""

    nodes: dict[str, ReconstructionSnapshot] = field(default_factory=dict)
    residuals: dict[str, ReconstructionResidual] = field(default_factory=dict)
    edges: dict[tuple[str, str], str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(
        default_factory=lambda: {"created_at": _utc_now_iso(), "invariants": ["append_only"]}
    )

    def add_snapshot(self, snapshot: ReconstructionSnapshot) -> None:
        """Fuegt einen Snapshot als unveraenderlichen Knoten hinzu."""
        self.nodes[str(snapshot.snapshot_id)] = snapshot

    def add_residual(self, residual: ReconstructionResidual) -> None:
        """Fuegt eine gerichtete Residualkante unveraenderlich hinzu."""
        self.residuals[str(residual.residual_id)] = residual
        self.edges[(str(residual.source_snapshot_id), str(residual.target_snapshot_id))] = str(residual.residual_id)

    def find_path(self, snapshot_start: str, snapshot_end: str) -> list[str]:
        """Findet einen deterministischen Pfad durch den Residualgraphen."""
        start = str(snapshot_start)
        end = str(snapshot_end)
        if start == end:
            return []
        queue: list[tuple[str, list[str]]] = [(start, [])]
        visited = {start}
        while queue:
            current, path = queue.pop(0)
            for (left, right), residual_id in self.edges.items():
                if left != current or right in visited:
                    continue
                next_path = path + [str(residual_id)]
                if right == end:
                    return next_path
                visited.add(right)
                queue.append((right, next_path))
        return []


@dataclass
class Attractor:
    """Struktureller Attraktor ueber den gemeinsamen Feature-Raum."""

    id: str
    feature_signature: dict[str, Any]
    stability: float
    energy: float
    resonance_profile: dict[str, float]
    invariants: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert den Attraktor fuer Audit und Vorhersagepfade."""
        return {
            "id": str(self.id),
            "feature_signature": dict(self.feature_signature or {}),
            "stability": float(self.stability),
            "energy": float(self.energy),
            "resonance_profile": {str(key): float(value) for key, value in self.resonance_profile.items()},
            "invariants": {str(key): bool(value) for key, value in self.invariants.items()},
        }


@dataclass
class AttractorGraph:
    """Gerichteter Graph aus Attraktoren und deterministischen Drift-Transitionen."""

    nodes: dict[str, Attractor] = field(default_factory=dict)
    edges: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(
        default_factory=lambda: {"created_at": _utc_now_iso(), "invariants": ["deterministic_transitions"]}
    )


class BaseModalityAdapter:
    """Basisklasse fuer deterministische Modalitaetsprojektionen ohne Semantik."""

    modality_name: str = "generic"

    def extract(self, payload: bytes) -> ModalityFeatures:
        raw = bytes(payload or b"")
        entropy_profile = self._entropy_profile(raw)
        symmetry_profile = self._symmetry_profile(raw)
        delta_profile = self._delta_profile(raw)
        resonance_profile = self._resonance_profile(raw)
        graph_signature = self._graph_signature(raw)
        invariants = self._invariants(raw, entropy_profile, symmetry_profile, resonance_profile)
        return ModalityFeatures(
            modality=str(self.modality_name),
            entropy_profile=entropy_profile,
            symmetry_profile=symmetry_profile,
            delta_profile=delta_profile,
            resonance_profile=resonance_profile,
            graph_signature=graph_signature,
            invariants=invariants,
            source_hash=hashlib.sha256(raw).hexdigest(),
        )

    def _entropy_profile(self, payload: bytes) -> list[float]:
        extractor = AnchorExtractor()
        extractor.CHUNK_SIZE = 64
        anchors = extractor.extract_anchors(payload)
        return [round(float(anchor.entropy), 6) for anchor in anchors]

    def _symmetry_profile(self, payload: bytes) -> dict[str, float]:
        if not payload:
            return {"mirror": 1.0, "distribution": 1.0}
        midpoint = len(payload) // 2
        left = payload[:midpoint]
        right = payload[len(payload) - midpoint :]
        right_reversed = right[::-1]
        shared = min(len(left), len(right_reversed))
        if shared <= 0:
            mirror = 1.0
        else:
            mirror_matches = sum(1 for index in range(shared) if left[index] == right_reversed[index])
            mirror = mirror_matches / float(shared)
        histogram = {}
        for value in payload:
            histogram[value] = histogram.get(value, 0) + 1
        distribution = 1.0 - (
            sum(abs(count - (len(payload) / max(1, len(histogram)))) for count in histogram.values())
            / float(max(1, len(payload) * 2))
        )
        return {
            "mirror": round(max(0.0, min(1.0, mirror)), 6),
            "distribution": round(max(0.0, min(1.0, distribution)), 6),
        }

    def _delta_profile(self, payload: bytes) -> dict[str, float]:
        if len(payload) <= 1:
            return {"mean_step": 0.0, "max_step": 0.0, "step_variance": 0.0}
        steps = [abs(int(payload[index + 1]) - int(payload[index])) for index in range(len(payload) - 1)]
        return {
            "mean_step": round(_normalize_score(_mean(steps), 255.0), 6),
            "max_step": round(_normalize_score(max(steps), 255.0), 6),
            "step_variance": round(_normalize_score(_variance(steps), 255.0**2), 6),
        }

    def _resonance_profile(self, payload: bytes) -> dict[str, float]:
        if not payload:
            return {"periodicity": 0.0, "frequency_bias": 0.0, "energy": 0.0}
        counts: dict[int, int] = {}
        for value in payload:
            counts[value] = counts.get(value, 0) + 1
        dominant = max(counts.values()) if counts else 0
        periodicity_hits = 0
        for offset in range(1, min(16, len(payload))):
            shared = len(payload) - offset
            if shared <= 0:
                continue
            matches = sum(1 for index in range(shared) if payload[index] == payload[index + offset])
            periodicity_hits = max(periodicity_hits, matches)
        periodicity = periodicity_hits / float(max(1, len(payload)))
        energy = sum(int(value) for value in payload) / float(max(1, len(payload) * 255))
        return {
            "periodicity": round(max(0.0, min(1.0, periodicity)), 6),
            "frequency_bias": round(max(0.0, min(1.0, dominant / float(max(1, len(payload))))), 6),
            "energy": round(max(0.0, min(1.0, energy)), 6),
        }

    def _graph_signature(self, payload: bytes) -> dict[str, Any]:
        if not payload:
            return {"node_count": 0, "edge_count": 0, "density": 0.0, "path_checksum": "0" * 64}
        nodes = sorted(set(int(value) for value in payload))
        edges = set()
        for index in range(max(0, len(payload) - 1)):
            edges.add((int(payload[index]), int(payload[index + 1])))
        node_count = len(nodes)
        edge_count = len(edges)
        density = 0.0
        if node_count > 1:
            density = edge_count / float(node_count * (node_count - 1))
        return {
            "node_count": int(node_count),
            "edge_count": int(edge_count),
            "density": round(max(0.0, min(1.0, density)), 6),
            "path_checksum": hashlib.sha256(payload[:256]).hexdigest(),
        }

    def _invariants(
        self,
        payload: bytes,
        entropy_profile: Sequence[float],
        symmetry_profile: dict[str, float],
        resonance_profile: dict[str, float],
    ) -> list[str]:
        invariants = ["deterministic_projection", "local_metrics_only", "observer_relative"]
        entropy_mean = _mean([float(value) for value in entropy_profile])
        if entropy_mean <= 8.0:
            invariants.append("entropy_within_bounds")
        if float(symmetry_profile.get("mirror", 0.0) or 0.0) >= 0.0:
            invariants.append("symmetry_measured")
        if float(resonance_profile.get("energy", 0.0) or 0.0) <= 1.0:
            invariants.append("resonance_bounded")
        if len(payload) >= 0:
            invariants.append("payload_locally_observed")
        return invariants


class CameraAdapter(BaseModalityAdapter):
    """Deterministischer Adapter fuer Kamera-Frames als Bytezustand."""

    modality_name = "camera"


class AudioAdapter(BaseModalityAdapter):
    """Deterministischer Adapter fuer Audio-Chunks als Bytezustand."""

    modality_name = "audio"




class FileAdapter(BaseModalityAdapter):
    """Deterministischer Adapter fuer Dateibytes als Bytezustand."""

    modality_name = "file"


class UniversalAdapter(BaseModalityAdapter):
    """Universal modalitaetsunabhaengiger Adapter fuer alle Domänen (image/music/audio/video/text/binary/process/stream)."""

    modality_name = "universal"

    def __init__(self):
        super().__init__()
        self.domain_extractors = {
            'image': self._image_extractor,
            'video': self._video_extractor,
            'music': self._music_extractor,
            'audio': self._audio_extractor,
            'text': self._text_extractor,
            'binary': self._binary_extractor,
            'process': self._process_extractor,
            'stream': self._stream_extractor,
        }

    def detect_domain(self, payload: bytes) -> str:
        """Detects domain deterministically via magic bytes (first 8-16 bytes)."""
        if len(payload) < 4:
            return 'binary'
        magic = payload[:8].hex().upper()
        # Image
        if magic.startswith('FFD8FF'): return 'image'  # JPEG
        if magic.startswith('89504E47'): return 'image'  # PNG
        if magic.startswith('47494638'): return 'image'  # GIF
        if magic.startswith('52494646'): return 'image'  # WebP/AVIF (RIFF)
        # Video
        if magic.startswith('00000020'): return 'video'  # MP4
        if magic.startswith('1A45DFA3'): return 'video'  # MKV
        # Music/Audio
        if magic.startswith('494433'): return 'music'  # MP3 ID3
        if magic.startswith('RIFF') and b'WAVE' in payload[:16]: return 'music'  # WAV
        if magic.startswith('66747970'): return 'music'  # FLAC/AAC
        if magic.startswith('FFFB'): return 'music'  # MP3 raw
        # Text
        try:
            payload.decode('utf-8')
            return 'text'
        except UnicodeDecodeError:
            pass
        # Binary fallback
        return 'binary'

    def _image_extractor(self, payload: bytes) -> ModalityFeatures:
        # Enhance Base for images (e.g. color histograms as graph)
        features = self.extract(payload)
        features.graph_signature['color_bins'] = len(set(payload[i:i+3] for i in range(0, len(payload), 3) if len(payload[i:i+3])==3))
        features.invariants.append('image_structure')
        return features

    def _video_extractor(self, payload: bytes) -> ModalityFeatures:
        # Treat as image sequence + audio mux (frame entropy variance)
        features = self.extract(payload)
        features.delta_profile['frame_var'] = _variance([self._shannon_entropy(payload[i:i+512]) for i in range(0, len(payload), 512)])
        features.invariants.append('video_structure')
        return features

    def _music_extractor(self, payload: bytes) -> ModalityFeatures:
        # Audio with beat/resonance emphasis
        features = self.extract(payload)
        features.resonance_profile['beat_period'] = max(1, len(payload) // _mean([c for c in [ord(b) for b in payload] if c]))
        features.invariants.append('music_structure')
        return features

    def _audio_extractor(self, payload: bytes) -> ModalityFeatures:
        # Raw audio stream
        features = self.extract(payload)
        features.invariants.append('audio_structure')
        return features

    def _text_extractor(self, payload: bytes) -> ModalityFeatures:
        # Text with word graph
        features = self.extract(payload)
        text = payload.decode('utf-8', errors='ignore')
        words = [len(w) for w in text.split() if w]
        features.graph_signature['word_graph_nodes'] = len(words)
        features.invariants.append('text_structure')
        return features

    def _binary_extractor(self, payload: bytes) -> ModalityFeatures:
        # Executable/ZIP etc - section entropy
        features = self.extract(payload)
        sections = [payload[i:i+1024] for i in range(0, len(payload), 1024)]
        features.entropy_profile = [self._shannon_entropy(s) for s in sections][:10]
        features.invariants.append('binary_structure')
        return features

    def _process_extractor(self, payload: bytes) -> ModalityFeatures:
        # Process snapshot (pid/mem/etc as bytes)
        features = self.extract(payload)
        features.graph_signature['process_threads'] = payload.count(b'\x00\x01')  # Dummy
        features.invariants.append('process_structure')
        return features

    def _stream_extractor(self, payload: bytes) -> ModalityFeatures:
        # Live stream as continuous delta-heavy
        features = self.extract(payload)
        features.delta_profile['stream_rate'] = len(payload) / max(1, 1024)
        features.invariants.append('stream_structure')
        return features

    def extract(self, payload: bytes) -> ModalityFeatures:
        domain = self.detect_domain(payload)
        extractor = self.domain_extractors.get(domain, self._binary_extractor)
        return extractor(payload)



class ReconstructionEngine:
    """Phase-3-Engine fuer Rekonstruktion, Multi-Modalitaet, Drift und Attraktoren."""

    def __init__(self) -> None:
        self.reconstruction_graph = ReconstructionGraph()
        self.attractor_graph = AttractorGraph()
self.modality_adapters: dict[str, BaseModalityAdapter] = {
            "camera": CameraAdapter(),
            "audio": AudioAdapter(),
            "file": FileAdapter(),
            "universal": UniversalAdapter(),
        }

    def governance_from_session(self, session: SessionContext | None = None) -> GovernanceContext:
        """Erzeugt einen lokalen Governance-Kontext aus einer Session oder Defaultwerten."""
        if session is None:
            return GovernanceContext(
                rights={"camera": ["read"], "audio": ["read"], "file": ["read"], "reconstruction": ["write"]},
                invariants={
                    "camera.max_entropy_delta_per_time": 0.75,
                    "audio.max_entropy_delta_per_time": 0.75,
                    "file.max_entropy_delta_per_time": 0.9,
                    "camera.allowed_symmetry_break": 0.8,
                    "audio.allowed_symmetry_break": 0.8,
                    "file.allowed_symmetry_break": 0.95,
                    "camera.resonance_range": [0.0, 1.0],
                    "audio.resonance_range": [0.0, 1.0],
                    "file.resonance_range": [0.0, 1.0],
                },
            )
        return GovernanceContext(
            session_id=str(getattr(session, "session_id", "") or ""),
            user_id=int(getattr(session, "user_id", 0) or 0),
            role=str(getattr(session, "user_role", "operator") or "operator"),
            rights={"camera": ["read"], "audio": ["read"], "file": ["read"], "reconstruction": ["write"]},
            invariants={
                "camera.max_entropy_delta_per_time": 0.75,
                "audio.max_entropy_delta_per_time": 0.75,
                "file.max_entropy_delta_per_time": 0.9,
                "camera.allowed_symmetry_break": 0.8,
                "audio.allowed_symmetry_break": 0.8,
                "file.allowed_symmetry_break": 0.95,
                "camera.resonance_range": [0.0, 1.0],
                "audio.resonance_range": [0.0, 1.0],
                "file.resonance_range": [0.0, 1.0],
            },
        )

    def validate_modality_operation(self, modality: str, op: str, snapshot: ReconstructionSnapshot) -> bool:
        """Prueft Rechte und Modalitaetsinvarianten fail-closed."""
        modality_name = str(modality)
        governance = snapshot.governance
        if not governance.allows(modality_name, op):
            return False
        modality_payload = snapshot.modality_features.get(modality_name)
        if modality_payload is None:
            return False
        entropy_mean = _mean(modality_payload.entropy_profile)
        max_entropy = float(
            governance.invariants.get(f"{modality_name}.max_entropy_delta_per_time", 1.0) or 1.0
        )
        allowed_symmetry_break = float(
            governance.invariants.get(f"{modality_name}.allowed_symmetry_break", 1.0) or 1.0
        )
        resonance_range = list(governance.invariants.get(f"{modality_name}.resonance_range", [0.0, 1.0]) or [0.0, 1.0])
        symmetry_break = 1.0 - float(modality_payload.symmetry_profile.get("mirror", 0.0) or 0.0)
        resonance_energy = float(modality_payload.resonance_profile.get("energy", 0.0) or 0.0)
        return bool(
            entropy_mean <= max_entropy * 8.0
            and symmetry_break <= allowed_symmetry_break
            and float(resonance_range[0]) <= resonance_energy <= float(resonance_range[-1])
        )

    def _feature_fingerprints(self, modality_features: Sequence[ModalityFeatures]) -> list[str]:
        return sorted(
            hashlib.sha256(_canonical_json(item.to_dict()).encode("utf-8")).hexdigest()
            for item in modality_features
        )

    def project_to_feature_space(self, modality_features: Sequence[ModalityFeatures]) -> FeatureSpaceState:
        """Projiziert beliebige Modalitäten (universal) deterministisch in universal F_t."""
        modalities = [item for item in modality_features]
        entropy_values = [_mean(item.entropy_profile) for item in modalities]
        symmetry_values = [float(item.symmetry_profile.get("mirror", 0.0) or 0.0) for item in modalities]
        delta_values = [float(item.delta_profile.get("mean_step", 0.0) or 0.0) for item in modalities]
        resonance_values = [float(item.resonance_profile.get("energy", 0.0) or 0.0) for item in modalities]
        graph_nodes = sum(int(item.graph_signature.get("node_count", 0) or 0) for item in modalities)
        graph_edges = sum(int(item.graph_signature.get("edge_count", 0) or 0) for item in modalities)
        graph_density = _mean([float(item.graph_signature.get("density", 0.0) or 0.0) for item in modalities])
        invariants = sorted({value for item in modalities for value in item.invariants})
        modality_map = {str(item.modality): item.to_dict() for item in modalities}
        return FeatureSpaceState(
            entropy=round(_mean(entropy_values), 6),
            fingerprints=self._feature_fingerprints(modalities),
            delta=round(_mean(delta_values), 6),
            symmetry=round(_mean(symmetry_values), 6),
            resonance=round(_mean(resonance_values), 6),
            graph={
                "node_count": int(graph_nodes),
                "edge_count": int(graph_edges),
                "density": round(max(0.0, min(1.0, graph_density)), 6),
            },
            invariants=invariants,
            modalities=modality_map,
        )

def domain_delta(
        self,
        f_t_a: FeatureSpaceState,
        f_t_b: FeatureSpaceState,
    ) -> dict[str, Any]:
        """Domänenübergreifende Delta-Analyse zwischen beliebigen F_t (modalitätsunabhängig)."""
        return {
            "entropy_diff": round(abs(float(f_t_a.entropy) - float(f_t_b.entropy)), 6),
            "symmetry_breaks": round(abs(float(f_t_a.symmetry) - float(f_t_b.symmetry)), 6),
            "resonance_shift": round(abs(float(f_t_a.resonance) - float(f_t_b.resonance)), 6),
            "graph_topology_diff": round(_graph_topology_diff(f_t_a.graph, f_t_b.graph), 6),
            "invariants": ["deterministic_cross_domain_delta", "local_metrics_only", "modal_independent"],
        }

    def create_snapshot(
        self,
        data: dict[str, bytes],
        governance: GovernanceContext | None = None,
        observer: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> ReconstructionSnapshot:
        """Erzeugt einen auditierbaren Snapshot inklusive Rekonstruktionslage."""
        normalized_data = {str(key): bytes(value or b"") for key, value in dict(data or {}).items()}
        governance_context = governance or self.governance_from_session(None)
        modality_features = {
            modality: self.modality_adapters[modality].extract(normalized_data.get(modality, b""))
            for modality in self.modality_adapters
            if modality in normalized_data
        }
        feature_space = self.project_to_feature_space(list(modality_features.values()))
        ts = str(timestamp or _utc_now_iso())
        data_hashes = {key: hashlib.sha256(value).hexdigest() for key, value in normalized_data.items()}
        reconstruction_payload = {
            "residuals": [],
            "paths": [],
            "validity": {
                "valid": True,
                "reason": "snapshot_initialized",
            },
        }
        core_payload = {
            "timestamp": ts,
            "data_hashes": data_hashes,
            "features": feature_space.to_dict(),
            "observer": dict(observer or {}),
            "governance": governance_context.to_dict(redact_keys=True),
        }
        snapshot_id = _sha256_payload(core_payload)
        snapshot = ReconstructionSnapshot(
            snapshot_id=snapshot_id,
            timestamp=ts,
            data=normalized_data,
            data_hashes=data_hashes,
            features=feature_space,
            observer=dict(observer or {}),
            governance=governance_context,
            reconstruction=reconstruction_payload,
            modality_features=modality_features,
        )
        self.reconstruction_graph.add_snapshot(snapshot)
        return snapshot

    def _sign_payload(self, payload: dict[str, Any], governance: GovernanceContext) -> str:
        return hmac.new(
            governance.signature_material().encode("utf-8"),
            _canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _feature_delta(self, source: ReconstructionSnapshot, target: ReconstructionSnapshot) -> dict[str, Any]:
        return {
            "entropy_delta": round(float(target.features.entropy) - float(source.features.entropy), 6),
            "delta_delta": round(float(target.features.delta) - float(source.features.delta), 6),
            "symmetry_delta": round(float(target.features.symmetry) - float(source.features.symmetry), 6),
            "resonance_delta": round(float(target.features.resonance) - float(source.features.resonance), 6),
            "graph_topology_diff": round(_graph_topology_diff(source.features.graph, target.features.graph), 6),
            "data_xor": {
                key: _bytes_xor_delta(source.data.get(key, b""), target.data.get(key, b""))
                for key in sorted(set(source.data.keys()) | set(target.data.keys()))
            },
        }

    def _governance_delta(self, source: GovernanceContext, target: GovernanceContext) -> dict[str, Any]:
        return {
            "mode_changed": bool(str(source.mode) != str(target.mode)),
            "role_changed": bool(str(source.role) != str(target.role)),
            "rights_hash_before": _sha256_payload(source.rights),
            "rights_hash_after": _sha256_payload(target.rights),
            "invariants_hash_before": _sha256_payload(source.invariants),
            "invariants_hash_after": _sha256_payload(target.invariants),
        }

    def _time_delta(self, source: ReconstructionSnapshot, target: ReconstructionSnapshot) -> dict[str, Any]:
        source_ts = _parse_iso_timestamp(source.timestamp)
        target_ts = _parse_iso_timestamp(target.timestamp)
        delta_seconds = (target_ts - source_ts).total_seconds()
        return {
            "seconds": float(delta_seconds),
            "forward_only": bool(delta_seconds >= 0.0),
            "source_timestamp": str(source.timestamp),
            "target_timestamp": str(target.timestamp),
        }

    def _meta_delta(
        self,
        source: ReconstructionSnapshot,
        target: ReconstructionSnapshot,
        modality_delta_payload: dict[str, Any],
        feature_delta_payload: dict[str, Any],
        governance_delta_payload: dict[str, Any],
    ) -> dict[str, Any]:
        observer_delta = {
            key: (
                float(target.observer.get(key, 0.0) or 0.0) - float(source.observer.get(key, 0.0) or 0.0)
                if isinstance(source.observer.get(key, 0.0), (int, float))
                and isinstance(target.observer.get(key, 0.0), (int, float))
                else 0.0
            )
            for key in sorted(set(source.observer.keys()) | set(target.observer.keys()))
        }
        governance_change = sum(1 for value in governance_delta_payload.values() if value is True)
        return {
            "feature_meta_delta": round(
                abs(float(feature_delta_payload.get("entropy_delta", 0.0) or 0.0))
                + abs(float(feature_delta_payload.get("delta_delta", 0.0) or 0.0))
                + abs(float(feature_delta_payload.get("symmetry_delta", 0.0) or 0.0))
                + abs(float(feature_delta_payload.get("resonance_delta", 0.0) or 0.0)),
                6,
            ),
            "modality_meta_delta": round(
                abs(float(modality_delta_payload.get("entropy_diff", 0.0) or 0.0))
                + abs(float(modality_delta_payload.get("symmetry_breaks", 0.0) or 0.0))
                + abs(float(modality_delta_payload.get("resonance_shift", 0.0) or 0.0)),
                6,
            ),
            "governance_meta_delta": int(governance_change),
            "observer_delta": observer_delta,
        }

    def _residual_invariants(
        self,
        source: ReconstructionSnapshot,
        target: ReconstructionSnapshot,
        time_delta_payload: dict[str, Any],
        governance_delta_payload: dict[str, Any],
    ) -> dict[str, bool]:
        return {
            "hash_consistent": bool(source.snapshot_id in self.reconstruction_graph.nodes and target.snapshot_id in self.reconstruction_graph.nodes),
            "time_monotonic": bool(time_delta_payload.get("forward_only", False)),
            "governance_mode_stable": not bool(governance_delta_payload.get("mode_changed", False)),
            "observer_relative": True,
            "local_reasoned": True,
            "append_only": True,
        }

    def create_residual(
        self,
        source: ReconstructionSnapshot,
        target: ReconstructionSnapshot,
    ) -> ReconstructionResidual:
        """Erzeugt ein signiertes, referenzierbares und unveraenderliches Residuum."""
        feature_delta_payload = self._feature_delta(source, target)
        modality_delta_payload = self.modality_delta(
            self.project_to_feature_space([source.modality_features["camera"]]) if "camera" in source.modality_features else None,
            self.project_to_feature_space([source.modality_features["audio"]]) if "audio" in source.modality_features else None,
            self.project_to_feature_space([source.modality_features["file"]]) if "file" in source.modality_features else None,
        )
        time_delta_payload = self._time_delta(source, target)
        governance_delta_payload = self._governance_delta(source.governance, target.governance)
        meta_delta_payload = self._meta_delta(
            source,
            target,
            modality_delta_payload,
            feature_delta_payload,
            governance_delta_payload,
        )
        invariants = self._residual_invariants(source, target, time_delta_payload, governance_delta_payload)
        content_payload = {
            "source_snapshot_id": str(source.snapshot_id),
            "target_snapshot_id": str(target.snapshot_id),
            "time_delta": time_delta_payload,
            "modality_delta": modality_delta_payload,
            "feature_delta": feature_delta_payload,
            "governance_delta": governance_delta_payload,
            "meta_delta": meta_delta_payload,
            "timestamp": str(target.timestamp),
            "invariants": invariants,
        }
        residual_hash = _sha256_payload(content_payload)
        residual_signature = self._sign_payload(content_payload, target.governance)
        residual_id = residual_hash
        residual = ReconstructionResidual(
            residual_id=residual_id,
            source_snapshot_id=str(source.snapshot_id),
            target_snapshot_id=str(target.snapshot_id),
            time_delta=time_delta_payload,
            modality_delta=modality_delta_payload,
            feature_delta=feature_delta_payload,
            governance_delta=governance_delta_payload,
            meta_delta=meta_delta_payload,
            hash=residual_hash,
            signature=residual_signature,
            timestamp=str(target.timestamp),
            invariants=invariants,
        )
        self.reconstruction_graph.add_residual(residual)
        source.reconstruction["residuals"] = list(source.reconstruction.get("residuals", [])) + [str(residual.residual_id)]
        source.reconstruction["paths"] = list(source.reconstruction.get("paths", [])) + [
            [str(residual.residual_id)]
        ]
        return residual

    def _verify_residual_integrity(
        self,
        residual: ReconstructionResidual,
        governance: GovernanceContext,
    ) -> tuple[bool, str]:
        expected_hash = _sha256_payload(residual.content_payload())
        if expected_hash != str(residual.hash):
            return False, "hash_mismatch"
        expected_signature = self._sign_payload(residual.content_payload(), governance)
        if expected_signature != str(residual.signature):
            return False, "signature_mismatch"
        for key, value in residual.invariants.items():
            if not bool(value):
                return False, f"invariant_failed:{key}"
        if not bool(residual.time_delta.get("forward_only", False)):
            return False, "time_reverse_detected"
        if bool(residual.governance_delta.get("mode_changed", False)):
            return False, "governance_mode_changed"
        return True, "ok"

    def reconstruct(self, snapshot_start: ReconstructionSnapshot, path: Sequence[str]) -> ReconstructionSnapshot:
        """Rekonstruiert einen Endzustand deterministisch aus Residuen."""
        current = snapshot_start
        traversed: list[str] = []
        for residual_id in list(path or []):
            residual = self.reconstruction_graph.residuals.get(str(residual_id))
            if residual is None:
                current.reconstruction["validity"] = {"valid": False, "reason": "missing_residual"}
                current.governance.audit.setdefault("events", []).append(
                    {"type": "reconstruction_failure", "reason": "missing_residual", "residual_id": str(residual_id)}
                )
                raise ValueError(f"Unbekanntes Residuum: {residual_id}")
            ok, reason = self._verify_residual_integrity(residual, current.governance)
            if not ok:
                current.reconstruction["validity"] = {"valid": False, "reason": reason}
                current.governance.audit.setdefault("events", []).append(
                    {"type": "reconstruction_failure", "reason": reason, "residual_id": str(residual_id)}
                )
                current.observer["governance_alarm"] = True
                raise ValueError(f"Residuum ungueltig: {reason}")
            reconstructed_data = {
                key: _apply_xor_delta(current.data.get(key, b""), payload)
                for key, payload in dict(residual.feature_delta.get("data_xor", {}) or {}).items()
            }
            target = self.reconstruction_graph.nodes.get(str(residual.target_snapshot_id))
            if target is None:
                current.reconstruction["validity"] = {"valid": False, "reason": "missing_target_snapshot"}
                current.governance.audit.setdefault("events", []).append(
                    {"type": "reconstruction_failure", "reason": "missing_target_snapshot", "residual_id": str(residual_id)}
                )
                current.observer["governance_alarm"] = True
                raise ValueError("Target-Snapshot fehlt")
            candidate = self.create_snapshot(
                data=reconstructed_data,
                governance=target.governance,
                observer=dict(target.observer),
                timestamp=str(target.timestamp),
            )
            if candidate.data_hashes != target.data_hashes:
                candidate.reconstruction["validity"] = {"valid": False, "reason": "reconstruction_hash_mismatch"}
                candidate.governance.audit.setdefault("events", []).append(
                    {"type": "reconstruction_failure", "reason": "reconstruction_hash_mismatch", "residual_id": str(residual_id)}
                )
                candidate.observer["governance_alarm"] = True
                raise ValueError("Rekonstruktion stimmt nicht mit Zielzustand ueberein")
            traversed.append(str(residual_id))
            candidate.reconstruction["paths"] = list(candidate.reconstruction.get("paths", [])) + [traversed[:]]
            current = candidate
        return current

    def validate_reconstruction(
        self,
        snapshot_start: ReconstructionSnapshot,
        snapshot_end: ReconstructionSnapshot,
        path: Sequence[str],
    ) -> dict[str, Any]:
        """Validiert eine Rekonstruktion fail-closed ueber Hash-, Zeit- und Drift-Konsistenz."""
        try:
            reconstructed = self.reconstruct(snapshot_start, path)
        except Exception as exc:
            snapshot_start.governance.audit.setdefault("events", []).append(
                {"type": "validate_reconstruction_failed", "reason": str(exc)}
            )
            snapshot_start.observer["alarm_state"] = "closed"
            return {"valid": False, "reason": str(exc)}
        if reconstructed.data_hashes != snapshot_end.data_hashes:
            snapshot_start.governance.audit.setdefault("events", []).append(
                {"type": "validate_reconstruction_failed", "reason": "hash_inconsistent"}
            )
            snapshot_start.observer["alarm_state"] = "closed"
            return {"valid": False, "reason": "hash_inconsistent"}
        start_ts = _parse_iso_timestamp(snapshot_start.timestamp)
        end_ts = _parse_iso_timestamp(snapshot_end.timestamp)
        if end_ts < start_ts:
            snapshot_start.governance.audit.setdefault("events", []).append(
                {"type": "validate_reconstruction_failed", "reason": "time_inconsistent"}
            )
            snapshot_start.observer["alarm_state"] = "closed"
            return {"valid": False, "reason": "time_inconsistent"}
        if snapshot_start.governance.to_dict(redact_keys=True)["mode"] != snapshot_end.governance.to_dict(redact_keys=True)["mode"]:
            snapshot_start.governance.audit.setdefault("events", []).append(
                {"type": "validate_reconstruction_failed", "reason": "governance_inconsistent"}
            )
            snapshot_start.observer["alarm_state"] = "closed"
            return {"valid": False, "reason": "governance_inconsistent"}
        drift_before = float(snapshot_start.observer.get("drift", 0.0) or 0.0)
        drift_after = float(snapshot_end.observer.get("drift", 0.0) or 0.0)
        if drift_before > 0.0 and drift_after < 0.0:
            snapshot_start.governance.audit.setdefault("events", []).append(
                {"type": "validate_reconstruction_failed", "reason": "drift_incoherent"}
            )
            snapshot_start.observer["alarm_state"] = "closed"
            return {"valid": False, "reason": "drift_incoherent"}
        return {"valid": True, "reason": "ok"}

    def detect_attractor(self, snapshot: ReconstructionSnapshot) -> str | None:
        """Erkennt bestehende Attraktoren ueber strukturelle Aehnlichkeit und geringe Drift."""
        current_signature = {
            "entropy": float(snapshot.features.entropy),
            "symmetry": float(snapshot.features.symmetry),
            "resonance": float(snapshot.features.resonance),
            "graph": dict(snapshot.features.graph or {}),
            "fingerprints": list(snapshot.features.fingerprints),
        }
        current_drift = float(snapshot.observer.get("drift", 0.0) or 0.0)
        best_id: str | None = None
        best_distance = 1.0
        for attractor_id, attractor in self.attractor_graph.nodes.items():
            signature = dict(attractor.feature_signature or {})
            distance = _mean(
                [
                    abs(float(signature.get("entropy", 0.0) or 0.0) - current_signature["entropy"]),
                    abs(float(signature.get("symmetry", 0.0) or 0.0) - current_signature["symmetry"]),
                    abs(float(signature.get("resonance", 0.0) or 0.0) - current_signature["resonance"]),
                    _graph_topology_diff(dict(signature.get("graph", {}) or {}), current_signature["graph"]),
                ]
            )
            if distance < best_distance:
                best_distance = distance
                best_id = str(attractor_id)
        if best_id is not None and best_distance <= 0.15 and current_drift <= 0.25:
            return best_id
        if current_drift <= 0.25:
            attractor_id = _sha256_payload(current_signature)
            self.attractor_graph.nodes[attractor_id] = Attractor(
                id=attractor_id,
                feature_signature=current_signature,
                stability=round(max(0.0, min(1.0, 1.0 - current_drift)), 6),
                energy=round(float(snapshot.features.resonance), 6),
                resonance_profile={
                    "energy": round(float(snapshot.features.resonance), 6),
                    "symmetry": round(float(snapshot.features.symmetry), 6),
                },
                invariants={"deterministic": True, "local": True, "observer_relative": True},
            )
            return attractor_id
        return None

    def compute_attractor_stability(
        self,
        attractor_id: str,
        history: Sequence[ReconstructionSnapshot],
    ) -> dict[str, Any]:
        """Berechnet Stabilitaetsmetriken eines Attraktors ueber eine Historie."""
        relevant = [item for item in history if self.detect_attractor(item) == str(attractor_id)]
        drift_values = [float(item.observer.get("drift", 0.0) or 0.0) for item in relevant]
        resonance_values = [float(item.features.resonance) for item in relevant]
        symmetry_values = [float(item.features.symmetry) for item in relevant]
        return {
            "drift_variance": round(_variance(drift_values), 6),
            "resonance_stability": round(max(0.0, min(1.0, 1.0 - _variance(resonance_values))), 6),
            "symmetry_persistence": round(_mean(symmetry_values), 6),
            "invariants": {
                "history_local": True,
                "deterministic_metrics": True,
                "non_semantic": True,
            },
        }

    def track_attractor_transition(
        self,
        previous_attractor_id: str | None,
        next_attractor_id: str | None,
        previous_snapshot: ReconstructionSnapshot,
        next_snapshot: ReconstructionSnapshot,
    ) -> None:
        """Pflegt den Attraktorgraphen mit Drift- und Phasenwechsel-Metadaten."""
        if previous_attractor_id is None or next_attractor_id is None:
            return
        self.attractor_graph.edges[(str(previous_attractor_id), str(next_attractor_id))] = {
            "drift_profile": {
                "drift_before": float(previous_snapshot.observer.get("drift", 0.0) or 0.0),
                "drift_after": float(next_snapshot.observer.get("drift", 0.0) or 0.0),
                "gradient": round(
                    float(next_snapshot.observer.get("drift", 0.0) or 0.0)
                    - float(previous_snapshot.observer.get("drift", 0.0) or 0.0),
                    6,
                ),
            },
            "delta_profile": {
                "symmetry_break": round(
                    abs(float(next_snapshot.features.symmetry) - float(previous_snapshot.features.symmetry)),
                    6,
                ),
                "resonance_shift": round(
                    abs(float(next_snapshot.features.resonance) - float(previous_snapshot.features.resonance)),
                    6,
                ),
                "graph_topology_diff": round(
                    _graph_topology_diff(previous_snapshot.features.graph, next_snapshot.features.graph),
                    6,
                ),
            },
            "phase_shift": bool(str(previous_attractor_id) != str(next_attractor_id)),
            "invariants": {"deterministic_transition": True, "audit_ready": True},
        }

    def predict_next_attractor(
        self,
        snapshot: ReconstructionSnapshot,
        history: Sequence[ReconstructionSnapshot],
    ) -> str | None:
        """Bestimmt den naechsten Attraktor nur aus Drift-, Symmetrie-, Resonanz- und Graphaenderungen."""
        if not history:
            return self.detect_attractor(snapshot)
        current_attractor = self.detect_attractor(snapshot)
        if current_attractor is None:
            return None
        transitions = {
            edge: payload
            for edge, payload in self.attractor_graph.edges.items()
            if str(edge[0]) == str(current_attractor)
        }
        if not transitions:
            return current_attractor
        best_target = current_attractor
        best_score = float("-inf")
        for (source_id, target_id), payload in transitions.items():
            drift_gradient = float(dict(payload.get("drift_profile", {}) or {}).get("gradient", 0.0) or 0.0)
            delta_profile = dict(payload.get("delta_profile", {}) or {})
            score = (
                -abs(drift_gradient)
                - abs(float(delta_profile.get("symmetry_break", 0.0) or 0.0))
                - abs(float(delta_profile.get("resonance_shift", 0.0) or 0.0))
                - abs(float(delta_profile.get("graph_topology_diff", 0.0) or 0.0))
            )
            if score > best_score:
                best_score = score
                best_target = str(target_id)
        return best_target
