"""Verlustfreie Rekonstruktion aus Delta-Logs."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass
class ReconstructionResult:
    """Ergebnis einer Delta-Log-Rekonstruktion."""

    delta_log: list[dict[str, Any]]
    reconstructed_bytes: bytes
    reconstructed_hash: str
    merkle_root: str
    reconstruction_verified: bool


class LosslessReconstructionEngine:
    """Erzeugt und verifiziert verlustfreie Delta-Logs fuer Originalbytes."""

    def __init__(self, chunk_size: int = 512) -> None:
        self.chunk_size = max(64, int(chunk_size))

    def build_delta_log(self, raw_bytes: bytes) -> list[dict[str, Any]]:
        """Kodiert Originalbytes als replayfaehigen Delta-Log."""
        delta_log: list[dict[str, Any]] = [
            {"op": "init", "size": int(len(raw_bytes))},
        ]
        for offset in range(0, len(raw_bytes), self.chunk_size):
            chunk = raw_bytes[offset : offset + self.chunk_size]
            delta_log.append(
                {
                    "op": "add",
                    "offset": int(offset),
                    "length": int(len(chunk)),
                    "data": chunk.hex(),
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
            if op not in {"add", "move", "remove"}:
                continue
            offset = max(0, int(entry.get("offset", 0)))
            length = max(0, int(entry.get("length", 0)))
            if op == "remove":
                for index in range(offset, min(len(buffer), offset + length)):
                    buffer[index] = 0
                continue
            data_hex = str(entry.get("data", ""))
            chunk = bytes.fromhex(data_hex) if data_hex else b""
            if op == "move":
                source = max(0, int(entry.get("source_offset", 0)))
                chunk = bytes(buffer[source : source + length])
            end = min(len(buffer), offset + len(chunk))
            buffer[offset:end] = chunk[: max(0, end - offset)]
        return bytes(buffer)

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
