"""Parser fuer altes AELAB-DNA-Format."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LegacyDNANode:
    opcode: int
    left_index: int
    right_index: int
    aux_index: int
    slot: int
    value: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "opcode": int(self.opcode),
            "left_index": int(self.left_index),
            "right_index": int(self.right_index),
            "aux_index": int(self.aux_index),
            "slot": int(self.slot),
            "value": float(self.value),
        }


@dataclass
class LegacyDNARecord:
    format_tag: str
    format_version: int
    legacy_id: str
    header_metric: int
    declared_node_count: int
    nodes: list[LegacyDNANode]
    source_path: str = ""
    bucket: str = "sub"

    @property
    def dna_text(self) -> str:
        header = f"{self.format_tag} {self.format_version} {self.legacy_id} {self.header_metric} {self.declared_node_count}"
        rows = [
            f"{node.opcode} {node.left_index} {node.right_index} {node.aux_index} {node.slot} {node.value:.12f}"
            for node in self.nodes
        ]
        return "\n".join([header] + rows)

    @property
    def dna_hash(self) -> str:
        return hashlib.sha256(self.dna_text.encode("utf-8")).hexdigest()

    @property
    def constants(self) -> list[float]:
        return [
            float(node.value)
            for node in self.nodes
            if int(node.opcode) == 0 and not math.isclose(float(node.value), 0.0, abs_tol=1e-15)
        ]

    @property
    def reference_like_constants(self) -> list[float]:
        return [
            float(value)
            for value in self.constants
            if abs(float(value) - math.pi) <= 0.05
        ]

    def opcode_histogram(self) -> dict[str, int]:
        counts = Counter(int(node.opcode) for node in self.nodes)
        return {str(key): int(value) for key, value in sorted(counts.items())}

    def branching_nodes(self) -> int:
        return int(
            sum(
                1
                for node in self.nodes
                if int(node.left_index) >= 0 or int(node.right_index) >= 0 or int(node.aux_index) >= 0
            )
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format_tag": str(self.format_tag),
            "format_version": int(self.format_version),
            "legacy_id": str(self.legacy_id),
            "header_metric": int(self.header_metric),
            "declared_node_count": int(self.declared_node_count),
            "node_count": int(len(self.nodes)),
            "bucket": str(self.bucket),
            "source_path": str(self.source_path),
            "dna_hash": str(self.dna_hash),
            "constants": [float(value) for value in self.constants],
            "constant_count": int(len(self.constants)),
            "reference_like_constants": [float(value) for value in self.reference_like_constants],
            "opcode_histogram": self.opcode_histogram(),
            "branching_nodes": self.branching_nodes(),
            "nodes": [node.to_dict() for node in self.nodes],
        }


def infer_legacy_bucket(file_path: str) -> str:
    """Leitet den Ziel-Bucket aus der alten Ordnerstruktur ab."""
    lowered = str(file_path).replace("/", "\\").lower()
    if "\\subvault\\" in lowered or "\\sub_vault\\" in lowered or "\\sub\\" in lowered:
        return "sub"
    if "\\vault\\" in lowered:
        return "main"
    return "sub"


def parse_legacy_dna_text(text: str, source_path: str = "", bucket: str = "sub") -> LegacyDNARecord:
    """Parst eine einzelne Legacy-AELAB-DNA-Datei."""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    if not lines:
        raise ValueError("Leere DNA-Datei.")

    header = lines[0].split()
    if len(header) < 5 or str(header[0]).strip().upper() != "AELAB_DNA":
        raise ValueError("Unbekanntes oder unvollstaendiges AELAB-DNA-Format.")

    try:
        format_version = int(header[1])
        legacy_id = str(header[2])
        header_metric = int(float(header[3]))
        declared_node_count = int(float(header[4]))
    except Exception as exc:
        raise ValueError(f"DNA-Header konnte nicht gelesen werden: {exc}") from exc

    nodes: list[LegacyDNANode] = []
    for index, line in enumerate(lines[1:], start=1):
        parts = line.split()
        if len(parts) != 6:
            raise ValueError(f"DNA-Zeile {index} ist ungueltig: {line}")
        try:
            nodes.append(
                LegacyDNANode(
                    opcode=int(parts[0]),
                    left_index=int(parts[1]),
                    right_index=int(parts[2]),
                    aux_index=int(parts[3]),
                    slot=int(parts[4]),
                    value=float(parts[5]),
                )
            )
        except Exception as exc:
            raise ValueError(f"DNA-Zeile {index} konnte nicht geparst werden: {exc}") from exc

    return LegacyDNARecord(
        format_tag="AELAB_DNA",
        format_version=format_version,
        legacy_id=legacy_id,
        header_metric=header_metric,
        declared_node_count=declared_node_count,
        nodes=nodes,
        source_path=str(source_path),
        bucket=str(bucket),
    )


def parse_legacy_dna_file(file_path: str, bucket: str | None = None) -> LegacyDNARecord:
    """Parst eine DNA-Datei direkt vom Datentraeger."""
    path = Path(file_path)
    resolved_bucket = str(bucket or infer_legacy_bucket(str(path)))
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_legacy_dna_text(text=text, source_path=str(path), bucket=resolved_bucket)


def iter_legacy_dna_files(root_path: str) -> list[str]:
    """Liest rekursiv alle Legacy-DNA-Dateien unterhalb eines Ordners."""
    root = Path(root_path)
    if not root.is_dir():
        return []
    return [
        str(path)
        for path in sorted(root.rglob("*.dna"))
        if path.is_file()
    ]
