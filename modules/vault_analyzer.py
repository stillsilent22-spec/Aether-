"""Deterministische Analyse fuer lokale AELAB-DNA-Vaults."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any

PI_REFERENCE = 3.141592653590
PI_TOLERANCE = 0.0001
BAND_TOLERANCE = 0.001
INVARIANT_THRESHOLD = 0.60

KNOWN_BANDS: tuple[tuple[str, float], ...] = (
    ("PI", PI_REFERENCE),
    ("E", math.e),
    ("PHI", (1.0 + math.sqrt(5.0)) / 2.0),
    ("LOG2", math.log(2.0)),
)

FLOAT_PATTERN = re.compile(r"[-+]?(?:\d+\.\d+|\d+)(?:[eE][-+]?\d+)?")


@dataclass
class DNARecord:
    path: str
    file_name: str
    format_tag: str
    version: int
    dna_id: str
    header_fields: list[str]
    anchors: list[float]

    @property
    def unique_anchor_keys(self) -> list[str]:
        return sorted({_anchor_key(value) for value in self.anchors}, key=lambda item: float(item))

    @property
    def anchor_counts(self) -> dict[str, int]:
        counts = Counter(_anchor_key(value) for value in self.anchors)
        return {str(key): int(count) for key, count in sorted(counts.items(), key=lambda item: float(item[0]))}


def _anchor_key(value: float) -> str:
    return f"{float(value):.12f}"


def _safe_float(token: str) -> float | None:
    try:
        return float(token)
    except (TypeError, ValueError):
        return None


def _line_anchor_values(format_tag: str, line: str) -> list[float]:
    parts = [part for part in str(line).split() if part]
    if not parts:
        return []
    if format_tag in {"AETHER_AE_DNA", "AETHER_SHANWAY_DNA"} and len(parts) >= 2:
        value = _safe_float(parts[1])
        return [float(value)] if value is not None else []
    if format_tag == "AELAB_DNA":
        value = _safe_float(parts[-1])
        return [float(value)] if value is not None else []
    matches = [float(match.group(0)) for match in FLOAT_PATTERN.finditer(str(line))]
    if not matches:
        return []
    if len(parts) >= 2 and _safe_float(parts[1]) is not None:
        return [float(parts[1])]
    return [float(matches[-1])]


def parse_dna_file(file_path: Path) -> DNARecord:
    lines = [line.strip() for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    if not lines:
        raise ValueError("Leere DNA-Datei")
    header = lines[0].split()
    if len(header) < 3:
        raise ValueError("Unvollstaendiger DNA-Header")
    format_tag = str(header[0]).strip().upper()
    version = int(float(header[1]))
    dna_id = str(header[2])
    anchors: list[float] = []
    for line in lines[1:]:
        for value in _line_anchor_values(format_tag, line):
            if abs(float(value)) > 1e-12:
                anchors.append(float(value))
    return DNARecord(
        path=str(file_path),
        file_name=file_path.name,
        format_tag=format_tag,
        version=version,
        dna_id=dna_id,
        header_fields=[str(field) for field in header[3:]],
        anchors=anchors,
    )


def _band_label(center: float, band_index: int) -> str:
    for label, constant in KNOWN_BANDS:
        if abs(float(center) - float(constant)) <= BAND_TOLERANCE:
            return f"{label}_BAND"
    return f"RESONANCE_BAND_{band_index:03d}"


def _build_resonance_bands(
    frequency_counter: Counter[str],
    records: list[DNARecord],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    values = sorted(
        [(float(key), str(key), int(count)) for key, count in frequency_counter.items()],
        key=lambda item: item[0],
    )
    if not values:
        return [], {}

    grouped: list[list[tuple[float, str, int]]] = []
    current_group: list[tuple[float, str, int]] = [values[0]]
    weighted_sum = float(values[0][0] * values[0][2])
    weight_total = float(values[0][2])

    for value, key, count in values[1:]:
        current_center = float(weighted_sum / max(1.0, weight_total))
        if abs(float(value) - current_center) <= BAND_TOLERANCE:
            current_group.append((value, key, count))
            weighted_sum += float(value) * float(count)
            weight_total += float(count)
            continue
        grouped.append(current_group)
        current_group = [(value, key, count)]
        weighted_sum = float(value) * float(count)
        weight_total = float(count)
    grouped.append(current_group)

    band_lookup: dict[str, str] = {}
    bands: list[dict[str, Any]] = []
    for index, group in enumerate(grouped, start=1):
        total_frequency = int(sum(item[2] for item in group))
        center = float(sum(item[0] * item[2] for item in group) / max(1, total_frequency))
        label = _band_label(center, index)
        member_keys = [str(item[1]) for item in group]
        member_files = sorted(
            {
                record.file_name
                for record in records
                if any(key in record.anchor_counts for key in member_keys)
            }
        )
        band_entry = {
            "band_label": str(label),
            "classification": "PI_BAND" if str(label) == "PI_BAND" else "RESONANCE_BAND",
            "center": round(float(center), 12),
            "tolerance": float(BAND_TOLERANCE),
            "members": member_keys,
            "member_count": int(len(member_keys)),
            "frequency": int(total_frequency),
            "file_count": int(len(member_files)),
            "files": member_files,
            "range": {
                "min": round(float(group[0][0]), 12),
                "max": round(float(group[-1][0]), 12),
            },
        }
        bands.append(band_entry)
        for key in member_keys:
            band_lookup[str(key)] = str(label)
    return bands, band_lookup


def analyze_vault(vault_dir: str, output_path: str | None = None) -> dict[str, Any]:
    root = Path(vault_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Vault-Verzeichnis nicht gefunden: {root}")
    target = Path(output_path) if output_path is not None else root / "vault_analysis.json"

    records: list[DNARecord] = []
    skipped_files: list[dict[str, str]] = []
    for file_path in sorted(root.rglob("*.dna")):
        if not file_path.is_file():
            continue
        try:
            records.append(parse_dna_file(file_path))
        except Exception as exc:
            skipped_files.append({"path": str(file_path), "reason": str(exc)})

    frequency_counter: Counter[str] = Counter()
    file_occurrence_counter: Counter[str] = Counter()
    pi_hits: list[dict[str, Any]] = []
    degenerate_files: list[dict[str, Any]] = []
    co_occurrence_counter: Counter[tuple[str, str]] = Counter()
    co_occurrence_files: defaultdict[tuple[str, str], set[str]] = defaultdict(set)

    for record in records:
        anchor_counts = record.anchor_counts
        for key, count in anchor_counts.items():
            frequency_counter[str(key)] += int(count)
        for key in record.unique_anchor_keys:
            file_occurrence_counter[str(key)] += 1
        for value in record.anchors:
            deviation = abs(float(value) - PI_REFERENCE)
            if deviation <= PI_TOLERANCE:
                pi_hits.append(
                    {
                        "classification": "PI_RESONANCE",
                        "file": str(record.file_name),
                        "dna_id": str(record.dna_id),
                        "anchor_value": _anchor_key(value),
                        "deviation": round(float(deviation), 12),
                    }
                )
        if len(record.unique_anchor_keys) < 3:
            degenerate_files.append(
                {
                    "classification": "DEGENERATE_DNA",
                    "file": str(record.file_name),
                    "dna_id": str(record.dna_id),
                    "distinct_non_zero_anchor_count": int(len(record.unique_anchor_keys)),
                    "anchors": list(record.unique_anchor_keys),
                }
            )
        for left, right in combinations(record.unique_anchor_keys, 2):
            pair = tuple(sorted((str(left), str(right)), key=lambda item: float(item)))
            co_occurrence_counter[pair] += 1
            co_occurrence_files[pair].add(str(record.file_name))

    weighted_scores = {
        key: (1.0 / math.log(1.0 + float(count))) if int(count) > 0 else 0.0
        for key, count in frequency_counter.items()
    }
    resonance_bands, band_lookup = _build_resonance_bands(frequency_counter, records)

    anchor_frequency_table = [
        {
            "anchor_value": str(key),
            "frequency": int(frequency_counter[key]),
            "file_occurrence_count": int(file_occurrence_counter.get(key, 0)),
            "file_occurrence_rate": round(
                float(file_occurrence_counter.get(key, 0)) / max(1, len(records)),
                12,
            ),
            "band_label": str(band_lookup.get(key, "")),
        }
        for key in sorted(frequency_counter.keys(), key=lambda item: float(item))
    ]
    weighted_score_table = [
        {
            "anchor_value": str(key),
            "weight": round(float(weighted_scores[key]), 12),
            "frequency": int(frequency_counter[key]),
            "band_label": str(band_lookup.get(key, "")),
        }
        for key in sorted(weighted_scores.keys(), key=lambda item: float(item))
    ]
    clusters = [
        {
            "classification": "STRUCTURAL_CLUSTER",
            "anchor_pair": [str(left), str(right)],
            "band_pair": [str(band_lookup.get(left, "")), str(band_lookup.get(right, ""))],
            "file_count": int(co_occurrence_counter[(left, right)]),
            "files": sorted(co_occurrence_files[(left, right)]),
        }
        for left, right in sorted(
            (
                pair
                for pair, count in co_occurrence_counter.items()
                if int(count) >= 2
            ),
            key=lambda pair: (-int(co_occurrence_counter[pair]), float(pair[0]), float(pair[1])),
        )
    ]

    invariants = [
        {
            "anchor_value": str(key),
            "occurrence_count": int(file_occurrence_counter[key]),
            "occurrence_rate": round(float(file_occurrence_counter[key]) / max(1, len(records)), 12),
            "band_label": str(band_lookup.get(key, "")),
        }
        for key in sorted(file_occurrence_counter.keys(), key=lambda item: (-file_occurrence_counter[item], float(item)))
        if float(file_occurrence_counter[key]) / max(1, len(records)) >= INVARIANT_THRESHOLD
    ]

    interference_pairs: list[dict[str, Any]] = []
    for left_record, right_record in combinations(records, 2):
        left_set = set(left_record.unique_anchor_keys)
        right_set = set(right_record.unique_anchor_keys)
        shared = sorted(left_set & right_set, key=lambda item: float(item))
        total_unique = sorted(left_set | right_set, key=lambda item: float(item))
        shared_count = int(len(shared))
        score = (
            (float(shared_count) / max(1.0, float(len(total_unique))))
            * math.log(1.0 + float(shared_count))
        )
        if score > 0.7:
            classification = "CONSTRUCTIVE"
        elif score >= 0.3:
            classification = "NEUTRAL"
        else:
            classification = "DESTRUCTIVE"
        interference_pairs.append(
            {
                "left_file": str(left_record.file_name),
                "right_file": str(right_record.file_name),
                "shared_anchors": shared,
                "shared_count": int(shared_count),
                "total_unique_anchors": int(len(total_unique)),
                "interference_score": round(float(score), 12),
                "classification": str(classification),
            }
        )
    interference_pairs.sort(
        key=lambda item: (
            -float(item["interference_score"]),
            str(item["left_file"]),
            str(item["right_file"]),
        )
    )

    invariant_columns = [str(item["anchor_value"]) for item in invariants]
    resonance_rows: list[dict[str, Any]] = []
    for record in records:
        counts = record.anchor_counts
        weights = [round(float(counts.get(column, 0)) * float(weighted_scores.get(column, 0.0)), 12) for column in invariant_columns]
        resonance_rows.append(
            {
                "file": str(record.file_name),
                "dna_id": str(record.dna_id),
                "weights": weights,
                "cells": {
                    str(column): round(float(counts.get(column, 0)) * float(weighted_scores.get(column, 0.0)), 12)
                    for column in invariant_columns
                },
            }
        )

    result = {
        "schema": "aether.vault_analysis.v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vault_dir": str(root),
        "output_path": str(target),
        "file_count": int(len(records)),
        "anchor_frequency_table": anchor_frequency_table,
        "weighted_scores": weighted_score_table,
        "clusters": clusters,
        "resonance_hits": pi_hits,
        "degenerate_files": degenerate_files,
        "invariants": invariants,
        "interference_pairs": interference_pairs,
        "resonance_map": {
            "columns": invariant_columns,
            "rows": resonance_rows,
        },
        "resonance_bands": resonance_bands,
        "files": [
            {
                "file": str(record.file_name),
                "dna_id": str(record.dna_id),
                "format_tag": str(record.format_tag),
                "version": int(record.version),
                "anchor_count": int(len(record.anchors)),
                "distinct_anchor_count": int(len(record.unique_anchor_keys)),
                "header_fields": list(record.header_fields),
            }
            for record in records
        ],
        "skipped_files": skipped_files,
    }
    target.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analysiert AELAB-DNA-Dateien im lokalen Vault.")
    parser.add_argument("--vault-dir", default="data/aelab_vault", help="Verzeichnis mit DNA-Dateien")
    parser.add_argument("--output", default="", help="Optionaler Zielpfad fuer vault_analysis.json")
    args = parser.parse_args(argv)

    result = analyze_vault(vault_dir=args.vault_dir, output_path=args.output or None)
    print(
        "vault_analyzer: "
        f"files={int(result.get('file_count', 0) or 0)} "
        f"anchors={int(len(result.get('anchor_frequency_table', []) or []))} "
        f"clusters={int(len(result.get('clusters', []) or []))} "
        f"degenerate={int(len(result.get('degenerate_files', []) or []))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
