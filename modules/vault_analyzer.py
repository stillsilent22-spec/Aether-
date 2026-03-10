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

from .deep_scan_engine import DeepScanEngine

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

    @property
    def pi_resonance_confirmed(self) -> bool:
        return any(abs(float(value) - PI_REFERENCE) <= PI_TOLERANCE for value in self.anchors)


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


def _safe_log_weight(frequency: int) -> float:
    return 1.0 / math.log(1.0 + float(max(1, int(frequency))))


def _record_entropy(anchor_counts: dict[str, int]) -> float:
    total = float(sum(anchor_counts.values()))
    if total <= 0.0:
        return 0.0
    entropy = 0.0
    for count in anchor_counts.values():
        probability = float(count) / total
        entropy -= probability * math.log2(max(probability, 1e-12))
    max_entropy = math.log2(1.0 + float(len(anchor_counts)))
    if max_entropy <= 1e-12:
        return 0.0
    return float(entropy / max_entropy)


def _boundary_from_signal(goedel_signal: float) -> str:
    if float(goedel_signal) < 0.2:
        return "RECONSTRUCTABLE"
    if float(goedel_signal) < 0.6:
        return "STRUCTURAL_HYPOTHESIS"
    return "GOEDEL_LIMIT"


def _band_label(center: float, band_index: int) -> str:
    for label, constant in KNOWN_BANDS:
        if abs(float(center) - float(constant)) <= BAND_TOLERANCE:
            return f"{label}_BAND"
    return f"RESONANCE_BAND_{band_index:03d}"


def _classify_anchor_types(value: float, band_label: str = "") -> list[str]:
    types: list[str] = []
    numeric = float(value)
    absolute = abs(numeric)
    integer_like = abs(numeric - round(numeric)) <= 1e-9
    if integer_like:
        types.append("integer_like")
    else:
        types.append("float_like")
    if absolute <= (math.pi + 0.001) and not integer_like:
        types.append("geometric")
    if 0.0 < absolute <= 2.0 and not integer_like:
        types.append("ratio_like")
    if absolute < 0.1:
        types.append("micro")
    if absolute >= 10.0:
        types.append("large_magnitude")
    if band_label == "PI_BAND" or abs(numeric - PI_REFERENCE) <= BAND_TOLERANCE:
        types.append("pi_band")
    return sorted(set(types))


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
        bands.append(
            {
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
        )
        for key in member_keys:
            band_lookup[str(key)] = str(label)
    return bands, band_lookup


def _build_vault_gaps(
    records: list[DNARecord],
    frequency_counter: Counter[str],
    band_lookup: dict[str, str],
    structural_clusters: list[dict[str, Any]],
    pi_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    total_files = max(1, len(records))
    total_frequency = max(1, int(sum(frequency_counter.values())))
    type_frequency: Counter[str] = Counter()
    type_files: defaultdict[str, set[str]] = defaultdict(set)

    for record in records:
        for key, count in record.anchor_counts.items():
            anchor_types = _classify_anchor_types(float(key), str(band_lookup.get(key, "")))
            for anchor_type in anchor_types:
                type_frequency[anchor_type] += int(count)
                type_files[anchor_type].add(str(record.file_name))

    type_distribution = [
        {
            "anchor_type": str(anchor_type),
            "frequency": int(type_frequency[anchor_type]),
            "file_count": int(len(type_files.get(anchor_type, set()))),
            "file_rate": round(float(len(type_files.get(anchor_type, set()))) / float(total_files), 12),
            "gap_score": round(_safe_log_weight(int(type_frequency[anchor_type])), 12),
        }
        for anchor_type in sorted(type_frequency.keys())
    ]

    gaps: list[dict[str, Any]] = []
    geometric_rate = float(len(type_files.get("geometric", set()))) / float(total_files)
    geometric_gap_score = _safe_log_weight(int(type_frequency.get("geometric", 0)))
    if geometric_rate < 0.20:
        gaps.append(
            {
                "gap_id": "GEOMETRIC_UNDERREPRESENTED",
                "classification": "VAULT_GAP",
                "gap_score": round(float(geometric_gap_score), 12),
                "vault_gap": "Geometrische Anker sind im Vault schwach vertreten.",
                "suggested_next": "3D-Modelldateien, CAD, Blender",
                "reason": f"geometric_rate={geometric_rate:.3f} bei frequency={int(type_frequency.get('geometric', 0))}",
            }
        )

    integer_frequency = int(type_frequency.get("integer_like", 0))
    float_frequency = int(type_frequency.get("float_like", 0))
    float_ratio = float(float_frequency) / float(max(1, integer_frequency))
    if integer_frequency > 0 and float_ratio < 0.50:
        gaps.append(
            {
                "gap_id": "FLOAT_SPARSE",
                "classification": "VAULT_GAP",
                "gap_score": round(float(_safe_log_weight(float_frequency)), 12),
                "vault_gap": "Integer-Anker dominieren, differenzierte Float-Anker sind zu selten.",
                "suggested_next": "Audiodateien, Bilddateien mit Farbverlaeufen",
                "reason": f"integer_frequency={integer_frequency} float_frequency={float_frequency}",
            }
        )

    pi_files = sorted({str(item.get("file", "")) for item in pi_hits if str(item.get("file", "")).strip()})
    if len(pi_files) < 3:
        gaps.append(
            {
                "gap_id": "PI_BAND_THIN",
                "classification": "VAULT_GAP",
                "gap_score": round(float(_safe_log_weight(len(pi_files))), 12),
                "vault_gap": "Das PI-Resonanzband ist noch duenn belegt.",
                "suggested_next": "Mehr Binaerdateien mit zyklischen Strukturen",
                "reason": f"pi_file_count={len(pi_files)}",
            }
        )

    files_with_clusters = sorted(
        {
            str(file_name)
            for cluster in structural_clusters
            for file_name in list(cluster.get("files", []) or [])
        }
    )
    cluster_coverage = float(len(files_with_clusters)) / float(total_files)
    if not structural_clusters or cluster_coverage < 0.50:
        gaps.append(
            {
                "gap_id": "CLUSTERS_ISOLATED",
                "classification": "VAULT_GAP",
                "gap_score": round(float(_safe_log_weight(len(structural_clusters))), 12),
                "vault_gap": "Ko-Okkurrenz-Cluster bleiben isoliert oder fehlen noch.",
                "suggested_next": "Dateitypen die bekannte Cluster-Anker teilen koennten",
                "reason": f"structural_clusters={len(structural_clusters)} cluster_coverage={cluster_coverage:.3f}",
            }
        )

    rare_anchor_candidates = [
        {
            "anchor_value": str(key),
            "frequency": int(frequency_counter[key]),
            "gap_score": round(float(_safe_log_weight(int(frequency_counter[key]))), 12),
            "band_label": str(band_lookup.get(key, "")),
        }
        for key in sorted(frequency_counter.keys(), key=lambda item: (int(frequency_counter[item]), float(item)))[:16]
    ]
    gaps.sort(key=lambda item: (-float(item.get("gap_score", 0.0) or 0.0), str(item.get("gap_id", ""))))
    return {
        "anchor_type_distribution": type_distribution,
        "gaps": gaps,
        "rare_anchor_candidates": rare_anchor_candidates,
    }


def _run_deep_scan(records: list[DNARecord]) -> dict[str, Any]:
    engine = DeepScanEngine()
    base_anchor_map = {str(record.file_name): list(record.unique_anchor_keys) for record in records}
    geometry_anchor_map: dict[str, list[str]] = {}
    geometry_entries: list[dict[str, Any]] = []

    for record in records:
        result = engine.scan_file(record.path)
        geometry_anchor_map[str(record.file_name)] = list(result.anchor_keys)
        geometry_entries.append(result.to_payload())

    geometry_entries.sort(key=lambda item: str(item.get("file", "")))
    sibling_report = engine.build_sibling_report(base_anchor_map=base_anchor_map, geometry_anchor_map=geometry_anchor_map)
    return {
        "geometry": geometry_entries,
        "siblings": list(sibling_report.get("siblings", []) or []),
        "semantic_clusters": list(sibling_report.get("semantic_clusters", []) or []),
    }


def analyze_vault(vault_dir: str, output_path: str | None = None, deep: bool = False) -> dict[str, Any]:
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
        key: _safe_log_weight(int(count))
        for key, count in frequency_counter.items()
    }
    resonance_bands, band_lookup = _build_resonance_bands(frequency_counter, records)

    anchor_frequency_table = [
        {
            "anchor_value": str(key),
            "frequency": int(frequency_counter[key]),
            "file_occurrence_count": int(file_occurrence_counter.get(key, 0)),
            "file_occurrence_rate": round(float(file_occurrence_counter.get(key, 0)) / max(1, len(records)), 12),
            "band_label": str(band_lookup.get(key, "")),
            "anchor_types": _classify_anchor_types(float(key), str(band_lookup.get(key, ""))),
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

    structural_clusters = [
        {
            "classification": "STRUCTURAL_CLUSTER",
            "anchor_pair": [str(left), str(right)],
            "band_pair": [str(band_lookup.get(left, "")), str(band_lookup.get(right, ""))],
            "file_count": int(co_occurrence_counter[(left, right)]),
            "files": sorted(co_occurrence_files[(left, right)]),
        }
        for left, right in sorted(
            (pair for pair, count in co_occurrence_counter.items() if int(count) >= 2),
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
            -float(item.get("interference_score", 0.0) or 0.0),
            str(item.get("left_file", "")),
            str(item.get("right_file", "")),
        )
    )

    invariant_columns = [str(item["anchor_value"]) for item in invariants]
    resonance_rows: list[dict[str, Any]] = []
    invariant_key_set = set(invariant_columns)
    structural_cluster_pairs = {
        tuple(sorted([str(pair[0]), str(pair[1])], key=lambda item: float(item)))
        for cluster in structural_clusters
        for pair in [tuple(cluster.get("anchor_pair", []))]
        if len(tuple(cluster.get("anchor_pair", []))) == 2
    }

    files_payload: list[dict[str, Any]] = []
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

        unique_key_set = set(record.unique_anchor_keys)
        invariant_ratio = float(len(unique_key_set & invariant_key_set)) / float(max(1, len(unique_key_set)))
        cluster_hits = sum(1 for pair in structural_cluster_pairs if set(pair).issubset(unique_key_set))
        cluster_ratio = float(cluster_hits) / float(max(1, len(structural_cluster_pairs)))
        h_lambda = _record_entropy(counts)
        observer_mutual_info = float((0.65 * invariant_ratio) + (0.35 * cluster_ratio))
        goedel_signal = float(h_lambda / (h_lambda + observer_mutual_info + 1e-10))
        boundary = _boundary_from_signal(goedel_signal)
        files_payload.append(
            {
                "file": str(record.file_name),
                "path": str(record.path),
                "dna_id": str(record.dna_id),
                "format_tag": str(record.format_tag),
                "version": int(record.version),
                "anchor_count": int(len(record.anchors)),
                "distinct_anchor_count": int(len(record.unique_anchor_keys)),
                "header_fields": list(record.header_fields),
                "pi_resonance_confirmed": bool(record.pi_resonance_confirmed),
                "h_lambda": round(float(h_lambda), 12),
                "observer_mutual_info": round(float(observer_mutual_info), 12),
                "goedel_signal": round(float(goedel_signal), 12),
                "boundary": str(boundary),
                "it_from_bit_candidate": bool(goedel_signal < 0.3 and record.pi_resonance_confirmed),
            }
        )

    files_payload.sort(key=lambda item: str(item.get("file", "")))
    pi_hits.sort(key=lambda item: (str(item.get("file", "")), float(item.get("deviation", 0.0) or 0.0)))
    degenerate_files.sort(key=lambda item: (int(item.get("distinct_non_zero_anchor_count", 0)), str(item.get("file", ""))))
    vault_gaps = _build_vault_gaps(records, frequency_counter, band_lookup, structural_clusters, pi_hits)

    result: dict[str, Any] = {
        "schema": "aether.vault_analysis.v3",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vault_dir": str(root),
        "output_path": str(target),
        "file_count": int(len(records)),
        "anchor_frequency_table": anchor_frequency_table,
        "weighted_scores": weighted_score_table,
        "structural_clusters": structural_clusters,
        "clusters": structural_clusters,
        "resonance_hits": pi_hits,
        "degenerate_files": degenerate_files,
        "invariants": invariants,
        "vault_invariants": invariants,
        "interference_pairs": interference_pairs,
        "resonance_map": {
            "columns": invariant_columns,
            "rows": resonance_rows,
        },
        "resonance_bands": resonance_bands,
        "vault_gaps": vault_gaps,
        "files": files_payload,
        "skipped_files": skipped_files,
    }

    if deep:
        result.update(_run_deep_scan(records))
    else:
        result.update({"geometry": [], "siblings": [], "semantic_clusters": []})

    target.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analysiert AELAB-DNA-Dateien im lokalen Vault.")
    parser.add_argument("--vault-dir", default="data/aelab_vault", help="Verzeichnis mit DNA-Dateien")
    parser.add_argument("--output", default="", help="Optionaler Zielpfad fuer vault_analysis.json")
    parser.add_argument("--deep", action="store_true", help="Aktiviert geometrische Tiefenanalyse und Geschwister-Cluster")
    args = parser.parse_args(argv)

    result = analyze_vault(vault_dir=args.vault_dir, output_path=args.output or None, deep=bool(args.deep))
    print(
        "vault_analyzer: "
        f"files={int(result.get('file_count', 0) or 0)} "
        f"anchors={int(len(result.get('anchor_frequency_table', []) or []))} "
        f"clusters={int(len(result.get('structural_clusters', []) or []))} "
        f"degenerate={int(len(result.get('degenerate_files', []) or []))} "
        f"deep={bool(args.deep)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
