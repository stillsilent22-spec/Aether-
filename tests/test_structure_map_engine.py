from __future__ import annotations

from pathlib import Path

from aether_pipeline import AetherPipeline
from modules.analysis_capsule import AnalysisCapsuleEngine
from modules.structure_map_engine import StructureMapEngine


def test_structure_map_engine_projects_capsule_to_nodes_edges(tmp_path) -> None:
    sample_path = Path(tmp_path) / "map_sample.bin"
    sample_path.write_bytes((b"ANCHOR-MAP-" * 40) + bytes(range(96)))

    capsule = AnalysisCapsuleEngine().from_file(sample_path)
    snapshot = StructureMapEngine().build_from_capsule(capsule)

    assert snapshot.node_count > 0
    assert snapshot.edge_count >= 0
    assert snapshot.region_label.startswith("REGION ")
    assert len(snapshot.nodes) == snapshot.node_count
    assert len(snapshot.heatmap) == 16
    assert len(snapshot.heatmap[0]) == 16
    assert len(snapshot.scene_points) == snapshot.node_count


def test_pipeline_file_result_contains_structure_map(tmp_path) -> None:
    sample_path = Path(tmp_path) / "pipeline_map.bin"
    sample_path.write_bytes((b"LIVE-STRUCTURE-" * 24) + bytes(range(48)))

    result = AetherPipeline().process(sample_path)

    assert "structure_map" in result
    assert result["structure_map"]["node_count"] > 0
    assert "nodes" in result["structure_map"]
    assert "edges" in result["structure_map"]