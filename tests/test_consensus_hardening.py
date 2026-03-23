from __future__ import annotations

from modules.consensus_engine import (
    get_candidate_count,
    get_consensus_anchors,
    submit_candidate,
)


def test_consensus_promotes_on_three_unique_nodes(tmp_path) -> None:
    db_path = str(tmp_path / "consensus.db")
    ttd_hash = "ttd-promote-001"

    assert submit_candidate(ttd_hash, "runtime", "node-a", {"entropy": 0.2}, db_path=db_path) == "candidate"
    assert submit_candidate(ttd_hash, "runtime", "node-b", {"entropy": 0.3}, db_path=db_path) == "updated"
    assert submit_candidate(ttd_hash, "runtime", "node-c", {"entropy": 0.5}, db_path=db_path) == "promoted"

    anchors = get_consensus_anchors(db_path=db_path)
    assert len(anchors) == 1
    assert anchors[0]["ttd_hash"] == ttd_hash
    assert sorted(anchors[0]["source_nodes"]) == ["node-a", "node-b", "node-c"]
    assert get_candidate_count(db_path=db_path) == 0


def test_consensus_rejects_duplicate_node_as_quorum_progress(tmp_path) -> None:
    db_path = str(tmp_path / "consensus.db")
    ttd_hash = "ttd-dup-001"

    assert submit_candidate(ttd_hash, "runtime", "node-a", {"risk": 0.1}, db_path=db_path) == "candidate"
    # duplicate reports from same node must not create quorum progress
    assert submit_candidate(ttd_hash, "runtime", "node-a", {"risk": 0.9}, db_path=db_path) == "updated"

    anchors = get_consensus_anchors(db_path=db_path)
    assert anchors == []
    assert get_candidate_count(db_path=db_path) == 1
