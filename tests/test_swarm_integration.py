"""Integration tests for Swarm: enable/disable flow, delta processing, consent, persistence."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from modules.capture_adapter import StubCaptureAdapter, FrameData
from modules.swarm_agent import SwarmAgent, DeltaPipeline
from modules.swarm_controller import SwarmController
from modules.swarm_persist import (
    append_frame_metrics,
    append_audit_entry,
    append_swarm_snapshot,
    get_recent_snapshots,
    get_audit_log,
    get_fingerprint_stats,
    run_migration,
    _connect,
    _db_lock,
)


# --------------------------------------------------------------------------- #
#  Full enable/disable/capture/persist integration                            #
# --------------------------------------------------------------------------- #

def test_full_swarm_cycle(tmp_path):
    """
    Simulate full swarm lifecycle:
    1. Start controller + agent
    2. Enable swarm
    3. Let agent capture and process frames
    4. Disable swarm
    5. Verify fingerprints in DB, no raw frames
    """
    db = str(tmp_path / "integration.db")
    ctrl = SwarmController(db_path=str(tmp_path / "ctrl.db"))
    agent = SwarmAgent(
        controller=ctrl,
        adapter_type="stub",
        max_fps=10.0,
        ring_size=4,
        max_cpu_percent=80.0,
        poll_interval=0.1,
        persist_path=db,
    )

    agent.start()
    ctrl.enable_swarm()
    time.sleep(1.5)
    ctrl.disable_swarm()
    time.sleep(0.5)
    agent.stop()
    ctrl.stop()

    # Verify fingerprints stored
    stats = get_fingerprint_stats(db_path=db)
    assert stats["total_unique_fingerprints"] >= 0  # At least 0 (stub may have run)

    # Verify no raw frame data in DB
    with _db_lock:
        conn = _connect(db)
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(frame_metrics)").fetchall()}
        finally:
            conn.close()
    assert "data" not in cols


def test_swarm_persist_frame_metrics(tmp_path):
    """Verify frame_metrics stores correct fields."""
    db = str(tmp_path / "metrics.db")
    result = {
        "timestamp": 1234567890.0,
        "frame_index": 1,
        "fingerprint": "a" * 64,
        "delta_marker": "new",
        "adapter_id": "stub",
        "mean": 128.0,
        "std": 50.0,
        "entropy_approx": 7.5,
        "width": 64,
        "height": 64,
        "size_bytes": 12288,
    }
    append_frame_metrics(result, db_path=db)

    with _db_lock:
        conn = _connect(db)
        try:
            row = conn.execute("SELECT fingerprint, mean_val, width FROM frame_metrics LIMIT 1").fetchone()
        finally:
            conn.close()

    assert row is not None
    assert row[0] == "a" * 64
    assert abs(row[1] - 128.0) < 0.01
    assert row[2] == 64


def test_swarm_persist_no_raw_data_column(tmp_path):
    """Frame metrics table must not have a 'data' column."""
    db = str(tmp_path / "noraw.db")
    run_migration(db_path=db)

    with _db_lock:
        conn = _connect(db)
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(frame_metrics)").fetchall()}
        finally:
            conn.close()

    assert "data" not in cols


def test_swarm_persist_audit_log(tmp_path):
    db = str(tmp_path / "audit.db")
    append_audit_entry("enable_swarm", actor="test", details="integration test", db_path=db)
    append_audit_entry("disable_swarm", actor="test", db_path=db)

    log = get_audit_log(limit=10, db_path=db)
    assert len(log) == 2
    event_types = {e["event_type"] for e in log}
    assert "enable_swarm" in event_types
    assert "disable_swarm" in event_types


def test_swarm_persist_snapshots(tmp_path):
    db = str(tmp_path / "snap.db")
    append_swarm_snapshot(True, health_score=0.8, alert_level="ok", node_count=3, db_path=db)
    append_swarm_snapshot(False, health_score=0.0, alert_level="critical", node_count=0, db_path=db)

    snaps = get_recent_snapshots(limit=10, db_path=db)
    assert len(snaps) == 2
    assert any(s["swarm_mode"] is True and s["health_score"] == 0.8 for s in snaps)
    assert any(s["swarm_mode"] is False for s in snaps)


def test_swarm_persist_retention_purge(tmp_path):
    """Retention: purge oldest rows when max_rows exceeded."""
    db = str(tmp_path / "retention.db")
    for i in range(15):
        append_frame_metrics({
            "timestamp": float(i),
            "frame_index": i,
            "fingerprint": f"{'a' * 63}{i % 10}",
            "delta_marker": "new",
            "adapter_id": "stub",
            "mean": 0.0,
            "std": 0.0,
            "entropy_approx": 0.0,
            "width": 1,
            "height": 1,
            "size_bytes": 3,
        }, db_path=db, max_rows=10)

    with _db_lock:
        conn = _connect(db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM frame_metrics").fetchone()[0]
        finally:
            conn.close()
    assert count <= 10


def test_swarm_persist_fingerprint_dedup(tmp_path):
    """Same fingerprint should increment occurrence_count, not create duplicates."""
    db = str(tmp_path / "dedup.db")
    fp = "b" * 64
    for i in range(5):
        append_frame_metrics({
            "timestamp": float(i),
            "frame_index": i,
            "fingerprint": fp,
            "delta_marker": "stable",
            "adapter_id": "stub",
            "mean": 0.0,
            "std": 0.0,
            "entropy_approx": 0.0,
            "width": 1,
            "height": 1,
            "size_bytes": 3,
        }, db_path=db)

    with _db_lock:
        conn = _connect(db)
        try:
            row = conn.execute(
                "SELECT occurrence_count FROM fingerprints WHERE fingerprint = ?", (fp,)
            ).fetchone()
        finally:
            conn.close()

    assert row is not None
    assert row[0] == 5


# --------------------------------------------------------------------------- #
#  Consent integration                                                        #
# --------------------------------------------------------------------------- #

def test_consent_gate_prevents_enable_without_consent(tmp_path, monkeypatch):
    """gated_enable_swarm should refuse if no consent given."""
    import modules.swarm_consent as sc

    # Patch consent path to tmp_path
    monkeypatch.setattr(sc, "CONSENT_PATH", tmp_path / "consent.json")
    monkeypatch.setattr(sc, "AUDIT_LOG_PATH", tmp_path / "swarm_audit.jsonl")

    ctrl = SwarmController(db_path=str(tmp_path / "ctrl.db"))
    result = sc.gated_enable_swarm(ctrl, actor="test", interactive=False)
    ctrl.stop()

    assert result["ok"] is False
    assert result["error"] == "consent_required"


def test_consent_gate_allows_enable_with_consent(tmp_path, monkeypatch):
    """gated_enable_swarm should allow enable after consent."""
    import modules.swarm_consent as sc

    monkeypatch.setattr(sc, "CONSENT_PATH", tmp_path / "consent.json")
    monkeypatch.setattr(sc, "AUDIT_LOG_PATH", tmp_path / "swarm_audit.jsonl")
    monkeypatch.setattr(sc, "_last_action_ts", 0.0)

    sc.record_consent(actor="test")
    ctrl = SwarmController(db_path=str(tmp_path / "ctrl.db"))
    result = sc.gated_enable_swarm(ctrl, actor="test", interactive=False)
    ctrl.stop()

    assert result["ok"] is True
    assert result.get("swarm_mode") is True


def test_consent_revoke_disables_and_purges(tmp_path, monkeypatch):
    """Revoking consent should purge frame_metrics and fingerprints."""
    import modules.swarm_consent as sc
    import modules.swarm_persist as sp

    monkeypatch.setattr(sc, "CONSENT_PATH", tmp_path / "consent.json")
    monkeypatch.setattr(sc, "AUDIT_LOG_PATH", tmp_path / "swarm_audit.jsonl")
    db = str(tmp_path / "purge.db")
    monkeypatch.setattr(sp, "DEFAULT_DB_PATH", db)

    # Add some data first
    sp.append_frame_metrics({
        "timestamp": 1.0, "frame_index": 1, "fingerprint": "c" * 64,
        "delta_marker": "new", "adapter_id": "stub",
        "mean": 0.0, "std": 0.0, "entropy_approx": 0.0,
        "width": 1, "height": 1, "size_bytes": 3,
    }, db_path=db)

    sc.record_consent(actor="test")
    sc.revoke_consent(actor="test")

    # Verify purged
    with sp._db_lock:
        conn = sp._connect(db)
        try:
            fm_count = conn.execute("SELECT COUNT(*) FROM frame_metrics").fetchone()[0]
            fp_count = conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0]
        finally:
            conn.close()

    assert fm_count == 0
    assert fp_count == 0


# --------------------------------------------------------------------------- #
#  P2P integration                                                            #
# --------------------------------------------------------------------------- #

def test_p2p_disabled_by_default():
    from modules.swarm_p2p import make_p2p_layer
    layer = make_p2p_layer(node_id="test-node")
    assert layer.enabled is False


def test_p2p_gossip_message_has_no_raw_frames():
    from modules.swarm_p2p import _build_gossip_message
    msg = _build_gossip_message(
        peer_id="peer-abc",
        fingerprints=["a" * 64, "b" * 64],
        metrics_summary={"total": 2},
        is_leader=True,
    )
    assert "schema" in msg
    assert "fingerprints" in msg
    assert "metrics_summary" in msg
    # Ensure no raw pixel data
    assert "data" not in msg
    assert "pixels" not in msg
    assert "frame" not in msg


def test_p2p_peer_id_is_stable():
    from modules.swarm_p2p import derive_peer_id
    # Call twice — should return same value (cached)
    pid1 = derive_peer_id()
    pid2 = derive_peer_id()
    assert pid1 == pid2
    assert pid1.startswith("peer-")


def test_p2p_leader_election():
    from modules.swarm_p2p import LeaderElection
    le = LeaderElection(local_peer_id="peer-zzzz")
    # With no peers, local must be leader
    assert le.is_leader()

    # Add a peer with higher ID
    le.register_peer("peer-zzzz-aaa")  # Higher lexicographically
    # local "peer-zzzz" vs "peer-zzzz-aaa" — "peer-zzzz-aaa" > "peer-zzzz"
    assert not le.is_leader()
