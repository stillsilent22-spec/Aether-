"""
tests/test_genesis_protection.py -- Verify genesis invariant cannot be violated.

GENESIS_NODE_ID = "7a280b7e3ab3e042"
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

GENESIS_NODE_ID = "7a280b7e3ab3e042"


# ── solo_bootstrap never issues genesis id for a new node ─────────────────── #

def test_bootstrap_does_not_issue_genesis_id(tmp_path, monkeypatch):
    """run_bootstrap() must never generate a node_id equal to GENESIS_NODE_ID."""
    import solo_bootstrap as sb

    monkeypatch.setattr(sb, "_base", lambda: tmp_path)
    (tmp_path / "data" / "swarm").mkdir(parents=True)
    (tmp_path / "data" / "keys").mkdir(parents=True)

    result = sb.run_bootstrap(dry_run=False)
    assert result["node_id"] != GENESIS_NODE_ID


def test_bootstrap_genesis_binding_absent_by_default(tmp_path, monkeypatch):
    import solo_bootstrap as sb
    monkeypatch.setattr(sb, "_base", lambda: tmp_path)
    (tmp_path / "data" / "swarm").mkdir(parents=True)
    (tmp_path / "data" / "keys").mkdir(parents=True)
    assert not sb._local_genesis_binding_present(tmp_path)


def test_genesis_binding_detected_via_key_file(tmp_path):
    """_local_genesis_binding_present detects the genesis key file."""
    import solo_bootstrap as sb
    keys = tmp_path / "data" / "keys"
    keys.mkdir(parents=True)
    (keys / "genesis_node.key").write_bytes(b"dummy")
    assert sb._local_genesis_binding_present(tmp_path)


def test_genesis_binding_detected_via_node_json(tmp_path):
    import solo_bootstrap as sb
    swarm = tmp_path / "data" / "swarm"
    swarm.mkdir(parents=True)
    (tmp_path / "data" / "keys").mkdir(parents=True)
    node_data = {"node_id": GENESIS_NODE_ID, "role": "genesis"}
    (swarm / "node.json").write_text(json.dumps(node_data), encoding="utf-8")
    assert sb._local_genesis_binding_present(tmp_path)


def test_genesis_binding_not_detected_for_peer(tmp_path):
    import solo_bootstrap as sb
    swarm = tmp_path / "data" / "swarm"
    swarm.mkdir(parents=True)
    (tmp_path / "data" / "keys").mkdir(parents=True)
    node_data = {"node_id": "abcdef1234567890", "role": "peer"}
    (swarm / "node.json").write_text(json.dumps(node_data), encoding="utf-8")
    assert not sb._local_genesis_binding_present(tmp_path)


# ── bootstrap.py guard ────────────────────────────────────────────────────── #

def test_bootstrap_guard_genesis_halts():
    import bootstrap as bs
    with pytest.raises(SystemExit) as exc_info:
        bs._guard_genesis({"node_id": GENESIS_NODE_ID})
    assert exc_info.value.code != 0


def test_bootstrap_guard_passes_for_normal_node():
    import bootstrap as bs
    bs._guard_genesis({"node_id": "0011223344556677"})  # must not raise


# ── vault_identity node_id never equals genesis ───────────────────────────── #

def test_vault_identity_node_id_not_genesis(tmp_path):
    """
    A freshly created AEK file must not produce node_id == GENESIS_NODE_ID.
    (Statistical impossibility; this test validates the parsing pipeline.)
    """
    import hashlib
    import struct
    import os
    from modules.vault_identity import VaultIdentity

    seed = os.urandom(32)
    # Build a minimal valid AEK
    aek = bytearray(96)
    aek[0:4] = b"AEKP"
    struct.pack_into("<I", aek, 4, 1)
    aek[8:40] = seed
    aek[40:72] = os.urandom(32)
    struct.pack_into("<Q", aek, 72, 1700000000)
    cksum = hashlib.sha256(bytes(aek[:80])).digest()[:16]
    aek[80:96] = cksum

    identity = VaultIdentity.from_bytes(bytes(aek))
    assert identity.is_valid()
    assert identity.node_id != GENESIS_NODE_ID


# ── idempotence: second run must not change node_id ─────────────────────────── #

def test_bootstrap_idempotent(tmp_path, monkeypatch):
    import solo_bootstrap as sb
    monkeypatch.setattr(sb, "_base", lambda: tmp_path)
    (tmp_path / "data" / "swarm").mkdir(parents=True)
    (tmp_path / "data" / "keys").mkdir(parents=True)

    first  = sb.run_bootstrap(dry_run=False)
    second = sb.run_bootstrap(dry_run=False)
    assert first["node_id"] == second["node_id"]
    assert first["node_id"] != GENESIS_NODE_ID
