from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import solo_bootstrap as sb
from scripts.deduplicate_nodes import deduplicate_nodes


def _write_keypair(keys_dir: Path) -> str:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "node_private.key").write_bytes(private_pem)
    (keys_dir / "node_public.key").write_text(public_pem, encoding="utf-8")
    return public_pem


def _prepare_temp_root(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "aether"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sb, "__file__", str(root / "solo_bootstrap.py"))
    monkeypatch.setattr(sb, "is_yggdrasil_available", lambda: True)
    return root


def test_bootstrap_twice_same_node_id(tmp_path: Path, monkeypatch) -> None:
    """Zweimaliges bootstrap() mit gleichem Keypair -> gleiche node_id."""
    root = _prepare_temp_root(tmp_path, monkeypatch)
    public_key_pem = _write_keypair(root / "data" / "keys")

    node_dir = root / "data" / "swarm" / "nodes"
    node_dir.mkdir(parents=True, exist_ok=True)
    legacy_payload = {
        "schema": "aether.swarm.node.v2",
        "node_id": "6c9e2fcad95e2bd0",
        "public_key_pem": public_key_pem,
        "registered_at": "2026-03-21T20:24:51.417669+00:00",
        "role": "genesis",
        "relay": False,
        "yggdrasil_addr": None,
        "aether_version": "master-v13",
    }
    (root / "data" / "swarm").mkdir(parents=True, exist_ok=True)
    (root / "data" / "swarm" / "node.json").write_text(json.dumps(legacy_payload, indent=2), encoding="utf-8")
    (node_dir / "6c9e2fcad95e2bd0.json").write_text(json.dumps(legacy_payload, indent=2), encoding="utf-8")

    first = sb.run_bootstrap(dry_run=False)
    second = sb.run_bootstrap(dry_run=False)

    assert first["node_id"] == "6c9e2fcad95e2bd0"
    assert second["node_id"] == "6c9e2fcad95e2bd0"


def test_bootstrap_preserves_genesis_role(tmp_path: Path, monkeypatch) -> None:
    """Bootstrap ueberschreibt role=genesis nicht."""
    root = _prepare_temp_root(tmp_path, monkeypatch)
    public_key_pem = _write_keypair(root / "data" / "keys")
    node_path = root / "data" / "swarm" / "node.json"
    node_path.parent.mkdir(parents=True, exist_ok=True)
    node_path.write_text(
        json.dumps(
            {
                "schema": "aether.swarm.node.v2",
                "node_id": "6c9e2fcad95e2bd0",
                "public_key_pem": public_key_pem,
                "registered_at": "2026-03-21T20:24:51.417669+00:00",
                "role": "genesis",
                "relay": False,
                "yggdrasil_addr": None,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    sb.run_bootstrap(dry_run=False)
    payload = json.loads(node_path.read_text(encoding="utf-8"))
    assert payload["role"] == "genesis"


def test_no_duplicate_pubkeys_in_nodes_dir(tmp_path: Path) -> None:
    """Kein node.json doppelter public_key_pem in data/swarm/nodes/."""
    root = tmp_path / "aether"
    nodes_dir = root / "data" / "swarm" / "nodes"
    nodes_dir.mkdir(parents=True, exist_ok=True)
    public_key_pem = "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"

    first = {
        "node_id": "older-node",
        "public_key_pem": public_key_pem,
        "registered_at": "2026-03-21T20:24:51.417669+00:00",
        "schema": "aether.swarm.node.v2",
        "relay": False,
        "yggdrasil_addr": None,
    }
    second = {
        "node_id": "newer-node",
        "public_key_pem": public_key_pem,
        "registered_at": "2026-03-28T12:07:31.795598+00:00",
        "schema": "aether.swarm.node.v2",
        "relay": True,
        "yggdrasil_addr": "202::1",
    }
    (nodes_dir / "older-node.json").write_text(json.dumps(first, indent=2), encoding="utf-8")
    (nodes_dir / "newer-node.json").write_text(json.dumps(second, indent=2), encoding="utf-8")
    local_node_path = root / "data" / "swarm" / "node.json"
    local_node_path.parent.mkdir(parents=True, exist_ok=True)
    local_node_path.write_text(json.dumps(second, indent=2), encoding="utf-8")

    deduplicate_nodes(nodes_dir=nodes_dir, archive_dir=nodes_dir / "archive", local_node_path=local_node_path)

    pubkeys = []
    for path in sorted(nodes_dir.glob("*.json")):
        pubkeys.append(json.loads(path.read_text(encoding="utf-8"))["public_key_pem"])
    assert len(pubkeys) == len(set(pubkeys))


def test_deduplicate_prefers_older_node(tmp_path: Path) -> None:
    """Bei Duplikat: aeltere registered_at gewinnt."""
    root = tmp_path / "aether"
    nodes_dir = root / "data" / "swarm" / "nodes"
    nodes_dir.mkdir(parents=True, exist_ok=True)
    public_key_pem = "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"

    older = {
        "node_id": "keep-me",
        "public_key_pem": public_key_pem,
        "registered_at": "2026-03-21T20:24:51.417669+00:00",
        "schema": "aether.swarm.node.v2",
        "relay": False,
        "yggdrasil_addr": None,
    }
    newer = {
        "node_id": "archive-me",
        "public_key_pem": public_key_pem,
        "registered_at": "2026-03-28T12:07:31.795598+00:00",
        "schema": "aether.swarm.node.v2",
        "relay": False,
        "yggdrasil_addr": None,
    }
    (nodes_dir / "keep-me.json").write_text(json.dumps(older, indent=2), encoding="utf-8")
    (nodes_dir / "archive-me.json").write_text(json.dumps(newer, indent=2), encoding="utf-8")

    count = deduplicate_nodes(nodes_dir=nodes_dir, archive_dir=nodes_dir / "archive", local_node_path=root / "data" / "swarm" / "node.json")

    assert count == 1
    assert (nodes_dir / "keep-me.json").is_file()
    assert not (nodes_dir / "archive-me.json").exists()
    assert (nodes_dir / "archive" / "archive-me.json").is_file()