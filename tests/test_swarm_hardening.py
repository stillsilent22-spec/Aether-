from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.aethernet_transport import AethernetTransport
from modules.swarm_health import get_swarm_status


def _write_node(nodes_dir: Path, node_id: str, public_pem: str, role: str = "peer") -> None:
    payload = {
        "node_id": node_id,
        "public_key_pem": public_pem,
        "role": role,
    }
    (nodes_dir / f"{node_id}.json").write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def test_signed_payload_required_and_verified(tmp_path: Path) -> None:
    anchor_dir = tmp_path / "anchors"
    nodes_dir = tmp_path / "nodes"
    anchor_dir.mkdir(parents=True, exist_ok=True)
    nodes_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = tmp_path / "node_private.key"
    private_path.write_bytes(private_pem)
    _write_node(nodes_dir, "node-a", public_pem.decode("utf-8"), role="genesis")

    signer = AethernetTransport(
        node_id="node-a",
        anchor_dir=str(anchor_dir),
        nodes_dir=str(nodes_dir),
        lan_port=7391,
        local_private_key_path=str(private_path),
        require_signed_messages=True,
    )
    verifier = AethernetTransport(
        node_id="node-b",
        anchor_dir=str(anchor_dir),
        nodes_dir=str(nodes_dir),
        lan_port=7392,
        local_private_key_path=str(private_path),
        require_signed_messages=True,
    )

    base_payload = {
        "ttd_hash": "abc123",
        "node_id": "node-a",
        "metrics": {"entropy": 0.42},
    }

    signed = signer._sign_payload(base_payload)
    assert verifier._verify_signed_payload(signed)

    tampered = dict(signer._sign_payload(base_payload))
    tampered["ttd_hash"] = "evil"
    assert not verifier._verify_signed_payload(tampered)

    assert not verifier._verify_signed_payload(dict(base_payload))


def test_swarm_health_emits_alerts_for_degraded_state(tmp_path: Path) -> None:
    nodes_dir = tmp_path / "nodes"
    anchors_dir = tmp_path / "anchors"
    nodes_dir.mkdir(parents=True, exist_ok=True)
    anchors_dir.mkdir(parents=True, exist_ok=True)

    (nodes_dir / "node-1.json").write_text(
        json.dumps({"node_id": "node-1", "role": "genesis", "lan_url": ""}, ensure_ascii=True),
        encoding="utf-8",
    )
    (nodes_dir / "node-2.json").write_text(
        json.dumps({"node_id": "node-2", "role": "peer", "lan_url": ""}, ensure_ascii=True),
        encoding="utf-8",
    )

    status = get_swarm_status(
        nodes_dir=str(nodes_dir),
        anchor_dir=str(anchors_dir),
        consensus_db=str(tmp_path / "consensus.db"),
    )

    assert status["alert_level"] in ("warning", "critical")
    assert isinstance(status.get("alerts", []), list)
    assert status.get("alerts")
    assert float(status.get("health_score", 1.0)) < 1.0
