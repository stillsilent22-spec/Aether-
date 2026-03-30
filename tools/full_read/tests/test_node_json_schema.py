from __future__ import annotations

import ipaddress

from modules.key_derivation import AetherKeyTree
from modules.yggdrasil_addr import yggdrasil_addr_from_key_tree
from solo_bootstrap import build_node_record


def _sample_node_payload() -> dict:
    tree = AetherKeyTree(bytes(range(32)))
    return build_node_record(
        "abc123def4567890",
        "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
        yggdrasil_addr_from_key_tree(tree),
        relay=False,
        registered_at="2026-03-28T12:00:00+00:00",
    )


def test_node_json_has_no_ip() -> None:
    payload = _sample_node_payload()
    for key, value in payload.items():
        lowered = str(key).lower()
        if lowered == "yggdrasil_addr":
            continue
        assert "ip" not in lowered
        assert "host" not in lowered
        assert "port" not in lowered
        assert "address" not in lowered
        assert "127.0.0.1" not in str(value)


def test_node_json_v2_schema() -> None:
    payload = _sample_node_payload()
    assert payload["schema"] == "aether.swarm.node.v2"
    if payload["yggdrasil_addr"] is not None:
        parsed = ipaddress.IPv6Address(payload["yggdrasil_addr"])
        assert int(parsed) >> 121 == 0x01
    assert isinstance(payload["relay"], bool)