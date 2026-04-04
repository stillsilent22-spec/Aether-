from __future__ import annotations

import ipaddress

from modules.key_derivation import AetherKeyTree
from modules.yggdrasil_addr import yggdrasil_addr_from_key_tree


def _master_key() -> bytes:
    return bytes(range(32))


def test_hkdf_deterministic() -> None:
    left = AetherKeyTree(_master_key())
    right = AetherKeyTree(_master_key())
    assert left.yggdrasil_key == right.yggdrasil_key
    assert left.anchor_signing_key == right.anchor_signing_key
    assert left.data_key == right.data_key
    assert left.session_seed == right.session_seed


def test_hkdf_isolation() -> None:
    tree = AetherKeyTree(_master_key())
    assert tree.yggdrasil_key != tree.anchor_signing_key
    assert tree.anchor_signing_key != tree.data_key
    assert tree.data_key != tree.session_seed


def test_session_seed_not_equal_data_key() -> None:
    tree = AetherKeyTree(_master_key())
    assert tree.session_seed != tree.data_key


def test_yggdrasil_addr_format() -> None:
    tree = AetherKeyTree(_master_key())
    address = yggdrasil_addr_from_key_tree(tree)
    parsed = ipaddress.IPv6Address(address)
    assert parsed.version == 6
    assert int(parsed) >> 121 == 0x01


def test_zeroize() -> None:
    tree = AetherKeyTree(_master_key())
    tree.zeroize()
    assert bytes(tree._master) == bytes(32)