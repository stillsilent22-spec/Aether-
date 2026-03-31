import logging
logger = logging.getLogger(__name__)
"""Leitet eine Yggdrasil IPv6-Adresse aus dem Aether Yggdrasil-Key ab.

Yggdrasil v0.5+ verwendet Ed25519 Keys -> IPv6 im 200::/7 Bereich.
Die Adresse ist deterministisch: gleicher Key = gleiche Adresse.
Keine IP-Lookups, kein Netzwerkzugriff fuer die Ableitung.
"""

from __future__ import annotations

import ipaddress

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def derive_yggdrasil_address(yggdrasil_key_bytes: bytes) -> str:
    """Leitet die Yggdrasil IPv6-Adresse nach AddrForKey() ab."""
    if len(yggdrasil_key_bytes) != 32:
        raise ValueError("yggdrasil_key_bytes must be exactly 32 bytes")

    private_key = Ed25519PrivateKey.from_private_bytes(yggdrasil_key_bytes)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    inverted = bytes((~byte) & 0xFF for byte in public_key)
    prefix = bytes([0x02])
    addr = bytearray(16)
    addr[: len(prefix)] = prefix

    done = False
    ones = 0
    packed_bytes = bytearray()
    current_bits = 0
    bit_count = 0

    for index in range(8 * len(inverted)):
        bit = (inverted[index // 8] & (0x80 >> (index % 8))) >> (7 - (index % 8))
        if not done and bit != 0:
            ones += 1
            continue
        if not done and bit == 0:
            done = True
            continue
        current_bits = (current_bits << 1) | bit
        bit_count += 1
        if bit_count == 8:
            packed_bytes.append(current_bits)
            current_bits = 0
            bit_count = 0

    addr[len(prefix)] = ones & 0xFF
    payload = bytes(packed_bytes)
    addr[len(prefix) + 1 :] = payload[: max(0, len(addr) - len(prefix) - 1)]
    return str(ipaddress.IPv6Address(bytes(addr)))


def yggdrasil_addr_from_key_tree(key_tree: object) -> str:
    """Convenience-Wrapper: AetherKeyTree -> Yggdrasil-Adresse."""
    key_bytes = getattr(key_tree, "yggdrasil_key")
    return derive_yggdrasil_address(key_bytes)