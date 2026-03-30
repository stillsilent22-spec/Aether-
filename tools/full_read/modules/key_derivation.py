"""HKDF-Ableitungsbaum fuer Aether.

Master Key -> alle Child Keys via HKDF-SHA256.
Master Key verlaesst niemals den lokalen Speicher.
"""

from __future__ import annotations

import ctypes
from typing import Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class AetherKeyTree:
    """Leitet alle Aether-Keys deterministisch aus einem Master-Key ab."""

    CONTEXTS: Dict[str, bytes] = {
        "yggdrasil": b"aether/v1/transport/yggdrasil",
        "anchor-sign": b"aether/v1/anchor/signing",
        "data": b"aether/v1/vault/data",
        "session": b"aether/v1/session/seed",
    }

    def __init__(self, master_key_bytes: bytes) -> None:
        if len(master_key_bytes) != 32:
            raise ValueError("master_key_bytes must be exactly 32 bytes")
        self._master = bytearray(master_key_bytes)

    def derive(self, context: str) -> bytes:
        """Leitet einen 32-Byte Child-Key via HKDF-SHA256 ab."""
        if context not in self.CONTEXTS:
            raise KeyError(f"unknown key context: {context}")
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None, info=self.CONTEXTS[context])
        return hkdf.derive(bytes(self._master))

    @property
    def yggdrasil_key(self) -> bytes:
        return self.derive("yggdrasil")

    @property
    def anchor_signing_key(self) -> bytes:
        return self.derive("anchor-sign")

    @property
    def data_key(self) -> bytes:
        return self.derive("data")

    @property
    def session_seed(self) -> bytes:
        """RAM-only. Niemals persistieren."""
        return self.derive("session")

    def zeroize(self) -> None:
        """Ueberschreibt den Master-Key im Speicher."""
        if not self._master:
            return
        buf = (ctypes.c_ubyte * len(self._master)).from_buffer(self._master)
        ctypes.memset(ctypes.addressof(buf), 0, len(self._master))
        self._master[:] = b"\x00" * len(self._master)


def master_key_from_private_pem(private_key_pem: bytes) -> bytes:
    """Extrahiert den 32-Byte Ed25519-Seed aus einem PEM Private Key."""
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if len(raw) != 32:
        raise ValueError("unsupported private key length")
    return raw