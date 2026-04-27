"""vault_identity.py -- Read and validate the node's AEK vault identity file.

The AEK format (96 bytes):
  [0..3]   magic "AEKP"
  [4..7]   version uint32 LE (must be 1)
  [8..39]  Ed25519 seed (32 bytes)
  [40..71] Ed25519 public key (32 bytes)
  [72..79] creation timestamp uint64 LE (seconds since epoch)
  [80..81] CRC16/XMODEM(bytes 0..79)  -- integrity footer, no SHA
  [82..95] zero-padded (reserved)

Public API:
  load()                    -> VaultIdentity
  VaultIdentity.is_valid()  -> bool
  VaultIdentity.node_id     -> str   (hex of public key first 8 bytes)
  VaultIdentity.public_key  -> bytes (32 bytes)
  VaultIdentity.created_at  -> int   (unix timestamp)
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_AEK_MAGIC   = b"AEKP"
_AEK_VERSION = 1
_AEK_SIZE    = 96


def _crc16_xmodem(data: bytes) -> int:
    """CRC16/XMODEM: poly 0x1021, init 0x0000, no reflection, no XorOut."""
    crc = 0x0000
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


def _aek_path() -> Path:
    """Return ~/.aether/vault/node_identity.aek (cross-platform)."""
    home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or "~")
    return home / ".aether" / "vault" / "node_identity.aek"


def _verify_checksum(raw: bytes) -> bool:
    """Verify CRC16/XMODEM(raw[0:80]) == little-endian u16 at raw[80:82]."""
    expected = _crc16_xmodem(raw[:80])
    stored = struct.unpack_from("<H", raw, 80)[0]
    return expected == stored


@dataclass
class VaultIdentity:
    """Parsed and validated contents of an AEK file."""

    raw: bytes = field(repr=False)
    valid: bool = False
    error: str = ""

    seed: bytes       = b""
    public_key: bytes = b""
    created_at: int   = 0
    node_id: str      = ""

    @classmethod
    def from_bytes(cls, raw: bytes) -> "VaultIdentity":
        obj = cls(raw=raw)
        if len(raw) != _AEK_SIZE:
            obj.error = f"invalid size: {len(raw)} (expected {_AEK_SIZE})"
            return obj
        if raw[:4] != _AEK_MAGIC:
            obj.error = f"bad magic: {raw[:4]!r}"
            return obj
        version = struct.unpack_from("<I", raw, 4)[0]
        if version != _AEK_VERSION:
            obj.error = f"unsupported version: {version}"
            return obj
        if not _verify_checksum(raw):
            obj.error = "checksum mismatch"
            return obj
        obj.seed       = bytes(raw[8:40])
        obj.public_key = bytes(raw[40:72])
        obj.created_at = struct.unpack_from("<Q", raw, 72)[0]
        obj.node_id    = obj.public_key[:8].hex()
        obj.valid      = True
        return obj

    def is_valid(self) -> bool:
        return self.valid

    def created_dt(self) -> Optional[datetime]:
        if not self.valid:
            return None
        return datetime.fromtimestamp(self.created_at, tz=timezone.utc)

    def to_dict(self) -> dict:
        return {
            "valid":      self.valid,
            "error":      self.error,
            "node_id":    self.node_id,
            "public_key": self.public_key.hex(),
            "created_at": self.created_at,
            "created_dt": self.created_dt().isoformat() if self.created_dt() else None,
        }


def load(path: Optional[Path] = None) -> VaultIdentity:
    """
    Load and parse the AEK file.
    Returns a VaultIdentity with valid=False if the file is missing or corrupt.
    """
    p = path or _aek_path()
    try:
        raw = Path(p).read_bytes()
    except FileNotFoundError:
        obj = VaultIdentity(raw=b"")
        obj.error = f"AEK not found: {p}"
        return obj
    except OSError as exc:
        obj = VaultIdentity(raw=b"")
        obj.error = str(exc)
        return obj
    return VaultIdentity.from_bytes(raw)
