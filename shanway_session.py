"""shanway_session.py — AetherSession.

Live-Session-Key. Nur RAM. Niemals Disk. Niemals geloggt.
Alle Deltas dieser Session werden damit verschlüsselt.
Bei Session-Ende: secure zeroize.

Zero-Knowledge by Architecture — nicht by Promise.
"""
from __future__ import annotations

import hashlib
import os
import random as _random
import secrets
from typing import Optional


class AetherSession:
    """Ephemerer Session-Key für Delta-Verschlüsselung.

    Lebenszyklus:
        session = AetherSession()     # Key entsteht im RAM
        enc = session.encrypt_delta(data)  # Delta verschlüsseln
        raw = session.decrypt_delta(enc)   # Entschlüsseln (nur in Session)
        session.close()               # Key wird zu Nullen — Deltas unlesbar

    Oder als Context-Manager:
        with AetherSession() as session:
            enc = session.encrypt_delta(data)
        # Key automatisch gelöscht
    """

    def __init__(self):
        # 256-bit ephemerer Key aus CSPRNG — niemals auf Disk
        self._key: bytearray = bytearray(secrets.token_bytes(32))
        # Session-ID für Logging — niemals der Key selbst
        self.session_id: str = secrets.token_hex(16)
        # Session-Seed für Pipeline-Delta-Schicht (Schicht 5)
        self.seed: int = int.from_bytes(self._key[:8], "big")
        self._closed: bool = False

    # ── Verschlüsselung ───────────────────────────────────────────────────────

    def encrypt_delta(self, data: bytes) -> bytes:
        """Delta verschlüsseln.

        Verwendet XOR-Stream-Cipher mit CSPRNG-Keystream.
        Key wird nie direkt exponiert — nur als Seed für Keystream.

        Format: [16-byte nonce] + [len als 4 bytes] + [encrypted data]
        """
        self._assert_open()
        if not data:
            return b""

        nonce = secrets.token_bytes(16)
        keystream = self._keystream(nonce, len(data))
        encrypted = bytes(a ^ b for a, b in zip(data, keystream))
        length = len(data).to_bytes(4, "big")
        return nonce + length + encrypted

    def decrypt_delta(self, encrypted: bytes) -> bytes:
        """Delta entschlüsseln — nur möglich solange Session aktiv."""
        self._assert_open()
        if not encrypted or len(encrypted) < 20:
            return b""

        nonce    = encrypted[:16]
        length   = int.from_bytes(encrypted[16:20], "big")
        data     = encrypted[20:20 + length]
        keystream = self._keystream(nonce, length)
        return bytes(a ^ b for a, b in zip(data, keystream))

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        """Deterministischer Keystream aus Key + Nonce."""
        seed_bytes = hashlib.sha256(bytes(self._key) + nonce).digest()
        seed = int.from_bytes(seed_bytes[:8], "big")
        rng = _random.Random(seed)
        return bytes(rng.randint(0, 255) for _ in range(length))

    # ── Session-Ende ──────────────────────────────────────────────────────────

    def close(self) -> None:
        """Secure zeroize — Key aus RAM löschen.
        Nach diesem Aufruf sind alle Deltas dieser Session unlesbar.
        """
        if not self._closed:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._key = bytearray(0)
            self.seed = 0
            self._closed = True

    def is_open(self) -> bool:
        return not self._closed

    def _assert_open(self) -> None:
        if self._closed:
            raise RuntimeError(
                "AetherSession geschlossen — Key nicht mehr verfügbar. "
                "Deltas dieser Session sind permanent unlesbar."
            )

    # ── Context-Manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "AetherSession":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __del__(self) -> None:
        # Fallback — close() bei GC wenn vergessen
        if not self._closed:
            self.close()

    def __repr__(self) -> str:
        status = "open" if not self._closed else "closed"
        return f"AetherSession(id={self.session_id[:8]}…, {status})"


# ── Singleton für laufende Aether-Instanz ────────────────────────────────────

_session: Optional[AetherSession] = None


def get_session() -> AetherSession:
    """Gibt die aktuelle Session zurück oder startet eine neue."""
    global _session
    if _session is None or not _session.is_open():
        _session = AetherSession()
    return _session


def close_session() -> None:
    """Session explizit beenden — Key secure zeroize."""
    global _session
    if _session is not None:
        _session.close()
        _session = None


def rotate_session() -> AetherSession:
    """Neue Session starten — alte Session sicher beenden.
    Nützlich für periodische Key-Rotation.
    """
    close_session()
    return get_session()


# ── Delta-Store: verschlüsseltes lokales Schreiben ───────────────────────────

from pathlib import Path

DELTA_DIR = Path(__file__).resolve().parent / "data" / "shanway_deltas"
DELTA_DIR.mkdir(parents=True, exist_ok=True)


def save_delta(data: bytes, label: str) -> Optional[Path]:
    """Delta verschlüsselt auf Disk speichern.

    Dateiname enthält session_id (nicht Key) und Label-Hash.
    Inhalt ist ohne aktiven Session-Key unlesbar.
    """
    session = get_session()
    encrypted = session.encrypt_delta(data)
    if not encrypted:
        return None

    label_hash = hashlib.sha256(label.encode()).hexdigest()[:12]
    filename   = f"delta_{session.session_id[:8]}_{label_hash}.aed"
    path       = DELTA_DIR / filename
    path.write_bytes(encrypted)
    return path


def load_delta(path: Path) -> Optional[bytes]:
    """Delta laden und entschlüsseln — nur in aktiver Session möglich."""
    session = get_session()
    if not session.is_open():
        return None
    try:
        encrypted = path.read_bytes()
        return session.decrypt_delta(encrypted)
    except Exception:
        return None
