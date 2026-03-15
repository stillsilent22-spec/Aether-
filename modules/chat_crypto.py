"""Lokale Kryptohilfen fuer private und Gruppen-Chats."""

from __future__ import annotations

import base64
import hashlib
import os

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    Fernet = None
    AESGCM = None

    class InvalidToken(Exception):
        """Fallback-Fehlerklasse, wenn cryptography nicht installiert ist."""


def crypto_available() -> bool:
    """Liefert, ob Fernet fuer private und Gruppen-Chats verfuegbar ist."""
    return Fernet is not None


def require_crypto() -> None:
    """Bricht klar ab, wenn die lokale Chat-Kryptologie nicht verfuegbar ist."""
    if Fernet is None:
        raise RuntimeError(
            "Private und Gruppen-Chats benoetigen das Paket 'cryptography'."
        )


def derive_fernet_key(material: str, salt: bytes | None = None) -> str:
    """
    Leitet einen Fernet-Key aus beliebigem Material ab.

    Nutzt HKDF-SHA256 statt rohem SHA-256 um KDF-Sicherheitsgarantien
    zu erhalten (key separation, domain binding, salt).
    salt=None erzeugt einen stabilen deterministischen Key (Session-Scope).
    salt=os.urandom(16) erzeugt einen frischen ephemeren Key.
    """
    try:
        from cryptography.hazmat.primitives.hkdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.backends import default_backend
        hkdf = HKDF(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=salt if salt is not None else b"aether-fernet-v1",
            info=b"aether-chat-fernet-key",
            backend=default_backend(),
        )
        key_bytes = hkdf.derive(str(material).encode("utf-8"))
    except Exception:
        # Fallback: PBKDF2 wenn cryptography.hazmat nicht verfuegbar
        key_bytes = hashlib.pbkdf2_hmac(
            "sha256",
            str(material).encode("utf-8"),
            salt if salt is not None else b"aether-fernet-v1",
            iterations=100_000,
            dklen=32,
        )
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


def generate_group_key() -> str:
    """Erzeugt einen frischen Gruppen-Schluessel."""
    require_crypto()
    assert Fernet is not None
    return Fernet.generate_key().decode("ascii")


def encrypt_text(text: str, key: str) -> str:
    """Verschluesselt Klartext mit einem Fernet-Key."""
    require_crypto()
    assert Fernet is not None
    cipher = Fernet(str(key).encode("ascii"))
    return cipher.encrypt(str(text).encode("utf-8")).decode("ascii")


def decrypt_text(token: str, key: str) -> str:
    """Entschluesselt einen Fernet-Token wieder in Klartext."""
    require_crypto()
    assert Fernet is not None
    cipher = Fernet(str(key).encode("ascii"))
    return cipher.decrypt(str(token).encode("ascii")).decode("utf-8")


def require_aesgcm() -> None:
    """Bricht klar ab, wenn AES-GCM lokal nicht verfuegbar ist."""
    if AESGCM is None:
        raise RuntimeError(
            "Verschluesselte Rohdaten benoetigen das Paket 'cryptography'."
        )


def encrypt_bytes_aes256(payload: bytes, key: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Verschluesselt einen Bytestrom mit lokalem AES-256-GCM."""
    require_aesgcm()
    assert AESGCM is not None
    key_bytes = bytes(key)
    if len(key_bytes) != 32:
        raise ValueError("AES-256 benoetigt einen 32-Byte-Schluessel.")
    nonce = os.urandom(12)
    cipher = AESGCM(key_bytes)
    ciphertext = cipher.encrypt(nonce, bytes(payload), aad or None)
    return nonce, ciphertext


def decrypt_bytes_aes256(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Entschluesselt einen lokal abgelegten AES-256-GCM-Blob."""
    require_aesgcm()
    assert AESGCM is not None
    key_bytes = bytes(key)
    if len(key_bytes) != 32:
        raise ValueError("AES-256 benoetigt einen 32-Byte-Schluessel.")
    cipher = AESGCM(key_bytes)
    return cipher.decrypt(bytes(nonce), bytes(ciphertext), aad or None)
