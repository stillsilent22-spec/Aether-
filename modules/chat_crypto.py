import logging
logger = logging.getLogger(__name__)
import sys as _cc_sys
import time as _cc_time

class EphemeralKey:
    """Zeitlich begrenzter Schlüssel mit automatischem TTL und Zeroize. Windows-gehärtet."""
    DEFAULT_TTL_SECONDS: int = 3600
    def __init__(self, material: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._created_at = _cc_time.monotonic()
        self._ttl = float(max(60,int(ttl_seconds)))
        self._key: str | None = derive_fernet_key(str(material or ""))
        self._expired = False
    @property
    def is_valid(self) -> bool:
        if self._expired: return False
        if _cc_time.monotonic()-self._created_at > self._ttl:
            self.invalidate(); return False
        return True
    @property
    def remaining_seconds(self) -> float:
        return max(0.0,self._ttl-(_cc_time.monotonic()-self._created_at)) if not self._expired else 0.0
    def get_key(self) -> str:
        if not self.is_valid: raise RuntimeError("EphemeralKey abgelaufen.")
        assert self._key is not None; return self._key
    def invalidate(self) -> None:
        self._expired = True
        if self._key is not None and _cc_sys.platform.startswith("win"):
            try:
                import ctypes, sys
                ctypes.memset(ctypes.cast(id(self._key),ctypes.c_void_p),0,sys.getsizeof(self._key))
            except Exception: pass
        self._key = None
    def __del__(self) -> None:
        try: self.invalidate()
        except Exception: pass


# ---------------------------------------------------------------------------
# Cryptographic helpers — required by assistant_vault, assistant_chat, etc.
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError as e:
    _CRYPTO_AVAILABLE = False
    InvalidToken = Exception  # type: ignore[assignment,misc]

import base64 as _b64
import os as _os
import hashlib as _hashlib


def crypto_available() -> bool:
    """True wenn das 'cryptography'-Paket installiert ist, sonst False."""
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError as e:
        return False


def derive_fernet_key(material: str) -> str:
    """Leitet aus einem beliebigen String einen gueltigen Fernet-Key ab (PBKDF2-HMAC-SHA256)."""
    if not _CRYPTO_AVAILABLE:
        return ""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aether_fernet_v1",
        iterations=100_000,
    )
    raw = kdf.derive(material.encode("utf-8", errors="replace"))
    return _b64.urlsafe_b64encode(raw).decode()


def encrypt_text(text: str, key: str) -> str:
    """Verschluesselt einen String mit Fernet. Gibt verschluesselten Token als String zurueck."""
    if not _CRYPTO_AVAILABLE:
        return ""
    try:
        f = Fernet(key.encode() if isinstance(key, str) else key)
        return f.encrypt(text.encode("utf-8")).decode()
    except Exception as e:
        return ""


def decrypt_text(token: str, key: str) -> str:
    """Entschluesselt einen Fernet-Token zurueck zum Klartext-String. Bei Fehler: leerer String."""
    if not _CRYPTO_AVAILABLE:
        return ""
    try:
        f = Fernet(key.encode() if isinstance(key, str) else key)
        return f.decrypt(token.encode() if isinstance(token, str) else token).decode("utf-8")
    except Exception as e:
        return ""


def encrypt_bytes_aes256(data: bytes, key: bytes):
    """AES-GCM 256-bit Verschluesselung. Gibt (nonce, ciphertext) als Tuple zurueck."""
    if not _CRYPTO_AVAILABLE:
        return b"", b""
    try:
        key32 = _hashlib.sha256(key).digest()
        nonce = _os.urandom(12)
        ct = AESGCM(key32).encrypt(nonce, data, None)
        return nonce, ct
    except Exception as e:
        return b"", b""


def decrypt_bytes_aes256(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """AES-GCM Entschluesselung. Gibt Klartext-Bytes zurueck, bei Fehler leere bytes."""
    if not _CRYPTO_AVAILABLE:
        return b""
    try:
        key32 = _hashlib.sha256(key).digest()
        return AESGCM(key32).decrypt(nonce, ciphertext, None)
    except Exception as e:
        return b""


def generate_group_key() -> str:
    """Erzeugt einen neuen zufaelligen Fernet-Key als String."""
    if not _CRYPTO_AVAILABLE:
        return ""
    return Fernet.generate_key().decode()