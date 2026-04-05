"""
Krypto-Wrapper für registry.py und vault_chain.py.
Kein Chat-Protokoll, kein Netzwerk — nur Verschlüsselungs-Primitiven.
"""
import base64
import os
import secrets

try:
    from cryptography.fernet import Fernet
    from cryptography.fernet import InvalidToken
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

    class InvalidToken(Exception):  # type: ignore[no-redef]
        pass


def crypto_available() -> bool:
    """Gibt True zurück wenn die cryptography-Library installiert ist."""
    return _CRYPTO_AVAILABLE


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography nicht installiert")


def generate_group_key() -> bytes:
    """Gibt 32 kryptografisch zufällige Bytes zurück."""
    _require_crypto()
    return os.urandom(32)


def derive_fernet_key(secret: bytes, salt: bytes) -> bytes:
    """
    Leitet einen Fernet-kompatiblen 32-Byte-Key via HKDF-SHA256 ab.
    Gibt base64url-encodierten Key zurück (direkt für Fernet verwendbar).
    """
    _require_crypto()
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=b"aether-fernet-v1",
        backend=default_backend(),
    )
    raw = hkdf.derive(secret)
    return base64.urlsafe_b64encode(raw)


def encrypt_text(plaintext: str, key: bytes) -> str:
    """
    Fernet-Verschlüsselung eines Strings.
    key: 32 Byte raw — wird intern zu Fernet-Key konvertiert falls nötig.
    Gibt base64-Token als str zurück.
    """
    _require_crypto()
    fernet_key = _to_fernet_key(key)
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(token: str, key: bytes) -> str:
    """
    Fernet-Entschlüsselung.
    Wirft InvalidToken bei falschem Key oder korrupten Daten.
    """
    _require_crypto()
    fernet_key = _to_fernet_key(key)
    f = Fernet(fernet_key)
    return f.decrypt(token.encode("ascii")).decode("utf-8")


def encrypt_bytes_aes256(data: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM Verschlüsselung.
    Gibt nonce(12 Byte) + ciphertext + tag(16 Byte) zurück.
    """
    _require_crypto()
    if len(key) != 32:
        raise ValueError(f"Key muss 32 Byte sein, ist {len(key)}")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext_and_tag


def decrypt_bytes_aes256(data: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM Entschlüsselung.
    data: nonce(12) + ciphertext + tag(16)
    Wirft InvalidToken wenn Entschlüsselung fehlschlägt.
    """
    _require_crypto()
    if len(key) != 32:
        raise ValueError(f"Key muss 32 Byte sein, ist {len(key)}")
    if len(data) < 28:  # 12 nonce + mindestens 0 plaintext + 16 tag
        raise InvalidToken("Daten zu kurz für AES-GCM")
    nonce = data[:12]
    ciphertext_and_tag = data[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except Exception as exc:
        raise InvalidToken(str(exc)) from exc


# ── Interne Hilfsfunktion ────────────────────────────────────────────────────

def _to_fernet_key(key: bytes) -> bytes:
    """
    Konvertiert einen 32-Byte raw Key in einen Fernet-kompatiblen
    base64url-codierten Key, falls er noch nicht base64url-codiert ist.
    """
    if len(key) == 32:
        return base64.urlsafe_b64encode(key)
    # Bereits Fernet-Key (44 Byte base64)
    if len(key) == 44:
        return key
    raise ValueError(f"Ungültige Key-Länge: {len(key)} (erwartet 32 oder 44 Byte)")
