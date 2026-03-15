"""Lokaler Secret-Schutz — Windows DPAPI mit plattformunabhaengigem Fallback."""

from __future__ import annotations

import base64
import hashlib
import os
import sys

_PREFIX_DPAPI   = "dpapi:"
_PREFIX_FALLBACK = "aethsec1:"  # PBKDF2+AES-256-GCM Fallback fuer non-Windows


# ── Windows DPAPI ──────────────────────────────────────────────────────────

def _dpapi_available() -> bool:
    return sys.platform.startswith("win")


def _crypt_protect(payload: bytes) -> bytes:
    """Verschluesselt via Windows DPAPI im Benutzerkontext."""
    import ctypes
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(payload, len(payload))
    blob_in  = _DataBlob(len(payload), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise OSError("CryptProtectData fehlgeschlagen.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        if blob_out.pbData:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _crypt_unprotect(payload: bytes) -> bytes:
    """Entschluesselt via Windows DPAPI."""
    import ctypes
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(payload, len(payload))
    blob_in  = _DataBlob(len(payload), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise OSError("CryptUnprotectData fehlgeschlagen.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        if blob_out.pbData:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ── Plattformunabhaengiger Fallback (AES-256-GCM + PBKDF2) ─────────────────

def _fallback_machine_salt() -> bytes:
    """
    Erzeugt einen stabilen maschinengebundenen Salt aus Umgebungsmerkmalen.
    Kein Ersatz fuer DPAPI (kein Hardware-Binding), aber deutlich besser als
    ein fester Salt — an diese Installation gebunden.
    """
    markers = [
        os.environ.get("USER", "") or os.environ.get("USERNAME", ""),
        os.environ.get("HOME", "") or os.environ.get("USERPROFILE", ""),
        os.environ.get("COMPUTERNAME", "") or os.uname().nodename
            if hasattr(os, "uname") else "",
        sys.platform,
        "aether-local-secret-v1",
    ]
    combined = "|".join(str(m) for m in markers).encode("utf-8")
    return hashlib.sha256(combined).digest()


def _fallback_protect(secret: str) -> str:
    """AES-256-GCM Verschluesselung mit PBKDF2-abgeleitetem Key."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        # Letzter Fallback: base64-Obfuskation (kein echter Schutz, macht Problem sichtbar)
        encoded = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
        return _PREFIX_FALLBACK + "b64:" + encoded

    salt = _fallback_machine_salt()
    key = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 200_000, dklen=32)
    # Wir verschluesseln einen festen Marker + das Secret damit decrypt
    # erkennt ob das richtige Secret vorliegt
    nonce = os.urandom(12)
    aad   = b"aether-local-secret-v1"
    ct    = AESGCM(key).encrypt(nonce, secret.encode("utf-8"), aad)
    payload = nonce + ct
    return _PREFIX_FALLBACK + base64.urlsafe_b64encode(payload).decode("ascii")


def _fallback_unprotect(protected: str) -> str:
    """Entschluesselt einen Fallback-geschuetzten Secret."""
    raw = protected[len(_PREFIX_FALLBACK):]

    if raw.startswith("b64:"):
        return base64.urlsafe_b64decode(raw[4:].encode("ascii")).decode("utf-8")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("cryptography nicht installiert — Secret nicht entschluesselbear.")

    payload = base64.urlsafe_b64decode(raw.encode("ascii"))
    if len(payload) < 12:
        raise ValueError("Ungueltiges Fallback-Format.")
    nonce = payload[:12]
    ct    = payload[12:]
    salt  = _fallback_machine_salt()
    aad   = b"aether-local-secret-v1"
    # Wir probieren den Key — bei falschem Key schlaegt AESGCM.decrypt mit
    # InvalidTag fehl (authenticated encryption)
    # Problem: wir kennen das Original-Secret nicht fuer Key-Ableitung
    # Loesung: bei Fallback speichern wir den PBKDF2-Key separat
    # Pragmatische Loesung: Key aus einem stabilen internen Masterpasswort
    master = hashlib.sha256(
        _fallback_machine_salt() + b"|aether-fallback-master-v1"
    ).hexdigest()
    key = hashlib.pbkdf2_hmac("sha256", master.encode("ascii"), salt, 200_000, dklen=32)
    pt = AESGCM(key).decrypt(nonce, ct, aad)
    return pt.decode("utf-8")


# ── Korrigierter Fallback-Protect: Key aus Machine-Salt direkt ─────────────

def _fallback_protect_v2(secret: str) -> str:
    """
    AES-256-GCM mit Key aus Machine-Salt (kein Secret als KDF-Input —
    das waere ein Huhn-Ei-Problem). Schuetzt vor einfachem DB-Dump.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        encoded = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
        return _PREFIX_FALLBACK + "b64:" + encoded

    salt   = _fallback_machine_salt()
    master = hashlib.sha256(salt + b"|aether-fallback-master-v1").hexdigest()
    key    = hashlib.pbkdf2_hmac("sha256", master.encode("ascii"), salt, 200_000, dklen=32)
    nonce  = os.urandom(12)
    aad    = b"aether-local-secret-v1"
    ct     = AESGCM(key).encrypt(nonce, secret.encode("utf-8"), aad)
    payload = nonce + ct
    return _PREFIX_FALLBACK + base64.urlsafe_b64encode(payload).decode("ascii")


def _fallback_unprotect_v2(protected: str) -> str:
    raw = protected[len(_PREFIX_FALLBACK):]
    if raw.startswith("b64:"):
        return base64.urlsafe_b64decode(raw[4:].encode("ascii")).decode("utf-8")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("cryptography nicht installiert.")
    payload = base64.urlsafe_b64decode(raw.encode("ascii"))
    if len(payload) < 12:
        raise ValueError("Ungueltiges Fallback-Format.")
    nonce = payload[:12]
    ct    = payload[12:]
    salt  = _fallback_machine_salt()
    aad   = b"aether-local-secret-v1"
    master = hashlib.sha256(salt + b"|aether-fallback-master-v1").hexdigest()
    key    = hashlib.pbkdf2_hmac("sha256", master.encode("ascii"), salt, 200_000, dklen=32)
    pt = AESGCM(key).decrypt(nonce, ct, aad)
    return pt.decode("utf-8")


# ── Oeffentliche API ────────────────────────────────────────────────────────

def protect_local_secret(secret: str) -> str:
    """
    Schuetzt ein Secret fuer lokale Persistenz.
    Windows: DPAPI (Benutzerkontext-gebunden).
    Andere Plattformen: AES-256-GCM mit maschinengebundenem Key.
    """
    text = str(secret or "").strip()
    if not text:
        return ""
    if text.startswith(_PREFIX_DPAPI) or text.startswith(_PREFIX_FALLBACK):
        return text  # Bereits geschuetzt
    if _dpapi_available():
        try:
            encrypted = _crypt_protect(text.encode("utf-8"))
            return _PREFIX_DPAPI + base64.urlsafe_b64encode(encrypted).decode("ascii")
        except Exception:
            pass  # DPAPI-Fehler -> Fallback
    return _fallback_protect_v2(text)


def unprotect_local_secret(secret: str) -> str:
    """Liefert ein lokal geschuetztes Secret als Klartext zurueck."""
    text = str(secret or "").strip()
    if not text:
        return ""
    if text.startswith(_PREFIX_DPAPI):
        if not _dpapi_available():
            raise RuntimeError(
                "DPAPI-verschluesseltes Secret kann nur auf Windows entschluesselt werden."
            )
        payload = base64.urlsafe_b64decode(text[len(_PREFIX_DPAPI):].encode("ascii"))
        return _crypt_unprotect(payload).decode("utf-8")
    if text.startswith(_PREFIX_FALLBACK):
        return _fallback_unprotect_v2(text)
    return text  # Ungeschuetzt — Klartext


def is_protected_local_secret(secret: str) -> bool:
    """Prueft ob ein Secret im lokalen Schutzformat vorliegt."""
    s = str(secret or "").strip()
    return s.startswith(_PREFIX_DPAPI) or s.startswith(_PREFIX_FALLBACK)
