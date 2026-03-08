"""Lokaler Secret-Schutz fuer Windows-Desktopbetrieb."""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes


_PREFIX = "dpapi:"


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _blob_from_bytes(payload: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    """Erzeugt einen DATA_BLOB und haelt den Puffer lebendig."""
    buffer = ctypes.create_string_buffer(payload, len(payload))
    blob = _DataBlob(len(payload), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def _crypt_protect(payload: bytes) -> bytes:
    """Verschluesselt Daten ueber Windows DPAPI im Benutzerkontext."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, in_buffer = _blob_from_bytes(payload)
    out_blob = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptProtectData fehlgeschlagen.")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)
        del in_buffer


def _crypt_unprotect(payload: bytes) -> bytes:
    """Entschluesselt Daten ueber Windows DPAPI im Benutzerkontext."""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, in_buffer = _blob_from_bytes(payload)
    out_blob = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise OSError("CryptUnprotectData fehlgeschlagen.")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)
        del in_buffer


def protect_local_secret(secret: str) -> str:
    """Schuetzt ein Secret fuer lokale Persistenz."""
    text = str(secret or "").strip()
    if not text:
        return ""
    if text.startswith(_PREFIX):
        return text
    encrypted = _crypt_protect(text.encode("utf-8"))
    return _PREFIX + base64.urlsafe_b64encode(encrypted).decode("ascii")


def unprotect_local_secret(secret: str) -> str:
    """Liefert ein lokal geschuetztes Secret wieder als Klartext."""
    text = str(secret or "").strip()
    if not text:
        return ""
    if not text.startswith(_PREFIX):
        return text
    payload = base64.urlsafe_b64decode(text[len(_PREFIX) :].encode("ascii"))
    decrypted = _crypt_unprotect(payload)
    return decrypted.decode("utf-8")


def is_protected_local_secret(secret: str) -> bool:
    """Prueft auf das lokale DPAPI-Format."""
    return str(secret or "").strip().startswith(_PREFIX)
