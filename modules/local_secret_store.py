import logging
logger = logging.getLogger(__name__)
"""Lokaler Secret-Speicher mit leichtgewichtiger Schutzhuelle."""

import base64
import sys as _ls_sys
from typing import Any as _ls_Any
from typing import Optional


_PROTECTED_PREFIX = "aether-local:v1:"


def is_protected_local_secret(value: str) -> bool:
    return str(value or "").startswith(_PROTECTED_PREFIX)


def protect_local_secret(secret: str) -> str:
    raw = str(secret or "").encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii")
    return f"{_PROTECTED_PREFIX}{encoded}"


def unprotect_local_secret(protected_value: str) -> str:
    value = str(protected_value or "")
    if not is_protected_local_secret(value):
        return value
    payload = value[len(_PROTECTED_PREFIX) :]
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
    except Exception as e:
        return ""
    try:
        return decoded.decode("utf-8")
    except Exception as e:
        return ""


class ProtectedSecret:
    """Kontextmanager fuer sichere Nutzung lokaler Secrets."""

    def __init__(self, protected_value: str) -> None:
        self._protected = str(protected_value or "")
        self._cleartext: Optional[str] = None

    def __enter__(self) -> str:
        self._cleartext = unprotect_local_secret(self._protected)
        return self._cleartext

    def __exit__(self, *args: _ls_Any) -> None:
        # Python-Strings sind unveränderlich — ctypes.memset(id(str)) überschreibt
        # den Python-Objekt-Header im RAM, nicht den eigentlichen Zeichenpuffer.
        # Das ist keine sichere Zeroization sondern eine Memory-Corruption-Quelle.
        # Sicherer Ansatz: Referenz aufgeben + GC so früh wie möglich auslösen.
        # Für produktionshärteren Schutz: Secrets als bytearray speichern (veränderlich).
        if self._cleartext is not None:
            try:
                import gc
                self._cleartext = None
                gc.collect(0)  # Generierung 0 — schnell, gibt kurzlebige Objekte frei
            except Exception as e:
                logger.warning(f"[local_secret_store] Fehler: {e}")
                self._cleartext = None

    def __del__(self) -> None:
        try:
            self.__exit__()
        except Exception as e:
            logger.warning(f"[local_secret_store] Fehler: {e}")
            pass