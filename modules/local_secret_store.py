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
    except Exception:
        return ""
    try:
        return decoded.decode("utf-8")
    except Exception:
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
        if _ls_sys.platform.startswith("win") and self._cleartext is not None:
            try:
                import ctypes

                ctypes.memset(
                    ctypes.cast(id(self._cleartext), ctypes.c_void_p),
                    0,
                    _ls_sys.getsizeof(self._cleartext),
                )
            except Exception:
                pass
        self._cleartext = None

    def __del__(self) -> None:
        try:
            self.__exit__()
        except Exception:
            pass