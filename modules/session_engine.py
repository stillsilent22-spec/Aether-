import gc as _gc
import sys as _sys
import ctypes as _ctypes
import secrets as _secrets
from typing import Any as _Any


class SecuritySession:
    """Leichtgewichtiges Objekt, das eine verifizierte Login-Session beschreibt."""

    def __init__(
        self,
        username: str = "local",
        user_id: int = 0,
        session_id: str = "",
        user_role: str = "operator",
        security_mode: str = "PROD",
    ) -> None:
        self.username = str(username or "local")
        self.user_id = int(user_id or 0)
        self.session_id = str(session_id) if session_id else _secrets.token_hex(16)
        self.user_role = str(user_role or "operator")
        self.security_mode = str(security_mode or "PROD")


class SessionContext:
    """
    Laufzeit-Kontext fuer eine authentifizierte Aether-Session.

    Haelt alle session-lokalen Zustandsdaten: Nutzeridentitaet, Settings,
    ephemere Schluessel. Sensitive Attribute werden bei Sessionende via
    ``cleanup()`` sicher geloescht.
    """

    def __init__(self, security_session: "SecuritySession | None" = None) -> None:
        ss = security_session
        self.username: str = str(getattr(ss, "username", "local") or "local")
        self.user_id: int = int(getattr(ss, "user_id", 0) or 0)
        self.session_id: str = str(getattr(ss, "session_id", "") or _secrets.token_hex(16))
        self.user_role: str = str(getattr(ss, "user_role", "operator") or "operator")
        self.security_mode: str = str(getattr(ss, "security_mode", "PROD") or "PROD")
        self.user_settings: dict[str, Any] = {}
        # Ephemere Schluessel — werden bei cleanup() zeroized
        self.live_session_key: str = ""
        self.live_session_fingerprint: str = ""
        self.raw_storage_key_hex: str = ""
        self.raw_storage_key_fingerprint: str = ""


def secure_zeroize(obj: _Any) -> None:
    """Überschreibt sensitive Objekte im RAM mit Nullbytes (Windows-only). Fail-silent."""
    if not _sys.platform.startswith("win"):
        return
    try:
        if isinstance(obj, bytearray):
            for idx in range(len(obj)):
                obj[idx] = 0
        elif isinstance(obj, (bytes, str)):
            try:
                _ctypes.memset(id(obj), 0, _sys.getsizeof(obj))
            except Exception:
                pass
        elif isinstance(obj, dict):
            for value in list(obj.values()):
                secure_zeroize(value)
            try:
                obj.clear()
            except Exception:
                pass
        elif isinstance(obj, list):
            for item in list(obj):
                secure_zeroize(item)
            try:
                obj.clear()
            except Exception:
                pass
    except Exception:
        pass
    finally:
        try:
            _gc.collect()
        except Exception:
            pass

def _session_cleanup_patch(self) -> None:
    """Zeroizt alle sensitiven Session-Keys. Nur Windows. Fail-silent."""
    try:
        from modules.security_engine import secure_zeroize
    except Exception:
        try:
            from .security_engine import secure_zeroize
        except Exception:
            return
    for attr in ("live_session_key", "live_session_fingerprint",
                 "raw_storage_key_hex", "raw_storage_key_fingerprint"):
        try:
            secure_zeroize(getattr(self, attr, ""))
            setattr(self, attr, "")
        except Exception:
            pass

# Monkey-patch cleanup + __del__ onto SessionContext
SessionContext.cleanup = _session_cleanup_patch


def _session_del_patch(self) -> None:
    try:
        self.cleanup()
    except Exception:
        pass


SessionContext.__del__ = _session_del_patch