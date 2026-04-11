import logging
logger = logging.getLogger(__name__)
import gc as _gc
import hashlib as _hashlib
import sys as _sys
import ctypes as _ctypes
import secrets as _secrets
from datetime import datetime as _datetime, timezone as _timezone
from typing import Any as _Any
from typing import Optional as _Optional


def _datetime_now_iso() -> str:
    return _datetime.now(_timezone.utc).isoformat()


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

    def __init__(self, security_session: "SecuritySession | None" = None, seed: _Optional[int] = None) -> None:
        ss = security_session
        self.username: str = str(getattr(ss, "username", "local") or "local")
        self.user_id: int = int(getattr(ss, "user_id", 0) or 0)
        self.session_id: str = str(getattr(ss, "session_id", "") or _secrets.token_hex(16))
        self.user_role: str = str(getattr(ss, "user_role", "operator") or "operator")
        self.security_mode: str = str(getattr(ss, "security_mode", "PROD") or "PROD")
        self.seed: _Optional[int] = int(seed) if seed is not None else None
        self.created_at: str = str(getattr(ss, "created_at", "") or _datetime_now_iso())
        self.user_settings: dict[str, Any] = {}
        # Ephemere Schluessel — werden bei cleanup() zeroized
        self.live_session_key: str = ""
        self.live_session_fingerprint: str = ""
        self.raw_storage_key_hex: str = ""
        self.raw_storage_key_fingerprint: str = ""

    def get_seed(self) -> int:
        if self.seed is None:
            stable = f"{self.username}|{self.user_id}|{self.session_id}".encode("utf-8")
            self.seed = int.from_bytes(stable[:8].ljust(8, b"0"), "big", signed=False)
        return int(self.seed)

    @staticmethod
    def noise_from_seed(seed: int, length: int) -> bytes:
        seed_value = int(seed or 0) & ((1 << 64) - 1)
        target_length = max(0, int(length or 0))
        chunks = bytearray()
        counter = 0
        while len(chunks) < target_length:
            payload = f"{seed_value}:{counter}".encode("utf-8")
            chunks.extend(_hashlib.sha256(payload).digest())
            counter += 1
        return bytes(chunks[:target_length])


def secure_zeroize(obj: _Any) -> None:
    """Überschreibt sensitive Objekte im RAM mit Nullbytes (Windows-only). Fail-silent."""
    if not _sys.platform.startswith("win"):
        return
    try:
        if isinstance(obj, bytearray):
            for idx in range(len(obj)):
                obj[idx] = 0
        elif isinstance(obj, memoryview):
            try:
                obj[:] = b"\x00" * len(obj)
            except Exception as e:
                logger.warning(f"[session_engine] Stiller Fehler: {e}")
                pass
        elif isinstance(obj, (bytes, str)):
            return
        elif isinstance(obj, dict):
            for value in list(obj.values()):
                secure_zeroize(value)
            try:
                obj.clear()
            except Exception as e:
                logger.warning(f"[session_engine] Stiller Fehler: {e}")
                pass
        elif isinstance(obj, list):
            for item in list(obj):
                secure_zeroize(item)
            try:
                obj.clear()
            except Exception as e:
                logger.warning(f"[session_engine] Stiller Fehler: {e}")
                pass
    except Exception as e:
        logger.warning(f"[session_engine] Stiller Fehler: {e}")
        pass
    finally:
        try:
            _gc.collect()
        except Exception as e:
            logger.warning(f"[session_engine] Stiller Fehler: {e}")
            pass

def _session_cleanup_patch(self) -> None:
    """Zeroizt alle sensitiven Session-Keys. Nur Windows. Fail-silent."""
    try:
        from modules.security_engine import secure_zeroize
    except Exception as e:
        try:
            from .security_engine import secure_zeroize
        except Exception as e:
            logger.warning(f"[session_engine] Stiller Fehler: {e}")
            return
    for attr in ("live_session_key", "live_session_fingerprint",
                 "raw_storage_key_hex", "raw_storage_key_fingerprint"):
        try:
            secure_zeroize(getattr(self, attr, ""))
            setattr(self, attr, "")
        except Exception as e:
            logger.warning(f"[session_engine] Stiller Fehler: {e}")
            pass

# Monkey-patch cleanup + __del__ onto SessionContext
SessionContext.cleanup = _session_cleanup_patch


def _session_del_patch(self) -> None:
    try:
        self.cleanup()
    except Exception as e:
        logger.warning(f"[session_engine] Stiller Fehler: {e}")
        pass


SessionContext.__del__ = _session_del_patch