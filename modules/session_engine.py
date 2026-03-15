import gc as _gc
import sys as _sys
import ctypes as _ctypes
from typing import Any as _Any

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

SessionContext.cleanup = _session_cleanup_patch

def _session_del_patch(self) -> None:
    try:
        self.cleanup()
    except Exception:
        pass

SessionContext.__del__ = _session_del_patch