import sys as _ls_sys
from typing import Any as _ls_Any

class ProtectedSecret:
    """Kontextmanager für sichere Nutzung lokaler Secrets. Zeroizt nach Verwendung. Windows-only."""
    def __init__(self, protected_value: str) -> None:
        self._protected = str(protected_value or "")
        self._cleartext: str | None = None
    def __enter__(self) -> str:
        self._cleartext = unprotect_local_secret(self._protected)
        return self._cleartext
    def __exit__(self, *args: _ls_Any) -> None:
        if _ls_sys.platform.startswith("win") and self._cleartext is not None:
            try:
                import ctypes
                ctypes.memset(ctypes.cast(id(self._cleartext),ctypes.c_void_p),0,_ls_sys.getsizeof(self._cleartext))
            except Exception:
                pass
        self._cleartext = None
    def __del__(self) -> None:
        try: self.__exit__()
        except Exception: pass