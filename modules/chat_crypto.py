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