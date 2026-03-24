import gc as _gc
import sys as _sys
import ctypes as _ctypes
from typing import Any as _Any


class SecurityManager:
    """
    Verwaltet Login und Sitzungseroeffnung fuer Aether.

    ``prompt_login()`` oeffnet einen tkinter-Dialog (GUI-Modus) oder
    faellt auf einen CLI-Prompt zurueck. Gibt eine ``SecuritySession``
    zurueck, die anschliessend in einen ``SessionContext`` gehuellt wird.
    """

    def __init__(self, registry: "Any" = None) -> None:
        self.registry = registry

    def prompt_login(self) -> "Any":
        """Loginmaske: tkinter-Dialog mit CLI-Fallback. Gibt SecuritySession zurueck."""
        try:
            from .session_engine import SecuritySession
        except ImportError:
            from modules.session_engine import SecuritySession  # type: ignore

        username = ""
        user_id = 0
        user_role = "operator"

        # --- tkinter Login-Dialog ---
        try:
            import tkinter as tk
            import tkinter.simpledialog as sd

            root = tk.Tk()
            root.withdraw()
            raw = sd.askstring(
                "Aether Login",
                "Benutzername:",
                parent=root,
            )
            root.destroy()
            if raw is not None:
                username = str(raw).strip()
        except Exception:
            pass

        # --- CLI-Fallback ---
        if not username:
            try:
                username = input("Aether Login — Benutzername: ").strip()
            except Exception:
                username = "local"

        if not username:
            username = "local"

        # Nutzer-ID aus Registry laden (best-effort)
        if self.registry is not None:
            try:
                record = self.registry.get_user_by_name(username)
                if record:
                    user_id = int(record.get("user_id", 0) or 0)
                    user_role = str(record.get("role", "operator") or "operator")
            except Exception:
                pass

        return SecuritySession(
            username=username,
            user_id=user_id,
            user_role=user_role,
        )


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


# ---------------------------------------------------------------------------
# Device-scoped payload encryption helpers — required by observer_engine, etc.
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet as _se_Fernet
    _SE_CRYPTO = True
except ImportError:
    _SE_CRYPTO = False

import hashlib as _se_hashlib
import base64 as _se_base64
import json as _se_json


def _se_derive_key(purpose: str, session_salt: str, session_id: str) -> bytes:
    """Interner Helfer: SHA256-basierter Fernet-Key aus purpose + salt + session_id."""
    digest = _se_hashlib.sha256(
        f"{purpose}|{session_salt}|{session_id}".encode("utf-8")
    ).digest()
    return _se_base64.urlsafe_b64encode(digest)


def encrypt_device_scoped_payload(
    payload: dict, session_like: _Any, purpose: str, session_salt: str
) -> dict:
    """Serialisiert und verschluesselt payload mit einem sitzungsgebundenen Key."""
    try:
        if not _SE_CRYPTO:
            raise RuntimeError("cryptography not available")
        sid = str(getattr(session_like, "session_id", "") or "")
        key = _se_derive_key(purpose, session_salt, sid)
        token = _se_Fernet(key).encrypt(_se_json.dumps(payload).encode("utf-8")).decode()
        return {"v": 1, "purpose": purpose, "token": token}
    except Exception as exc:
        return {"v": 1, "purpose": purpose, "token": "", "error": str(exc)}


def decrypt_device_scoped_payload(
    envelope: dict, session_like: _Any, purpose: str, session_salt: str
) -> dict:
    """Entschluesselt ein envelope-dict von encrypt_device_scoped_payload. Bei Fehler: {}."""
    try:
        if not _SE_CRYPTO:
            return {}
        if envelope.get("purpose") != purpose:
            return {}
        sid = str(getattr(session_like, "session_id", "") or "")
        key = _se_derive_key(purpose, session_salt, sid)
        raw = _se_Fernet(key).decrypt(envelope["token"].encode("utf-8")).decode("utf-8")
        return _se_json.loads(raw)
    except Exception:
        return {}