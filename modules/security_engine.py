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