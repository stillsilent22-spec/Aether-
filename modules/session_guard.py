from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
"""modules/session_guard.py — Entry-point enforcement for Aether.

Every runnable script that is NOT the main registration window must call
`require_session()` as the first action inside its `if __name__ == "__main__"`
block.  The function exits with a clear error message when no valid registered
session exists, preventing modules from being used in isolation without first
going through the bootstrap/registration window (python start.py).
"""

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS_FILE = _ROOT / "data" / "settings.json"
_KEY_FILE = _ROOT / "data" / "keys" / "node_private.key"
_ENTRY_HINT = "Start Aether via the registration window:  python start.py"


def require_session() -> None:
    """Abort with an informative message if no valid registered session exists.

    Checks:
    1. data/settings.json exists and contains solo_genesis_mode = True
    2. data/keys/node_private.key exists (generated during bootstrap)
    """
    if not _SETTINGS_FILE.is_file():
        print(f"[AETHER] No session found — registration required.\n  {_ENTRY_HINT}")
        sys.exit(1)

    try:
        settings = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
        if not settings.get("solo_genesis_mode"):
            raise ValueError("solo_genesis_mode not set")
    except Exception as e:
        print(f"[AETHER] Session invalid or incomplete — please re-register.\n  {_ENTRY_HINT}")
        sys.exit(1)

    if not _KEY_FILE.is_file():
        print(f"[AETHER] Node identity missing — registration required.\n  {_ENTRY_HINT}")
        sys.exit(1)
