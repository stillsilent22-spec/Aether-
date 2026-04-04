from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
"""modules/session_guard.py — Entry-point enforcement for Aether.

Every runnable script that is NOT the main registration window must call
`require_session()` as the first action inside its `if __name__ == "__main__"`
block.  The function exits with a clear error message when no valid registered
session exists, preventing modules from being used in isolation without first
going through the bootstrap/registration window (python start.py).

Device-lock enforcement:
  - Exactly ONE account per device is allowed.
  - The same account cannot run on two different devices.
  - Violation aborts with a clear message and exit code 1.
"""

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SETTINGS_FILE = _ROOT / "data" / "settings.json"
_KEY_FILE = _ROOT / "data" / "keys" / "node_private.key"
_ENTRY_HINT = "Start Aether via the registration window:  python start.py"


def _derive_node_id_from_key(key_path: Path) -> str:
    """Leitet die node_id aus dem oeffentlichen Schluessel ab."""
    try:
        import hashlib
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pem = key_path.read_bytes()
        private_key = load_pem_private_key(pem, password=None)
        pub = private_key.public_key()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return hashlib.sha256(pub_bytes).hexdigest()[:16]
    except Exception:
        return ""


def require_session() -> None:
    """Abort with an informative message if no valid registered session exists.

    Checks:
    1. data/settings.json exists and contains solo_genesis_mode = True
    2. data/keys/node_private.key exists (generated during bootstrap)
    3. Device binding: this key belongs to THIS hardware (device_lock)
    4. No second account exists on this device (device_lock)
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

    # Device-lock check: one account per device, one device per account
    try:
        from modules.device_lock import verify_binding, DeviceLockError, initialize_binding
        node_id = _derive_node_id_from_key(_KEY_FILE)
        if not node_id:
            # Can't verify without node_id — skip silently (degraded state)
            logger.warning("[session_guard] node_id konnte nicht abgeleitet werden — device_lock uebersprungen.")
            return
        try:
            verify_binding(node_id)
        except DeviceLockError as lock_err:
            print(f"\n[AETHER] DEVICE-LOCK VERLETZUNG:\n  {lock_err}\n\n  {_ENTRY_HINT}")
            sys.exit(1)
    except ImportError:
        logger.warning("[session_guard] device_lock nicht verfuegbar — Bindungspruefung uebersprungen.")
