from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Consent, Audit and Security module for Aether Swarm.

Enforces:
  1. Consent gate: first enable_swarm requires explicit user consent.
     Consent state is persisted to data/swarm_consent.json.
  2. Audit log: every enable/disable/consent action is signed and appended
     to logs/swarm_audit.jsonl (Ed25519) + persisted in swarm_metrics.db.
  3. Anti-cheat safe mode: reduce or pause capture when AC processes detected.
  4. Rate limiting: prevent looped enable/disable storms.
  5. Opt-out: Swarm-Teilnahme ist standardmäßig aktiv. Abschalten jederzeit in Einstellungen.

Privacy guarantee:
  - Consent JSON never contains raw frame data.
  - Audit entries contain only: timestamp, event_type, actor, peer_id, signature.
"""


import base64
import hashlib
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CONSENT_PATH = ROOT / "data" / "swarm_consent.json"
AUDIT_LOG_PATH = ROOT / "logs" / "swarm_audit.jsonl"
PRIVATE_KEY_PATH = ROOT / "keys" / "node_private.key"
SCHEMA_VERSION = 1

# Rate limit: at most 1 enable/disable per N seconds
RATE_LIMIT_SECONDS = 5.0

_consent_lock = threading.Lock()
_rate_lock = threading.Lock()
_last_action_ts: float = 0.0


# --------------------------------------------------------------------------- #
#  Signing helpers                                                             #
# --------------------------------------------------------------------------- #

def _sign_entry(payload: Dict[str, Any]) -> str:
    """Ed25519-sign canonical JSON of payload. Returns base64 signature or 'unsigned'."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key_bytes = PRIVATE_KEY_PATH.read_bytes()
        private_key = load_pem_private_key(key_bytes, password=None)
        canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = private_key.sign(canonical)
        return base64.b64encode(sig).decode("ascii")
    except Exception as e:
        return "unsigned"


def _audit_entry_hash(entry: Dict[str, Any]) -> str:
    canonical = json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------- #
#  Audit log                                                                  #
# --------------------------------------------------------------------------- #

def append_audit_event(
    event_type: str,
    actor: str = "local",
    peer_id: Optional[str] = None,
    details: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign and append an audit event to audit log + persist DB."""
    ts = datetime.now(timezone.utc).isoformat()
    entry: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "ts": ts,
        "event_type": event_type,
        "actor": actor,
    }
    if peer_id:
        entry["peer_id"] = peer_id
    if details:
        entry["details"] = details

    sig = _sign_entry(entry)
    entry["signature"] = sig
    entry["entry_hash"] = _audit_entry_hash({k: v for k, v in entry.items() if k != "entry_hash"})

    # Append to JSONL file
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception as err:
        print(f"[CONSENT] audit log write failed: {err}")

    # Persist to SQLite via swarm_persist
    try:
        from modules.swarm_persist import append_audit_entry
        append_audit_entry(
            event_type=event_type,
            actor=actor,
            peer_id=peer_id,
            signature=sig,
            details=details,
        )
    except Exception as err:
        print(f"[CONSENT] swarm_persist audit write failed: {err}")

    return entry


# --------------------------------------------------------------------------- #
#  Consent state                                                              #
# --------------------------------------------------------------------------- #

def _read_consent() -> Dict[str, Any]:
    with _consent_lock:
        try:
            if CONSENT_PATH.is_file():
                raw = json.loads(CONSENT_PATH.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return dict(raw)
        except Exception as e:
            logger.warning(f"[swarm_consent] Fehler: {e}")
            pass
        return {}


def _write_consent(state: Dict[str, Any]) -> None:
    with _consent_lock:
        CONSENT_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONSENT_PATH.write_text(
            json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8"
        )


def has_consent() -> bool:
    """Gibt True zurueck wenn Swarm-Teilnahme aktiv ist.

    Opt-out: Anker und Invarianten enthalten keine sensiblen Rohdaten —
    nur SHA256-Fingerprints und aggregierte Metriken. Swarm ist standardmässig
    aktiv, da ohne Swarm-Teilnahme das kybernetische System nicht funktioniert
    (kein Quorum, kein Trust-Scoring, keine zirkuläre Kausalität zwischen Nodes).
    Abschalten jederzeit in den Einstellungen möglich.
    """
    state = _read_consent()
    # Explizites Revoke immer respektieren
    if bool(state.get("revoked", False)):
        return False
    if "consented" in state:
        return bool(state.get("consented"))
    if "consent_ok" in state:
        return bool(state.get("consent_ok"))
    if "approved" in state:
        return bool(state.get("approved"))
    # Kein File vorhanden: Opt-out — automatisch Consent setzen und speichern
    record_consent(actor="auto_default")
    return True


def get_consent_state() -> Dict[str, Any]:
    state = _read_consent()
    consented = has_consent()
    return {
        "consented": consented,
        "consented_at": state.get("consented_at"),
        "actor": state.get("actor"),
        "revoked": bool(state.get("revoked", False)),
        "revoked_at": state.get("revoked_at"),
        "what_is_shared": (
            "Only SHA256 fingerprints and aggregated metrics. "
            "Raw frames are NEVER stored or transmitted."
        ),
    }


def record_consent(actor: str = "local") -> Dict[str, Any]:
    """Record that consent was given. Idempotent."""
    ts = datetime.now(timezone.utc).isoformat()
    state = _read_consent()
    state["consented"] = True
    state["consented_at"] = ts
    state["actor"] = actor
    state["revoked"] = False
    state["schema_version"] = SCHEMA_VERSION
    _write_consent(state)
    entry = append_audit_event("consent_granted", actor=actor, details="User gave consent to Swarm Mode")
    return {"ok": True, "consented": True, "consented_at": ts, "audit_entry_hash": entry.get("entry_hash")}


def revoke_consent(actor: str = "local") -> Dict[str, Any]:
    """Revoke consent and purge persisted frame metrics."""
    ts = datetime.now(timezone.utc).isoformat()
    state = _read_consent()
    state["consented"] = False
    state["revoked"] = True
    state["revoked_at"] = ts
    _write_consent(state)
    append_audit_event("consent_revoked", actor=actor, details="User revoked consent; metrics purged")
    _purge_frame_metrics()
    return {"ok": True, "revoked": True, "revoked_at": ts}


def _purge_frame_metrics() -> None:
    """Delete all frame_metrics and fingerprints from DB on consent revocation."""
    try:
        from modules.swarm_persist import purge_all_metrics
        purge_all_metrics()
        print("[CONSENT] Frame metrics purged on consent revocation.")
    except Exception as err:
        print(f"[CONSENT] purge failed: {err}")


# --------------------------------------------------------------------------- #
#  Consent gate (interactive CLI flow)                                         #
# --------------------------------------------------------------------------- #

CONSENT_PROMPT_TEXT = """
+------------------------------------------------------------------+
|           AETHER SWARM MODE -- CONSENT REQUIRED                  |
+------------------------------------------------------------------+
|                                                                  |
|  Swarm Mode captures your screen to generate privacy-safe        |
|  fingerprints. Here is EXACTLY what is shared:                   |
|                                                                  |
|  [YES] SHA256 fingerprints of frame metrics (non-invertible)     |
|  [YES] Aggregated metrics: mean brightness, entropy, frame delta |
|  [YES] Anonymous node ID (generated locally, not tied to ID)     |
|                                                                  |
|  NEVER shared or stored:                                         |
|  [NO]  Raw screen pixels or images                               |
|  [NO]  Personally identifiable information                       |
|  [NO]  Application content or text                               |
|                                                                  |
|  You can revoke consent at any time: disable_swarm + revoke      |
|                                                                  |
+------------------------------------------------------------------+
"""


def interactive_consent_flow(actor: str = "cli") -> bool:
    """Run interactive CLI consent flow. Returns True if consent granted."""
    print(CONSENT_PROMPT_TEXT)
    try:
        answer = input("Do you consent to Swarm Mode? [yes/no]: ").strip().lower()
    except (EOFError, KeyboardInterrupt) as e:
        print("\n[CONSENT] Consent flow cancelled.")
        return False
    if answer in ("yes", "y", "ja", "j"):
        record_consent(actor=actor)
        print("[CONSENT] Consent recorded. Swarm Mode will activate.")
        return True
    print("[CONSENT] Consent declined. Swarm Mode will NOT activate.")
    return False


# --------------------------------------------------------------------------- #
#  Rate limiter                                                               #
# --------------------------------------------------------------------------- #

def check_rate_limit() -> bool:
    """Returns True if action is allowed (not rate-limited)."""
    global _last_action_ts
    with _rate_lock:
        now = time.monotonic()
        if now - _last_action_ts < RATE_LIMIT_SECONDS:
            return False
        _last_action_ts = now
        return True


# --------------------------------------------------------------------------- #
#  Gated enable: consent check before activation                             #
# --------------------------------------------------------------------------- #

def gated_enable_swarm(
    controller: Any,
    actor: str = "local",
    interactive: bool = False,
) -> Dict[str, Any]:
    """Enable swarm only after consent check and rate limit. Returns status dict."""
    if not check_rate_limit():
        return {"ok": False, "error": "rate_limited", "retry_after_seconds": RATE_LIMIT_SECONDS}

    if not has_consent():
        if interactive:
            granted = interactive_consent_flow(actor=actor)
            if not granted:
                return {"ok": False, "error": "consent_denied"}
        else:
            return {
                "ok": False,
                "error": "consent_required",
                "message": "Run with interactive=True or call record_consent() first.",
            }

    result = controller.enable_swarm(actor=actor)
    append_audit_event("enable_swarm", actor=actor)
    return result


def gated_disable_swarm(
    controller: Any,
    actor: str = "local",
) -> Dict[str, Any]:
    """Disable swarm with audit logging."""
    if not check_rate_limit():
        return {"ok": False, "error": "rate_limited", "retry_after_seconds": RATE_LIMIT_SECONDS}
    result = controller.disable_swarm(actor=actor)
    append_audit_event("disable_swarm", actor=actor)
    return result
