import logging
logger = logging.getLogger(__name__)
import gc as _gc
import sys as _sys
import ctypes as _ctypes
from typing import Any as _Any
from typing import Optional as _Optional


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
            logger.warning("[security_engine] Stiller Fehler")
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
                logger.warning("[security_engine] Stiller Fehler")
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
        elif isinstance(obj, memoryview):
            try:
                obj[:] = b"\x00" * len(obj)
            except Exception:
                logger.warning("[security_engine] Stiller Fehler")
                pass
        elif isinstance(obj, (bytes, str)):
            return
        elif isinstance(obj, dict):
            for value in list(obj.values()):
                secure_zeroize(value)
            try:
                obj.clear()
            except Exception:
                logger.warning("[security_engine] Stiller Fehler")
                pass
        elif isinstance(obj, list):
            for item in list(obj):
                secure_zeroize(item)
            try:
                obj.clear()
            except Exception:
                logger.warning("[security_engine] Stiller Fehler")
                pass
    except Exception:
        logger.warning("[security_engine] Stiller Fehler")
        pass
    finally:
        try:
            _gc.collect()
        except Exception:
            logger.warning("[security_engine] Stiller Fehler")
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
        logger.warning(f"[security_engine] Fehler: {exc}")
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
        logger.warning("[security_engine] Stiller Fehler")
        return {}


def pseudonymous_network_identity(session_like: _Any, purpose: str = "public") -> str:
    username = str(getattr(session_like, "username", "") or "local")
    session_id = str(getattr(session_like, "session_id", "") or "")
    seed = f"{purpose}|{username}|{session_id}".encode("utf-8")
    return _se_hashlib.sha256(seed).hexdigest()[:24]


def public_ttd_share_policy(scope: str = "metrics_only") -> dict:
    normalized = str(scope or "metrics_only").strip().lower()
    if normalized == "signed":
        return {
            "scope": normalized,
            "share_public_anchor": True,
            "share_signature": True,
            "raw_data_included": False,
            "deltas_included": False,
            "internal_only": False,
        }
    return {
        "scope": "metrics_only",
        "share_public_anchor": True,
        "share_signature": False,
        "raw_data_included": False,
        "deltas_included": False,
        "internal_only": False,
    }


def public_ttd_quorum_policy(session_like: _Any) -> dict:
    role = str(getattr(session_like, "user_role", "operator") or "operator").strip().lower()
    auto_trusted = role == "admin"
    return {
        "uploader_role": role or "operator",
        "quorum_threshold": 1 if auto_trusted else 3,
        "auto_trusted": auto_trusted,
    }


import re as _re

_SENSITIVE_PATTERNS = {
    "iban": _re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "credential": _re.compile(
        r"\b(password|passwort|pwd|pin|tan|otp|cvv|iban|bic|login|konto|account)\b\s*[:=]\s*\S+",
        _re.IGNORECASE,
    ),
    "seed_phrase": _re.compile(r"\b(seed phrase|mnemonic|wallet seed|recovery phrase)\b", _re.IGNORECASE),
}
_CARD_PATTERN = _re.compile(r"(?:\d[ -]*?){13,19}")
_BANKING_KEYWORDS = frozenset(
    ("banking", "onlinebanking", "kreditkarte", "debitkarte", "iban", "tan")
)


def _luhn_valid(number_text: str) -> bool:
    """Prueft eine Ziffernfolge gegen den Luhn-Algorithmus (Kreditkarten)."""
    digits = [int(c) for c in str(number_text) if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        val = digit * 2 if idx % 2 == parity else digit
        if val > 9:
            val -= 9
        checksum += val
    return checksum % 10 == 0


def sensitive_data_scan(text: str) -> dict:
    """
    Scannt Text auf strukturell erkennbare sensitive Datenfelder.

    Erkennt: IBAN-Muster, Credential-Paare (key=value), Seed-Phrasen,
    Kreditkartennummern (Luhn-validiert), Banking-Keywords.

    Gibt ein Dict mit 'hits' (Trefferliste) und 'sensitive' (bool) zurueck.
    Kein semantisches Urteil — nur Mustererkennung.
    """
    raw = str(text or "")
    hits: list[str] = []
    for label, pattern in _SENSITIVE_PATTERNS.items():
        if pattern.search(raw):
            hits.append(label)
    for match in _CARD_PATTERN.findall(raw):
        if _luhn_valid(match):
            hits.append("credit_card")
            break
    lowered = raw.lower()
    if any(kw in lowered for kw in _BANKING_KEYWORDS):
        hits.append("banking_keyword")
    unique_hits = sorted(set(hits))
    return {"sensitive": bool(unique_hits), "hits": unique_hits}


def validate_public_ttd_candidate(
    candidate: dict,
    *,
    fingerprint_payload: _Optional[dict] = None,
    reflection_payload: _Optional[dict] = None,
) -> dict:
    candidate_payload = dict(candidate or {})
    public_metrics = dict(candidate_payload.get("public_metrics", {}) or {})
    residual = float(public_metrics.get("residual", candidate_payload.get("residual", 0.0)) or 0.0)
    symmetry = float(public_metrics.get("symmetry", candidate_payload.get("symmetry", 0.0)) or 0.0)
    i_obs_ratio = float(public_metrics.get("i_obs_ratio", 0.0) or 0.0)
    delta_stability = float(candidate_payload.get("delta_stability", 0.0) or 0.0)
    recursive_count = int(len(list(dict(reflection_payload or {}).get("recursive_reflections", []) or [])))
    valid = bool(str(candidate_payload.get("hash", "") or "").strip())
    valid = valid and residual >= 0.0 and symmetry > 0.0 and delta_stability > 0.0
    return {
        "valid": valid,
        "metrics": {
            "residual": residual,
            "symmetry": symmetry,
            "i_obs_ratio": i_obs_ratio,
            "delta_stability": delta_stability,
            "recursive_count": recursive_count,
            "source_label": str(dict(fingerprint_payload or {}).get("source_label", "") or ""),
        },
        "reason": "ok" if valid else "invalid_candidate",
    }