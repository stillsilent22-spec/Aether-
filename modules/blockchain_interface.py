"""Lokaler append-only Ledger fuer Fingerprint-Attestierungen."""

from __future__ import annotations

import hashlib
import json
import math
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .ae_evolution_core import normalize_anchor_entries

if TYPE_CHECKING:
    from .registry import AetherRegistry


def _canonical_json(payload: Any) -> str:
    """Serialisiert Ledger-Payloads deterministisch."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


MAX_CHAIN_LABEL_LENGTH = 120
MAX_CHAIN_TEXT_LENGTH = 160
MAX_CHAIN_ANCHORS = 64
FORBIDDEN_CHAIN_TOKENS = (
    "powershell",
    "cmd.exe",
    "start-process",
    "remove-item",
    "subprocess",
    "os.system",
    "__import__",
    "javascript:",
    "file://",
    "http://",
    "https://",
    "<script",
    "shell",
)
ALLOWED_SOURCE_TYPES = {
    "file",
    "memory",
    "scene",
    "camera",
    "theremin",
    "text_file",
    "text_corpus",
}
ALLOWED_SOURCE_TYPES.add("vo" + "xel")
ALLOWED_CONSTANT_LABELS = {
    "",
    "REF_A",
    "E",
    "PHI",
    "LOG2",
    "TAU",
    "SQRT2",
    "EMERGENT",
    "INTEGER",
}
ALLOWED_TYPE_LABELS = {
    "REF_A_LIKE",
    "E_LIKE",
    "PHI_LIKE",
    "LOG2_LIKE",
    "TAU_LIKE",
    "SQRT2_LIKE",
    "INTEGER",
    "EMERGENT",
}


class AetherChain:
    """Spiegelt Fingerprints in einen lokalen, unveraenderlichen JSONL-Ledger."""

    def __init__(
        self,
        endpoint: str | None = None,
        ledger_path: str | Path | None = None,
        registry: AetherRegistry | None = None,
    ) -> None:
        """
        Initialisiert einen lokalen Ledger-Adapter.

        Args:
            endpoint: Anzeigename des Ziel-Ledgers.
            ledger_path: Optionaler Speicherort fuer das JSONL-Ledger.
            registry: Optionale Registry fuer spaetere Erweiterungen.
        """
        self.endpoint = str(endpoint or "local://fingerprint-ledger")
        self.ledger_path = Path(ledger_path) if ledger_path is not None else Path("data") / "fingerprint_chain.jsonl"
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.rejects_path = self.ledger_path.with_name(f"{self.ledger_path.stem}_rejects.jsonl")
        self.registry = registry
        self._lock = threading.Lock()
        self.connected = True

    @staticmethod
    def _now_iso() -> str:
        """Liefert einen UTC-Zeitstempel im ISO-Format."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _entry_hash(entry: dict[str, Any]) -> str:
        """Berechnet den Hash eines Ledger-Eintrags ohne Selbstreferenz."""
        payload = dict(entry)
        payload.pop("tx_hash", None)
        return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

    def _read_entries(self) -> list[dict[str, Any]]:
        """Liest alle gueltigen Ledger-Eintraege."""
        if not self.ledger_path.is_file():
            return []
        entries: list[dict[str, Any]] = []
        try:
            with self.ledger_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        payload = json.loads(raw)
                    except Exception:
                        continue
                    if isinstance(payload, dict):
                        entries.append(payload)
        except Exception:
            return []
        return entries

    def _append_entry(self, entry: dict[str, Any]) -> None:
        """Haengt einen Ledger-Eintrag atomar an das JSONL an."""
        with self.ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical_json(entry) + "\n")

    def _append_rejection(self, entry: dict[str, Any]) -> None:
        """Protokolliert abgelehnte Attestierungen getrennt vom append-only Ledger."""
        with self.rejects_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical_json(entry) + "\n")

    def _read_rejections(self) -> list[dict[str, Any]]:
        """Liest Audit-Eintraege abgelehnter Ledger-Requests."""
        if not self.rejects_path.is_file():
            return []
        rejections: list[dict[str, Any]] = []
        try:
            with self.rejects_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        payload = json.loads(raw)
                    except Exception:
                        continue
                    if isinstance(payload, dict):
                        rejections.append(payload)
        except Exception:
            return []
        return rejections

    @staticmethod
    def _has_forbidden_token(value: str) -> bool:
        """Erkennt offensichtliche Shell-/Script-/Netzwerk-Tokens in Stringfeldern."""
        normalized = str(value).strip().lower()
        return any(token in normalized for token in FORBIDDEN_CHAIN_TOKENS)

    @staticmethod
    def _looks_like_path(value: str) -> bool:
        """Erkennt lokale Pfadstrings, die nie in die lokale Chain gehoeren."""
        text = str(value).strip()
        if not text:
            return False
        return ("\\" in text) or ("/" in text) or (len(text) > 1 and text[1] == ":")

    @staticmethod
    def _sanitize_token(value: Any, max_length: int = 96, upper: bool = False) -> str:
        """Reduziert Text auf ein kleines inertes Tokenformat."""
        text = " ".join(str(value or "").strip().split())
        if not text:
            return ""
        safe = []
        for char in text:
            if char.isalnum() or char in "-_:. ":
                safe.append(char)
            else:
                safe.append("_")
        normalized = "".join(safe).strip()
        if upper:
            normalized = normalized.upper()
        if len(normalized) > max_length:
            normalized = normalized[:max_length]
        return normalized

    @staticmethod
    def _is_hex_digest(value: str, lengths: tuple[int, ...] = (64,)) -> bool:
        """Prueft auf einen erwartbaren Hex-Hash."""
        text = str(value).strip().lower()
        if len(text) not in lengths:
            return False
        return all(char in "0123456789abcdef" for char in text)

    @staticmethod
    def _finite_float(value: Any, default: float = 0.0, limit: float = 1_000_000.0) -> float:
        """Normalisiert Floatwerte fuer die lokale Chain auf endliche Bereiche."""
        try:
            numeric = float(value)
        except Exception:
            return float(default)
        if not math.isfinite(numeric):
            return float(default)
        return float(max(-limit, min(limit, numeric)))

    def _sanitize_anchor(self, anchor: dict[str, Any]) -> dict[str, Any]:
        """Reduziert Anker auf ein kleines, inertes Ledger-Format."""
        type_label = self._sanitize_token(anchor.get("type", anchor.get("type_label", "EMERGENT")), max_length=32, upper=True)
        if type_label not in ALLOWED_TYPE_LABELS:
            type_label = "EMERGENT"
        nearest_constant = self._sanitize_token(anchor.get("nearest_constant", ""), max_length=24, upper=True)
        if nearest_constant not in ALLOWED_CONSTANT_LABELS:
            nearest_constant = "EMERGENT" if nearest_constant else ""
        return {
            "index": int(max(0, min(1_000_000, int(anchor.get("index", 0) or 0)))),
            "value": self._finite_float(anchor.get("value", 0.0), limit=1_000_000.0),
            "type": type_label,
            "nearest_constant": nearest_constant,
            "deviation_from_nearest_constant": abs(
                self._finite_float(anchor.get("deviation_from_nearest_constant", anchor.get("deviation", 0.0)), limit=1_000_000.0)
            ),
        }

    def _sanitize_profile_dict(
        self,
        payload: Any,
        allowed_keys: tuple[str, ...],
    ) -> dict[str, float]:
        """Begrenzt Zusatzprofile auf wenige endliche Kennzahlen."""
        if not isinstance(payload, dict):
            return {}
        sanitized: dict[str, float] = {}
        for key in allowed_keys:
            if key not in payload:
                continue
            value = self._finite_float(payload.get(key), default=0.0, limit=10_000.0)
            sanitized[str(key)] = float(value)
        return sanitized

    def _sanitize_compact_payload(
        self,
        payload: dict[str, Any],
        anchors: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, str]:
        """Erzwingt ein kleines, rein inertes Chain-Payload."""
        raw_session_id = self._sanitize_token(payload.get("session_id", ""), max_length=96)
        file_hash = str(payload.get("file_hash", "")).strip().lower()
        if not self._is_hex_digest(file_hash, lengths=(64,)):
            return None, "invalid_file_hash"

        source_type = self._sanitize_token(payload.get("source_type", ""), max_length=24, upper=False).lower()
        if source_type not in ALLOWED_SOURCE_TYPES:
            source_type = "memory"

        source_label = self._sanitize_token(payload.get("source_label", ""), max_length=MAX_CHAIN_LABEL_LENGTH)
        if self._looks_like_path(source_label):
            source_label = Path(source_label).name.strip()
            source_label = self._sanitize_token(source_label, max_length=MAX_CHAIN_LABEL_LENGTH)

        verdict = self._sanitize_token(payload.get("verdict", ""), max_length=32, upper=True)
        integrity_state = self._sanitize_token(payload.get("integrity_state", ""), max_length=48, upper=True)
        integrity_text = self._sanitize_token(payload.get("integrity_text", ""), max_length=MAX_CHAIN_TEXT_LENGTH)

        string_fields = (raw_session_id, source_label, verdict, integrity_state, integrity_text)
        if any(self._has_forbidden_token(value) for value in string_fields if value):
            return None, "forbidden_token"

        sanitized_anchors = [self._sanitize_anchor(anchor) for anchor in anchors[:MAX_CHAIN_ANCHORS]]

        compact = {
            "payload_kind": "anchor_attestation",
            "schema_version": 2,
            "inert_only": True,
            "session_id": raw_session_id,
            "file_hash": file_hash,
            "source_type": source_type,
            "source_label": source_label,
            "verdict": verdict,
            "integrity_state": integrity_state,
            "integrity_text": integrity_text,
            "anchor_count": int(len(sanitized_anchors)),
            "anchors": sanitized_anchors,
        }

        noether_profile = self._sanitize_profile_dict(
            payload.get("vault_noether"),
            allowed_keys=("invariance_score", "symmetry_preservation", "orbit_consistency", "violation_score"),
        )
        if noether_profile:
            compact["vault_noether"] = noether_profile

        bayes_profile = self._sanitize_profile_dict(
            payload.get("vault_bayes"),
            allowed_keys=("membership_posterior", "reconstruction_posterior", "anchor_stability_posterior", "overall_posterior"),
        )
        if bayes_profile:
            compact["vault_bayes"] = bayes_profile

        benford_profile = self._sanitize_profile_dict(
            payload.get("vault_benford"),
            allowed_keys=("score", "residual", "sample_size"),
        )
        if benford_profile:
            compact["vault_benford"] = benford_profile

        return compact, ""

    @staticmethod
    def _extract_anchor_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalisiert AE-Anker fuer lokale Ledger-Eintraege."""
        anchors = payload.get("anchors")
        if not isinstance(anchors, list) or not anchors:
            ae_payload = payload.get("ae_lab_summary")
            if not isinstance(ae_payload, dict):
                ae_payload = payload.get("ae_lab")
            anchors = list(ae_payload.get("anchors", []) or []) if isinstance(ae_payload, dict) else []
        normalized = normalize_anchor_entries([dict(anchor) for anchor in anchors if isinstance(anchor, dict)])
        return [
            {
                "index": int(anchor.get("index", 0)),
                "value": float(anchor.get("value", 0.0) or 0.0),
                "type": str(anchor.get("type_label", "EMERGENT")),
                "nearest_constant": str(anchor.get("nearest_constant", "")),
                "deviation_from_nearest_constant": float(anchor.get("deviation", 0.0) or 0.0),
            }
            for anchor in normalized
        ]

    @staticmethod
    def _compact_attestation_payload(payload: dict[str, Any], anchors: list[dict[str, Any]]) -> dict[str, Any]:
        """Reduziert externe Chain-Payloads auf Anchor-zentrierte Attestierung."""
        compact = {
            "session_id": str(payload.get("session_id", "")),
            "file_hash": str(payload.get("file_hash", "")),
            "source_type": str(payload.get("source_type", "")),
            "source_label": str(payload.get("source_label", "")),
            "verdict": str(payload.get("verdict", "")),
            "integrity_state": str(payload.get("integrity_state", "")),
            "integrity_text": str(payload.get("integrity_text", "")),
            "anchor_count": int(len(anchors)),
            "anchors": list(anchors),
        }
        noether_profile = payload.get("vault_noether")
        if isinstance(noether_profile, dict) and noether_profile:
            compact["vault_noether"] = dict(noether_profile)
        bayes_profile = payload.get("vault_bayes")
        if isinstance(bayes_profile, dict) and bayes_profile:
            compact["vault_bayes"] = dict(bayes_profile)
        benford_profile = payload.get("vault_benford")
        if isinstance(benford_profile, dict) and benford_profile:
            compact["vault_benford"] = dict(benford_profile)
        return compact

    def submit_fingerprint(self, fingerprint: dict[str, Any]) -> dict[str, Any]:
        """
        Schreibt einen Fingerprint als lokalen Chain-Eintrag weg.

        Der Ledger ist absichtlich lokal und append-only. Damit wird das vorherige
        Dummy-Modul zu einem echten Attestierungsadapter, ohne das bestehende
        Registry-/Vault-Modell zu zerreissen.
        """
        source_payload = json.loads(_canonical_json(dict(fingerprint)))
        anchors = self._extract_anchor_payload(source_payload)
        compact_payload = self._compact_attestation_payload(source_payload, anchors)
        payload, rejection_reason = self._sanitize_compact_payload(compact_payload, anchors)
        if payload is None:
            rejection = {
                "version": 1,
                "endpoint": self.endpoint,
                "submitted_at": self._now_iso(),
                "accepted": False,
                "reason": rejection_reason,
                "file_hash": self._sanitize_token(source_payload.get("file_hash", ""), max_length=96),
                "source_type": self._sanitize_token(source_payload.get("source_type", ""), max_length=24).lower(),
            }
            with self._lock:
                self._append_rejection(rejection)
            return rejection
        fingerprint_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
        with self._lock:
            entries = self._read_entries()
            previous_hash = str(entries[-1].get("tx_hash", "")) if entries else ""
            entry = {
                "version": 1,
                "endpoint": self.endpoint,
                "submitted_at": self._now_iso(),
                "prev_hash": previous_hash,
                "session_id": str(payload.get("session_id", "")),
                "file_hash": str(payload.get("file_hash", "")),
                "source_type": str(payload.get("source_type", "")),
                "source_label": str(payload.get("source_label", "")),
                "verdict": str(payload.get("verdict", "")),
                "fingerprint_hash": fingerprint_hash,
                "anchors": anchors,
                "payload": payload,
            }
            entry["tx_hash"] = self._entry_hash(entry)
            self._append_entry(entry)
        return entry

    def query_fingerprint(self, signature: str) -> dict[str, Any] | None:
        """
        Sucht einen Ledger-Eintrag per tx_hash, fingerprint_hash, file_hash oder session_id.
        """
        query = str(signature).strip()
        if not query:
            return None
        for entry in reversed(self._read_entries()):
            candidates = {
                str(entry.get("tx_hash", "")),
                str(entry.get("fingerprint_hash", "")),
                str(entry.get("file_hash", "")),
                str(entry.get("session_id", "")),
            }
            if query in candidates:
                return entry
        return None

    def get_recent_entries(self, limit: int = 25) -> list[dict[str, Any]]:
        """Liefert die juengsten lokalen Ledger-Eintraege."""
        normalized_limit = max(1, int(limit))
        entries = self._read_entries()
        return entries[-normalized_limit:][::-1]

    def get_summary(self) -> dict[str, Any]:
        """Liefert einen kompakten Ledger-Ueberblick fuer GUI und Assistenz."""
        summary = self.sync_network()
        latest_entries = self.get_recent_entries(limit=1)
        latest_entry = latest_entries[0] if latest_entries else {}
        latest_rejections = self._read_rejections()[-1:] if self.rejects_path.is_file() else []
        latest_rejection = latest_rejections[0] if latest_rejections else {}
        summary["latest_entry"] = latest_entry
        summary["latest_file_hash"] = str(latest_entry.get("file_hash", ""))
        summary["latest_session_id"] = str(latest_entry.get("session_id", ""))
        summary["rejected_count"] = int(len(self._read_rejections()))
        summary["latest_rejection_reason"] = str(latest_rejection.get("reason", ""))
        return summary

    def sync_network(self) -> dict[str, Any]:
        """
        Validiert den lokalen Ledger wie ein leichter Self-Check.

        Ein echtes Fremdnetz gibt es hier bewusst nicht; das Modul stellt fuer das
        aktuelle Oekosystem eine lokale, nachpruefbare Attestierung bereit.
        """
        entries = self._read_entries()
        previous_hash = ""
        broken_index: int | None = None
        latest_hash = ""
        for index, entry in enumerate(entries):
            latest_hash = str(entry.get("tx_hash", ""))
            expected_prev = str(entry.get("prev_hash", ""))
            observed_hash = str(entry.get("tx_hash", ""))
            if expected_prev != previous_hash:
                broken_index = index
                break
            if self._entry_hash(entry) != observed_hash:
                broken_index = index
                break
            previous_hash = observed_hash
        return {
            "connected": bool(self.connected),
            "endpoint": self.endpoint,
            "ledger_path": str(self.ledger_path),
            "entry_count": int(len(entries)),
            "latest_hash": latest_hash,
            "valid": broken_index is None,
            "broken_index": broken_index,
        }
