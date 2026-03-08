"""Oeffentliche Verankerung mit lokalem Receipt- und Retry-Pfad."""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


DEFAULT_SETTINGS = {
    "blockcypher_token": "",
    "pinata_jwt": "",
    "pinata_api_key": "",
    "pinata_api_secret": "",
}


def _canonical_json(payload: Any) -> str:
    """Serialisiert Public-Anchor-Payloads deterministisch."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


class PublicBlockchainAnchor:
    """Verankert bestaetigte Bloecke sinnvoll lokal und optional online."""

    def __init__(self, settings_path: str) -> None:
        self.settings_path = Path(settings_path)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.queue_path = self.settings_path.parent / "public_anchor_queue.json"
        self.receipt_path = self.settings_path.parent / "public_anchor_receipts.jsonl"
        self._lock = threading.Lock()

    @staticmethod
    def _now_iso() -> str:
        """Liefert einen UTC-Zeitstempel."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _payload_hash(block_payload: dict[str, Any]) -> str:
        """Hash des zu verankernden Block-Payloads."""
        return hashlib.sha256(_canonical_json(dict(block_payload)).encode("utf-8")).hexdigest()

    @staticmethod
    def _block_hash(block_payload: dict[str, Any]) -> str:
        """Bevorzugt den bereits berechneten Block-Hash, sonst den Payload-Hash."""
        return str(block_payload.get("block_hash", "")).strip() or PublicBlockchainAnchor._payload_hash(block_payload)

    def _append_receipt(self, receipt: dict[str, Any]) -> None:
        """Haengt einen lokalen Receipt append-only an."""
        with self.receipt_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical_json(receipt) + "\n")

    def _load_queue_unlocked(self) -> list[dict[str, Any]]:
        """Liest den Pending-Anchor-Queue-Stand ohne zusaetzliche Sperren."""
        if not self.queue_path.is_file():
            return []
        try:
            payload = json.loads(self.queue_path.read_text(encoding="utf-8"))
        except Exception:
            return []
        return payload if isinstance(payload, list) else []

    def _save_queue_unlocked(self, jobs: list[dict[str, Any]]) -> None:
        """Speichert die Pending-Queue ohne zusaetzliche Sperren."""
        self.queue_path.write_text(json.dumps(jobs, ensure_ascii=True, indent=2), encoding="utf-8")

    def _has_blockcypher(self, settings: dict[str, str]) -> bool:
        """Prueft auf BlockCypher-Zugangsdaten."""
        return bool(str(settings.get("blockcypher_token", "")).strip())

    def _has_pinata(self, settings: dict[str, str]) -> bool:
        """Prueft auf Pinata-Zugangsdaten."""
        jwt = str(settings.get("pinata_jwt", "")).strip()
        api_key = str(settings.get("pinata_api_key", "")).strip()
        api_secret = str(settings.get("pinata_api_secret", "")).strip()
        return bool(jwt) or bool(api_key and api_secret)

    def _queue_job(
        self,
        block_payload: dict[str, Any],
        status: str,
        error: str = "",
        partial: dict[str, Any] | None = None,
        anchor_job_id: str = "",
    ) -> tuple[dict[str, Any], int]:
        """Merkt einen Block fuer spaetere Nachverankerung vor."""
        payload_hash = self._payload_hash(block_payload)
        block_hash = self._block_hash(block_payload)
        now = self._now_iso()
        with self._lock:
            jobs = self._load_queue_unlocked()
            existing = None
            if anchor_job_id:
                existing = next((job for job in jobs if str(job.get("anchor_job_id", "")) == anchor_job_id), None)
            if existing is None:
                existing = next((job for job in jobs if str(job.get("payload_hash", "")) == payload_hash), None)
            if existing is None:
                existing = {
                    "anchor_job_id": anchor_job_id or hashlib.sha256(f"{payload_hash}|{now}".encode("utf-8")).hexdigest()[:24],
                    "created_at": now,
                    "payload": dict(block_payload),
                    "payload_hash": payload_hash,
                    "block_hash": block_hash,
                    "attempts": 0,
                }
                jobs.append(existing)
            existing["updated_at"] = now
            existing["status"] = str(status)
            existing["last_error"] = str(error)
            existing["attempts"] = int(existing.get("attempts", 0)) + 1
            if partial:
                if partial.get("eth_tx"):
                    existing["eth_tx"] = str(partial.get("eth_tx", ""))
                if partial.get("ipfs_cid"):
                    existing["ipfs_cid"] = str(partial.get("ipfs_cid", ""))
            self._save_queue_unlocked(jobs)
            return dict(existing), int(len(jobs))

    def _remove_job(self, anchor_job_id: str) -> int:
        """Entfernt einen erledigten Pending-Job aus der Queue."""
        if not str(anchor_job_id).strip():
            return self.pending_count()
        with self._lock:
            jobs = self._load_queue_unlocked()
            filtered = [job for job in jobs if str(job.get("anchor_job_id", "")) != str(anchor_job_id)]
            self._save_queue_unlocked(filtered)
            return int(len(filtered))

    def _store_receipt(
        self,
        block_payload: dict[str, Any],
        mode: str,
        status: str,
        eth_tx: str = "",
        ipfs_cid: str = "",
        error: str = "",
        anchor_job_id: str = "",
    ) -> dict[str, Any]:
        """Persistiert ein lokales Receipt fuer jeden Anchor-Versuch."""
        now = self._now_iso()
        payload_hash = self._payload_hash(block_payload)
        receipt = {
            "receipt_id": hashlib.sha256(f"{payload_hash}|{status}|{now}".encode("utf-8")).hexdigest()[:24],
            "timestamp": now,
            "mode": str(mode),
            "status": str(status),
            "block_hash": self._block_hash(block_payload),
            "payload_hash": payload_hash,
            "eth_tx": str(eth_tx),
            "ipfs_cid": str(ipfs_cid),
            "error": str(error),
            "anchor_job_id": str(anchor_job_id),
        }
        with self._lock:
            self._append_receipt(receipt)
        return receipt

    def _build_result(
        self,
        receipt: dict[str, Any],
        queue_size: int,
    ) -> dict[str, Any]:
        """Verdichtet Receipt-Daten fuer GUI und Registry."""
        return {
            "mode": str(receipt.get("mode", "")),
            "anchor_status": str(receipt.get("status", "")),
            "eth_tx": str(receipt.get("eth_tx", "")),
            "ipfs_cid": str(receipt.get("ipfs_cid", "")),
            "error": str(receipt.get("error", "")),
            "anchor_job_id": str(receipt.get("anchor_job_id", "")),
            "anchor_receipt_id": str(receipt.get("receipt_id", "")),
            "queue_size": int(queue_size),
        }

    def _push_blockcypher_raw_tx(self, raw_tx: str, settings: dict[str, str]) -> tuple[str, str, bool]:
        """
        Uebergibt nur bereits signierte Ethereum-Transaktionen an BlockCypher.

        Damit wird kein falscher "fake on-chain" Request mehr erzeugt. Ohne `eth_raw_tx`
        im Payload bleibt der Blockchain-Teil bewusst unvollstaendig.
        """
        token = str(settings.get("blockcypher_token", "")).strip()
        if not token:
            return "", "blockcypher_token_missing", False
        try:
            payload = json.dumps({"tx": str(raw_tx).strip()}).encode("utf-8")
            request = urllib.request.Request(
                f"https://api.blockcypher.com/v1/eth/main/txs/push?token={token}",
                data=payload,
                method="POST",
            )
            request.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(request, timeout=12) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace") or "{}")
            tx_hash = str(body.get("tx", {}).get("hash", body.get("hash", ""))).strip()
            if not tx_hash:
                return "", "blockcypher_no_tx_hash", True
            return tx_hash, "", False
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return "", f"blockcypher: {exc}", True

    def _pin_ipfs(self, block_payload: dict[str, Any], settings: dict[str, str]) -> tuple[str, str, bool]:
        """Pinnt den Block-Payload als JSON bei Pinata."""
        try:
            request_payload = {
                "pinataContent": dict(block_payload),
                "pinataMetadata": {"name": f"aether-{self._block_hash(block_payload)[:16]}"},
                "pinataOptions": {"cidVersion": 1},
            }
            payload = json.dumps(request_payload).encode("utf-8")
            request = urllib.request.Request(
                "https://api.pinata.cloud/pinning/pinJSONToIPFS",
                data=payload,
                method="POST",
            )
            request.add_header("Content-Type", "application/json")
            jwt = str(settings.get("pinata_jwt", "")).strip()
            if jwt:
                request.add_header("Authorization", f"Bearer {jwt}")
            else:
                request.add_header("pinata_api_key", str(settings.get("pinata_api_key", "")).strip())
                request.add_header("pinata_secret_api_key", str(settings.get("pinata_api_secret", "")).strip())
            with urllib.request.urlopen(request, timeout=15) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace") or "{}")
            cid = str(body.get("IpfsHash", "")).strip()
            if not cid:
                return "", "pinata_no_cid", True
            return cid, "", False
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return "", f"pinata: {exc}", True

    def _execute_attempt(self, block_payload: dict[str, Any], settings: dict[str, str]) -> dict[str, Any]:
        """Fuehrt einen einzelnen Anchor-Versuch aus und markiert nur retryfaehige Fehler."""
        has_blockcypher = self._has_blockcypher(settings)
        has_pinata = self._has_pinata(settings)
        attempt = {
            "mode": "online" if (has_blockcypher or has_pinata) else "offline",
            "eth_tx": "",
            "ipfs_cid": "",
            "errors": [],
            "retryable": False,
        }
        if attempt["mode"] == "offline":
            attempt["errors"].append("credentials_missing")
            return attempt
        if has_pinata:
            cid, error, retryable = self._pin_ipfs(block_payload, settings)
            attempt["ipfs_cid"] = cid
            if error:
                attempt["errors"].append(error)
                attempt["retryable"] = attempt["retryable"] or retryable
        if has_blockcypher:
            raw_tx = str(block_payload.get("eth_raw_tx", "") or block_payload.get("eth_signed_tx", "")).strip()
            if raw_tx:
                tx_hash, error, retryable = self._push_blockcypher_raw_tx(raw_tx, settings)
                attempt["eth_tx"] = tx_hash
                if error:
                    attempt["errors"].append(error)
                    attempt["retryable"] = attempt["retryable"] or retryable
            else:
                attempt["errors"].append("eth_raw_tx_missing")
        return attempt

    @staticmethod
    def _status_from_attempt(attempt: dict[str, Any]) -> str:
        """Leitet einen nutzbaren Anchor-Status aus dem Versuch ab."""
        eth_tx = str(attempt.get("eth_tx", "")).strip()
        ipfs_cid = str(attempt.get("ipfs_cid", "")).strip()
        errors = [str(item).strip() for item in list(attempt.get("errors", [])) if str(item).strip()]
        if str(attempt.get("mode", "")) == "offline":
            return "QUEUED OFFLINE"
        if eth_tx and ipfs_cid:
            return "⬡ ON-CHAIN + IPFS"
        if eth_tx:
            return "⬡ ON-CHAIN"
        if ipfs_cid:
            return "IPFS PINNED"
        if bool(attempt.get("retryable")):
            return "QUEUED RETRY"
        if errors:
            return "ANCHOR INCOMPLETE"
        return "ANCHOR PENDING"

    def load_settings(self) -> dict[str, str]:
        """Liest gespeicherte API-Zugangsdaten."""
        if not self.settings_path.is_file():
            return dict(DEFAULT_SETTINGS)
        try:
            raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except Exception:
            return dict(DEFAULT_SETTINGS)
        settings = dict(DEFAULT_SETTINGS)
        if isinstance(raw, dict):
            for key in settings:
                settings[key] = str(raw.get(key, "")).strip()
        return settings

    def save_settings(self, settings: dict[str, str]) -> None:
        """Persistiert API-Zugangsdaten lokal."""
        normalized = dict(DEFAULT_SETTINGS)
        for key in normalized:
            normalized[key] = str(settings.get(key, "")).strip()
        self.settings_path.write_text(json.dumps(normalized, ensure_ascii=True, indent=2), encoding="utf-8")

    def is_online_mode(self) -> bool:
        """Prueft, ob mindestens ein echter Online-Anchor-Pfad konfiguriert ist."""
        settings = self.load_settings()
        return self._has_blockcypher(settings) or self._has_pinata(settings)

    def load_pending_jobs(self) -> list[dict[str, Any]]:
        """Liefert aktuell wartende Public-Anchor-Jobs."""
        with self._lock:
            return self._load_queue_unlocked()

    def get_recent_receipts(self, limit: int = 20) -> list[dict[str, Any]]:
        """Liest die juengsten lokalen Anchor-Receipts."""
        if not self.receipt_path.is_file():
            return []
        receipts: list[dict[str, Any]] = []
        try:
            with self.receipt_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        payload = json.loads(raw)
                    except Exception:
                        continue
                    if isinstance(payload, dict):
                        receipts.append(payload)
        except Exception:
            return []
        normalized_limit = max(1, int(limit))
        return receipts[-normalized_limit:][::-1]

    def pending_count(self) -> int:
        """Anzahl wartender Public-Anchor-Jobs."""
        return int(len(self.load_pending_jobs()))

    def get_summary(self) -> dict[str, Any]:
        """Verdichtet Queue-, Online- und Receipt-Status fuer GUI und Assistenz."""
        recent = self.get_recent_receipts(limit=1)
        latest = recent[0] if recent else {}
        return {
            "online": bool(self.is_online_mode()),
            "pending": int(self.pending_count()),
            "latest_status": str(latest.get("status", "")),
            "latest_mode": str(latest.get("mode", "")),
            "latest_receipt_id": str(latest.get("receipt_id", "")),
            "latest_block_hash": str(latest.get("block_hash", "")),
            "latest_error": str(latest.get("error", "")),
        }

    def anchor_async(
        self,
        block_payload: dict[str, Any],
        callback: Callable[[dict[str, Any]], None],
    ) -> None:
        """Fuehrt Public Anchoring im Hintergrund aus und liefert immer ein lokales Receipt."""
        settings = self.load_settings()

        def worker() -> None:
            attempt = self._execute_attempt(block_payload, settings)
            anchor_job_id = ""
            queue_size = self.pending_count()
            if str(attempt.get("mode", "")) == "offline":
                job, queue_size = self._queue_job(block_payload, status="queued_offline", error="credentials_missing")
                anchor_job_id = str(job.get("anchor_job_id", ""))
            elif bool(attempt.get("retryable")):
                error_text = " | ".join(str(item) for item in list(attempt.get("errors", [])) if str(item).strip())
                job, queue_size = self._queue_job(
                    block_payload,
                    status="queued_retry",
                    error=error_text,
                    partial=attempt,
                )
                anchor_job_id = str(job.get("anchor_job_id", ""))
            status = self._status_from_attempt(attempt)
            receipt = self._store_receipt(
                block_payload=block_payload,
                mode=str(attempt.get("mode", "")),
                status=status,
                eth_tx=str(attempt.get("eth_tx", "")),
                ipfs_cid=str(attempt.get("ipfs_cid", "")),
                error=" | ".join(str(item) for item in list(attempt.get("errors", [])) if str(item).strip()),
                anchor_job_id=anchor_job_id,
            )
            callback(self._build_result(receipt, queue_size=queue_size))

        threading.Thread(target=worker, daemon=True).start()

    def flush_pending_async(self, callback: Callable[[dict[str, Any]], None] | None = None) -> None:
        """Versucht wartende Jobs mit den aktuellen Zugangsdaten erneut zu verankern."""
        settings = self.load_settings()

        def worker() -> None:
            processed = 0
            jobs = self.load_pending_jobs()
            for job in jobs:
                block_payload = dict(job.get("payload", {}) or {})
                anchor_job_id = str(job.get("anchor_job_id", ""))
                attempt = self._execute_attempt(block_payload, settings)
                status = self._status_from_attempt(attempt)
                if status in {"⬡ ON-CHAIN + IPFS", "⬡ ON-CHAIN", "IPFS PINNED", "ANCHOR INCOMPLETE"}:
                    remaining = self._remove_job(anchor_job_id)
                elif str(attempt.get("mode", "")) == "offline":
                    remaining = self.pending_count()
                else:
                    updated_job, remaining = self._queue_job(
                        block_payload,
                        status="queued_retry",
                        error=" | ".join(str(item) for item in list(attempt.get("errors", [])) if str(item).strip()),
                        partial=attempt,
                        anchor_job_id=anchor_job_id,
                    )
                    anchor_job_id = str(updated_job.get("anchor_job_id", anchor_job_id))
                self._store_receipt(
                    block_payload=block_payload,
                    mode=str(attempt.get("mode", "")),
                    status=status,
                    eth_tx=str(attempt.get("eth_tx", "")),
                    ipfs_cid=str(attempt.get("ipfs_cid", "")),
                    error=" | ".join(str(item) for item in list(attempt.get("errors", [])) if str(item).strip()),
                    anchor_job_id=anchor_job_id,
                )
                processed += 1
                if str(attempt.get("mode", "")) == "offline":
                    break
            if callback is not None:
                callback(
                    {
                        "processed": int(processed),
                        "remaining": int(self.pending_count()),
                        "mode": "online" if self.is_online_mode() else "offline",
                    }
                )

        threading.Thread(target=worker, daemon=True).start()
