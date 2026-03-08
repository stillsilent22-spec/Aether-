"""Verschluesselter Relay-Sync fuer Mehrrechner-Chat."""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from .chat_crypto import decrypt_bytes_aes256, encrypt_bytes_aes256


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Serialisiert Sync-Payloads deterministisch."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _derive_transport_key(shared_secret: str) -> tuple[bytes, str]:
    """Leitet Transport-Key und Header-Token aus einem Secret ab."""
    import hashlib

    normalized = str(shared_secret).strip()
    if len(normalized) < 8:
        raise ValueError("Das Sync-Secret muss mindestens 8 Zeichen lang sein.")
    secret_digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    token = hashlib.sha256(secret_digest).hexdigest()
    return secret_digest, token


def encrypt_sync_event(payload: dict[str, Any], shared_secret: str) -> str:
    """Verpackt ein Sync-Ereignis AES-256-GCM-verschluesselt als Base64-Blob."""
    key, _ = _derive_transport_key(shared_secret)
    nonce, ciphertext = encrypt_bytes_aes256(_canonical_json(payload), key)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_sync_event(blob: str, shared_secret: str) -> dict[str, Any]:
    """Entschluesselt einen Relay-Blob wieder in ein JSON-Ereignis."""
    key, _ = _derive_transport_key(shared_secret)
    raw = base64.urlsafe_b64decode(str(blob).encode("ascii"))
    if len(raw) < 13:
        raise ValueError("Ungueltiger Sync-Blob.")
    payload = decrypt_bytes_aes256(raw[:12], raw[12:], key)
    decoded = json.loads(payload.decode("utf-8"))
    return dict(decoded) if isinstance(decoded, dict) else {}


def build_sync_headers(shared_secret: str) -> dict[str, str]:
    """Erzeugt die Auth-Header fuer Relay-Aufrufe."""
    _, token = _derive_transport_key(shared_secret)
    return {
        "Content-Type": "application/json; charset=utf-8",
        "X-Aether-Token": token,
    }


def local_bind_address() -> str:
    """Versucht eine brauchbare LAN-Adresse fuer Host-Hinweise zu finden."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return str(probe.getsockname()[0])
    except Exception:
        return "127.0.0.1"
    finally:
        try:
            probe.close()
        except Exception:
            pass


@dataclass
class RelayEvent:
    """Opaquer Relay-Datensatz."""

    event_id: int
    created_at: str
    origin_node: str
    blob: str


class _RelayStore:
    """Append-only JSONL-Speicher fuer Relay-Ereignisse."""

    def __init__(self, storage_path: str) -> None:
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._events: list[RelayEvent] = []
        self._last_id = 0
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            with self.storage_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    raw = json.loads(line)
                    event = RelayEvent(
                        event_id=int(raw.get("id", 0)),
                        created_at=str(raw.get("created_at", "")),
                        origin_node=str(raw.get("origin_node", "")),
                        blob=str(raw.get("blob", "")),
                    )
                    self._events.append(event)
                    self._last_id = max(self._last_id, event.event_id)
        except Exception:
            self._events = []
            self._last_id = 0

    def append(self, blob: str, origin_node: str) -> RelayEvent:
        with self._lock:
            self._last_id += 1
            event = RelayEvent(
                event_id=self._last_id,
                created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                origin_node=str(origin_node),
                blob=str(blob),
            )
            with self.storage_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "id": event.event_id,
                            "created_at": event.created_at,
                            "origin_node": event.origin_node,
                            "blob": event.blob,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
            self._events.append(event)
            return event

    def get_events(self, after_id: int = 0, limit: int = 128) -> list[RelayEvent]:
        threshold = max(0, int(after_id))
        cap = max(1, min(512, int(limit)))
        with self._lock:
            selected = [event for event in self._events if int(event.event_id) > threshold]
            return selected[:cap]


class ChatRelayServer:
    """Einfacher HTTP-Relay-Server fuer verschluesselte Chat-Ereignisse."""

    def __init__(self, storage_path: str, host: str = "0.0.0.0", port: int = 8765) -> None:
        self.storage = _RelayStore(storage_path)
        self.host = str(host)
        self.port = int(port)
        self._thread: threading.Thread | None = None
        self._server: ThreadingHTTPServer | None = None
        self._token = ""

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    def start(self, shared_secret: str) -> str:
        """Startet den Relay-Host auf dem konfigurierten Port."""
        if self.is_running:
            return f"http://{local_bind_address()}:{self.port}"
        _, self._token = _derive_transport_key(shared_secret)
        storage = self.storage
        expected_token = self._token

        class Handler(BaseHTTPRequestHandler):
            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(int(status))
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _auth_ok(self) -> bool:
                if self.path.startswith("/health"):
                    return True
                provided = str(self.headers.get("X-Aether-Token", "")).strip()
                return bool(provided) and provided == expected_token

            def do_GET(self) -> None:  # noqa: N802
                if not self._auth_ok():
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                parsed = parse.urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "service": "aether-chat-relay",
                            "running": True,
                            "events": len(storage.get_events(after_id=0, limit=1_000_000)),
                        },
                    )
                    return
                if parsed.path != "/events":
                    self._send_json(404, {"ok": False, "error": "not_found"})
                    return
                params = parse.parse_qs(parsed.query)
                after_id = int((params.get("after") or ["0"])[0] or 0)
                limit = int((params.get("limit") or ["128"])[0] or 128)
                events = storage.get_events(after_id=after_id, limit=limit)
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "events": [
                            {
                                "id": int(item.event_id),
                                "created_at": str(item.created_at),
                                "origin_node": str(item.origin_node),
                                "blob": str(item.blob),
                            }
                            for item in events
                        ],
                    },
                )

            def do_POST(self) -> None:  # noqa: N802
                if not self._auth_ok():
                    self._send_json(403, {"ok": False, "error": "forbidden"})
                    return
                if self.path != "/publish":
                    self._send_json(404, {"ok": False, "error": "not_found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except Exception:
                    length = 0
                raw = self.rfile.read(max(0, length))
                try:
                    payload = json.loads(raw.decode("utf-8") or "{}")
                except Exception:
                    self._send_json(400, {"ok": False, "error": "invalid_json"})
                    return
                blob = str(payload.get("blob", "")).strip()
                if not blob:
                    self._send_json(400, {"ok": False, "error": "missing_blob"})
                    return
                origin_node = str(payload.get("origin_node", "")).strip()
                event = storage.append(blob=blob, origin_node=origin_node)
                self._send_json(200, {"ok": True, "event_id": int(event.event_id)})

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://{local_bind_address()}:{self.port}"

    def stop(self) -> None:
        """Beendet den Relay-Host sauber."""
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        finally:
            self._server = None
            self._thread = None
            self._token = ""


class ChatSyncClient:
    """HTTP-Client fuer verschluesselten Chat-Sync."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = max(1.0, float(timeout))

    @staticmethod
    def _normalize_url(base_url: str) -> str:
        candidate = str(base_url).strip().rstrip("/")
        if not candidate:
            raise ValueError("Die Relay-URL darf nicht leer sein.")
        if not candidate.startswith(("http://", "https://")):
            candidate = f"http://{candidate}"
        return candidate

    def health(self, base_url: str) -> dict[str, Any]:
        """Prueft, ob ein Relay erreichbar ist."""
        target = f"{self._normalize_url(base_url)}/health"
        req = request.Request(target, method="GET")
        with request.urlopen(req, timeout=self.timeout) as response:
            return dict(json.loads(response.read().decode("utf-8")))

    def publish(self, base_url: str, shared_secret: str, payload: dict[str, Any], origin_node: str) -> int:
        """Publiziert ein verschluesseltes Ereignis an das Relay."""
        target = f"{self._normalize_url(base_url)}/publish"
        body = json.dumps(
            {
                "origin_node": str(origin_node),
                "blob": encrypt_sync_event(payload, shared_secret),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        req = request.Request(
            target,
            data=body,
            headers=build_sync_headers(shared_secret),
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout) as response:
            payload_box = dict(json.loads(response.read().decode("utf-8")))
        return int(payload_box.get("event_id", 0) or 0)

    def fetch(self, base_url: str, shared_secret: str, after_id: int = 0, limit: int = 128) -> list[dict[str, Any]]:
        """Laedt neue Ereignisse vom Relay und entschluesselt sie lokal."""
        params = parse.urlencode({"after": max(0, int(after_id)), "limit": max(1, min(512, int(limit)))})
        target = f"{self._normalize_url(base_url)}/events?{params}"
        req = request.Request(
            target,
            headers=build_sync_headers(shared_secret),
            method="GET",
        )
        with request.urlopen(req, timeout=self.timeout) as response:
            payload = dict(json.loads(response.read().decode("utf-8")))
        events: list[dict[str, Any]] = []
        for item in list(payload.get("events", [])):
            blob = str(dict(item).get("blob", "")).strip()
            if not blob:
                continue
            decrypted = decrypt_sync_event(blob, shared_secret)
            decrypted["_remote_event_id"] = int(dict(item).get("id", 0) or 0)
            decrypted["_remote_origin_node"] = str(dict(item).get("origin_node", ""))
            decrypted["_remote_created_at"] = str(dict(item).get("created_at", ""))
            events.append(decrypted)
        return events


def sync_error_text(exc: Exception) -> str:
    """Formatiert Netzwerkfehler kompakt fuer UI und Logs."""
    if isinstance(exc, error.HTTPError):
        return f"HTTP {exc.code}: {exc.reason}"
    if isinstance(exc, error.URLError):
        return f"Netzwerkfehler: {exc.reason}"
    return str(exc)
