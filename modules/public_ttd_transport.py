"""Optionaler Netzwerktransport fuer oeffentliche TTD-Anker."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from urllib import error, parse, request


DEFAULT_TTD_NETWORK_SETTINGS = {
    "enabled": False,
    "ipfs_api_url": "http://127.0.0.1:5001/api/v0/add?pin=true",
    "ipfs_gateway_urls": "http://127.0.0.1:8080/ipfs/\nhttps://ipfs.io/ipfs/",
    "mirror_publish_url": "",
    "mirror_pull_urls": "",
    "tracked_cids": "",
    "timeout_seconds": "12",
}


def _normalized_lines(value: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value]
    else:
        items = [line.strip() for line in str(value or "").replace(",", "\n").splitlines()]
    return [item for item in items if item]


def _multipart_form(field_name: str, filename: str, payload: bytes) -> tuple[bytes, str]:
    boundary = f"----AetherBoundary{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        "Content-Type: application/json\r\n\r\n"
    ).encode("utf-8") + payload + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, boundary


class PublicTTDTransport:
    """Kleiner, fail-closed Transport fuer metrics-only TTD-Bundles."""

    def __init__(self, settings_path: str | Path = "data/public_ttd_anchor_pool/network_settings.json") -> None:
        self.settings_path = Path(settings_path)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)

    def load_settings(self) -> dict[str, Any]:
        settings = dict(DEFAULT_TTD_NETWORK_SETTINGS)
        if self.settings_path.is_file():
            try:
                raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
            except Exception:
                raw = {}
            if isinstance(raw, dict):
                settings.update({str(key): raw.get(key) for key in settings.keys() if key in raw})
        settings["enabled"] = bool(settings.get("enabled", False))
        settings["timeout_seconds"] = str(settings.get("timeout_seconds", "12") or "12")
        return settings

    def save_settings(self, settings: dict[str, Any]) -> dict[str, Any]:
        merged = dict(DEFAULT_TTD_NETWORK_SETTINGS)
        merged.update({str(key): value for key, value in dict(settings or {}).items() if key in merged})
        merged["enabled"] = bool(merged.get("enabled", False))
        self.settings_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        return merged

    def is_enabled(self) -> bool:
        return bool(self.load_settings().get("enabled", False))

    def _timeout(self, settings: dict[str, Any]) -> float:
        try:
            return max(2.0, min(60.0, float(settings.get("timeout_seconds", "12") or 12.0)))
        except Exception:
            return 12.0

    def _request_json(
        self,
        url: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        timeout: float = 12.0,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        body = b""
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json; charset=utf-8")
        req = request.Request(str(url).strip(), data=body if body else None, method=str(method).upper())
        for key, value in request_headers.items():
            req.add_header(str(key), str(value))
        with request.urlopen(req, timeout=float(timeout)) as response:
            raw = response.read().decode("utf-8", errors="replace")
        decoded = json.loads(raw or "{}")
        return dict(decoded) if isinstance(decoded, dict) else {"payload": decoded}

    def publish_bundle_http(self, bundle: dict[str, Any], publish_url: str, *, timeout: float = 12.0) -> dict[str, Any]:
        """Sendet ein Bundle als JSON an einen expliziten Mirror-Endpunkt."""
        try:
            response = self._request_json(
                str(publish_url).strip(),
                method="POST",
                payload=dict(bundle or {}),
                timeout=timeout,
            )
            return {"ok": True, "transport": "http_mirror", "response": response}
        except Exception as exc:
            return {"ok": False, "transport": "http_mirror", "error": str(exc)}

    def publish_bundle_ipfs(self, bundle: dict[str, Any], ipfs_api_url: str, *, timeout: float = 12.0) -> dict[str, Any]:
        """Publiziert ein Bundle ueber die lokale IPFS-HTTP-API."""
        try:
            payload = json.dumps(dict(bundle or {}), ensure_ascii=False, indent=2).encode("utf-8")
            body, boundary = _multipart_form("file", "aether_public_ttd_anchor.json", payload)
            req = request.Request(str(ipfs_api_url).strip(), data=body, method="POST")
            req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
            with request.urlopen(req, timeout=float(timeout)) as response:
                raw = response.read().decode("utf-8", errors="replace")
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            decoded = json.loads(lines[-1] if lines else "{}")
            cid = str(decoded.get("Hash", "") or "").strip()
            if not cid:
                return {"ok": False, "transport": "ipfs_api", "error": "ipfs_no_cid"}
            return {"ok": True, "transport": "ipfs_api", "cid": cid, "response": decoded}
        except Exception as exc:
            return {"ok": False, "transport": "ipfs_api", "error": str(exc)}

    def fetch_bundle_http(self, url: str, *, timeout: float = 12.0) -> dict[str, Any]:
        """Laedt ein einzelnes Envelope oder eine Bundle-Liste via HTTP."""
        return self._request_json(str(url).strip(), timeout=timeout)

    def fetch_bundle_ipfs(self, cid: str, gateway_urls: list[str], *, timeout: float = 12.0) -> dict[str, Any]:
        """Laedt ein Bundle ueber eine konfigurierte IPFS-Gateway-Liste."""
        normalized_cid = str(cid or "").strip()
        last_error = ""
        for gateway in _normalized_lines(gateway_urls):
            target = str(gateway).rstrip("/") + "/" + normalized_cid
            try:
                return self._request_json(target, timeout=timeout)
            except Exception as exc:
                last_error = str(exc)
        raise RuntimeError(last_error or "ipfs_gateway_unreachable")

    def publish_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Publiziert ein Bundle optional an Mirror und/oder IPFS."""
        settings = self.load_settings()
        if not bool(settings.get("enabled", False)):
            return {"published": False, "reason": "network_disabled", "network_used": False}
        timeout = self._timeout(settings)
        result = {
            "published": False,
            "network_used": False,
            "ipfs": {},
            "mirror": {},
        }
        ipfs_api_url = str(settings.get("ipfs_api_url", "") or "").strip()
        if ipfs_api_url:
            result["network_used"] = True
            ipfs_result = self.publish_bundle_ipfs(bundle, ipfs_api_url, timeout=timeout)
            result["ipfs"] = ipfs_result
            if bool(ipfs_result.get("ok", False)):
                tracked = _normalized_lines(settings.get("tracked_cids", ""))
                cid = str(ipfs_result.get("cid", "") or "").strip()
                if cid and cid not in tracked:
                    tracked.append(cid)
                    settings["tracked_cids"] = "\n".join(tracked[-128:])
                    self.save_settings(settings)
                result["published"] = True
        publish_url = str(settings.get("mirror_publish_url", "") or "").strip()
        if publish_url:
            result["network_used"] = True
            mirror_result = self.publish_bundle_http(bundle, publish_url, timeout=timeout)
            result["mirror"] = mirror_result
            if bool(mirror_result.get("ok", False)):
                result["published"] = True
        if not result["network_used"]:
            result["reason"] = "no_transport_configured"
        return result

    def pull_remote_bundles(self) -> dict[str, Any]:
        """Zieht Remote-Bundles ueber Mirror-URLs und/oder IPFS-CIDs."""
        settings = self.load_settings()
        if not bool(settings.get("enabled", False)):
            return {"remote_bundles": [], "errors": [], "network_used": False}
        timeout = self._timeout(settings)
        bundles: list[dict[str, Any]] = []
        errors_out: list[str] = []
        network_used = False
        for url in _normalized_lines(settings.get("mirror_pull_urls", "")):
            network_used = True
            try:
                fetched = self.fetch_bundle_http(url, timeout=timeout)
            except Exception as exc:
                errors_out.append(f"{url}: {exc}")
                continue
            if isinstance(fetched, dict):
                bundles.append(fetched)
        tracked_cids = _normalized_lines(settings.get("tracked_cids", ""))
        gateway_urls = _normalized_lines(settings.get("ipfs_gateway_urls", ""))
        for cid in tracked_cids:
            network_used = True
            try:
                fetched = self.fetch_bundle_ipfs(cid, gateway_urls, timeout=timeout)
            except Exception as exc:
                errors_out.append(f"{cid}: {exc}")
                continue
            if isinstance(fetched, dict):
                bundles.append(fetched)
        return {
            "remote_bundles": bundles,
            "errors": errors_out,
            "network_used": network_used,
        }
