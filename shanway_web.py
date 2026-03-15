"""shanway_web.py — Rohmaterial-Schicht.
Holt mehrere Quellen. Kein Urteil. Nur Bytes.
Shanway entscheidet danach was davon existiert.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

TIMEOUT = 8
MAX_BYTES = 32_768  # 32 KB — genug für Strukturmessung


@dataclass
class RawSource:
    url: str
    raw_bytes: bytes
    fetched_at: str
    status: str           # "ok" | "error"
    title: Optional[str] = None
    error: Optional[str] = None


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else None


def _fetch_one(url: str) -> RawSource:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Shanway/1.0 (structural-analysis)"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES)
        title = None
        try:
            title = _extract_title(raw.decode("utf-8", errors="replace"))
        except Exception:
            pass
        return RawSource(url=url, raw_bytes=raw, fetched_at=ts,
                         status="ok", title=title)
    except Exception as exc:
        return RawSource(url=url, raw_bytes=b"", fetched_at=ts,
                         status="error", error=str(exc))


def _ddg_urls(query: str, n: int = 5) -> list[str]:
    """DuckDuckGo HTML — keine API, kein Key."""
    encoded = urllib.parse.quote_plus(query)
    try:
        req = urllib.request.Request(
            f"https://html.duckduckgo.com/html/?q={encoded}",
            headers={"User-Agent": "Mozilla/5.0 (compatible; Shanway/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            html = resp.read(65536).decode("utf-8", errors="replace")
        matches = re.findall(r'href="//duckduckgo\.com/l/\?uddg=([^"&]+)', html)
        urls: list[str] = []
        for m in matches:
            try:
                decoded = urllib.parse.unquote(m)
                if decoded.startswith("http"):
                    urls.append(decoded)
            except Exception:
                pass
            if len(urls) >= n:
                break
        return urls
    except Exception:
        return []


def fetch_sources(query: str, extra_urls: list[str] | None = None,
                  n: int = 5) -> list[RawSource]:
    """Holt n Quellen für query + optionale explizite URLs.
    Gibt nur erfolgreiche Quellen mit Inhalt zurück.
    """
    urls = _ddg_urls(query, n)
    for u in (extra_urls or []):
        if u not in urls:
            urls.append(u)
    sources = [_fetch_one(u) for u in urls]
    return [s for s in sources if s.status == "ok" and s.raw_bytes]
