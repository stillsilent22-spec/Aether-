"""Sicherer Browser-Companion auf Basis von pywebview."""

from __future__ import annotations

import html
import importlib.util
import math
import multiprocessing as mp
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus, urljoin, urlparse
from urllib.request import Request, urlopen

try:
    import numpy as np
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    np = None

try:
    from PIL import Image
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    Image = None


HATE_PATTERN_TERMS = {
    "hate",
    "hass",
    "vermin",
    "parasite",
    "parasiten",
    "subhuman",
    "abschaum",
    "vernichten",
    "ausrotten",
}
SCAM_PATTERN_TERMS = {
    "wallet",
    "seed phrase",
    "urgent",
    "dringend",
    "limited offer",
    "verdienen",
    "bitcoin",
    "crypto",
    "konto",
    "password",
    "passwort",
    "gift card",
}
FAKE_PATTERN_TERMS = {
    "breaking",
    "schock",
    "exclusive",
    "unglaublich",
    "leaked",
    "geheime wahrheit",
    "wake up",
    "die medien",
}


def _normalize_url(url: str) -> str:
    """Normalisiert Nutzereingaben auf browserfaehige URLs."""
    candidate = str(url).strip()
    if not candidate:
        return "https://example.org"
    lowered = candidate.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return candidate
    return f"https://{candidate}"


def _browser_process_main(command_queue, event_queue, initial_url: str) -> None:
    """Faehrt den nativen pywebview-Browser in einem separaten Prozess."""
    try:
        import webview
    except Exception as exc:  # pragma: no cover - runtime only
        event_queue.put({"kind": "error", "message": f"pywebview import failed: {exc}"})
        return

    current_url = _normalize_url(initial_url)
    window_ref: dict[str, Any] = {"window": None}
    dock_state = {
        "active": False,
        "parent": 0,
        "style": None,
        "exstyle": None,
        "floating_width": 1180,
        "floating_height": 760,
    }

    user32 = None
    if sys.platform.startswith("win"):
        try:
            import ctypes

            user32 = ctypes.windll.user32
        except Exception:
            user32 = None

    GWL_STYLE = -16
    GWL_EXSTYLE = -20
    SW_HIDE = 0
    SW_SHOW = 5
    SWP_NOZORDER = 0x0004
    SWP_NOOWNERZORDER = 0x0200
    SWP_FRAMECHANGED = 0x0020
    SWP_SHOWWINDOW = 0x0040
    WS_CHILD = 0x40000000
    WS_POPUP = 0x80000000
    WS_CAPTION = 0x00C00000
    WS_THICKFRAME = 0x00040000
    WS_MINIMIZEBOX = 0x00020000
    WS_MAXIMIZEBOX = 0x00010000
    WS_SYSMENU = 0x00080000
    WS_CLIPSIBLINGS = 0x04000000
    WS_CLIPCHILDREN = 0x02000000
    WS_EX_APPWINDOW = 0x00040000
    WS_EX_WINDOWEDGE = 0x00000100

    def _native_hwnd() -> int:
        window = window_ref.get("window")
        native = getattr(window, "native", None)
        handle = getattr(native, "Handle", None)
        if handle is None:
            return 0
        try:
            return int(handle.ToInt64())
        except Exception:
            try:
                return int(handle.ToInt32())
            except Exception:
                return 0

    def _show_native() -> None:
        hwnd = _native_hwnd()
        if hwnd and user32 is not None:
            user32.ShowWindow(hwnd, SW_SHOW)
            user32.UpdateWindow(hwnd)
            return
        window = window_ref.get("window")
        if window is not None:
            try:
                window.show()
            except Exception:
                pass

    def _hide_native() -> None:
        hwnd = _native_hwnd()
        if hwnd and user32 is not None:
            user32.ShowWindow(hwnd, SW_HIDE)
            return
        window = window_ref.get("window")
        if window is not None:
            try:
                window.hide()
            except Exception:
                pass

    def _dock_window(host_handle: int, width: int, height: int) -> None:
        hwnd = _native_hwnd()
        if not hwnd or not host_handle:
            return
        target_width = max(320, int(width))
        target_height = max(180, int(height))
        if user32 is None:
            window = window_ref.get("window")
            if window is not None:
                try:
                    window.resize(target_width, target_height)
                    window.show()
                except Exception:
                    pass
            return

        if dock_state["style"] is None:
            dock_state["style"] = int(user32.GetWindowLongW(hwnd, GWL_STYLE))
            dock_state["exstyle"] = int(user32.GetWindowLongW(hwnd, GWL_EXSTYLE))
        dock_state["floating_width"] = target_width
        dock_state["floating_height"] = target_height
        _hide_native()
        user32.SetParent(hwnd, int(host_handle))
        style = int(user32.GetWindowLongW(hwnd, GWL_STYLE))
        style = (
            (style | WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN)
            & ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU | WS_POPUP)
        )
        user32.SetWindowLongW(hwnd, GWL_STYLE, style)
        exstyle = int(user32.GetWindowLongW(hwnd, GWL_EXSTYLE))
        exstyle = exstyle & ~(WS_EX_APPWINDOW | WS_EX_WINDOWEDGE)
        user32.SetWindowLongW(hwnd, GWL_EXSTYLE, exstyle)
        user32.SetWindowPos(
            hwnd,
            0,
            0,
            0,
            target_width,
            target_height,
            SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW,
        )
        dock_state["active"] = True
        dock_state["parent"] = int(host_handle)

    def _sync_docked_bounds(width: int, height: int) -> None:
        hwnd = _native_hwnd()
        if not hwnd:
            return
        target_width = max(320, int(width))
        target_height = max(180, int(height))
        dock_state["floating_width"] = target_width
        dock_state["floating_height"] = target_height
        if user32 is None:
            window = window_ref.get("window")
            if window is not None:
                try:
                    window.resize(target_width, target_height)
                except Exception:
                    pass
            return
        user32.SetWindowPos(
            hwnd,
            0,
            0,
            0,
            target_width,
            target_height,
            SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW,
        )

    def _undock_window(width: int | None = None, height: int | None = None) -> None:
        hwnd = _native_hwnd()
        if not hwnd:
            return
        target_width = max(720, int(width or dock_state["floating_width"]))
        target_height = max(480, int(height or dock_state["floating_height"]))
        dock_state["floating_width"] = target_width
        dock_state["floating_height"] = target_height
        if user32 is None:
            window = window_ref.get("window")
            if window is not None:
                try:
                    window.resize(target_width, target_height)
                    window.show()
                except Exception:
                    pass
            dock_state["active"] = False
            dock_state["parent"] = 0
            return

        _hide_native()
        user32.SetParent(hwnd, 0)
        if dock_state["style"] is not None:
            user32.SetWindowLongW(hwnd, GWL_STYLE, int(dock_state["style"]))
        if dock_state["exstyle"] is not None:
            user32.SetWindowLongW(hwnd, GWL_EXSTYLE, int(dock_state["exstyle"]))
        user32.SetWindowPos(
            hwnd,
            0,
            80,
            80,
            target_width,
            target_height,
            SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_FRAMECHANGED | SWP_SHOWWINDOW,
        )
        dock_state["active"] = False
        dock_state["parent"] = 0

    def emit_snapshot() -> None:
        window = window_ref.get("window")
        if window is None:
            return
        try:
            url = ""
            if hasattr(window, "get_current_url"):
                url = str(window.get_current_url() or "")
            if not url:
                url = current_url
            title = str(window.evaluate_js("document.title") or "")
            html = str(
                window.evaluate_js(
                    "(function(){return document.documentElement ? document.documentElement.outerHTML : '';})()"
                )
                or ""
            )
            event_queue.put(
                {
                    "kind": "loaded",
                    "url": url,
                    "title": title,
                    "html": html,
                    "timestamp": time.time(),
                    "secure": url.lower().startswith("https://"),
                }
            )
        except Exception as exc:  # pragma: no cover - runtime only
            event_queue.put({"kind": "error", "message": f"browser snapshot failed: {exc}"})

    def apply_command(command: dict[str, Any]) -> None:
        nonlocal current_url
        window = window_ref.get("window")
        if window is None:
            return
        kind = str(command.get("cmd", ""))
        try:
            if kind == "navigate":
                current_url = _normalize_url(str(command.get("url", current_url)))
                window.load_url(current_url)
            elif kind == "back":
                window.evaluate_js("window.history.back();")
            elif kind == "forward":
                window.evaluate_js("window.history.forward();")
            elif kind == "reload":
                window.evaluate_js("window.location.reload();")
            elif kind == "show":
                _show_native()
            elif kind == "hide":
                _hide_native()
            elif kind == "dock":
                _dock_window(
                    int(command.get("host_handle", 0)),
                    int(command.get("width", dock_state["floating_width"])),
                    int(command.get("height", dock_state["floating_height"])),
                )
            elif kind == "bounds":
                _sync_docked_bounds(
                    int(command.get("width", dock_state["floating_width"])),
                    int(command.get("height", dock_state["floating_height"])),
                )
            elif kind == "undock":
                _undock_window(
                    int(command.get("width", dock_state["floating_width"])),
                    int(command.get("height", dock_state["floating_height"])),
                )
            elif kind == "stop":
                window.destroy()
        except Exception as exc:  # pragma: no cover - runtime only
            event_queue.put({"kind": "error", "message": f"browser command failed: {exc}"})

    def command_pump() -> None:
        while True:
            command = command_queue.get()
            if str(command.get("cmd", "")) == "stop":
                apply_command(command)
                break
            apply_command(command)

    def on_loaded(*_args) -> None:
        emit_snapshot()

    def startup(*_args) -> None:
        threading.Thread(target=command_pump, daemon=True).start()
        event_queue.put({"kind": "ready", "url": current_url, "secure": current_url.lower().startswith("https://")})

    window = webview.create_window("Aether Browser", url=current_url, hidden=True)
    window_ref["window"] = window
    try:
        window.events.loaded += on_loaded
    except Exception:
        pass
    webview.start(startup, debug=False, http_server=False)


@dataclass
class BrowserSnapshot:
    """Beschreibt den geladenen Zustand einer Browserseite."""

    url: str
    title: str
    html: str
    timestamp: float
    secure: bool


class BrowserEngine:
    """Steuert einen separaten pywebview-Prozess und reicht Snapshots an die GUI weiter."""

    def __init__(self, initial_url: str = "https://example.org") -> None:
        self.initial_url = _normalize_url(initial_url)
        self.available = bool(importlib.util.find_spec("webview"))
        self._ctx = mp.get_context("spawn")
        self._command_queue = None
        self._event_queue = None
        self._process = None

    @property
    def is_running(self) -> bool:
        """Liefert, ob der Browserprozess aktuell aktiv ist."""
        return self._process is not None and self._process.is_alive()

    def start(self) -> bool:
        """Startet den Browserprozess, falls pywebview verfuegbar ist."""
        if not self.available:
            return False
        if self.is_running:
            return True
        self._command_queue = self._ctx.Queue()
        self._event_queue = self._ctx.Queue()
        self._process = self._ctx.Process(
            target=_browser_process_main,
            args=(self._command_queue, self._event_queue, self.initial_url),
            daemon=True,
        )
        self._process.start()
        return True

    def stop(self) -> None:
        """Beendet den Browserprozess sauber."""
        if self._command_queue is not None:
            try:
                self._command_queue.put({"cmd": "stop"})
            except Exception:
                pass
        if self._process is not None:
            self._process.join(timeout=2.0)
            if self._process.is_alive():
                self._process.terminate()
            self._process = None
        self._command_queue = None
        self._event_queue = None

    def navigate(self, url: str) -> None:
        """Laedt eine neue URL im Browser."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "navigate", "url": _normalize_url(url)})

    @staticmethod
    def _download_payload(
        url: str,
        timeout: float = 6.0,
        max_bytes: int = 524288,
    ) -> dict[str, Any]:
        """Laedt eine URL fail-closed mit begrenztem Bytebudget fuer lokale Analyse."""
        request = Request(
            _normalize_url(url),
            headers={
                "User-Agent": "AetherBrowser/1.0 (+local probe)",
                "Accept-Language": "de-DE,de;q=0.8,en;q=0.6",
            },
        )
        with urlopen(request, timeout=max(1.0, float(timeout))) as response:
            payload = response.read(max(1024, int(max_bytes)))
            headers = {str(key).lower(): str(value) for key, value in dict(response.headers).items()}
            try:
                status_code = int(getattr(response, "status", 200) or 200)
            except Exception:
                status_code = 200
            final_url = str(getattr(response, "url", url) or url)
        content_type = str(headers.get("content-type", "") or "").split(";", 1)[0].strip().lower()
        return {
            "url": str(url),
            "final_url": str(final_url),
            "status_code": int(status_code),
            "headers": headers,
            "content_type": str(content_type),
            "content_length": int(len(payload)),
            "raw_bytes": bytes(payload),
            "secure": str(final_url).lower().startswith("https://"),
        }

    @staticmethod
    def _download_text(url: str, timeout: float = 6.0) -> str:
        """Laedt schlanken HTML-Text fuer optionale Suchkontexte fail-closed."""
        request = Request(
            _normalize_url(url),
            headers={
                "User-Agent": "AetherBrowser/1.0 (+local companion)",
                "Accept-Language": "de-DE,de;q=0.8,en;q=0.6",
            },
        )
        with urlopen(request, timeout=max(1.0, float(timeout))) as response:
            payload = response.read()
        return payload.decode("utf-8", errors="replace")

    @staticmethod
    def strip_html_text(raw_html: str, limit_chars: int = 1200) -> str:
        """Verdichtet HTML robust zu einem kurzen, lokal weiterverarbeitbaren Text."""
        markup = str(raw_html or "")
        if not markup.strip():
            return ""
        markup = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", markup)
        markup = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", markup)
        markup = re.sub(r"(?is)<[^>]+>", " ", markup)
        markup = html.unescape(markup)
        markup = re.sub(r"\s+", " ", markup).strip()
        if len(markup) <= max(80, int(limit_chars)):
            return markup
        return markup[: max(80, int(limit_chars))].rsplit(" ", 1)[0].strip()

    @staticmethod
    def _byte_entropy(raw_bytes: bytes) -> float:
        """Berechnet eine robuste Shannon-Entropie fuer Bytestichproben."""
        payload = bytes(raw_bytes or b"")
        if not payload:
            return 0.0
        counts: dict[int, int] = {}
        for value in payload:
            counts[int(value)] = int(counts.get(int(value), 0)) + 1
        total = float(len(payload))
        entropy = 0.0
        for count in counts.values():
            probability = float(count) / total
            entropy -= probability * math.log2(max(probability, 1e-12))
        return float(entropy)

    @staticmethod
    def _categorize_content_type(content_type: str, url: str) -> str:
        """Leitet eine grobe Kategorie aus MIME-Typ oder URL-Endung ab."""
        normalized = str(content_type or "").strip().lower()
        suffix = urlparse(str(url or "")).path.lower()
        if normalized.startswith("text/html") or suffix.endswith((".html", ".htm", "/")):
            return "html"
        if normalized.startswith("image/") or suffix.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")):
            return "image"
        if normalized.startswith("video/") or suffix.endswith((".mp4", ".mov", ".mkv", ".webm")):
            return "video"
        if normalized.startswith("audio/") or suffix.endswith((".mp3", ".wav", ".ogg", ".flac", ".aac")):
            return "audio"
        if normalized.startswith("text/") or suffix.endswith((".txt", ".md", ".json", ".xml", ".css", ".js")):
            return "text"
        return "binary"

    @staticmethod
    def _build_text_preview_rgb(text: str, size: int = 64) -> Any:
        """Baut eine leichte Layout-Miniatur aus HTML- oder Textinhalt."""
        target = max(32, int(size))
        if np is None:
            return None
        canvas = np.zeros((target, target, 3), dtype=np.uint8)
        lines = [str(line).strip() for line in str(text or "").splitlines() if str(line).strip()]
        if not lines:
            lines = [BrowserEngine.strip_html_text(str(text or ""), limit_chars=420)]
        lines = lines[: target]
        max_length = max(1, max(len(line) for line in lines if line))
        for index, line in enumerate(lines):
            row = min(target - 1, int((index / max(1, len(lines))) * target))
            width = max(1, int((len(line) / max_length) * target))
            diversity = len(set(line)) / max(1, len(line))
            blue = int(110 + (90 * diversity))
            red = int(40 + (155 * min(1.0, sum(1 for char in line if not char.isalnum() and not char.isspace()) / max(1, len(line)))))
            green = int(70 + (140 * min(1.0, len(line) / max_length)))
            canvas[row : min(target, row + 2), :width, :] = np.array([red, green, blue], dtype=np.uint8)
        return canvas

    @staticmethod
    def _build_entropy_preview_rgb(raw_bytes: bytes, size: int = 64) -> Any:
        """Baut eine generische Entropie-Miniatur aus Bytestroemen."""
        target = max(32, int(size))
        if np is None:
            return None
        payload = bytes(raw_bytes or b"")
        if not payload:
            return np.zeros((target, target, 3), dtype=np.uint8)
        chunk_size = max(8, int(math.ceil(len(payload) / float(target * target))))
        values: list[float] = []
        for start in range(0, len(payload), chunk_size):
            chunk = payload[start : start + chunk_size]
            if not chunk:
                continue
            values.append(BrowserEngine._byte_entropy(chunk) / 8.0)
            if len(values) >= target * target:
                break
        if not values:
            values = [0.0]
        if len(values) < target * target:
            values.extend([values[-1]] * ((target * target) - len(values)))
        array = np.asarray(values[: target * target], dtype=np.float64).reshape(target, target)
        red = np.clip(array * 255.0, 0.0, 255.0).astype(np.uint8)
        green = np.clip((1.0 - np.abs(array - 0.5) * 2.0) * 220.0, 0.0, 255.0).astype(np.uint8)
        blue = np.clip((1.0 - array) * 255.0, 0.0, 255.0).astype(np.uint8)
        return np.stack([red, green, blue], axis=2)

    @staticmethod
    def _build_image_preview_rgb(raw_bytes: bytes, size: int = 64) -> Any:
        """Dekodiert Bilddaten zu einer kleinen RGB-Miniatur."""
        target = max(32, int(size))
        if np is None or Image is None:
            return None
        try:
            import io

            image = Image.open(io.BytesIO(bytes(raw_bytes or b""))).convert("RGB")
            image.thumbnail((target, target))
            canvas = Image.new("RGB", (target, target), (6, 12, 24))
            offset = ((target - image.width) // 2, (target - image.height) // 2)
            canvas.paste(image, offset)
            return np.asarray(canvas, dtype=np.uint8)
        except Exception:
            return None

    @staticmethod
    def _image_probe(raw_bytes: bytes) -> dict[str, Any]:
        """Extrahiert leichte Symmetrie-/Kontrastsignale aus Bilddaten."""
        preview_rgb = BrowserEngine._build_image_preview_rgb(raw_bytes, size=64)
        if preview_rgb is None or np is None:
            return {"preview_rgb": None, "symmetry": 0.0, "contrast": 0.0, "mean_intensity": 0.0}
        image = np.asarray(preview_rgb[:, :, :3], dtype=np.float64)
        gray = np.mean(image, axis=2)
        normalized = gray / max(1.0, float(np.max(gray)))
        symmetry = 1.0 - float(np.mean(np.abs(normalized - np.fliplr(normalized))))
        contrast = float(np.std(normalized))
        mean_intensity = float(np.mean(normalized))
        return {
            "preview_rgb": preview_rgb,
            "symmetry": float(max(0.0, min(1.0, symmetry))),
            "contrast": float(max(0.0, min(1.0, contrast))),
            "mean_intensity": float(max(0.0, min(1.0, mean_intensity))),
        }

    @classmethod
    def inspect_url(
        cls,
        url: str,
        timeout: float = 6.0,
        max_bytes: int = 524288,
    ) -> dict[str, Any]:
        """Analysiert eine Ziel-URL lokal ohne volles Oeffnen auf Struktur- und Risikosignale."""
        normalized_url = _normalize_url(url)
        try:
            download = cls._download_payload(normalized_url, timeout=timeout, max_bytes=max_bytes)
        except Exception as exc:
            return {
                "ok": False,
                "url": str(normalized_url),
                "final_url": str(normalized_url),
                "error": str(exc),
                "risk_label": "CRITICAL",
                "risk_score": 1.0,
                "risk_reasons": [f"Download fehlgeschlagen: {exc}"],
                "open_recommended": False,
            }

        raw_bytes = bytes(download.get("raw_bytes", b"") or b"")
        content_type = str(download.get("content_type", "") or "")
        category = cls._categorize_content_type(content_type, str(download.get("final_url", normalized_url)))
        entropy = cls._byte_entropy(raw_bytes)
        header_blob = "\n".join(f"{key}: {value}" for key, value in sorted(dict(download.get("headers", {})).items()))
        header_entropy = cls._byte_entropy(header_blob.encode("utf-8", errors="replace"))
        text_sample = ""
        title = ""
        summary = ""
        script_count = 0
        style_count = 0
        inline_base64 = 0
        eval_hits = 0
        external_resources = 0
        suspicious_long_lines = 0
        preview_rgb = None
        preview_summary = ""
        missing_data: list[str] = []
        risk_reasons: list[str] = []

        if category == "html":
            html_text = raw_bytes.decode("utf-8", errors="replace")
            text_sample = cls.strip_html_text(html_text, limit_chars=2000)
            summary = cls.strip_html_text(html_text, limit_chars=720)
            title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text)
            if title_match:
                title = re.sub(r"\s+", " ", html.unescape(title_match.group(1))).strip()
            script_count = len(re.findall(r"(?is)<script\b", html_text))
            style_count = len(re.findall(r"(?is)<style\b", html_text))
            inline_base64 = len(re.findall(r"data:[^;]+;base64,", html_text, flags=re.IGNORECASE))
            eval_hits = len(
                re.findall(
                    r"(?i)(?:\beval\s*\(|\batob\s*\(|fromcharcode\s*\(|document\.write\s*\(|unescape\s*\()",
                    html_text,
                )
            )
            external_resources = len(re.findall(r"""(?i)(?:src|href)\s*=\s*["']https?://""", html_text))
            suspicious_long_lines = sum(1 for line in html_text.splitlines() if len(line.strip()) > 320)
            preview_rgb = cls._build_text_preview_rgb(text_sample or summary, size=64)
            preview_summary = "Layout-Heatmap aus HTML/Textdichte"
        elif category in {"text", "binary", "audio", "video"}:
            text_sample = raw_bytes.decode("utf-8", errors="replace") if category == "text" else ""
            summary = " ".join(text_sample.split())[:720] if text_sample else ""
            preview_rgb = cls._build_text_preview_rgb(summary, size=64) if summary else cls._build_entropy_preview_rgb(raw_bytes, size=64)
            preview_summary = "Textlayout" if summary else "Entropie-Map aus Bytestrom"
            if category == "video":
                missing_data.append("Temporale Frame-Drift ohne lokalen Decoder nur stichprobenartig bewertbar")
            if category == "audio":
                missing_data.append("Audiofront ohne lokalen Decoder nur ueber Header/Bytes bewertet")
        elif category == "image":
            image_probe = cls._image_probe(raw_bytes)
            preview_rgb = image_probe.get("preview_rgb")
            preview_summary = "Downsample-Miniatur aus Bilddaten"
        else:
            preview_rgb = cls._build_entropy_preview_rgb(raw_bytes, size=64)
            preview_summary = "Generische Entropie-Miniatur"

        if not title:
            title = urlparse(str(download.get("final_url", normalized_url))).netloc or str(normalized_url)

        lowered_text = f"{title} {summary} {text_sample}".lower()
        hate_hits = sum(1 for term in HATE_PATTERN_TERMS if term in lowered_text)
        scam_hits = sum(1 for term in SCAM_PATTERN_TERMS if term in lowered_text)
        fake_hits = sum(1 for term in FAKE_PATTERN_TERMS if term in lowered_text)

        obfuscation_score = max(
            0.0,
            min(
                1.0,
                (0.22 * min(1.0, eval_hits / 4.0))
                + (0.18 * min(1.0, inline_base64 / 3.0))
                + (0.16 * min(1.0, suspicious_long_lines / 6.0))
                + (0.14 * min(1.0, max(0.0, entropy - 6.4) / 1.6))
                + (0.10 * min(1.0, script_count / 12.0))
            ),
        )
        ai_generation_score = 0.0
        frontend_symmetry = 0.0
        frontend_entropy = 0.0
        if preview_rgb is not None and np is not None:
            image = np.asarray(preview_rgb[:, :, :3], dtype=np.float64)
            gray = np.mean(image, axis=2)
            frontend_symmetry = float(max(0.0, min(1.0, 1.0 - np.mean(np.abs((gray / max(1.0, float(np.max(gray)))) - np.fliplr(gray / max(1.0, float(np.max(gray)))))))))
            histogram = np.histogram(gray, bins=16, range=(0, 255))[0].astype(np.float64)
            probabilities = histogram[histogram > 0.0] / max(1.0, float(histogram.sum()))
            frontend_entropy = float(-np.sum(probabilities * np.log2(probabilities))) if probabilities.size > 0 else 0.0
            ai_generation_score = max(
                0.0,
                min(
                    1.0,
                    (0.22 * min(1.0, frontend_entropy / 4.0))
                    + (0.18 * max(0.0, frontend_symmetry - 0.82))
                    + (0.14 * min(1.0, max(0.0, entropy - 5.8) / 2.0)),
                ),
            )

        hate_score = max(0.0, min(1.0, (0.55 * min(1.0, hate_hits / 2.0)) + (0.18 * min(1.0, fake_hits / 3.0))))
        fake_score = max(
            0.0,
            min(
                1.0,
                (0.28 * min(1.0, fake_hits / 3.0))
                + (0.18 * min(1.0, max(0.0, header_entropy - 4.2) / 2.0))
                + (0.16 * min(1.0, max(0.0, entropy - 5.9) / 1.6))
                + (0.12 * min(1.0, external_resources / 12.0)),
            ),
        )
        scam_score = max(
            0.0,
            min(
                1.0,
                (0.42 * min(1.0, scam_hits / 3.0))
                + (0.28 * obfuscation_score)
                + (0.10 * min(1.0, eval_hits / 2.0)),
            ),
        )
        risk_score = max(ai_generation_score, hate_score, fake_score, scam_score, obfuscation_score * 0.92)

        if scam_score >= 0.66 or obfuscation_score >= 0.66:
            risk_reasons.append("Obfuskation oder Script-Verschleierung erkannt")
        if hate_score >= 0.52:
            risk_reasons.append("Asymmetrische Sprachmuster mit Hate-Speech-Potenzial erkannt")
        if fake_score >= 0.50:
            risk_reasons.append("Inkonsistente oder sensationsgetriebene Struktur erhoeht Fakenews-Risiko")
        if ai_generation_score >= 0.46:
            risk_reasons.append("Frontend-Signale wirken stark synthetisch oder uebermaessig glatt")
        if not risk_reasons:
            risk_reasons.append("Keine dominante Anomalie erkannt; Struktur bleibt vorlaeufig konsistent")

        if risk_score >= 0.72:
            risk_label = "CRITICAL"
        elif risk_score >= 0.40:
            risk_label = "SUSPICIOUS"
        else:
            risk_label = "CLEAN"

        if not bool(download.get("secure", False)):
            risk_reasons.append("Transport nicht ueber HTTPS gesichert")
            risk_score = max(risk_score, 0.38)
            if risk_label == "CLEAN":
                risk_label = "SUSPICIOUS"

        safe_headers = {
            key: value
            for key, value in dict(download.get("headers", {})).items()
            if key in {"content-type", "content-length", "server", "cache-control", "content-security-policy", "x-frame-options"}
        }
        backend_summary = (
            f"Headers {len(safe_headers)} | MIME {content_type or '--'} | "
            f"Scripts {script_count} | Styles {style_count} | Obfuskation {obfuscation_score:.2f}"
        )
        frontend_summary = (
            f"{preview_summary or 'keine Miniatur'} | Frontend-Entropie {frontend_entropy:.2f} | "
            f"Symmetrie {frontend_symmetry * 100.0:.0f}%"
        )
        return {
            "ok": True,
            "url": str(normalized_url),
            "final_url": str(download.get("final_url", normalized_url)),
            "title": str(title or ""),
            "summary": str(summary or text_sample[:720]),
            "text_sample": str(text_sample or ""),
            "content_type": str(content_type or ""),
            "category": str(category),
            "status_code": int(download.get("status_code", 200) or 200),
            "headers": safe_headers,
            "content_length": int(download.get("content_length", 0) or 0),
            "secure": bool(download.get("secure", False)),
            "entropy": float(entropy),
            "header_entropy": float(header_entropy),
            "script_count": int(script_count),
            "style_count": int(style_count),
            "inline_base64": int(inline_base64),
            "eval_hits": int(eval_hits),
            "external_resources": int(external_resources),
            "obfuscation_score": float(obfuscation_score),
            "ai_generation_score": float(ai_generation_score),
            "hate_risk_score": float(hate_score),
            "fake_risk_score": float(fake_score),
            "scam_risk_score": float(scam_score),
            "risk_score": float(max(0.0, min(1.0, risk_score))),
            "risk_label": str(risk_label),
            "risk_reasons": list(dict.fromkeys(str(item) for item in risk_reasons if str(item).strip())),
            "frontend_summary": str(frontend_summary),
            "backend_summary": str(backend_summary),
            "missing_data": list(missing_data),
            "open_recommended": bool(risk_label == "CLEAN"),
            "raw_bytes": raw_bytes,
            "miniature_rgb": preview_rgb,
        }

    @staticmethod
    def build_search_url(query: str, provider: str = "duckduckgo") -> str:
        """Erzeugt eine schlanke Such-URL fuer lokale Kontextsuche."""
        normalized_query = str(query or "").strip()
        if not normalized_query:
            normalized_query = "file format structure"
        encoded = quote_plus(normalized_query)
        selected = str(provider or "duckduckgo").strip().lower()
        if selected == "bing":
            return f"https://www.bing.com/search?q={encoded}"
        if selected == "google":
            return f"https://www.google.com/search?q={encoded}"
        return f"https://duckduckgo.com/?q={encoded}"

    @staticmethod
    def build_search_fetch_url(query: str, provider: str = "duckduckgo", searx_base_url: str = "") -> str:
        """Erzeugt eine HTML-taugliche Such-URL fuer schlanke Kontextabrufe."""
        normalized_query = str(query or "").strip()
        if not normalized_query:
            normalized_query = "file format structure"
        encoded = quote_plus(normalized_query)
        selected = str(provider or "duckduckgo").strip().lower()
        if selected == "searxng":
            base = str(searx_base_url or "").strip().rstrip("/")
            if not base:
                raise ValueError("SearxNG-Provider erfordert eine lokale Basis-URL.")
            return f"{base}/search?q={encoded}&format=html"
        return f"https://duckduckgo.com/html/?q={encoded}"

    def search(self, query: str, provider: str = "duckduckgo") -> str:
        """Startet eine lokale Websuche im Companion-Browser und liefert die Ziel-URL."""
        url = self.build_search_url(query, provider=provider)
        self.navigate(url)
        return str(url)

    @classmethod
    def fetch_search_context(
        cls,
        query: str,
        provider: str = "duckduckgo",
        timeout: float = 6.0,
        searx_base_url: str = "",
    ) -> dict[str, Any]:
        """Laedt einen kurzen Netz-Kontext fuer Shanway ohne Rohdatenpersistenz."""
        cleaned_query = " ".join(str(query or "").split()).strip()
        if not cleaned_query:
            return {
                "ok": False,
                "provider": str(provider or "duckduckgo"),
                "query": "",
                "url": "",
                "summary": "",
                "error": "empty_query",
            }
        try:
            fetch_url = cls.build_search_fetch_url(
                cleaned_query,
                provider=provider,
                searx_base_url=searx_base_url,
            )
            raw_html = cls._download_text(fetch_url, timeout=timeout)
            summary = cls.strip_html_text(raw_html, limit_chars=1200)
            return {
                "ok": bool(summary),
                "provider": str(provider or "duckduckgo"),
                "query": cleaned_query,
                "url": str(fetch_url),
                "summary": str(summary),
                "search_url": cls.build_search_url(cleaned_query, provider=provider),
                "error": "" if summary else "empty_summary",
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": str(provider or "duckduckgo"),
                "query": cleaned_query,
                "url": "",
                "summary": "",
                "search_url": cls.build_search_url(cleaned_query, provider=provider),
                "error": str(exc),
            }

    def back(self) -> None:
        """Geht in der Browserhistorie zurueck."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "back"})

    def forward(self) -> None:
        """Geht in der Browserhistorie vor."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "forward"})

    def reload(self) -> None:
        """Laedt die aktuelle Seite neu."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "reload"})

    def show(self) -> None:
        """Zeigt den Browser sichtbar an."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "show"})

    def hide(self) -> None:
        """Versteckt den Browser, ohne den Prozess zu beenden."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "hide"})

    def dock(self, host_handle: int, width: int, height: int) -> None:
        """Dockt den nativen Browser in ein Hostfenster ein."""
        if self._command_queue is None:
            return
        self._command_queue.put(
            {
                "cmd": "dock",
                "host_handle": int(host_handle),
                "width": int(width),
                "height": int(height),
            }
        )

    def sync_bounds(self, width: int, height: int) -> None:
        """Aktualisiert die Groesse der aktuell sichtbaren Browserflaeche."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "bounds", "width": int(width), "height": int(height)})

    def undock(self, width: int = 1180, height: int = 760) -> None:
        """Loest einen eingedockten Browser wieder in ein eigenes Fenster."""
        if self._command_queue is None:
            return
        self._command_queue.put({"cmd": "undock", "width": int(width), "height": int(height)})

    def poll_events(self, limit: int = 8) -> list[dict[str, Any]]:
        """Liest aufgelaufene Browserereignisse nicht-blockierend aus."""
        if self._event_queue is None:
            return []
        events: list[dict[str, Any]] = []
        for _ in range(max(1, limit)):
            try:
                item = self._event_queue.get_nowait()
            except queue.Empty:
                break
            events.append(dict(item))
        return events
