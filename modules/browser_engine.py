"""Sicherer Browser-Companion auf Basis von pywebview."""

from __future__ import annotations

import importlib.util
import multiprocessing as mp
import queue
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus


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

    def search(self, query: str, provider: str = "duckduckgo") -> str:
        """Startet eine lokale Websuche im Companion-Browser und liefert die Ziel-URL."""
        url = self.build_search_url(query, provider=provider)
        self.navigate(url)
        return str(url)

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
