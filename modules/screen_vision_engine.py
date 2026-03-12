"""Scoped screen capture fuer explizite Aether-Dateianalysen."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import mss
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    mss = None

try:
    import numpy as np
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    np = None

try:
    import pygetwindow as gw
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    gw = None

if TYPE_CHECKING:
    from .analysis_engine import AnalysisEngine, AetherFingerprint


def contains_email_pattern(text: str) -> bool:
    raw = str(text or "").lower()
    at_pos = raw.find("@")
    if at_pos < 0:
        return False
    before = raw[:at_pos]
    after = raw[at_pos + 1 :]
    return bool(before and after and "." in after and before[-1].isalnum())


def contains_password_field_pattern(text: str) -> bool:
    raw = str(text or "").lower()
    return (
        'type="password"' in raw
        or "type='password'" in raw
        or "input_type=password" in raw
        or "pwd=" in raw
        or "pass=" in raw
    )


def is_private_context(source: str, content_hint: str) -> bool:
    communication = (
        "chat",
        "dm",
        "direct_message",
        "message",
        "messenger",
        "groupchat",
        "group_chat",
        "group_message",
        "channel_message",
        "whatsapp",
        "telegram",
        "signal_app",
        "discord_dm",
        "slack_dm",
        "teams_chat",
        "sms",
        "mms",
        "imessage",
        "facetime",
        "skype",
        "viber",
    )
    email = (
        "mail",
        "email",
        "e-mail",
        "inbox",
        "outbox",
        "outlook",
        "gmail",
        "thunderbird",
        "protonmail",
        "smtp",
        "imap",
        "pop3",
        "compose",
        "draft",
        "sent_mail",
        "mailbox",
    )
    credentials = (
        "password",
        "passwort",
        "passwd",
        "pwd",
        "passphrase",
        "credentials",
        "credential",
        "login_form",
        "auth_token",
        "access_token",
        "refresh_token",
        "api_key",
        "secret_key",
        "private_key",
        "signing_key",
        "2fa",
        "otp",
        "totp",
        "pin_entry",
        "pin_code",
        "security_code",
    )
    personal = (
        "keychain",
        "password_manager",
        "biometric",
        "face_id",
        "fingerprint",
        "touch_id",
        "personal_vault",
        "private_notes",
    )
    src = str(source or "").lower()
    hint = str(content_hint or "").lower()
    for patterns in (communication, email, credentials, personal):
        if any(pattern in src or pattern in hint for pattern in patterns):
            return True
    return contains_email_pattern(hint) or contains_password_field_pattern(hint)


def _anchor_keys_from_fingerprint(fingerprint: "AetherFingerprint | None") -> list[str]:
    if fingerprint is None:
        return []
    payload = dict(getattr(fingerprint, "scan_payload", {}) or {})
    entries = list(payload.get("scan_anchor_entries", []) or [])
    values = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            value = float(entry.get("value", 0.0) or 0.0)
        except (TypeError, ValueError):
            continue
        if abs(value) <= 1e-12:
            continue
        values.append(f"{value:.12f}")
    return sorted(set(values), key=lambda item: float(item))


@dataclass
class ScreenVisionResult:
    screen_vision: str
    source: str
    active_window: str
    visual_anchors: list[str]
    file_anchors: list[str]
    convergence: float
    delta_visual_only: list[str]
    delta_file_only: list[str]
    status: str
    reason: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "SCREEN_VISION": str(self.screen_vision),
            "SOURCE": str(self.source),
            "ACTIVE_WINDOW": str(self.active_window),
            "VISUAL_ANCHORS": list(self.visual_anchors),
            "FILE_ANCHORS": list(self.file_anchors),
            "CONVERGENCE": round(float(self.convergence), 12),
            "DELTA_VISUAL_ONLY": list(self.delta_visual_only),
            "DELTA_FILE_ONLY": list(self.delta_file_only),
            "status": str(self.status),
            "reason": str(self.reason),
        }


class ScreenVisionEngine:
    """Kapselt fail-closed Screen-Vision fuer explizite Drop-Analysen."""

    @staticmethod
    def _dependencies_ready() -> bool:
        return bool(mss is not None and np is not None and gw is not None)

    @staticmethod
    def capture_screen(region: dict[str, int] | None = None):
        if not ScreenVisionEngine._dependencies_ready():
            raise RuntimeError("screen vision dependencies unavailable")
        with mss.mss() as sct:
            monitor = dict(region or sct.monitors[1])
            frame = np.array(sct.grab(monitor))
        return frame

    @staticmethod
    def capture_analysis_region(window_title: str, file_path: str):
        if not ScreenVisionEngine._dependencies_ready():
            raise RuntimeError("screen vision dependencies unavailable")
        if not str(window_title or "").strip():
            raise RuntimeError("window title required for scoped capture")
        if not str(file_path or "").strip():
            raise RuntimeError("file path required for scoped capture")
        if is_private_context(window_title, file_path):
            raise RuntimeError("private analysis regions are blocked")
        windows = [window for window in list(gw.getWindowsWithTitle(window_title) or []) if int(window.width) > 0 and int(window.height) > 0]
        if not windows:
            raise RuntimeError(f"analysis window not found: {window_title}")
        window = sorted(
            windows,
            key=lambda item: (-int(getattr(item, "width", 0) or 0) * int(getattr(item, "height", 0) or 0), str(getattr(item, "title", ""))),
        )[0]
        region = {
            "top": int(window.top),
            "left": int(window.left),
            "width": int(window.width),
            "height": int(window.height),
        }
        return ScreenVisionEngine.capture_screen(region=region), str(getattr(window, "title", "") or window_title)

    @staticmethod
    def compute_interference(file_anchor_keys: list[str], visual_anchor_keys: list[str]) -> tuple[float, list[str], list[str]]:
        file_set = set(str(item) for item in list(file_anchor_keys or []))
        visual_set = set(str(item) for item in list(visual_anchor_keys or []))
        shared = file_set & visual_set
        total_unique = file_set | visual_set
        if not total_unique:
            return 0.0, [], []
        convergence = float(len(shared)) / float(len(total_unique))
        return (
            convergence,
            sorted(visual_set - file_set, key=lambda item: float(item)),
            sorted(file_set - visual_set, key=lambda item: float(item)),
        )

    def capture_and_compare(
        self,
        analysis_engine: "AnalysisEngine",
        window_title: str,
        file_path: str,
        file_fingerprint: "AetherFingerprint",
        explicit_trigger: bool,
    ) -> ScreenVisionResult:
        if not explicit_trigger:
            return ScreenVisionResult(
                screen_vision="disabled",
                source=Path(str(file_path or "")).name,
                active_window="",
                visual_anchors=[],
                file_anchors=_anchor_keys_from_fingerprint(file_fingerprint),
                convergence=0.0,
                delta_visual_only=[],
                delta_file_only=[],
                status="skipped",
                reason="screen vision requires explicit file drop trigger",
            )
        frame, active_window = self.capture_analysis_region(window_title=window_title, file_path=file_path)
        screen_fingerprint = analysis_engine.analyze_bytes(
            frame.tobytes(),
            source_label=f"SCREEN::{Path(str(file_path)).name}",
            source_type="screen",
        )
        visual_anchors = _anchor_keys_from_fingerprint(screen_fingerprint)
        file_anchors = _anchor_keys_from_fingerprint(file_fingerprint)
        convergence, delta_visual_only, delta_file_only = self.compute_interference(file_anchors, visual_anchors)
        return ScreenVisionResult(
            screen_vision="scoped",
            source=Path(str(file_path or "")).name,
            active_window=active_window,
            visual_anchors=visual_anchors[:16],
            file_anchors=file_anchors[:16],
            convergence=convergence,
            delta_visual_only=delta_visual_only[:16],
            delta_file_only=delta_file_only[:16],
            status="ok",
        )


class ShanwayAetherVision:
    """
    Permanenter, fail-closed Vision-Loop fuer Aether-eigene Oberflaechen.

    Erfasst ausschliesslich Aether-Fenster und respektiert dieselbe
    Privacy-Boundary wie der Runtime-Pfad.
    """

    AETHER_WINDOW_KEYWORDS = ["aether", "shanway", "vera_aether"]
    SAMPLE_INTERVAL_MS: int = 500

    def __init__(self, analysis_engine: Any, bus_publish_fn: Any) -> None:
        self.analysis_engine = analysis_engine
        self.bus_publish = bus_publish_fn
        self._running = False
        self._current_state: dict[str, Any] = {}

    def start(self) -> None:
        import threading

        self._running = True
        thread = threading.Thread(target=self._vision_loop, daemon=True)
        thread.start()

    def stop(self) -> None:
        self._running = False

    def _vision_loop(self) -> None:
        import time

        while self._running:
            try:
                frame = self._capture_aether_frame()
                if frame:
                    self._current_state = frame
                    self._proactive_check(frame)
            except Exception:
                pass
            time.sleep(self.SAMPLE_INTERVAL_MS / 1000.0)

    def _capture_aether_frame(self) -> dict[str, Any] | None:
        if gw is None or mss is None:
            return None
        windows = list(gw.getAllWindows() or [])
        aether_window = None
        for window in windows:
            title_lower = str(getattr(window, "title", "") or "").lower()
            if any(keyword in title_lower for keyword in self.AETHER_WINDOW_KEYWORDS):
                aether_window = window
                break
        if aether_window is None:
            return None
        title = str(getattr(aether_window, "title", "") or "")
        if is_private_context(title, ""):
            return None
        return {
            "window_title": title,
            "timestamp": int(__import__("time").time()),
            "active": True,
        }

    def _proactive_check(self, frame: dict[str, Any]) -> None:
        bus_publish = getattr(self, "bus_publish", None)
        if callable(bus_publish):
            try:
                bus_publish(
                    {
                        "type": "shanway_aether_vision",
                        "window_title": str(frame.get("window_title", "") or ""),
                        "timestamp": int(frame.get("timestamp", 0) or 0),
                    }
                )
            except Exception:
                return

    @property
    def current_state(self) -> dict[str, Any]:
        return dict(self._current_state)
