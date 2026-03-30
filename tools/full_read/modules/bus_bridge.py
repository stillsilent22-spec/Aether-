"""Rust bus bridge via CLI subprocess and shared JSONL transport."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


def _default_cli_binary() -> str:
    base = Path("target") / "release"
    if os.name == "nt":
        return str(base / "aether-cli.exe")
    return str(base / "aether-cli")


@dataclass
class BusBridgeEvent:
    event_type: str
    payload: dict[str, Any]
    ts: str
    source: str = "rust_bus"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": str(self.event_type),
            "payload": dict(self.payload or {}),
            "ts": str(self.ts),
            "source": str(self.source or "rust_bus"),
        }


class RustBusBridge:
    """Thin subprocess bridge for the Rust shell event stream."""

    def __init__(
        self,
        cli_binary: str = "",
        event_filter: list[str] | None = None,
    ) -> None:
        self.cli_binary = str(cli_binary or _default_cli_binary())
        self.event_filter = [str(item) for item in list(event_filter or []) if str(item).strip()]
        self._available = Path(self.cli_binary).is_file()
        self._stream_thread: threading.Thread | None = None
        self._process: subprocess.Popen[str] | None = None
        self._recent_events: deque[dict[str, Any]] = deque(maxlen=512)
        self._lock = threading.Lock()
        self._running = False

    def available(self) -> bool:
        return bool(self._available and Path(self.cli_binary).is_file())

    def start(self, callback: Callable[[dict[str, Any]], None]) -> None:
        if not self.available() or self._running:
            if not Path(self.cli_binary).is_file():
                self._available = False
            return
        self._running = True
        self._stream_thread = threading.Thread(
            target=self._stream_loop,
            args=(callback,),
            daemon=True,
            name="RustBusBridge",
        )
        self._stream_thread.start()

    def stop(self) -> None:
        self._running = False
        process = self._process
        self._process = None
        if process is not None:
            try:
                process.terminate()
            except Exception:
                pass

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        if not self.available():
            return
        try:
            subprocess.run(
                [
                    self.cli_binary,
                    "--bus-publish",
                    "--event",
                    str(event_type),
                    "--payload",
                    json.dumps(payload or {}, ensure_ascii=True, sort_keys=True),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=4.0,
            )
        except Exception:
            return

    def recent_events(self, seconds: float = 60.0) -> list[dict[str, Any]]:
        cutoff = time.time() - max(0.0, float(seconds))
        with self._lock:
            return [
                dict(item)
                for item in list(self._recent_events)
                if float(item.get("_epoch", 0.0) or 0.0) >= cutoff
            ]

    def _stream_loop(self, callback: Callable[[dict[str, Any]], None]) -> None:
        command = [self.cli_binary, "--bus-stream"]
        if self.event_filter:
            command.extend(["--filter", ",".join(self.event_filter)])
        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
            )
        except Exception:
            self._available = False
            self._running = False
            return

        assert self._process.stdout is not None
        for raw_line in self._process.stdout:
            if not self._running:
                break
            line = str(raw_line or "").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            event_type = str(payload.get("event_type", "") or "")
            if self.event_filter and event_type not in self.event_filter:
                continue
            event = BusBridgeEvent(
                event_type=event_type,
                payload=dict(payload.get("payload", {}) or {}),
                ts=str(payload.get("ts", "") or ""),
            ).to_dict()
            event["_epoch"] = time.time()
            with self._lock:
                self._recent_events.append(dict(event))
            try:
                callback(dict(event))
            except Exception:
                continue
        self._running = False
