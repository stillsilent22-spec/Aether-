from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.browser_engine import BrowserEngine


def emit(payload: dict) -> None:
    try:
        sys.stdout.write(json.dumps(payload, ensure_ascii=True) + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def main() -> int:
    initial_url = "https://duckduckgo.com/"
    if len(sys.argv) > 1 and str(sys.argv[1]).strip():
        initial_url = str(sys.argv[1]).strip()

    engine = BrowserEngine(initial_url=initial_url)
    if not engine.available:
        emit({"kind": "error", "message": "pywebview ist lokal nicht verfuegbar."})
        return 1
    if not engine.start():
        emit({"kind": "error", "message": "Browserprozess konnte nicht gestartet werden."})
        return 1

    stop_flag = threading.Event()

    def poll_events() -> None:
        while not stop_flag.is_set():
            try:
                for item in engine.poll_events(limit=10):
                    emit(dict(item))
            except Exception as exc:
                emit({"kind": "error", "message": f"browser event pump failed: {exc}"})
            stop_flag.wait(0.2)

    threading.Thread(target=poll_events, daemon=True).start()
    emit({"kind": "bridge_ready", "message": "browser dock bridge ready"})

    try:
        for line in sys.stdin:
            raw = str(line or "").strip()
            if not raw:
                continue
            try:
                command = json.loads(raw)
            except Exception as exc:
                emit({"kind": "error", "message": f"ungultiger JSON-Befehl: {exc}"})
                continue

            kind = str(command.get("cmd", "")).strip().lower()
            try:
                if kind == "navigate":
                    engine.navigate(str(command.get("url", initial_url)))
                elif kind == "search":
                    query = str(command.get("query", "")).strip()
                    target = BrowserEngine.build_search_url(query, provider="duckduckgo")
                    engine.navigate(target)
                elif kind == "dock":
                    engine.dock(
                        int(command.get("host_handle", 0)),
                        int(command.get("width", 1280)),
                        int(command.get("height", 820)),
                    )
                elif kind == "bounds":
                    engine.sync_bounds(
                        int(command.get("width", 1280)),
                        int(command.get("height", 820)),
                    )
                elif kind == "show":
                    engine.show()
                elif kind == "hide":
                    engine.hide()
                elif kind == "undock":
                    engine.undock(
                        int(command.get("width", 1180)),
                        int(command.get("height", 760)),
                    )
                elif kind == "stop":
                    break
                else:
                    emit({"kind": "error", "message": f"unbekannter Befehl: {kind}"})
            except Exception as exc:
                emit({"kind": "error", "message": f"browser command failed: {exc}"})
    finally:
        stop_flag.set()
        try:
            engine.stop()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
