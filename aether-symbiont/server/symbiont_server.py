"""symbiont_server.py — Aether Symbiont LSP/JSON-RPC Server.

Startet einen asynchronen JSON-RPC-Server auf stdin/stdout (kompatibel mit
VS Code Language Server Protocol). Implementiert 7 Methoden:

  aether/profile    → StructuralProfile für ein Signal
  aether/razor      → RazorReport für eine Signalmenge
  aether/snapshot   → Snapshot im Vault speichern
  aether/diff       → Zwei Snapshots vergleichen
  aether/twins      → Twin-Cluster in Signalmenge finden
  aether/complete   → Completions filtern + ranken
  aether/status     → Server-Status
    /bootstrap/status → Bootstrap-Status aus lokalen Dateien
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Callable, Dict, Optional

# ── Pfad-Setup (Server läuft in aether-symbiont/server/) ─────────────────────
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules.symbiont_core      import AetherSymbiont
from modules.symbiont_vault     import SymbiontVault
from modules.meta_ockham        import MetaOckhamEngine
from modules.completion_filter  import SymbiontCompletionFilter

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [symbiont_server] %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("symbiont_server")

# ── Globale Instanzen ─────────────────────────────────────────────────────────

_symbiont  = AetherSymbiont()
_vault     = SymbiontVault()
_ockham    = MetaOckhamEngine()
_filter    = SymbiontCompletionFilter()
_start_ts  = time.time()
_req_count = 0

# ── Live-Event-Log ────────────────────────────────────────────────────────────
_events: collections.deque = collections.deque(maxlen=500)
_event_idx: int = 0


def _bootstrap_status_payload() -> dict:
    settings_path = Path(_ROOT) / "data" / "settings.json"
    anchors_dir = Path(_ROOT) / "data" / "anchors"
    consent_path = Path(_ROOT) / "data" / "swarm_consent.json"
    private_key_path = Path(_ROOT) / "keys" / "node_private.key"

    solo_genesis_mode = False
    needs_bootstrap = True
    if settings_path.is_file():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            solo_genesis_mode = bool(settings.get("solo_genesis_mode", False))
            needs_bootstrap = not solo_genesis_mode
        except Exception:
            needs_bootstrap = True

    pack_count = 0
    total_anchors = 0
    if anchors_dir.is_dir():
        for pack_path in anchors_dir.glob("*.pack"):
            pack_count += 1
            try:
                raw = json.loads(pack_path.read_text(encoding="utf-8"))
                anchors = raw.get("anchors", []) if isinstance(raw, dict) else []
                if isinstance(anchors, list):
                    total_anchors += len(anchors)
            except Exception:
                continue

    consent_ok = False
    if consent_path.is_file():
        try:
            consent_data = json.loads(consent_path.read_text(encoding="utf-8"))
            consent_ok = bool(
                consent_data.get("consent_ok")
                or consent_data.get("consent")
                or consent_data.get("approved")
                or consent_data.get("allow_swarm")
            )
        except Exception:
            consent_ok = False

    keypair_ok = private_key_path.is_file() and private_key_path.stat().st_size > 0

    return {
        "needs_bootstrap": bool(needs_bootstrap),
        "solo_genesis_mode": bool(solo_genesis_mode),
        "pack_count": int(pack_count),
        "total_anchors": int(total_anchors),
        "consent_ok": bool(consent_ok),
        "keypair_ok": bool(keypair_ok),
    }


def _log_event(kind: str, detail: str = "") -> None:
    """Haengt einen Eintrag an den globalen Live-Event-Ring an."""
    global _event_idx
    _event_idx += 1
    _events.append({
        "idx":    _event_idx,
        "ts":     round(time.time(), 3),
        "kind":   kind,
        "detail": detail,
    })


# ── JSON-RPC Dispatcher ───────────────────────────────────────────────────────

HANDLERS: Dict[str, Callable] = {}


def register(method: str):
    def decorator(fn: Callable) -> Callable:
        HANDLERS[method] = fn
        return fn
    return decorator


# ── Handler ───────────────────────────────────────────────────────────────────

@register("aether/profile")
async def handle_profile(params: dict) -> dict:
    """
    params: { "signal": str | list[int] }
    """
    raw = params.get("signal", "")
    if isinstance(raw, list):
        signal = bytes(raw)
    else:
        signal = str(raw)
    profile = _symbiont.profile(signal)
    result = profile.to_dict()
    _log_event("profile", f"signal_len={len(signal)} entropy={result.get('entropy_mean', '?')}")
    return result


@register("aether/razor")
async def handle_razor(params: dict) -> dict:
    """
    params: { "signals": list[str] }
    """
    signals = [str(s) for s in params.get("signals", [])]
    if not signals:
        return {"error": "no_signals"}
    report = _ockham.apply_razor(signals)
    result = report.to_dict()
    _log_event("razor", f"n={len(signals)} kept={result.get('kept_count', '?')}")
    return result


@register("aether/snapshot")
async def handle_snapshot(params: dict) -> dict:
    """
    params: { "signal": str }
    """
    raw = params.get("signal", "")
    signal = str(raw)
    profile = _symbiont.profile(signal)
    handle = _vault.store_snapshot(profile)
    result = handle.to_dict()
    _log_event("snapshot", f"id={result.get('snapshot_id', '?')}")
    return result


@register("aether/diff")
async def handle_diff(params: dict) -> dict:
    """
    params: { "snapshot_id_a": str, "snapshot_id_b": str }
    """
    id_a = str(params.get("snapshot_id_a", ""))
    id_b = str(params.get("snapshot_id_b", ""))
    pa = _vault.load_snapshot(id_a)
    pb = _vault.load_snapshot(id_b)
    if pa is None or pb is None:
        return {"error": "snapshot_not_found", "id_a": id_a, "id_b": id_b}
    delta = _symbiont.delta(
        pa.signal_id.encode(),   # Re-profile aus gespeicherten Daten nicht möglich
        pb.signal_id.encode(),   # → Signal-IDs als Proxy-Signale verwenden
    )
    return delta.to_dict()


@register("aether/twins")
async def handle_twins(params: dict) -> dict:
    """
    params: { "signals": list[str] }
    """
    signals = [str(s) for s in params.get("signals", [])]
    clusters = _ockham.find_twin_clusters(signals)
    return {"clusters": [c.to_dict() for c in clusters]}


@register("aether/complete")
async def handle_complete(params: dict) -> dict:
    """
    params: { "query": str, "completions": list[str] }
    """
    query       = str(params.get("query", ""))
    completions = [str(c) for c in params.get("completions", [])]
    result      = _filter.rank(query, completions)
    return result.to_dict()


@register("aether/status")
async def handle_status(params: dict) -> dict:
    return {
        "status":      "running",
        "uptime_s":    round(time.time() - _start_ts, 1),
        "req_count":   _req_count,
        "event_count": _event_idx,
        "vault_path":  _vault._db_path,
        "timestamp":   time.time(),
    }


@register("/bootstrap/status")
async def handle_bootstrap_status(params: dict) -> dict:
    return _bootstrap_status_payload()


@register("aether/bootstrap_status")
async def handle_bootstrap_status_rpc(params: dict) -> dict:
    return _bootstrap_status_payload()


@register("aether/events")
async def handle_events(params: dict) -> dict:
    """
    params: { "since_idx": int, "limit": int }
    Returns events with idx > since_idx, newest last.
    """
    since_idx = int(params.get("since_idx", 0))
    limit = max(1, min(int(params.get("limit", 50)), 200))
    evts = [e for e in _events if e["idx"] > since_idx]
    if len(evts) > limit:
        evts = evts[-limit:]
    return {"events": evts, "last_idx": _event_idx}


# ── JSON-RPC Transport (stdin/stdout) ─────────────────────────────────────────

async def _read_message(reader: asyncio.StreamReader) -> Optional[dict]:
    """Liest eine JSON-RPC-Nachricht (Content-Length framed)."""
    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if not line:
            return None
        decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
        if not decoded:
            break
        if ":" in decoded:
            key, _, val = decoded.partition(":")
            headers[key.strip().lower()] = val.strip()
    length = int(headers.get("content-length", "0"))
    if length == 0:
        return None
    body = await reader.readexactly(length)
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None


async def _write_message(writer: asyncio.StreamWriter, obj: dict) -> None:
    """Schreibt eine JSON-RPC-Antwort (Content-Length framed)."""
    body = json.dumps(obj).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    writer.write(header + body)
    await writer.drain()


async def _handle_request(writer: asyncio.StreamWriter, msg: dict) -> None:
    global _req_count
    _req_count += 1
    req_id  = msg.get("id")
    method  = str(msg.get("method", ""))
    params  = msg.get("params") or {}

    handler = HANDLERS.get(method)
    if handler is None:
        if req_id is not None:
            await _write_message(writer, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })
        return

    try:
        result = await handler(params)
        if req_id is not None:
            await _write_message(writer, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            })
    except Exception as exc:
        log.exception("handler error: method=%s", method)
        if req_id is not None:
            await _write_message(writer, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": str(exc)},
            })


async def _serve_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername", ("?", 0))
    _log_event("connect", f"{peer[0]}:{peer[1]}")
    try:
        while True:
            msg = await _read_message(reader)
            if msg is None:
                break
            await _handle_request(writer, msg)
    finally:
        _log_event("disconnect", f"{peer[0]}:{peer[1]}")
        writer.close()
        await writer.wait_closed()


async def _stdio_main() -> None:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    write_transport, write_protocol = await loop.connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout.buffer
    )
    writer = asyncio.StreamWriter(write_transport, write_protocol, reader, loop)

    log.warning("Symbiont LSP server running (stdin/stdout JSON-RPC).")
    while True:
        msg = await _read_message(reader)
        if msg is None:
            break
        asyncio.ensure_future(_handle_request(writer, msg))


async def _tcp_main(host: str, port: int) -> None:
    server = await asyncio.start_server(_serve_connection, host=host, port=port)
    sockets = server.sockets or []
    bound = sockets[0].getsockname() if sockets else (host, port)
    log.warning("Symbiont LSP server running (tcp %s:%s JSON-RPC).", bound[0], bound[1])
    _log_event("server_start", f"tcp {bound[0]}:{bound[1]}")
    async with server:
        await server.serve_forever()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Aether Symbiont JSON-RPC server")
    parser.add_argument("--tcp-host", default="")
    parser.add_argument("--tcp-port", type=int, default=0)
    args = parser.parse_args()

    try:
        if int(args.tcp_port or 0) > 0:
            await _tcp_main(str(args.tcp_host or "127.0.0.1"), int(args.tcp_port))
        else:
            await _stdio_main()
    finally:
        _vault.close()


if __name__ == "__main__":
    asyncio.run(main())
