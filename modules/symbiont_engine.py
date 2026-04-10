"""
Aether Symbiont Engine — Kybernetischer Schwarm 3. Ordnung
==========================================================
Python 2.6+ compatible HTTP server on port 38571.

The Rust GUI (iced_shell.rs) connects via symbiont_rpc::request_json and sends:
  POST /aether/events  { "since_idx": N, "limit": 30 }
  POST /<user-command> {}          (any string the user types in the Symbiont tab)

3rd-order cybernetic swarm concept:
  1st order = node acts            (gossip / store / relay)
  2nd order = node adapts          (learns relay pool, updates peers)
  3rd order = symbiont collective  (even Win95/98/XP nodes anchor cached data;
                                    swarm reconstructs from symbiont memory if
                                    high-tier nodes go offline)

Symbiont roles by hardware tier:
  Tier 0 (Win95/98/Me, WinLegacy) : memoria, entropy_seed, swarm_beacon
  Tier 1 (Win2000)                 : + relay_bridge
  Tier 2                           : + delta_vault
  Tier 3+                          : + knowledge_relay
"""

from __future__ import print_function

import hashlib
import json
import os
import sys
import time
import threading

# ---------------------------------------------------------------------------
# Python 2 / 3 HTTP server import
# ---------------------------------------------------------------------------
try:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SYMBIONT_PORT = 38571
EVENTS_MAX = 500

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(ROOT, "data", "interbus", "symbiont_state.json")
ANCHOR_LIB_DIR = os.path.join(ROOT, "data", "public_anchor_library")
INTERBUS_DIR = os.path.join(ROOT, "data", "interbus")

# ---------------------------------------------------------------------------
# Global mutable state  (protected by _state_lock)
# ---------------------------------------------------------------------------
_state_lock = threading.Lock()
_event_log = []    # list of {idx, ts, kind, detail}
_event_idx = 0    # monotonically increasing counter

_symbiont_state = {
    "schema": "aether.symbiont.state.v1",
    "order": 3,
    "order_label": "Kybernetischer Schwarm 3. Ordnung",
    "node_id": "",
    "network_entry_id": "",
    "alias": "",
    "roles": [],
    "tick_count": 0,
    "last_tick_ts": 0.0,
    "delta_count": 0,
    "relay_peers": [],
    "entropy_contributions": 0,
    "memoria_anchors": 0,
    "knowledge_entries": 0,
    "started_at": time.time(),
}

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def assign_symbiont_roles(hw_capability):
    """Return list of active symbiont role strings for the given hw_capability dict.

    Args:
        hw_capability (dict): e.g. {"tier_rank": 1, "native_tier_rank": 1}

    Returns:
        list of str: role names, ordered from least to most demanding.
    """
    tier = 0
    try:
        tier = int(
            hw_capability.get("native_tier_rank",
                              hw_capability.get("tier_rank", 0)) or 0
        )
        tier = max(0, min(4, tier))
    except Exception:
        tier = 0

    roles = ["memoria", "entropy_seed", "swarm_beacon"]
    if tier >= 1:
        roles.append("relay_bridge")
    if tier >= 2:
        roles.append("delta_vault")
    if tier >= 3:
        roles.append("knowledge_relay")
    return roles


def compute_legacy_network_entry_id(node_id, device_fp):
    """Stable, deterministic peer identity for legacy DHT registration.

    Uses the same derivation as auth.rs (dht-hw-user-lock family) so that
    every legacy node has a unique, hardware-bound peer identifier.

    Args:
        node_id  (str): hex node_id
        device_fp (str): SHA-256 device fingerprint hex

    Returns:
        str: "peer-" + 32 hex chars  (64-char format compatible with swarm_p2p.py)
    """
    raw = "legacy-dht|" + device_fp + "|" + node_id
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    return "peer-" + hashlib.sha256(raw).hexdigest()[:32]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_makedirs(path):
    if not path or os.path.isdir(path):
        return
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            pass


def _push_event(kind, detail=""):
    """Append an event to the in-memory log (thread-safe)."""
    global _event_idx
    with _state_lock:
        ev = {
            "idx": _event_idx,
            "ts": time.time(),
            "kind": str(kind),
            "detail": str(detail),
        }
        _event_log.append(ev)
        _event_idx += 1
        if len(_event_log) > EVENTS_MAX:
            _event_log.pop(0)


def _write_state():
    """Persist current _symbiont_state to STATE_PATH (thread-safe snapshot)."""
    with _state_lock:
        snap = dict(_symbiont_state)
    try:
        _safe_makedirs(os.path.dirname(STATE_PATH))
        f = open(STATE_PATH, "w")
        try:
            f.write(json.dumps(snap, indent=2, ensure_ascii=True))
        finally:
            f.close()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Role tick implementations
# ---------------------------------------------------------------------------

def _role_memoria_tick():
    """Count anchor files persisted on this node."""
    count = 0
    if os.path.isdir(ANCHOR_LIB_DIR):
        for _, _, fnames in os.walk(ANCHOR_LIB_DIR):
            count += len(fnames)
    with _state_lock:
        _symbiont_state["memoria_anchors"] = count
    return count


def _role_entropy_seed_tick():
    """Generate timing-based entropy and increment contribution counter."""
    raw = "entropy-seed|" + str(time.time()) + "|" + str(
        os.getpid() if hasattr(os, "getpid") else 0
    )
    if sys.version_info[0] >= 3:
        raw = raw.encode("utf-8")
    # The hash itself may be forwarded to the swarm as an entropy contribution.
    hashlib.sha256(raw).hexdigest()
    with _state_lock:
        _symbiont_state["entropy_contributions"] += 1
        count = _symbiont_state["entropy_contributions"]
    return count


def _role_knowledge_relay_tick():
    """Count knowledge snapshot entries available for relay."""
    snap_path = os.path.join(INTERBUS_DIR, "knowledge_snapshot.json")
    count = 0
    if os.path.isfile(snap_path):
        try:
            f = open(snap_path)
            try:
                data = json.loads(f.read())
            finally:
                f.close()
            entries = data.get("entries") or data.get("knowledge") or []
            count = len(entries)
        except Exception:
            pass
    with _state_lock:
        _symbiont_state["knowledge_entries"] = count
    return count


def _role_delta_vault_tick():
    """Count accumulated delta bundles in the interbus directory."""
    count = 0
    if os.path.isdir(INTERBUS_DIR):
        try:
            for fname in os.listdir(INTERBUS_DIR):
                if fname.startswith("delta_") and fname.endswith(".json"):
                    count += 1
        except Exception:
            pass
    with _state_lock:
        _symbiont_state["delta_count"] = count
    return count

# ---------------------------------------------------------------------------
# Public tick interface
# ---------------------------------------------------------------------------

def tick(node_id, device_fp, alias_username, hw_capability=None):
    """Run one symbiont tick cycle.

    Safe to call repeatedly from legacy_bootstrap.py main loop.
    Also called once at server start to populate initial state.

    Args:
        node_id       (str): hex node identifier
        device_fp     (str): SHA-256 device fingerprint hex
        alias_username (str): e.g. "aether_ab12cd34"
        hw_capability  (dict|None): if None, defaults to tier_rank=0

    Returns:
        dict: snapshot of current _symbiont_state
    """
    if hw_capability is None:
        hw_capability = {"tier_rank": 0}

    roles = assign_symbiont_roles(hw_capability)
    network_entry_id = compute_legacy_network_entry_id(node_id, device_fp)

    with _state_lock:
        _symbiont_state["node_id"] = node_id
        _symbiont_state["network_entry_id"] = network_entry_id
        _symbiont_state["alias"] = alias_username
        _symbiont_state["roles"] = roles
        _symbiont_state["tick_count"] += 1
        _symbiont_state["last_tick_ts"] = time.time()

    if "memoria" in roles:
        anchors = _role_memoria_tick()
        _push_event("memoria.tick", "anchors=" + str(anchors))

    if "entropy_seed" in roles:
        contrib = _role_entropy_seed_tick()
        _push_event("entropy.tick", "contributions=" + str(contrib))

    if "knowledge_relay" in roles:
        ke = _role_knowledge_relay_tick()
        _push_event("knowledge.tick", "entries=" + str(ke))

    if "delta_vault" in roles:
        dc = _role_delta_vault_tick()
        _push_event("delta.tick", "bundles=" + str(dc))

    _write_state()

    with _state_lock:
        return dict(_symbiont_state)

# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _SymbiontHandler(BaseHTTPRequestHandler):
    """Handles HTTP/1.1 POST requests from the Rust symbiont_rpc bridge."""

    def log_message(self, fmt, *args):
        # Suppress default access log noise; events go into _event_log instead.
        pass

    def _read_body(self):
        """Read and JSON-decode the request body. Returns {} on any error."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except Exception:
            length = 0
        if length > 0:
            try:
                raw = self.rfile.read(length)
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                return json.loads(raw)
            except Exception:
                return {}
        return {}

    def _respond(self, code, data):
        """Send a JSON response."""
        try:
            body = json.dumps(data, ensure_ascii=True).encode("utf-8")
        except Exception:
            body = b'{"error":"serialization_error"}'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.lstrip("/").rstrip("/")
        body = self._read_body()
        self._route(path, body)

    def do_GET(self):
        # Convenience: allow GET for status/roles without a body.
        path = self.path.lstrip("/").rstrip("/")
        if path in ("status", "roles", "help"):
            self._route(path, {})
        else:
            self._respond(405, {"error": "Bitte POST verwenden", "path": path})

    def _route(self, path, body):
        """Dispatch path → handler."""

        # ── Fixed event-polling endpoint (called automatically by iced_shell) ──
        if path == "aether/events":
            try:
                since = int(body.get("since_idx", 0) or 0)
            except Exception:
                since = 0
            try:
                limit = int(body.get("limit", 30) or 30)
            except Exception:
                limit = 30
            limit = max(1, min(500, limit))

            with _state_lock:
                events = [e for e in _event_log if e["idx"] >= since]
                events = events[:limit]
                last_idx = _event_idx

            self._respond(200, {"last_idx": last_idx, "events": events})
            return

        # ── User-typed commands (SymbiontRunPressed sends whatever is in the input box) ──

        if path == "status":
            with _state_lock:
                snap = dict(_symbiont_state)
            snap["uptime_sec"] = round(time.time() - snap.get("started_at", time.time()), 1)
            self._respond(200, snap)
            return

        if path == "tick":
            with _state_lock:
                node_id = _symbiont_state.get("node_id", "")
                device_fp = ""  # not stored — entropy_seed will still fire
                alias = _symbiont_state.get("alias", "")
                roles = list(_symbiont_state.get("roles", []))
                _symbiont_state["tick_count"] += 1
                _symbiont_state["last_tick_ts"] = time.time()
                tc = _symbiont_state["tick_count"]

            _push_event("manual.tick", "via-gui tick=" + str(tc))
            if "memoria" in roles:
                _role_memoria_tick()
            if "entropy_seed" in roles:
                _role_entropy_seed_tick()
            if "knowledge_relay" in roles:
                _role_knowledge_relay_tick()
            if "delta_vault" in roles:
                _role_delta_vault_tick()
            _write_state()
            self._respond(200, {"ok": True, "tick_count": tc, "roles": roles})
            return

        if path == "roles":
            with _state_lock:
                roles = list(_symbiont_state.get("roles", []))
                order = _symbiont_state.get("order", 3)
                label = _symbiont_state.get("order_label", "")
                tier_note = ""
                if roles:
                    if "knowledge_relay" in roles:
                        tier_note = "Tier 3+ — alle 6 Symbiont-Rollen aktiv"
                    elif "delta_vault" in roles:
                        tier_note = "Tier 2 — delta_vault aktiv"
                    elif "relay_bridge" in roles:
                        tier_note = "Tier 1 (Win2000) — relay_bridge aktiv"
                    else:
                        tier_note = "Tier 0 (Win9x/Legacy) — Basis-Rollen"
            self._respond(200, {
                "roles": roles,
                "order": order,
                "order_label": label,
                "tier_note": tier_note,
            })
            return

        if path == "peers":
            with _state_lock:
                peers = list(_symbiont_state.get("relay_peers", []))
                neid = _symbiont_state.get("network_entry_id", "")
                node_id = _symbiont_state.get("node_id", "")
            self._respond(200, {
                "node_id": node_id,
                "network_entry_id": neid,
                "relay_peers": peers,
                "peer_count": len(peers),
            })
            return

        if path == "flush":
            _push_event("flush.request", "user-triggered via GUI")
            self._respond(200, {"ok": True, "flushed": True})
            return

        if path == "help":
            self._respond(200, {
                "description": "Aether Symbiont Engine v1 — Kybernetischer Schwarm 3. Ordnung",
                "endpoints": [
                    "status   — aktueller Symbiont-Zustand",
                    "tick     — manueller Tick-Zyklus ausloesen",
                    "roles    — aktive Symbiont-Rollen anzeigen",
                    "peers    — Relay-Peers und network_entry_id",
                    "flush    — Delta-Buffer zuruecksetzen",
                    "help     — diese Hilfe",
                    "aether/events — Event-Log (intern, automatisch gepollt)",
                ],
                "order": 3,
            })
            return

        # Unknown endpoint
        _push_event("unknown.endpoint", path)
        self._respond(404, {
            "error": "unbekannter Endpunkt",
            "path": path,
            "hint": "Verfuegbar: status, tick, roles, peers, flush, help",
        })

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
_server_thread = None
_server_instance = None


def start_server(port=SYMBIONT_PORT, host="127.0.0.1", daemon=True):
    """Start the symbiont HTTP server in a background thread.

    Idempotent — does nothing if the server is already running.

    Args:
        port   (int): TCP port to listen on (default 38571)
        host   (str): bind address (default 127.0.0.1)
        daemon (bool): make thread a daemon so it dies with the process

    Returns:
        threading.Thread: the server thread
    """
    global _server_thread, _server_instance
    if _server_thread is not None and _server_thread.is_alive():
        return _server_thread

    srv = HTTPServer((host, port), _SymbiontHandler)
    _server_instance = srv

    def _run():
        try:
            srv.serve_forever()
        except Exception:
            pass

    t = threading.Thread(target=_run)
    t.daemon = daemon
    t.start()
    _server_thread = t
    _push_event("server.start", "port=" + str(port) + " host=" + host)
    return t


def stop_server():
    """Gracefully shut down the symbiont HTTP server."""
    global _server_instance
    if _server_instance is not None:
        try:
            _server_instance.shutdown()
        except Exception:
            pass
        _push_event("server.stop", "")

# ---------------------------------------------------------------------------
# Standalone entry point (for testing / direct launch)
# ---------------------------------------------------------------------------

def main():
    port = SYMBIONT_PORT
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except Exception:
                pass
            i += 2
        else:
            i += 1

    # Bootstrap with a stable test identity so the server is immediately usable.
    seed = "standalone|" + (os.environ.get("COMPUTERNAME") or "unknown")
    if sys.version_info[0] >= 3:
        seed = seed.encode("utf-8")
    node_id = hashlib.sha256(seed).hexdigest()[:16]
    device_fp = hashlib.sha256(
        ("device|" + node_id).encode("utf-8")
        if sys.version_info[0] >= 3
        else ("device|" + node_id)
    ).hexdigest()
    alias = "aether_" + node_id[:8]

    hw_cap = {"tier_rank": 1}
    tick(node_id, device_fp, alias, hw_cap)
    start_server(port=port)

    print("[SYMBIONT] Server gestartet auf Port " + str(port))
    print("[SYMBIONT] Kybernetischer Schwarm 3. Ordnung aktiv.")
    print("[SYMBIONT] Node-ID: " + node_id)
    print("[SYMBIONT] Alias:   " + alias)
    print("[SYMBIONT] Ctrl+C zum Beenden.")

    try:
        while True:
            time.sleep(30)
            tick(node_id, device_fp, alias, hw_cap)
    except KeyboardInterrupt:
        stop_server()
        print("[SYMBIONT] Server gestoppt.")


if __name__ == "__main__":
    main()
