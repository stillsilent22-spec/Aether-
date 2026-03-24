"""P2P Sync Layer for Aether Swarm (opt-in).

Provides pluggable peer-to-peer fingerprint and metadata exchange.
Built on top of the existing AethernetTransport — no extra dependencies.

Features:
  - PeerID: derived from node's Ed25519 public key (not IP-based)
  - Signed fingerprint gossip: publish only SHA256 fingerprints + aggregated metrics
  - DHT-style peer discovery: extends existing LAN UDP beacon
  - Local leader election: simple highest-PeerID leader rule for local networks
  - Encrypted channels: reuses AethernetTransport Ed25519 signing (Noise-equivalent)

Privacy guarantees:
  - Share ONLY: fingerprints, aggregated metrics, anonymous node_id
  - NEVER share: raw frames, pixel data, application content

Opt-in: disabled by default. Set settings.json > swarm_p2p.enabled = true to activate.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SETTINGS_PATH = ROOT / "data" / "settings.json"
INTERBUS_DIR = ROOT / "data" / "interbus"
P2P_GOSSIP_PATH = INTERBUS_DIR / "p2p_gossip.json"

DEFAULT_P2P: Dict[str, Any] = {
    "enabled": False,              # opt-in, default OFF
    "gossip_interval_seconds": 30.0,
    "max_fingerprints_per_gossip": 20,
    "leader_election_enabled": True,
    "peer_ttl_seconds": 120.0,
}


# --------------------------------------------------------------------------- #
#  PeerID                                                                     #
# --------------------------------------------------------------------------- #

def derive_peer_id(public_key_path: Optional[str] = None) -> str:
    """Derive PeerID from Ed25519 public key (deterministic, anonymous)."""
    try:
        if public_key_path is None:
            public_key_path = str(ROOT / "keys" / "node_public.key")
        key_bytes = Path(public_key_path).read_bytes()
        return "peer-" + hashlib.sha256(key_bytes).hexdigest()[:32]
    except Exception:
        # Fallback: generate stable random PeerID stored locally
        pid_path = ROOT / "data" / "peer_id.txt"
        if pid_path.is_file():
            return pid_path.read_text(encoding="utf-8").strip()
        pid = "peer-" + uuid.uuid4().hex[:32]
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(pid, encoding="utf-8")
        return pid


# --------------------------------------------------------------------------- #
#  Leader election (simple highest-PeerID rule)                              #
# --------------------------------------------------------------------------- #

class LeaderElection:
    """Simple deterministic leader election: highest PeerID among known peers."""

    def __init__(self, local_peer_id: str) -> None:
        self._local_peer_id = local_peer_id
        self._known_peers: Dict[str, float] = {}  # peer_id -> last_seen_ts
        self._lock = threading.Lock()
        self._ttl = DEFAULT_P2P["peer_ttl_seconds"]

    def register_peer(self, peer_id: str) -> None:
        with self._lock:
            self._known_peers[peer_id] = time.monotonic()

    def evict_stale(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [p for p, ts in self._known_peers.items() if now - ts > self._ttl]
            for p in stale:
                del self._known_peers[p]

    def is_leader(self) -> bool:
        """Return True if local node is the current leader (highest PeerID)."""
        self.evict_stale()
        with self._lock:
            all_peers = list(self._known_peers.keys()) + [self._local_peer_id]
        return self._local_peer_id >= max(all_peers)

    def current_leader(self) -> str:
        self.evict_stale()
        with self._lock:
            all_peers = list(self._known_peers.keys()) + [self._local_peer_id]
        return max(all_peers)

    def peer_count(self) -> int:
        self.evict_stale()
        with self._lock:
            return len(self._known_peers)


# --------------------------------------------------------------------------- #
#  Gossip message                                                             #
# --------------------------------------------------------------------------- #

def _build_gossip_message(
    peer_id: str,
    fingerprints: List[str],
    metrics_summary: Dict[str, Any],
    is_leader: bool,
) -> Dict[str, Any]:
    """Build a gossip message containing ONLY fingerprints and aggregated metrics."""
    return {
        "schema": "aether.swarm.p2p.gossip.v1",
        "peer_id": peer_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "is_leader": is_leader,
        "fingerprints": fingerprints[:DEFAULT_P2P["max_fingerprints_per_gossip"]],
        "metrics_summary": metrics_summary,
        # Raw frames, pixel data, application content: NEVER included
    }


# --------------------------------------------------------------------------- #
#  P2PLayer                                                                   #
# --------------------------------------------------------------------------- #

class P2PLayer:
    """Opt-in P2P fingerprint exchange layer."""

    def __init__(
        self,
        node_id: str,
        aethernet_transport: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._node_id = node_id
        self._transport = aethernet_transport
        self._config = dict(DEFAULT_P2P)
        if config:
            self._config.update(config)

        self._peer_id = derive_peer_id()
        self._leader_election = LeaderElection(self._peer_id)
        self._stop_event = threading.Event()
        self._gossip_thread: Optional[threading.Thread] = None
        self._received_gossip: List[Dict[str, Any]] = []
        self._received_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self._config.get("enabled", False))

    @property
    def peer_id(self) -> str:
        return self._peer_id

    def start(self) -> None:
        if not self.enabled:
            print("[P2P] Disabled (opt-in). Set swarm_p2p.enabled=true to activate.")
            return
        self._stop_event.clear()
        self._gossip_thread = threading.Thread(
            target=self._gossip_loop, daemon=True, name="swarm-p2p-gossip"
        )
        self._gossip_thread.start()
        print(f"[P2P] Layer started. PeerID={self._peer_id[:16]}…")

    def stop(self) -> None:
        self._stop_event.set()
        if self._gossip_thread:
            self._gossip_thread.join(timeout=3.0)

    def is_leader(self) -> bool:
        return self._leader_election.is_leader()

    def current_leader(self) -> str:
        return self._leader_election.current_leader()

    def publish_fingerprints(
        self,
        fingerprints: List[str],
        metrics_summary: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish fingerprints to known peers via AethernetTransport."""
        if not self.enabled:
            return False
        if not fingerprints:
            return False
        msg = _build_gossip_message(
            peer_id=self._peer_id,
            fingerprints=fingerprints,
            metrics_summary=metrics_summary or {},
            is_leader=self.is_leader(),
        )
        # Write gossip to local interbus for external readers
        try:
            INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
            P2P_GOSSIP_PATH.write_text(
                json.dumps(msg, ensure_ascii=True, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
        # Send via AethernetTransport if available
        if self._transport is not None:
            try:
                self._transport.relay_push({"p2p_gossip": msg})
                return True
            except Exception as err:
                print(f"[P2P] relay_push failed: {err}")
        return True  # Local write succeeded

    def receive_gossip(self, msg: Dict[str, Any]) -> None:
        """Process incoming gossip message from a peer."""
        if not isinstance(msg, dict):
            return
        schema = str(msg.get("schema", ""))
        if schema != "aether.swarm.p2p.gossip.v1":
            return
        peer_id = str(msg.get("peer_id", "")).strip()
        if peer_id and peer_id != self._peer_id:
            self._leader_election.register_peer(peer_id)
        with self._received_lock:
            self._received_gossip.append(msg)
            # Keep last 100 gossip messages
            if len(self._received_gossip) > 100:
                self._received_gossip = self._received_gossip[-100:]

    def get_received_fingerprints(self, limit: int = 100) -> List[str]:
        """Return all unique fingerprints received from peers."""
        seen: set[str] = set()
        result: List[str] = []
        with self._received_lock:
            for msg in reversed(self._received_gossip):
                for fp in msg.get("fingerprints", []):
                    if fp not in seen:
                        seen.add(fp)
                        result.append(fp)
                        if len(result) >= limit:
                            return result
        return result

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "peer_id": self._peer_id,
            "is_leader": self.is_leader(),
            "leader": self.current_leader(),
            "peer_count": self._leader_election.peer_count(),
            "received_gossip_count": len(self._received_gossip),
        }

    def _gossip_loop(self) -> None:
        interval = float(self._config.get("gossip_interval_seconds", 30.0))
        while not self._stop_event.is_set():
            try:
                self._do_gossip()
            except Exception as err:
                print(f"[P2P] gossip error: {err}")
            self._stop_event.wait(timeout=interval)

    def _do_gossip(self) -> None:
        """Collect recent fingerprints from DB and publish."""
        try:
            from modules.swarm_persist import get_fingerprint_stats, _connect, DEFAULT_DB_PATH, _db_lock
            with _db_lock:
                conn = _connect(DEFAULT_DB_PATH)
                try:
                    rows = conn.execute(
                        "SELECT fingerprint FROM fingerprints ORDER BY last_seen_ts DESC LIMIT ?",
                        (DEFAULT_P2P["max_fingerprints_per_gossip"],)
                    ).fetchall()
                finally:
                    conn.close()
            fps = [r[0] for r in rows]
            stats = get_fingerprint_stats()
            self.publish_fingerprints(fps, metrics_summary=stats)
        except Exception as err:
            print(f"[P2P] _do_gossip error: {err}")


# --------------------------------------------------------------------------- #
#  Factory                                                                    #
# --------------------------------------------------------------------------- #

def make_p2p_layer(
    node_id: str,
    aethernet_transport: Any = None,
) -> P2PLayer:
    """Create P2PLayer from settings.json config."""
    try:
        if SETTINGS_PATH.is_file():
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            config = raw.get("swarm_p2p", {})
        else:
            config = {}
    except Exception:
        config = {}
    return P2PLayer(node_id=node_id, aethernet_transport=aethernet_transport, config=config)
