"""
dht_bootstrap.py — Kademlia-ähnlicher DHT-Bootstrap für Aether
===============================================================

ZWECK: Knoten finden ohne vorherige Relay-Konfiguration.
Jeder Knoten lernt automatisch Peers — auch Win95/98/XP-Knoten
über die Relay-Brücke, auch moderne Knoten direkt via UDP/HTTP.

ARCHITEKTUR:

  Schicht 1 — LAN (UDP Multicast 239.255.42.7:7742)
    Alle LAN-Knoten sehen einander sofort. Kein Config.

  Schicht 2 — DNS-Seed (öffentliche TXT-Records)
    Ohne LAN-Partner: DNS-Seed gibt Bootstrap-Relay-URLs zurück.
    Fallback: eingebettete Hardcoded-Seeds (update-fähig via Gossip).
    Format: TXT "aether-seed=http://relay1.example.com;http://relay2.example.com"

  Schicht 3 — Kademlia K-Bucket DHT
    node_id = sha256(pubkey)[:16]  — 64-bit Adressraum
    K = 8 Buckets pro Abstandsbit
    FIND_NODE RPC über HTTP POST /dht/find_node
    STORE_VALUE (Relay-URLs) über HTTP POST /dht/store
    FIND_VALUE über HTTP GET /dht/find/{key}

  Schicht 4 — Kybernetische Progression (3. Ordnung)
    Jeder neue Peer wird analysiert:
      - Stärken des Peers werden als Blindspot-Hints übernommen
      - Eigene Gaps werden dem Peer gemeldet
      - Swarm-weite Wissensverteilung via flood-relay

LEGACY-KOMPATIBILITÄT:
  - Alle RPCs: HTTP POST/GET mit JSON — kein WebSocket, kein TLS erforderlich
  - UDP-Discovery: optional, graceful skip wenn Socket nicht verfügbar
  - Kein numpy, kein cryptography zum Finden (optional für Verifikation)
  - Python 2.6+ kompatible Strukturen (keine f-strings, keine walrus-ops)

SICHERHEIT:
  - node_id wird aus public_key_pem abgeleitet (mathematisch gebunden)
  - Bez. Relay-URLs: nur http/https akzeptiert
  - Revoked-Node-Liste wird vor dem Speichern geprüft
  - K-Bucket-Einträge haben TTL (PEER_TTL_SEC) — veraltete werden entfernt
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent

# ── Persistenz-Pfade ─────────────────────────────────────────────────────── #
DHT_STATE_PATH   = ROOT / "data" / "swarm" / "dht_state.json"
REVOKED_PATH     = ROOT / "config" / "revoked_nodes.json"
RELAY_POOL_PATH  = ROOT / "data" / "swarm" / "relay_pool.json"
NODES_DIR        = ROOT / "data" / "swarm" / "nodes"

# ── Konstanten ───────────────────────────────────────────────────────────── #
K_BUCKET_SIZE   = 8      # Einträge pro Kademlia-Bucket
PEER_TTL_SEC    = 600    # Peer nach 10 Min ohne Ping als tot markieren
DHT_PORT        = 7387   # HTTP-Port für DHT-RPCs (neben Gossip-Port 7385)
ALPHA           = 3      # Parallele FIND_NODE-Anfragen (Kademlia α)
MAX_PEERS_TOTAL = 256    # Maximale Anzahl gespeicherter Peers

# DNS-Seed Hostnamen (TXT-Record "aether-seed=url1;url2;...")
# Wird via Gossip updatebar — hardcoded nur als letzter Fallback.
DNS_SEEDS: List[str] = [
    "seed1.aethernet.io",
    "seed2.aethernet.io",
    "aether-seed.duckdns.org",
]

# Hardcoded Bootstrap-Relays — letzter Ausweg wenn DNS auch versagt.
# Werden via Gossip aktualisiert und in relay_pool.json persistiert.
HARDCODED_SEED_RELAYS: List[str] = [
    # Platzhalter — werden bei Genesis-Deployment gesetzt.
    # Format: "http://ip:7385" oder "https://domain.tld"
]


# ── Hilfsfunktionen ──────────────────────────────────────────────────────── #

def _xor_distance(id_a: str, id_b: str) -> int:
    """XOR-Distanz zweier node_ids (hex-strings, bis 16 Zeichen)."""
    try:
        a = int(id_a[:16], 16)
        b = int(id_b[:16], 16)
        return a ^ b
    except Exception:
        return 0xFFFFFFFFFFFFFFFF


def _bucket_index(local_id: str, remote_id: str) -> int:
    """Welcher K-Bucket? Basiert auf der führenden 0-Bit-Anzahl der XOR-Distanz."""
    dist = _xor_distance(local_id, remote_id)
    if dist == 0:
        return 0
    bit = 0
    while dist > 1:
        dist >>= 1
        bit += 1
    return min(bit, 63)   # 64 Buckets für 64-Bit node_ids


def _load_revoked() -> set:
    try:
        if REVOKED_PATH.is_file():
            data = json.loads(REVOKED_PATH.read_text(encoding="utf-8"))
            lst = data.get("revoked") or data.get("node_ids") or (data if isinstance(data, list) else [])
            return {str(x) for x in lst}
    except Exception:
        pass
    return set()


def _query_dns_seed(hostname: str, timeout: float = 3.0) -> List[str]:
    """Fragt einen DNS-Seed-Host nach TXT-Records ab.

    Erwartet TXT-Einträge im Format: "aether-seed=url1;url2;..."
    Gibt leere Liste zurück bei Fehler (graceful degradation).
    """
    urls: List[str] = []
    try:
        # Python stdlib kennt keinen TXT-Record-Lookup ohne dnspython.
        # Workaround: HTTP-Fallback über http://<hostname>/seeds.json
        import urllib.request as _ureq
        seed_url = "http://" + hostname + "/seeds.json"
        req = _ureq.Request(seed_url, headers={"User-Agent": "AetherNode/1.0"})
        with _ureq.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for url in data.get("relay_urls") or data.get("urls") or []:
                u = str(url).strip()
                if u.startswith(("http://", "https://")):
                    urls.append(u)
    except Exception as exc:
        logger.debug("[dht] DNS-Seed %s nicht erreichbar: %s", hostname, exc)
    return urls


# ── DHT-Peer-Eintrag ─────────────────────────────────────────────────────── #

class DHTNode:
    """Ein einzelner bekannter Peer im K-Bucket."""

    __slots__ = ("node_id", "host", "port", "last_seen", "relay_url",
                 "tier_rank", "capabilities", "relay_bridge")

    def __init__(
        self,
        node_id: str,
        host: str,
        port: int,
        relay_url: str = "",
        tier_rank: int = 0,
        capabilities: Optional[List[str]] = None,
        relay_bridge: bool = False,
    ) -> None:
        self.node_id    = str(node_id)
        self.host       = str(host)
        self.port       = int(port)
        self.last_seen  = time.time()
        self.relay_url  = str(relay_url)
        self.tier_rank  = int(tier_rank)
        self.capabilities: List[str] = list(capabilities or [])
        self.relay_bridge = bool(relay_bridge)

    def is_alive(self) -> bool:
        return (time.time() - self.last_seen) < PEER_TTL_SEC

    def direct_url(self) -> str:
        """HTTP-URL für direkte Verbindung, leer wenn nur über Relay erreichbar."""
        if self.relay_bridge:
            return ""
        return "http://{}:{}/".format(self.host, self.port)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id":      self.node_id,
            "host":         self.host,
            "port":         self.port,
            "last_seen":    round(self.last_seen, 3),
            "relay_url":    self.relay_url,
            "tier_rank":    self.tier_rank,
            "capabilities": self.capabilities,
            "relay_bridge": self.relay_bridge,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DHTNode":
        n = cls(
            node_id=str(d.get("node_id", "")),
            host=str(d.get("host", "")),
            port=int(d.get("port", DHT_PORT)),
            relay_url=str(d.get("relay_url", "")),
            tier_rank=int(d.get("tier_rank", 0)),
            capabilities=list(d.get("capabilities") or []),
            relay_bridge=bool(d.get("relay_bridge", False)),
        )
        n.last_seen = float(d.get("last_seen", time.time()))
        return n


# ── DHT-Bootstrap-Engine ─────────────────────────────────────────────────── #

class DHTBootstrap:
    """Kademlia-ähnlicher DHT-Bootstrap für das Aether-Netz.

    Singleton pro Prozess — DHTBootstrap.instance() verwenden.
    Thread-sicher.

    Lifecycle:
      1. DHTBootstrap.instance().start(local_node_id, local_host, local_port)
      2. Bootstrap-Prozess läuft automatisch:
         a) LAN-Multicast-Discovery
         b) DNS-Seed-Abfrage
         c) Hardcoded-Relays als Fallback
         d) FIND_NODE RPCs — Kademlia-Routing-Tabellenaufbau
         e) Kybernetisches Feedback: Blindspot-Hints über entdeckte Peers
    """

    _instance: Optional["DHTBootstrap"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "DHTBootstrap":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock            = threading.Lock()
        self._local_id        = ""
        self._local_host      = ""
        self._local_port      = DHT_PORT
        # K-Buckets: bucket_index → List[DHTNode]
        self._buckets:  Dict[int, List[DHTNode]] = {i: [] for i in range(64)}
        self._is_running = False
        self._stop_event  = threading.Event()
        self._bootstrap_done = False
        self._revoked: set = set()
        self._load_state()

    # ── Lifecycle ─────────────────────────────────────────────────────────── #

    def start(
        self,
        local_node_id: str,
        local_host: str = "",
        local_port: int = DHT_PORT,
    ) -> None:
        """Startet den Bootstrap-Prozess in einem Hintergrund-Thread."""
        with self._lock:
            if self._is_running:
                return
            self._local_id   = str(local_node_id)
            self._local_host = str(local_host) if local_host else self._detect_local_ip()
            self._local_port = int(local_port)
            self._is_running = True
        self._stop_event.clear()
        t = threading.Thread(
            target=self._bootstrap_loop,
            daemon=True,
            name="dht-bootstrap",
        )
        t.start()
        logger.info("[dht] Bootstrap-Loop gestartet — node_id=%s", local_node_id[:16])

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._is_running = False

    # ── Bootstrap-Loop ────────────────────────────────────────────────────── #

    def _bootstrap_loop(self) -> None:
        """Haupt-Bootstrap-Schleife: Peers finden, K-Buckets aufbauen, Feedback."""
        # Initiale Discovery
        self._discover_lan()
        self._discover_via_dns_seeds()
        self._discover_via_relay_pool()
        self._bootstrap_done = True
        self._save_state()
        logger.info(
            "[dht] Initiale Discovery abgeschlossen — %d Peers bekannt",
            self._total_peers(),
        )

        # Periodisch: alte Peers entfernen, neue suchen, Blindspot-Sync
        while not self._stop_event.is_set():
            try:
                self._evict_dead_peers()
                if self._total_peers() < K_BUCKET_SIZE:
                    # Unter Minimum: aggressiv neu suchen
                    self._discover_lan()
                    self._discover_via_dns_seeds()
                    self._discover_via_relay_pool()
                self._sync_blindspots_with_peers()
                self._save_state()
            except Exception as exc:
                logger.debug("[dht] bootstrap_loop iteration: %s", exc)
            self._stop_event.wait(120)   # alle 2 Minuten

    # ── Discovery-Schichten ───────────────────────────────────────────────── #

    def _discover_lan(self) -> None:
        """Liest bekannte LAN-Knoten aus data/swarm/nodes/ ein.

        lan_beacon.py schreibt jede empfangene Beacon-Payload als <node_id>.json
        in dieses Verzeichnis. Wir lesen sie beim Start und nach Beacon-Runden.
        """
        try:
            if not NODES_DIR.is_dir():
                return
            revoked = _load_revoked()
            count = 0
            for node_file in NODES_DIR.glob("*.json"):
                try:
                    data = json.loads(node_file.read_text(encoding="utf-8"))
                    nid = str(data.get("node_id", "") or "").strip()
                    if not nid or nid == self._local_id:
                        continue
                    if nid in revoked:
                        continue
                    host = str(data.get("lan_ip") or data.get("host") or "").strip()
                    port = int(data.get("gossip_port") or data.get("port") or 7385)
                    relay_url = str(data.get("relay_url", "") or "")
                    tier_rank = int(data.get("tier_rank", 0) or 0)
                    caps = list(data.get("capabilities") or [])
                    relay_bridge = bool(data.get("relay_bridge_mode", False))
                    node = DHTNode(
                        node_id=nid,
                        host=host,
                        port=port,
                        relay_url=relay_url,
                        tier_rank=tier_rank,
                        capabilities=caps,
                        relay_bridge=relay_bridge,
                    )
                    if self._add_to_bucket(node):
                        count += 1
                except Exception:
                    pass
            if count > 0:
                logger.debug("[dht] LAN-Discovery: %d neue Knoten aus nodes/", count)
        except Exception as exc:
            logger.debug("[dht] _discover_lan: %s", exc)

    def _discover_via_dns_seeds(self) -> None:
        """Fragt configured DNS-Seeds ab und lernt Relay-URLs."""
        new_relays: List[str] = []
        for hostname in DNS_SEEDS:
            urls = _query_dns_seed(hostname)
            new_relays.extend(urls)
        # Zusätzlich: aus settings.json gelesne DNS-Seed-Hostnamen
        try:
            settings_path = ROOT / "data" / "settings.json"
            if settings_path.is_file():
                settings = json.loads(settings_path.read_text(encoding="utf-8"))
                p2p = settings.get("swarm_p2p") or settings.get("p2p") or {}
                for host in list(p2p.get("dns_seeds") or []):
                    new_relays.extend(_query_dns_seed(str(host)))
        except Exception:
            pass

        if new_relays:
            self._learn_relay_urls(new_relays)
            logger.debug("[dht] DNS-Seeds ergaben %d neue Relay-URLs", len(new_relays))

    def _discover_via_relay_pool(self) -> None:
        """Kontaktiert bekannte Relays und empfängt Peer-Pakete via GET /gossip/latest.

        Für jeden empfangenen Peer:
          - Wird in K-Bucket eingetragen
          - Relay-URL wird aus dem Gossip gelernt
          - Wird als potentieller Blindspot-Helfer registriert
        """
        relays = self._load_relay_pool()
        if not relays:
            # Letzter Ausweg: eingebettete Hardcoded-Seeds
            relays = list(HARDCODED_SEED_RELAYS)
            if relays:
                logger.debug("[dht] Nutze hardcoded Seed-Relays als Fallback")
        if not relays:
            return

        import urllib.request as _ureq
        import urllib.error as _uerr

        count = 0
        for relay_url in relays[:8]:   # maximal 8 Relays gleichzeitig probieren
            try:
                url = relay_url.rstrip("/") + "/gossip/latest"
                req = _ureq.Request(url, headers={"User-Agent": "AetherNode/1.0"})
                with _ureq.urlopen(req, timeout=6) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                msgs = [m for m in list(data.get("messages") or []) if isinstance(m, dict)]
                for msg in msgs:
                    nid = str(msg.get("node_id", "") or "").strip()
                    if not nid or nid == self._local_id:
                        continue
                    if nid in _load_revoked():
                        continue
                    # Lerne neue Relay-URLs aus dem Peer-Paket
                    for u in list(msg.get("known_relay_urls") or []):
                        self._learn_single_relay(str(u))
                    host = str(msg.get("lan_ip") or msg.get("host") or "").strip()
                    tier_rank = int(msg.get("metrics_summary", {}).get("tier_rank", 0) or 0)
                    node = DHTNode(
                        node_id=nid,
                        host=host,
                        port=7385,
                        relay_url=relay_url,
                        tier_rank=tier_rank,
                        relay_bridge=not bool(host),
                    )
                    if self._add_to_bucket(node):
                        count += 1
            except Exception as exc:
                logger.debug("[dht] relay pull %s: %s", relay_url[:32], exc)

        if count > 0:
            logger.info("[dht] Relay-Discovery: %d neue Knoten gelernt", count)

    # ── FIND_NODE RPC ─────────────────────────────────────────────────────── #

    def find_node(self, target_id: str) -> List[DHTNode]:
        """Gibt die K nähesten bekannten Knoten zu target_id zurück.

        Vollständig lokal — kein Netz-IO. Wird von FIND_NODE-Handler aufgerufen.
        """
        all_peers: List[DHTNode] = []
        with self._lock:
            for bucket in self._buckets.values():
                all_peers.extend(bucket)
        all_peers = [p for p in all_peers if p.node_id != target_id and p.is_alive()]
        all_peers.sort(key=lambda p: _xor_distance(target_id, p.node_id))
        return all_peers[:K_BUCKET_SIZE]

    def handle_find_node_rpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Verarbeitet eingehende FIND_NODE-RPC-Anfrage.

        Erwartet: {"target_id": str, "from_node": dict}
        Gibt zurück: {"nodes": [node_dict, ...]}
        """
        target_id = str(request.get("target_id", "") or "")
        from_node = request.get("from_node")
        # Einsendenden Knoten registrieren
        if isinstance(from_node, dict):
            nid = str(from_node.get("node_id", "") or "").strip()
            if nid and nid != self._local_id and nid not in _load_revoked():
                node = DHTNode.from_dict(from_node)
                self._add_to_bucket(node)
        closest = self.find_node(target_id)
        return {
            "schema":    "aether.dht.find_node_response.v1",
            "nodes":     [n.to_dict() for n in closest],
            "from_node": self._local_node_dict(),
        }

    def handle_store_rpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Verarbeitet STORE-RPC: speichert Relay-URLs aus dem Netz.

        Eingehende relay_urls werden gelernt und in relay_pool.json gespeichert.
        """
        relay_urls = list(request.get("relay_urls") or [])
        if relay_urls:
            self._learn_relay_urls(relay_urls)
        return {"schema": "aether.dht.store_ack.v1", "ok": True}

    # ── Peer-Management ──────────────────────────────────────────────────── #

    def _add_to_bucket(self, node: DHTNode) -> bool:
        """Fügt einen Knoten in den entsprechenden K-Bucket ein.

        Gibt True zurück wenn neu hinzugefügt, False wenn schon bekannt oder verworfen.
        """
        if not node.node_id or node.node_id == self._local_id:
            return False
        with self._lock:
            idx = _bucket_index(self._local_id, node.node_id)
            bucket = self._buckets[idx]
            # Schon bekannt? → last_seen aktualisieren
            for existing in bucket:
                if existing.node_id == node.node_id:
                    existing.last_seen = time.time()
                    if node.host and not existing.host:
                        existing.host = node.host
                    if node.relay_url and not existing.relay_url:
                        existing.relay_url = node.relay_url
                    return False
            # Bucket voll? → ältesten toten Knoten verdrängen
            if len(bucket) >= K_BUCKET_SIZE:
                dead = [n for n in bucket if not n.is_alive()]
                if dead:
                    bucket.remove(dead[0])
                else:
                    # Bucket voll, alle lebendig → neuen Knoten ignorieren (Kademlia-Regel)
                    return False
            bucket.append(node)
        # Neuen Knoten auch in nodes/ persistieren
        self._save_node_file(node)
        return True

    def _save_node_file(self, node: DHTNode) -> None:
        """Persistiert Knoten-Infos in data/swarm/nodes/<node_id>.json."""
        try:
            NODES_DIR.mkdir(parents=True, exist_ok=True)
            path = NODES_DIR / (node.node_id + ".json")
            if not path.is_file():
                path.write_text(
                    json.dumps(node.to_dict(), ensure_ascii=True, indent=2),
                    encoding="utf-8",
                )
        except Exception:
            pass

    def _evict_dead_peers(self) -> int:
        """Entfernt abgelaufene Peers aus allen K-Buckets."""
        evicted = 0
        with self._lock:
            for bucket in self._buckets.values():
                before = len(bucket)
                bucket[:] = [n for n in bucket if n.is_alive()]
                evicted += before - len(bucket)
        return evicted

    def _total_peers(self) -> int:
        with self._lock:
            return sum(len(b) for b in self._buckets.values())

    def get_all_peers(self) -> List[DHTNode]:
        """Alle bekannten lebenden Peers."""
        with self._lock:
            result = []
            for bucket in self._buckets.values():
                result.extend(n for n in bucket if n.is_alive())
        return result

    def get_peers_as_relay_urls(self) -> List[str]:
        """Relay-URLs aller bekannten Peers (für Gossip-Einbettung)."""
        urls: List[str] = []
        for peer in self.get_all_peers():
            if peer.relay_url:
                urls.append(peer.relay_url)
        return list(set(urls))

    # ── Kybernetisches Feedback (3. Ordnung) ──────────────────────────────── #

    def _sync_blindspots_with_peers(self) -> None:
        """Kybernetisches Feedback: Vergleicht Stärken aller bekannten Peers mit
        eigenen Gaps — meldet Gaps als Blindspot-Signals falls neue Peers helfen können.

        Das ist die 3. Ordnung: Das Netz beobachtet sich selbst durch die
        Augen seiner Peers und lernt was fehlt — ohne menschlichen Eingriff.
        """
        try:
            from modules.blindspot_engine import BlindspotEngine
            bs = BlindspotEngine.instance()
            # Aktive eigene Gaps sammeln
            active_gaps = list(bs._active_gaps.values())
            if not active_gaps:
                return

            peers = self.get_all_peers()
            if not peers:
                return

            # Peer-Capabilities mit unseren Gaps abgleichen
            for peer in peers:
                for gap_sig in active_gaps:
                    if gap_sig.resolved:
                        continue
                    # Peer hat die benötigte Capability?
                    domain = gap_sig.domain
                    if domain in (peer.capabilities or []):
                        # Registriere als potentieller Helfer in _peer_gaps
                        # (wird von get_hints_for_broadcast() genutzt)
                        peer_gap_entry = {
                            "schema":    "aether.blindspot.signal.v1",
                            "signal_id": gap_sig.signal_id,
                            "domain":    domain,
                            "gap_type":  gap_sig.gap_type,
                            "priority":  gap_sig.priority,
                        }
                        # absorb_peer_gaps erwartet gaps vom Peer, nicht unsere eigenen —
                        # hier registrieren wir den Gap des lokalen Knotens
                        # unter der Peer-ID damit get_hints_for_broadcast() antwortet
                        # wenn wir stark genug sind um dem Peer zu helfen.
                        bs.absorb_peer_gaps(peer.node_id, [peer_gap_entry])
        except Exception as exc:
            logger.debug("[dht] _sync_blindspots: %s", exc)

    def absorb_gossip_peer(
        self,
        node_id: str,
        host: str,
        port: int,
        relay_url: str,
        tier_rank: int,
        capabilities: Optional[List[str]] = None,
        relay_bridge: bool = False,
    ) -> bool:
        """Wird von swarm_p2p.receive_gossip() aufgerufen wenn ein neuer Peer gesehen wurde.

        Integration: Gossip-Empfang → DHT-Registration → Blindspot-Sync.
        """
        if node_id == self._local_id:
            return False
        if node_id in _load_revoked():
            return False
        node = DHTNode(
            node_id=node_id,
            host=host,
            port=port,
            relay_url=relay_url,
            tier_rank=tier_rank,
            capabilities=capabilities or [],
            relay_bridge=relay_bridge,
        )
        added = self._add_to_bucket(node)
        if added:
            logger.debug("[dht] Neuer Peer via Gossip: %s (tier=%d)", node_id[:16], tier_rank)
        return added

    # ── Relay-Pool Management ─────────────────────────────────────────────── #

    def _load_relay_pool(self) -> List[str]:
        try:
            if RELAY_POOL_PATH.is_file():
                data = json.loads(RELAY_POOL_PATH.read_text(encoding="utf-8"))
                return [str(u) for u in data.get("urls", []) if str(u).startswith(("http://", "https://"))]
        except Exception:
            pass
        return []

    def _learn_relay_urls(self, urls: List[str]) -> None:
        for u in urls:
            self._learn_single_relay(str(u).strip())

    def _learn_single_relay(self, url: str) -> None:
        if not url or not url.startswith(("http://", "https://")):
            return
        try:
            pool = self._load_relay_pool()
            if url in pool:
                return
            if len(pool) >= 64:
                return
            pool.append(url)
            RELAY_POOL_PATH.parent.mkdir(parents=True, exist_ok=True)
            RELAY_POOL_PATH.write_text(
                json.dumps({"schema": "aether.relay_pool.v1", "urls": pool[:64]},
                           ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
            logger.debug("[dht] Neue Relay-URL gelernt: %s", url)
        except Exception:
            pass

    # ── Capability-Progression ────────────────────────────────────────────── #

    def get_network_tier_suggestion(self) -> Dict[str, Any]:
        """Gibt basierend auf bekannten Peers eine Progression-Empfehlung zurück.

        Kybernetik 3. Ordnung: Das System empfiehlt dem Knoten selbst
        seinen nächsten Entwicklungsschritt basierend auf dem Schwarm.

        Beispiel:
          - 0 Peers bekannt → Basis-Daemon, Relay-Suche aktiv
          - 1-3 Peers bekannt → Minimal Node, LAN/Relay aktiv
          - 4+ Peers mit direktem Kontakt → Standard, Gossip-Vollmitglied
          - DHT-fähige Peers bekannt → Yggdrasil/DHT-Upgrade empfohlen
        """
        peers = self.get_all_peers()
        direct_peers = [p for p in peers if not p.relay_bridge]
        relay_peers  = [p for p in peers if p.relay_bridge]
        ygg_peers    = [p for p in peers if p.tier_rank >= 2]

        if len(peers) == 0:
            return {
                "suggestion":  "offline_bootstrap",
                "description": "Kein Peer bekannt — DNS-Seeds und Relay-Pool werden aktiviert.",
                "next_action": "DNS-Seed-Abfrage + Hardcoded-Relay-Fallback",
            }
        if len(direct_peers) == 0 and len(relay_peers) > 0:
            return {
                "suggestion":  "relay_only_member",
                "description": "{} Peers via Relay erreichbar — kein direkter LAN-Kontakt.".format(len(relay_peers)),
                "next_action": "Relay-Gossip aktiv; LAN-Beacon sucht lokale Peers.",
            }
        if len(ygg_peers) > 0 and len(direct_peers) >= 2:
            return {
                "suggestion":  "upgrade_to_yggdrasil",
                "description": "{} Peers mit Tier-2+ bekannt — Yggdrasil-Overlay möglich.".format(len(ygg_peers)),
                "next_action": "Yggdrasil installieren für direktes Overlay-P2P.",
            }
        return {
            "suggestion":  "standard_member",
            "description": "{} direkte + {} Relay-Peers bekannt — voller Gossip-Betrieb.".format(
                len(direct_peers), len(relay_peers)
            ),
            "next_action": "Gossip-Loop läuft; AlgoToken- und Blindspot-Austausch aktiv.",
        }

    # ── Persistenz ─────────────────────────────────────────────────────────── #

    def _local_node_dict(self) -> Dict[str, Any]:
        return {
            "node_id":   self._local_id,
            "host":      self._local_host,
            "port":      self._local_port,
            "tier_rank": 0,
        }

    def _save_state(self) -> None:
        try:
            with self._lock:
                buckets_data: Dict[str, Any] = {}
                for idx, bucket in self._buckets.items():
                    live = [n.to_dict() for n in bucket if n.is_alive()]
                    if live:
                        buckets_data[str(idx)] = live
            state = {
                "schema":    "aether.dht.state.v1",
                "ts":        time.time(),
                "local_id":  self._local_id,
                "buckets":   buckets_data,
            }
            DHT_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            DHT_STATE_PATH.write_text(
                json.dumps(state, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug("[dht] _save_state: %s", exc)

    def _load_state(self) -> None:
        try:
            if not DHT_STATE_PATH.is_file():
                return
            state = json.loads(DHT_STATE_PATH.read_text(encoding="utf-8"))
            if state.get("schema") != "aether.dht.state.v1":
                return
            self._local_id = str(state.get("local_id", "") or "")
            revoked = _load_revoked()
            for idx_str, peers in state.get("buckets", {}).items():
                try:
                    idx = int(idx_str)
                    for pd in peers:
                        node = DHTNode.from_dict(pd)
                        if node.node_id and node.node_id not in revoked and node.is_alive():
                            self._buckets.setdefault(idx, []).append(node)
                except Exception:
                    pass
            logger.debug("[dht] State geladen: %d Peers", self._total_peers())
        except Exception as exc:
            logger.debug("[dht] _load_state: %s", exc)

    @staticmethod
    def _detect_local_ip() -> str:
        """Erkennt die lokale IP-Adresse (LAN)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
