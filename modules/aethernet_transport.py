from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules import swarm_sync


class AethernetTransport:
    """Koordiniert LAN-First Anchor-Transport mit Git-Fallback fuer AetherNet."""

    UDP_BEACON_PORT: int = 7386

    def __init__(
        self,
        node_id: str,
        anchor_dir: str = "data/anchors",
        nodes_dir: str = "data/swarm/nodes",
        lan_port: int = 7385,
    ) -> None:
        self.node_id = str(node_id)
        self.anchor_dir = Path(anchor_dir)
        self.nodes_dir = Path(nodes_dir)
        self.lan_port = int(lan_port)
        self._receiver_started = False
        self._server: Optional[ThreadingHTTPServer] = None
        self._udp_started = False
        self.anchor_dir.mkdir(parents=True, exist_ok=True)
        self.nodes_dir.mkdir(parents=True, exist_ok=True)
        self._local_ip: str = self._detect_local_ip()

    def _anchor_path(self, pack_id: str) -> Path:
        """Leitet den lokalen Dateipfad fuer ein Anchor-Pack ab."""
        return self.anchor_dir / f"{pack_id}.pack"

    def _store_pack(self, pack: Dict[str, Any]) -> bool:
        """Speichert ein Anchor-Pack lokal als JSON-Datei ab."""
        try:
            pack_id = str(pack.get("pack_id", "")).strip()
            if not pack_id:
                return False
            self._anchor_path(pack_id).write_text(
                json.dumps(pack, ensure_ascii=True, sort_keys=True, indent=2),
                encoding="utf-8",
            )
            return True
        except Exception as err:
            print(f"[AETHERNET] store_pack failed: {err}")
            return False

    def _read_local_pack_ids(self) -> List[str]:
        """Liest alle lokal bekannten Pack-IDs aus dem Anchor-Verzeichnis."""
        try:
            return sorted(path.stem for path in self.anchor_dir.glob("*.pack"))
        except Exception as err:
            print(f"[AETHERNET] local pack listing failed: {err}")
            return []

    def push_pack(self, pack: Dict[str, Any]) -> str:
        """Versucht einen Anchor-Push zuerst ueber LAN und faellt danach auf Git zurueck."""
        try:
            if self._store_pack(pack):
                for base_url in self.discover_lan_nodes():
                    try:
                        request = urllib.request.Request(
                            urllib.parse.urljoin(base_url.rstrip("/") + "/", "anchor"),
                            data=json.dumps(pack, ensure_ascii=True, sort_keys=True).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with urllib.request.urlopen(request, timeout=2.0) as response:
                            if 200 <= int(response.status) < 300:
                                print(f"[AETHERNET] push via LAN to {base_url}")
                                return "lan"
                    except Exception:
                        continue
            if swarm_sync.push_anchor_pack(pack):
                print("[AETHERNET] push via Git fallback")
                return "git"
            return "failed"
        except Exception as err:
            print(f"[AETHERNET] push_pack failed: {err}")
            return "failed"

    def pull_packs(self) -> List[Dict[str, Any]]:
        """Zieht Packets ueber LAN bekannter Nodes und faellt optional auf Git zurueck."""
        try:
            seen_pack_ids = set()
            pulled: List[Dict[str, Any]] = []

            for base_url in self.discover_lan_nodes():
                try:
                    with urllib.request.urlopen(
                        urllib.parse.urljoin(base_url.rstrip("/") + "/", "anchors"),
                        timeout=2.0,
                    ) as response:
                        payload = json.loads(response.read().decode("utf-8"))
                    for pack_id in list(payload.get("pack_ids", [])):
                        if str(pack_id) in seen_pack_ids:
                            continue
                        try:
                            with urllib.request.urlopen(
                                urllib.parse.urljoin(base_url.rstrip("/") + "/", f"anchor/{pack_id}"),
                                timeout=2.0,
                            ) as pack_response:
                                pack_payload = json.loads(pack_response.read().decode("utf-8"))
                            if self._store_pack(pack_payload):
                                seen_pack_ids.add(str(pack_payload.get("pack_id", pack_id)))
                                pulled.append(pack_payload)
                        except Exception:
                            continue
                except Exception:
                    continue

            git_new_ids = swarm_sync.pull_anchors()
            for pack_id in git_new_ids:
                if str(pack_id) in seen_pack_ids:
                    continue
                path = self._anchor_path(str(pack_id))
                if path.exists():
                    try:
                        pack_payload = json.loads(path.read_text(encoding="utf-8"))
                        seen_pack_ids.add(str(pack_payload.get("pack_id", pack_id)))
                        pulled.append(pack_payload)
                    except Exception:
                        continue
            return pulled
        except Exception as err:
            print(f"[AETHERNET] pull_packs failed: {err}")
            return []

    def start_lan_receiver(self) -> None:
        """Startet einen einfachen LAN-HTTP-Receiver fuer Anchor-Packs im Daemon-Thread."""
        try:
            if self._receiver_started:
                return

            transport = self

            class AnchorHandler(BaseHTTPRequestHandler):
                def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
                    body = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def _read_json_payload(self) -> Optional[Dict[str, Any]]:
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                        raw = self.rfile.read(length)
                        payload = json.loads(raw.decode("utf-8"))
                        if isinstance(payload, dict):
                            return payload
                    except Exception:
                        return None
                    return None

                def do_POST(self) -> None:  # noqa: N802
                    payload = self._read_json_payload()
                    if payload is None:
                        self._send_json(400, {"ok": False})
                        return

                    if self.path == "/anchor":
                        ok = transport._store_pack(payload)
                        self._send_json(200 if ok else 400, {"ok": ok})
                        return

                    if self.path == "/peer":
                        transport._store_peer_from_beacon(payload)
                        self._send_json(200, {"ok": True})
                        return

                    if self.path == "/consensus/candidate":
                        try:
                            from modules.consensus_engine import submit_candidate

                            submit_candidate(
                                ttd_hash=str(payload.get("ttd_hash", "")),
                                anchor_type=str(payload.get("anchor_type", "remote")),
                                node_id=str(payload.get("node_id", "unknown")),
                                metrics=dict(payload.get("metrics", {})),
                                software_context=str(payload.get("software_context", "aether")),
                            )
                            self._send_json(200, {"ok": True})
                        except Exception:
                            self._send_json(500, {"ok": False})
                        return

                    self._send_json(404, {"ok": False})

                def do_GET(self) -> None:  # noqa: N802
                    if self.path == "/ping":
                        self._send_json(200, {"node_id": transport.node_id, "alive": True})
                        return
                    if self.path == "/anchors":
                        self._send_json(200, {"pack_ids": transport._read_local_pack_ids()})
                        return
                    if self.path.startswith("/anchor/"):
                        pack_id = self.path.split("/anchor/", 1)[1].strip()
                        pack_path = transport._anchor_path(pack_id)
                        if pack_path.exists():
                            try:
                                payload = json.loads(pack_path.read_text(encoding="utf-8"))
                                self._send_json(200, payload)
                                return
                            except Exception:
                                pass
                        self._send_json(404, {"ok": False})
                        return

                    if self.path == "/peers":
                        peers: List[Dict[str, Any]] = []
                        for node_path in transport.nodes_dir.glob("*.json"):
                            try:
                                payload = json.loads(node_path.read_text(encoding="utf-8"))
                                if isinstance(payload, dict):
                                    peers.append(payload)
                            except Exception:
                                continue
                        self._send_json(200, {"peers": peers})
                        return

                    if self.path == "/consensus/candidates":
                        try:
                            from modules.consensus_engine import get_consensus_anchors

                            candidates = list(get_consensus_anchors())
                        except Exception:
                            candidates = []
                        self._send_json(200, {"candidates": candidates})
                        return

                    self._send_json(404, {"ok": False})

                def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                    return

            self._server = ThreadingHTTPServer(("0.0.0.0", self.lan_port), AnchorHandler)
            thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            thread.start()
            self._receiver_started = True
            print(f"[AETHERNET] LAN receiver active on :{self.lan_port}")
        except Exception as err:
            print(f"[AETHERNET] start_lan_receiver failed: {err}")

    def discover_lan_nodes(self) -> List[str]:
        """Liest bekannte LAN-URLs aus den Node-JSON-Dateien des Schwarms."""
        try:
            urls: List[str] = []
            for path in self.nodes_dir.glob("*.json"):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    if str(payload.get("node_id", "")) == self.node_id:
                        continue
                    lan_url = str(payload.get("lan_url", "")).strip()
                    if lan_url:
                        urls.append(lan_url)
                except Exception:
                    continue
            return sorted(set(urls))
        except Exception as err:
            print(f"[AETHERNET] discover_lan_nodes failed: {err}")
            return []

    # ------------------------------------------------------------------ #
    #  UDP Broadcast Auto-Discovery                                        #
    # ------------------------------------------------------------------ #

    def _detect_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return str(ip)
        except Exception:
            return "127.0.0.1"

    def _beacon_payload(self) -> bytes:
        info = {
            "node_id": self.node_id,
            "lan_url": f"http://{self._local_ip}:{self.lan_port}",
            "version": "aether-beacon-v1",
        }
        return json.dumps(info, ensure_ascii=True, sort_keys=True).encode("utf-8")

    def _store_peer_from_beacon(self, info: Dict[str, Any]) -> None:
        """Persists a peer discovered via UDP beacon or relay into nodes_dir."""
        try:
            peer_id = str(info.get("node_id", "")).strip()
            if not peer_id or peer_id == self.node_id:
                return
            peer_path = self.nodes_dir / f"{peer_id}.json"
            existing: Dict[str, Any] = {}
            if peer_path.exists():
                try:
                    existing = json.loads(peer_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
            existing.update(
                {
                    "node_id": peer_id,
                    "lan_url": str(info.get("lan_url", "")).strip(),
                    "discovered_via": str(info.get("version", "udp_broadcast")),
                }
            )
            peer_path.write_text(
                json.dumps(existing, ensure_ascii=True, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as err:
            print(f"[AETHERNET] store_peer_from_beacon failed: {err}")

    def start_udp_discovery(self) -> None:
        """Starts UDP broadcast sender + listener for automatic LAN peer discovery."""
        if self._udp_started:
            return
        self._udp_started = True
        beacon_bytes = self._beacon_payload()
        beacon_port = self.UDP_BEACON_PORT
        lan_port = self.lan_port

        def _sender() -> None:
            import time
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while True:
                try:
                    sock.sendto(beacon_bytes, ("255.255.255.255", beacon_port))
                except Exception:
                    pass
                time.sleep(30)

        def _listener() -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", beacon_port))
            except Exception as err:
                print(f"[AETHERNET] UDP listener bind failed: {err}")
                return
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    info = json.loads(data.decode("utf-8"))
                    if not str(info.get("lan_url", "")).strip():
                        info["lan_url"] = f"http://{addr[0]}:{lan_port}"
                    self._store_peer_from_beacon(info)
                except Exception:
                    continue

        threading.Thread(target=_sender, daemon=True, name="aether-udp-beacon").start()
        threading.Thread(target=_listener, daemon=True, name="aether-udp-listener").start()
        print(f"[AETHERNET] UDP discovery active (broadcast port {beacon_port})")

    # ------------------------------------------------------------------ #
    #  Internet Relay                                                      #
    # ------------------------------------------------------------------ #

    def relay_push(self, relay_url: str) -> bool:
        """POST self to a relay server so internet peers can discover us."""
        if not relay_url:
            return False
        try:
            payload = {
                "node_id": self.node_id,
                "lan_url": f"http://{self._local_ip}:{self.lan_port}",
                "version": "aether-relay-v1",
            }
            req = urllib.request.Request(
                relay_url.rstrip("/") + "/register",
                data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return 200 <= int(resp.status) < 300
        except Exception as err:
            print(f"[AETHERNET] relay_push failed: {err}")
            return False

    def relay_pull(self, relay_url: str) -> int:
        """GET peer list from relay and register peers locally. Returns count added."""
        if not relay_url:
            return 0
        try:
            with urllib.request.urlopen(relay_url.rstrip("/") + "/peers", timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            count = 0
            for peer in list(data.get("peers", [])):
                if isinstance(peer, dict):
                    self._store_peer_from_beacon(peer)
                    count += 1
            return count
        except Exception as err:
            print(f"[AETHERNET] relay_pull failed: {err}")
            return 0

    # ------------------------------------------------------------------ #
    #  Consensus Gossip                                                    #
    # ------------------------------------------------------------------ #

    def sync_consensus_with_peers(self, consensus_db: str = "data/consensus.db") -> None:
        """Gossipt consensus-Kandidaten zu allen erreichbaren Peers und holt deren."""
        try:
            from modules.consensus_engine import get_consensus_anchors, submit_candidate
        except Exception:
            return
        peer_urls = self.discover_lan_nodes()
        if not peer_urls:
            return
        try:
            local_anchors = list(get_consensus_anchors(db_path=consensus_db))
        except Exception:
            local_anchors = []
        for base_url in peer_urls:
            for anchor in local_anchors:
                try:
                    body = json.dumps(
                        {
                            "ttd_hash": str(anchor.get("ttd_hash", "")),
                            "anchor_type": str(anchor.get("anchor_type", "consensus")),
                            "node_id": self.node_id,
                            "software_context": str(anchor.get("software_context", "aether")),
                            "metrics": dict(anchor.get("metrics", {})),
                        },
                        ensure_ascii=True,
                    ).encode("utf-8")
                    req = urllib.request.Request(
                        base_url.rstrip("/") + "/consensus/candidate",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=2.0)
                except Exception:
                    pass
            try:
                with urllib.request.urlopen(
                    base_url.rstrip("/") + "/consensus/candidates", timeout=2.0
                ) as resp:
                    remote = json.loads(resp.read().decode("utf-8"))
                for candidate in list(remote.get("candidates", [])):
                    try:
                        submit_candidate(
                            ttd_hash=str(candidate.get("ttd_hash", "")),
                            anchor_type=str(candidate.get("anchor_type", "remote")),
                            node_id=str(candidate.get("node_id", "unknown")),
                            metrics=dict(candidate.get("metrics", {})),
                            software_context=str(candidate.get("software_context", "aether")),
                            db_path=consensus_db,
                        )
                    except Exception:
                        pass
            except Exception:
                pass