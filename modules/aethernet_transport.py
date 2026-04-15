from __future__ import annotations
import logging
logger = logging.getLogger(__name__)

import base64
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import socket
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib as _hashlib

# swarm_sync, FrameDeltaCodec, P2PAnchorPool werden lazy geladen:
# - swarm_sync bringt subprocess/git-Machinery mit (nicht nötig auf relay-only Nodes)
# - FrameDeltaCodec braucht nur Nodes die aktiv Frames kodieren
# - P2PAnchorPool braucht nur Nodes die Quorum-TTD verwalten
_swarm_sync = None  # lazy, geladen bei erstem push_pack/pull_packs
_FrameDeltaCodec = None  # lazy
_P2PAnchorPool = None  # lazy


def _get_swarm_sync():
    global _swarm_sync
    if _swarm_sync is None:
        from modules import swarm_sync as _ss
        _swarm_sync = _ss
    return _swarm_sync


def _get_frame_delta_codec_class():
    global _FrameDeltaCodec
    if _FrameDeltaCodec is None:
        from modules.frame_delta_engine import FrameDeltaCodec as _fdc
        _FrameDeltaCodec = _fdc
    return _FrameDeltaCodec


def _get_p2p_anchor_pool_class():
    global _P2PAnchorPool
    if _P2PAnchorPool is None:
        from modules.p2p_anchor_pool import P2PAnchorPool as _pap
        _P2PAnchorPool = _pap
    return _P2PAnchorPool

_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_NODE_JSON = _ROOT / "data" / "swarm" / "node.json"


def _read_local_node_role() -> str:
    """Liest die Rolle des lokalen Knotens aus node.json (genesis/peer/operator)."""
    try:
        if _LOCAL_NODE_JSON.is_file():
            payload = json.loads(_LOCAL_NODE_JSON.read_text(encoding="utf-8"))
            return str(payload.get("role", "operator") or "operator").strip().lower()
    except Exception:
        pass
    return "operator"


class AethernetTransport:
    """Koordiniert LAN-First Anchor-Transport mit Git-Fallback fuer AetherNet."""

    UDP_BEACON_PORT: int = 7386
    SIGNATURE_MAX_SKEW_SECONDS: int = 300
    NONCE_TTL_SECONDS: int = 900
    PACK_MAX_BYTES: int = 262_144
    FORBIDDEN_PACK_KEYS = {
        "delta",
        "delta_entries",
        "delta_pack",
        "encrypted_data",
        "xor_patches",
        "session_seed",
        "session_key",
        "private_key",
        "raw",
        "raw_bytes",
        "pixel_data",
        "frame_data",
    }

    def __init__(
        self,
        node_id: str,
        anchor_dir: str = "data/anchors",
        nodes_dir: str = "data/swarm/nodes",
        lan_port: int = 7385,
        local_private_key_path: str = "keys/node_private.key",
        require_signed_messages: bool = True,
    ) -> None:
        self.node_id = str(node_id)
        self.anchor_dir = Path(anchor_dir)
        self.nodes_dir = Path(nodes_dir)
        self.lan_port = int(lan_port)
        self.local_private_key_path = Path(local_private_key_path)
        self.require_signed_messages = bool(require_signed_messages)
        self._receiver_started = False
        self._server: Optional[ThreadingHTTPServer] = None
        self._udp_started = False
        self._seen_nonces: Dict[str, float] = {}
        self.anchor_dir.mkdir(parents=True, exist_ok=True)
        self.nodes_dir.mkdir(parents=True, exist_ok=True)
        self._local_ip: str = self._detect_local_ip()
        self._frame_codec = None   # lazy: geladen bei erstem encode_frame-Aufruf
        self._anchor_pool = None   # lazy: geladen bei erstem TTD-Quorum-Aufruf
        self._ttd_records: dict = {}       # Quorum-Stand: pack_id → TTD-Record
        self._pending_anchors: dict = {}   # Warten auf Quorum: pack_id → AnchorPack
        # AELab-Invarianten-Bahn: kein Quorum, kein Genesis-Gate
        self._algo_dir = self.anchor_dir.parent / "algo_tokens"
        self._algo_dir.mkdir(parents=True, exist_ok=True)
        # Relay-Bridge-Inbox: Gossip von Internet-Peers ohne Yggdrasil.
        # POST /gossip → Inbox; GET /gossip/latest → zurückgeben.
        self._relay_gossip_inbox: List[Dict[str, Any]] = []
        self._relay_gossip_lock = threading.Lock()
        # Legacy-Proto-Inbox: Ultra-Legacy-Knoten (Win95/98/XP) senden Compact-Pakete.
        # POST /gossip/legacy → Empfang + Übersetzung ins volle Schema.
        # GET /gossip/legacy/latest → letzte 50 Compact-Pakete für Legacy-Clients.
        self._legacy_gossip_inbox: List[str] = []   # Roh-Compact-Strings
        self._legacy_gossip_lock = threading.Lock()
        # Persistierter Relay-Pool und Peer-Cache (survive restarts)
        self._relay_pool_path = self.nodes_dir.parent / "relay_pool.json"
        self._peer_cache_path = self.nodes_dir.parent / "peer_cache.json"
        self._relay_pool_lock = threading.Lock()
        # Beim Startup: Records die bereits auto_push_ready=True haben sofort flushen.
        self._flush_pending_auto_push()

    def _flush_pending_auto_push(self) -> None:
        """Schiebt beim Transport-Start alle gespeicherten Packs durch die er bereits
        auto_push_ready sind — damit ein Neustart keine push-bereiten Packs blockiert.

        Liest lokale .pack-Dateien, prüft ob das zugehörige TTD-Record auto_push_ready
        trägt (via Pool-Rekonstruktion), und tut push_pack() wenn ja.
        Nur performance_route + (genesis_trust ODER peer_quorum) wird geflusht.
        Kein neues Quorum wird erzwungen — reines Drain already-decided records.
        """
        try:
            pack_ids = self._read_local_pack_ids()
        except Exception:
            return
        for pack_id in pack_ids:
            try:
                pack_path = self._anchor_path(pack_id)
                if not pack_path.is_file():
                    continue
                import json as _j
                pack = _j.loads(pack_path.read_text(encoding="utf-8"))
                if not isinstance(pack, dict):
                    continue
                # Nur performance_route artefakte fliessen automatisch
                artifact_class = str(pack.get("artifact_class", "") or "").strip()
                if artifact_class and artifact_class != "performance_route":
                    continue
                # TTD-Record wiederherstellen wenn vorhanden
                if pack_id in self._ttd_records:
                    record = self._ttd_records[pack_id]
                else:
                    # Aus public_metrics im Pack einen Minimal-Record rekonstruieren
                    if self._anchor_pool is None:
                        self._anchor_pool = _get_p2p_anchor_pool_class()()
                    record = self._anchor_pool.build_record({
                        "ttd_hash": pack_id,
                        "uploader_node_id": str(pack.get("node_id", self.node_id) or self.node_id),
                        "uploader_role": str(pack.get("uploader_role", "operator") or "operator"),
                        "public_metrics": dict(pack.get("public_metrics", {}) or {}),
                        "artifact_class": "performance_route",
                    })
                    self._ttd_records[pack_id] = record
                if bool(record.get("auto_push_ready", False)):
                    trust_reason = str(record.get("auto_push_reason", record.get("trust_reason", "")) or "")
                    result = self.push_pack(pack)
                    print(
                        f"[AETHERNET] Startup-Flush ({pack_id[:16]}…) "
                        f"reason={trust_reason} → {result}"
                    )
            except Exception as err:
                print(f"[AETHERNET] flush_pending_auto_push: {err}")
                continue

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _canonical_signed_payload(payload: Dict[str, Any]) -> bytes:
        body = dict(payload)
        body.pop("_sig_b64", None)
        body.pop("_sig_node_id", None)
        body.pop("_sig_ts", None)
        body.pop("_sig_nonce", None)
        return json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _known_public_key(self, signer_node_id: str) -> str:
        try:
            node_path = self.nodes_dir / f"{signer_node_id}.json"
            if not node_path.is_file():
                return ""
            payload = json.loads(node_path.read_text(encoding="utf-8"))
            return str(payload.get("public_key_pem", "") or "").strip()
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return ""

    def _sign_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        envelope = dict(payload)
        envelope["_sig_node_id"] = self.node_id
        envelope["_sig_ts"] = self._utc_now_iso()
        envelope["_sig_nonce"] = uuid.uuid4().hex
        try:
            if not self.local_private_key_path.is_file():
                if self.require_signed_messages:
                    print("[AETHERNET] signature required but private key missing")
                return envelope
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            private_key = load_pem_private_key(self.local_private_key_path.read_bytes(), password=None)
            signature = private_key.sign(self._canonical_signed_payload(envelope))
            envelope["_sig_b64"] = base64.b64encode(signature).decode("ascii")
            return envelope
        except Exception as err:
            print(f"[AETHERNET] payload signing failed: {err}")
            return envelope

    def _prune_seen_nonces(self, now_ts: float) -> None:
        stale = [
            nonce
            for nonce, ts in self._seen_nonces.items()
            if (now_ts - float(ts)) > float(self.NONCE_TTL_SECONDS)
        ]
        for nonce in stale:
            self._seen_nonces.pop(nonce, None)

    def _verify_signed_payload(self, payload: Dict[str, Any]) -> bool:
        if not isinstance(payload, dict):
            return False
        sig_b64 = str(payload.get("_sig_b64", "") or "").strip()
        signer = str(payload.get("_sig_node_id", "") or "").strip()
        sig_ts = str(payload.get("_sig_ts", "") or "").strip()
        nonce = str(payload.get("_sig_nonce", "") or "").strip()

        if not sig_b64:
            return not self.require_signed_messages
        if not signer or not sig_ts or not nonce:
            return False
        if signer == self.node_id:
            return False

        try:
            parsed_ts = datetime.fromisoformat(sig_ts)
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            skew = abs((datetime.now(timezone.utc) - parsed_ts).total_seconds())
            if skew > float(self.SIGNATURE_MAX_SKEW_SECONDS):
                return False
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return False

        now_ts = time.time()
        self._prune_seen_nonces(now_ts)
        if nonce in self._seen_nonces:
            return False

        public_key_pem = self._known_public_key(signer)
        if not public_key_pem:
            return False

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(base64.b64decode(sig_b64), self._canonical_signed_payload(payload))
            self._seen_nonces[nonce] = now_ts
            return True
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return False

    @staticmethod
    def _extract_base_url(node_payload: Dict[str, Any]) -> str:
        return str(node_payload.get("lan_url", "") or "").strip()

    def _probe_peer_url(self, base_url: str, timeout: float = 1.5) -> bool:
        try:
            with urllib.request.urlopen(base_url.rstrip("/") + "/ping", timeout=timeout) as response:
                return 200 <= int(response.status) < 300
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return False

    def _update_peer_probe_state(self, peer_path: Path, payload: Dict[str, Any], reachable: bool) -> None:
        try:
            now_iso = self._utc_now_iso()
            current = dict(payload)
            failures = int(current.get("consecutive_failures", 0) or 0)
            if reachable:
                current["consecutive_failures"] = 0
                current["state"] = "active"
                current["last_seen_utc"] = now_iso
            else:
                current["consecutive_failures"] = failures + 1
                current["state"] = "stalled"
            current["last_probe_utc"] = now_iso
            peer_path.write_text(
                json.dumps(current, ensure_ascii=True, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return

    def refresh_peer_states(self) -> Dict[str, int]:
        """Aktualisiert Reachability und Failure-Streaks, damit Peers sauber rejoinen koennen."""
        total = 0
        reachable = 0
        stalled = 0
        for peer_path in self.nodes_dir.glob("*.json"):
            try:
                payload = json.loads(peer_path.read_text(encoding="utf-8"))
            except Exception as e:
                continue
            peer_id = str(payload.get("node_id", "") or "").strip()
            if not peer_id or peer_id == self.node_id:
                continue
            base_url = self._extract_base_url(payload)
            if not base_url:
                continue
            total += 1
            is_reachable = self._probe_peer_url(base_url)
            if is_reachable:
                reachable += 1
            else:
                stalled += 1
            self._update_peer_probe_state(peer_path, payload, is_reachable)
        return {"total": int(total), "reachable": int(reachable), "stalled": int(stalled)}

    def _anchor_path(self, pack_id: str) -> Path:
        """Leitet den lokalen Dateipfad fuer ein Anchor-Pack ab."""
        return self.anchor_dir / f"{pack_id}.pack"

    @staticmethod
    def _normalized_candidate_node_id(candidate: Dict[str, Any]) -> str:
        node_id = str(candidate.get("node_id", "") or "").strip()
        if node_id:
            return node_id
        source_nodes = candidate.get("source_nodes", [])
        if isinstance(source_nodes, list) and source_nodes:
            first = str(source_nodes[0] or "").strip()
            if first:
                return first
        return "remote-peer"

    def _pack_payload_is_safe(self, pack: Dict[str, Any]) -> bool:
        """Fail-closed policy fuer oeffentliche Anchor-Packs.

        Im Netz sind nur strukturierte, nicht-sensitive Packdaten erlaubt.
        """
        if not isinstance(pack, dict):
            return False

        schema = str(pack.get("schema", "") or "").strip().lower()
        if schema and schema not in {"aether.anchor.pack.v1", "aether.anchor_pack.v1"}:
            return False

        pack_id = str(pack.get("pack_id", "") or "").strip()
        if not pack_id:
            return False

        try:
            encoded = json.dumps(pack, ensure_ascii=True, sort_keys=True).encode("utf-8")
        except Exception:
            return False
        if len(encoded) > int(self.PACK_MAX_BYTES):
            return False

        stack: List[Any] = [pack]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                for key, value in current.items():
                    key_text = str(key or "").strip().lower()
                    if key_text in self.FORBIDDEN_PACK_KEYS:
                        return False
                    if isinstance(value, (bytes, bytearray, memoryview)):
                        return False
                    if isinstance(value, (dict, list, tuple)):
                        stack.append(value)
            elif isinstance(current, (list, tuple)):
                for value in current:
                    if isinstance(value, (bytes, bytearray, memoryview)):
                        return False
                    if isinstance(value, (dict, list, tuple)):
                        stack.append(value)
        return True

    def register_local_anchor(self, frame: bytes, public_metrics: Optional[Dict[str, Any]] = None) -> str:
        """
        Frame lokal durch FrameDeltaCodec analysieren.
        Vault-Hit-Signaturen (DNA) werden als Pending-Anker registriert.

        public_metrics: optionale Analyse-Kennzahlen (symmetry, residual,
            delta_stability …) aus dem unmittelbar vorgelagerten Pipeline-Schritt.
            Werden im Pending-Pack gespeichert und beim Submit an den Pool
            weitergegeben, damit _apply_trust_state den Trust-Score berechnen kann.
            Genesis-Nodes benoetigen trust_score >= 0.65 — auch ohne Quorum.

        Kein Push — Anker wartet auf Quorum (normale Nodes) oder besteht den
        Trust-Score-Check (Genesis-Node).
        Rohdaten verlassen das Geraet nie (FORBIDDEN_PACK_KEYS greift).
        """
        if self._frame_codec is None:
            self._frame_codec = _get_frame_delta_codec_class()()
        packets = self._frame_codec.encode_frame(frame)
        dna_sigs = [pkt["sig"] for pkt in packets if pkt.get("type") == "dna"]
        if not dna_sigs:
            return "no_vault_hits"
        pack_id = _hashlib.sha256(
            "".join(sorted(dna_sigs)).encode()
        ).hexdigest()[:32]
        if pack_id not in self._pending_anchors:
            self._pending_anchors[pack_id] = {
                "schema": "aether.anchor.pack.v1",
                "pack_id": pack_id,
                "anchors": dna_sigs,
                "source": "frame_delta",
                "node_id": self.node_id,
                "public_metrics": dict(public_metrics or {}),
            }
            self._submit_anchor_to_pool(self._pending_anchors[pack_id], self.node_id)
        return "pending_quorum"

    def _submit_anchor_to_pool(self, pack: dict, peer_node_id: str) -> bool:
        """
        Bestaetigung eines Nodes fuer einen Anker einreichen.

        Fuer normale Nodes: True wenn Quorum (>= 3 unabhaengige Nodes) erreicht.
        Fuer Genesis-Node: True wenn trust_score >= 0.65 (Quorum wird uebersprungen).
        Der Trust-Score ist in BEIDEN Faellen eine unumgehbare Schranke.
        Genesis ist der einzige privilegierte Node — kein 'admin' existiert.
        """
        from modules.registry import is_genesis_node as _is_genesis_node
        ttd_hash = str(pack.get("pack_id", "")).strip()
        if not ttd_hash:
            return False
        # Rolle des einreichenden Nodes kryptografisch pruefen.
        # Nur "genesis" wenn node_id == registrierter Genesis-Node — sonst "operator".
        uploader_is_genesis = _is_genesis_node(str(peer_node_id or ""))
        uploader_role = "genesis" if uploader_is_genesis else "operator"
        payload = {
            "pseudonym": peer_node_id,
            "ttd_hash": ttd_hash,
            "uploader_node_id": str(peer_node_id or ""),
            "uploader_role": uploader_role,
            "public_metrics": dict(pack.get("public_metrics", {}) or {}),
        }
        if ttd_hash in self._ttd_records:
            if self._anchor_pool is None:
                self._anchor_pool = _get_p2p_anchor_pool_class()()
            if self._anchor_pool.validator_present(self._ttd_records[ttd_hash], peer_node_id):
                return bool(self._ttd_records[ttd_hash].get("quorum_met", False))
            self._ttd_records[ttd_hash] = self._anchor_pool.merge_record(
                self._ttd_records[ttd_hash], payload
            )
        else:
            if self._anchor_pool is None:
                self._anchor_pool = _get_p2p_anchor_pool_class()()
            self._ttd_records[ttd_hash] = self._anchor_pool.build_record(payload)
        record = self._ttd_records[ttd_hash]
        quorum_met = bool(record.get("quorum_met", False))
        trust_reason = str(record.get("trust_reason", "") or "")
        if quorum_met and ttd_hash in self._pending_anchors:
            anchor_pack = self._pending_anchors.pop(ttd_hash)
            result = self.push_pack(anchor_pack)
            print(
                f"[AETHERNET] Push ({ttd_hash[:16]}\u2026) "
                f"reason={trust_reason} \u2192 {result}"
            )
        elif uploader_is_genesis and not quorum_met:
            # Genesis hat submittet aber Trust-Score-Gate hat nicht bestanden.
            score = round(float(record.get("pipeline_trust_score", 0.0) or 0.0), 4)
            print(
                f"[AETHERNET] Genesis-Push geblockt ({ttd_hash[:16]}\u2026): "
                f"trust_score={score} < 0.65 — Quorum-Bypass verweigert."
            )
        return quorum_met

    def _store_pack(self, pack: Dict[str, Any]) -> bool:
        """Speichert ein Anchor-Pack lokal als JSON-Datei ab."""
        try:
            if not self._pack_payload_is_safe(pack):
                print("[AETHERNET] store_pack blocked: payload violates public-pack policy")
                return False
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

    # ------------------------------------------------------------------
    # AELab-Invarianten-Bahn — peer-to-peer, kein Quorum, kein Genesis-Gate
    # Einzige Bedingung: verify_algo_token() muss bestehen (Struktur-Integrität).
    # delta_nodes, Rohdaten und Session-Keys verlassen das Gerät nie (seal_invariant)
    # ------------------------------------------------------------------

    def _algo_path(self, token_id: str) -> Path:
        return self._algo_dir / f"{token_id}.algo"

    def _read_local_algo_ids(self) -> List[str]:
        try:
            return sorted(p.stem for p in self._algo_dir.glob("*.algo"))
        except Exception:
            return []

    def push_algo_token(self, aelab_result: Dict[str, Any], domain_hint: str = "generic") -> str:
        """Baut einen AlgoToken aus einem AELab-Ergebnis und teilt ihn direkt mit allen
        erreichbaren Peers — ohne Quorum, ohne Genesis-Gate.

        Nur strukturell valide Tokens (verify_algo_token) werden gesendet.
        Rohdaten, Deltas und Session-Keys sind im AlgoToken nicht enthalten.
        """
        from modules.algo_share import build_algo_token, verify_algo_token
        token = build_algo_token(
            aelab_result,
            domain_hint=domain_hint,
            source_node_id=self.node_id,
        )
        if token is None:
            return "not_ready"  # commit_allowed=False — Tree noch nicht gut genug
        if not verify_algo_token(token):
            return "invalid"
        token_dict = token.to_dict()
        token_dict["schema"] = "aether.algo_token.v1"
        # Lokal speichern
        try:
            self._algo_path(token.token_id).write_text(
                json.dumps(token_dict, ensure_ascii=True, sort_keys=True, indent=2),
                encoding="utf-8",
            )
        except Exception as err:
            print(f"[AETHERNET] algo_token store failed: {err}")
        # An alle LAN-Peers senden
        signed = self._sign_payload(token_dict)
        sent = 0
        for base_url in self.discover_lan_nodes():
            try:
                req = urllib.request.Request(
                    urllib.parse.urljoin(base_url.rstrip("/") + "/", "algo"),
                    data=json.dumps(signed, ensure_ascii=True, sort_keys=True).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    if 200 <= int(resp.status) < 300:
                        sent += 1
            except Exception:
                continue
        result = f"lan:{sent}" if sent else "local_only"
        print(f"[AETHERNET] AlgoToken ({token.token_id[:16]}…) domain={domain_hint} → {result}")
        return result

    def pull_algo_tokens(self) -> List[Dict[str, Any]]:
        """Holt AlgoTokens von allen erreichbaren LAN-Peers.
        Kein Quorum nötig — empfangene Tokens werden nur nach verify_algo_token geprüft.
        """
        from modules.algo_share import AlgoToken, verify_algo_token
        seen: set = set()
        pulled: List[Dict[str, Any]] = []
        for base_url in self.discover_lan_nodes():
            try:
                with urllib.request.urlopen(
                    urllib.parse.urljoin(base_url.rstrip("/") + "/", "algos"),
                    timeout=2.0,
                ) as resp:
                    listing = json.loads(resp.read().decode("utf-8"))
                for token_id in list(listing.get("token_ids", [])):
                    if str(token_id) in seen:
                        continue
                    try:
                        with urllib.request.urlopen(
                            urllib.parse.urljoin(base_url.rstrip("/") + "/", f"algo/{token_id}"),
                            timeout=2.0,
                        ) as tr:
                            td = json.loads(tr.read().decode("utf-8"))
                        if str(td.get("schema", "")) != "aether.algo_token.v1":
                            continue
                        # Struktur-Integrität prüfen
                        token = AlgoToken(
                            token_id=str(td.get("token_id", "")),
                            tree_signature=str(td.get("tree_signature", "")),
                            invariant_profile=list(td.get("invariant_profile", [])),
                            fitness_score=float(td.get("fitness_score", 0.0)),
                            domain_hint=str(td.get("domain_hint", "generic")),
                            cascade_version=str(td.get("cascade_version", "")),
                            node_count=int(td.get("node_count", 0)),
                            depth=int(td.get("depth", 0)),
                            source_node_id=str(td.get("source_node_id", "") or "").strip(),
                            emitted_ts=float(td.get("emitted_ts", 0.0)),
                        )
                        if not verify_algo_token(token):
                            continue
                        seen.add(token.token_id)
                        # Lokal cachen
                        self._algo_path(token.token_id).write_text(
                            json.dumps(td, ensure_ascii=True, sort_keys=True, indent=2),
                            encoding="utf-8",
                        )
                        pulled.append(td)
                    except Exception:
                        continue
            except Exception:
                continue
        return pulled

    def push_pack(self, pack: Dict[str, Any]) -> str:
        """Versucht einen Anchor-Push zuerst ueber LAN und faellt danach auf Git zurueck."""
        try:
            if not self._store_pack(pack):
                return "failed"

            signed_pack = self._sign_payload(pack)
            for base_url in self.discover_lan_nodes():
                try:
                    request = urllib.request.Request(
                        urllib.parse.urljoin(base_url.rstrip("/") + "/", "anchor"),
                        data=json.dumps(signed_pack, ensure_ascii=True, sort_keys=True).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(request, timeout=2.0) as response:
                        if 200 <= int(response.status) < 300:
                            print(f"[AETHERNET] push via LAN to {base_url}")
                            return "lan"
                except Exception as e:
                    continue
            if _get_swarm_sync().push_anchor_pack(pack):
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
                        except Exception as e:
                            continue
                except Exception as e:
                    continue

            git_new_ids = _get_swarm_sync().pull_anchors()
            for pack_id in git_new_ids:
                if str(pack_id) in seen_pack_ids:
                    continue
                path = self._anchor_path(str(pack_id))
                if path.exists():
                    try:
                        pack_payload = json.loads(path.read_text(encoding="utf-8"))
                        seen_pack_ids.add(str(pack_payload.get("pack_id", pack_id)))
                        pulled.append(pack_payload)
                    except Exception as e:
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
                    except Exception as e:
                        logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
                        return None
                    return None

                def do_POST(self) -> None:  # noqa: N802
                    payload = self._read_json_payload()
                    if payload is None:
                        self._send_json(400, {"ok": False})
                        return

                    if self.path == "/anchor":
                        if not transport._verify_signed_payload(payload):
                            self._send_json(401, {"ok": False, "error": "invalid_signature"})
                            return
                        ok = transport._store_pack(payload)
                        if ok:
                            peer_id = str(payload.get("_sig_node_id", "unknown"))
                            transport._submit_anchor_to_pool(
                                {"pack_id": str(payload.get("pack_id", ""))},
                                peer_id,
                            )
                        self._send_json(200 if ok else 400, {"ok": ok})
                        return

                    if self.path == "/peer":
                        if not transport._verify_signed_payload(payload):
                            self._send_json(401, {"ok": False, "error": "invalid_signature"})
                            return
                        transport._store_peer_from_beacon(payload)
                        self._send_json(200, {"ok": True})
                        return

                    if self.path == "/consensus/candidate":
                        if not transport._verify_signed_payload(payload):
                            self._send_json(401, {"ok": False, "error": "invalid_signature"})
                            return
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
                        except Exception as e:
                            self._send_json(500, {"ok": False})
                        return

                    if self.path == "/gossip":
                        # Relay-Bridge: Legacy-/kein-Yggdrasil-Nodes senden Gossip.
                        # Keine Signaturpflicht — Legacy-Nodes haben ggf. noch keinen
                        # vollständigen Key-Stack. Schema-Check als Mindestfilter.
                        schema = str(payload.get("schema", "") or "")
                        if schema == "aether.swarm.p2p.gossip.v1":
                            with transport._relay_gossip_lock:
                                transport._relay_gossip_inbox.append(payload)
                                if len(transport._relay_gossip_inbox) > 200:
                                    transport._relay_gossip_inbox = transport._relay_gossip_inbox[-200:]
                            # Lerne neue Relay-URLs aus dem Gossip-Paket
                            for rurl in list(payload.get("known_relay_urls") or []):
                                transport._learn_relay_url(str(rurl))
                            self._send_json(200, {"ok": True})
                        else:
                            self._send_json(400, {"ok": False, "error": "invalid_gossip_schema"})
                        return

                    if self.path == "/gossip/legacy":
                        # Legacy-Proto: Compact-Paket von Win95/98/XP-Knoten.
                        # Wird übersetzt und in den normalen Gossip-Inbox aufgenommen.
                        raw_body = None
                        try:
                            length = int(self.headers.get("Content-Length", 0) or 0)
                            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                        if raw_body:
                            try:
                                from modules.legacy_proto import translate_to_full_gossip
                                full_pkt = translate_to_full_gossip(raw_body, transport.node_id)
                                if full_pkt and isinstance(full_pkt, dict):
                                    with transport._relay_gossip_lock:
                                        transport._relay_gossip_inbox.append(full_pkt)
                                        if len(transport._relay_gossip_inbox) > 200:
                                            transport._relay_gossip_inbox = transport._relay_gossip_inbox[-200:]
                                    # Relay-URLs aus dem Legacy-Paket lernen
                                    for rurl in list(full_pkt.get("known_relay_urls") or []):
                                        transport._learn_relay_url(str(rurl))
                                    # Auch roh in Legacy-Inbox speichern (für legacy/latest)
                                    with transport._legacy_gossip_lock:
                                        transport._legacy_gossip_inbox.append(raw_body)
                                        if len(transport._legacy_gossip_inbox) > 50:
                                            transport._legacy_gossip_inbox = transport._legacy_gossip_inbox[-50:]
                                    self._send_json(200, {"ok": True})
                                    return
                            except Exception as _lp_err:
                                logger.debug(f"[aethernet] legacy_proto translate: {_lp_err}")
                        self._send_json(400, {"ok": False, "error": "invalid_legacy_packet"})
                        return

                    if self.path == "/register":
                        # Legacy-Node meldet seine LAN-URL → Relay kennt ihn,
                        # und teilt seine bekannten Relays mit (bidirektionales Lernen).
                        transport._store_peer_from_beacon(payload)
                        for rurl in list(payload.get("known_relay_urls") or []):
                            transport._learn_relay_url(str(rurl))
                        # Antwort enthält unsere bekannten Relays → Peer lernt sie
                        known = transport._get_relay_pool()
                        self._send_json(200, {"ok": True, "known_relay_urls": known})
                        return

                    if self.path == "/relay-pool":
                        # Ein anderer Knoten meldet eine oder mehrere Relay-URLs.
                        for rurl in list(payload.get("relay_urls") or []):
                            transport._learn_relay_url(str(rurl))
                        self._send_json(200, {"ok": True,
                                              "known_relay_urls": transport._get_relay_pool()})
                        return

                    if self.path == "/algo":
                        # AELab-Invarianten-Bahn: kein Quorum, kein Genesis-Gate
                        # Nur verify_algo_token() als Strukturprüfung
                        if not transport._verify_signed_payload(payload):
                            self._send_json(401, {"ok": False, "error": "invalid_signature"})
                            return
                        try:
                            from modules.algo_share import AlgoToken, verify_algo_token
                            schema = str(payload.get("schema", ""))
                            if schema != "aether.algo_token.v1":
                                self._send_json(400, {"ok": False, "error": "wrong_schema"})
                                return
                            token = AlgoToken(
                                token_id=str(payload.get("token_id", "")),
                                tree_signature=str(payload.get("tree_signature", "")),
                                invariant_profile=list(payload.get("invariant_profile", [])),
                                fitness_score=float(payload.get("fitness_score", 0.0)),
                                domain_hint=str(payload.get("domain_hint", "generic")),
                                cascade_version=str(payload.get("cascade_version", "")),
                                node_count=int(payload.get("node_count", 0)),
                                depth=int(payload.get("depth", 0)),
                            )
                            if not verify_algo_token(token):
                                self._send_json(422, {"ok": False, "error": "token_invalid"})
                                return
                            transport._algo_path(token.token_id).write_text(
                                json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2),
                                encoding="utf-8",
                            )
                            self._send_json(200, {"ok": True, "token_id": token.token_id})
                        except Exception as e:
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
                    if self.path == "/algos":
                        self._send_json(200, {"token_ids": transport._read_local_algo_ids()})
                        return
                    if self.path.startswith("/algo/"):
                        token_id = self.path.split("/algo/", 1)[1].strip()
                        tp = transport._algo_path(token_id)
                        if tp.exists():
                            try:
                                self._send_json(200, json.loads(tp.read_text(encoding="utf-8")))
                                return
                            except Exception:
                                pass
                        self._send_json(404, {"ok": False})
                        return
                    if self.path.startswith("/anchor/"):
                        pack_id = self.path.split("/anchor/", 1)[1].strip()
                        pack_path = transport._anchor_path(pack_id)
                        if pack_path.exists():
                            try:
                                payload = json.loads(pack_path.read_text(encoding="utf-8"))
                                self._send_json(200, payload)
                                return
                            except Exception as e:
                                logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
                                pass
                        self._send_json(404, {"ok": False})
                        return

                    if self.path == "/peers":
                        peers: List[Dict[str, Any]] = []
                        for node_path in transport.nodes_dir.glob("*.json"):
                            try:
                                p = json.loads(node_path.read_text(encoding="utf-8"))
                                if isinstance(p, dict):
                                    peers.append(p)
                            except Exception:
                                continue
                        self._send_json(200, {"peers": peers,
                                              "relay_pool": transport._get_relay_pool()})
                        return

                    if self.path == "/relay-pool":
                        self._send_json(200, {"relay_urls": transport._get_relay_pool()})
                        return

                    if self.path == "/gossip/latest":
                        # Gibt letzte 50 Gossip-Pakete zurück (für Relay-Bridge-Clients).
                        with transport._relay_gossip_lock:
                            msgs = list(transport._relay_gossip_inbox[-50:])
                        self._send_json(200, {"messages": msgs})
                        return

                    if self.path == "/gossip/legacy/latest":
                        # Gibt letzte 50 Compact-Legacy-Pakete zurück.
                        # Falls keine Legacy-Pakete da, aktuelle volle Gossip als übersetzte
                        # Kurzform zurückgeben (damit Legacy-Clients etwas bekommen).
                        with transport._legacy_gossip_lock:
                            raw_pkts = list(transport._legacy_gossip_inbox[-50:])
                        self._send_json(200, {"packets": raw_pkts})
                        return

                    if self.path == "/consensus/candidates":
                        try:
                            from modules.consensus_engine import get_consensus_anchors

                            candidates = []
                            for item in list(get_consensus_anchors()):
                                if not isinstance(item, dict):
                                    continue
                                candidate = dict(item)
                                candidate["node_id"] = transport._normalized_candidate_node_id(candidate)
                                candidates.append(candidate)
                        except Exception as e:
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
            self.refresh_peer_states()
            urls: List[str] = []
            for path in self.nodes_dir.glob("*.json"):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    if str(payload.get("node_id", "")) == self.node_id:
                        continue
                    lan_url = str(payload.get("lan_url", "")).strip()
                    if lan_url:
                        if str(payload.get("state", "active")).strip().lower() == "stalled":
                            continue
                        urls.append(lan_url)
                except Exception as e:
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
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return "127.0.0.1"

    def _beacon_payload(self) -> bytes:
        info = {
            "node_id": self.node_id,
            "lan_url": f"http://{self._local_ip}:{self.lan_port}",
            "version": "aether-beacon-v1",
        }
        signed_info = self._sign_payload(info)
        return json.dumps(signed_info, ensure_ascii=True, sort_keys=True).encode("utf-8")

    def _store_peer_from_beacon(self, info: Dict[str, Any]) -> None:
        """Persists a peer discovered via UDP beacon or relay into nodes_dir."""
        try:
            if not self._verify_signed_payload(info):
                return
            peer_id = str(info.get("node_id", "")).strip()
            if not peer_id or peer_id == self.node_id:
                return
            peer_path = self.nodes_dir / f"{peer_id}.json"
            existing: Dict[str, Any] = {}
            if peer_path.exists():
                try:
                    existing = json.loads(peer_path.read_text(encoding="utf-8"))
                except Exception as e:
                    logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
                    pass
            existing.update(
                {
                    "node_id": peer_id,
                    "lan_url": str(info.get("lan_url", "")).strip(),
                    "discovered_via": str(info.get("version", "udp_broadcast")),
                    "last_seen_utc": self._utc_now_iso(),
                    "state": "active",
                    "consecutive_failures": 0,
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
                except Exception as e:
                    logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
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
                except Exception as e:
                    continue

        threading.Thread(target=_sender, daemon=True, name="aether-udp-beacon").start()
        threading.Thread(target=_listener, daemon=True, name="aether-udp-listener").start()
        print(f"[AETHERNET] UDP discovery active (broadcast port {beacon_port})")

    # ------------------------------------------------------------------ #
    #  Relay-Pool — verteiltes Relay-Verzeichnis                          #
    # ------------------------------------------------------------------ #

    def _get_relay_pool(self) -> List[str]:
        """Gibt alle bekannten Relay-URLs aus dem persistierten Pool zurück."""
        try:
            if self._relay_pool_path.is_file():
                data = json.loads(self._relay_pool_path.read_text(encoding="utf-8"))
                return [str(u).strip() for u in data.get("urls", []) if str(u).strip()]
        except Exception:
            pass
        return []

    def _learn_relay_url(self, url: str) -> None:
        """Fügt eine neue Relay-URL zum persistierten Pool hinzu (idempotent).

        Wird aufgerufen wenn ein anderer Knoten seine Relay-URL im Gossip oder
        beim /register mitteilt. Nodes lernen das Netz so von selbst.
        """
        url = url.strip()
        if not url or not url.startswith(("http://", "https://")):
            return
        with self._relay_pool_lock:
            pool = self._get_relay_pool()
            if url in pool:
                return
            pool.append(url)
            try:
                self._relay_pool_path.parent.mkdir(parents=True, exist_ok=True)
                self._relay_pool_path.write_text(
                    json.dumps({"schema": "aether.relay_pool.v1", "urls": pool[:64]},
                               ensure_ascii=True, indent=2),
                    encoding="utf-8",
                )
            except Exception:
                pass

    def _save_peer_to_cache(self, peer: Dict[str, Any]) -> None:
        """Schreibt einen bekannten Peer in den lokalen Peer-Cache.

        Der Cache überleben Neustarts — beim nächsten Start sind sofort Peers bekannt,
        ohne dass die Genesis-Node online sein muss.
        """
        node_id = str(peer.get("node_id", "")).strip()
        if not node_id:
            return
        try:
            cache: Dict[str, Any] = {}
            if self._peer_cache_path.is_file():
                cache = json.loads(self._peer_cache_path.read_text(encoding="utf-8"))
            if not isinstance(cache, dict):
                cache = {}
            cache[node_id] = {
                "node_id": node_id,
                "lan_url": str(peer.get("lan_url", "") or ""),
                "relay_url": str(peer.get("relay_url", "") or ""),
                "alias_username": str(peer.get("alias_username", "") or ""),
                "last_seen": self._utc_now_iso(),
            }
            # Maximal 512 Peers im Cache
            if len(cache) > 512:
                oldest = sorted(cache.items(), key=lambda x: x[1].get("last_seen", ""))[:len(cache) - 512]
                for k, _ in oldest:
                    del cache[k]
            self._peer_cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._peer_cache_path.write_text(
                json.dumps(cache, ensure_ascii=True, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def _save_gossip_peer(self, info: Dict[str, Any]) -> None:
        """Persistiert einen per Gossip oder Bootstrap bekannt gewordenen Peer in nodes_dir.

        Kein Signatur-Check — Gossip-Pakete sind bereits durch device-lock/genesis-
        Spoofing-Check in P2PLayer.receive_gossip() validiert. Peers aus bootstrap_from_relay
        stammen von einem vertrauenswürdigen Relay, das wir selbst angesprochen haben.
        KEIN Speichern von privaten Daten — nur node_id, yggdrasil_addr, peer_id.
        """
        node_id = str(info.get("node_id", "")).strip()
        if not node_id or node_id == self.node_id:
            return
        try:
            node_path = self.nodes_dir / f"{node_id}.json"
            existing: Dict[str, Any] = {}
            if node_path.exists():
                try:
                    existing = json.loads(node_path.read_text(encoding="utf-8"))
                except Exception as e:
                    logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            ygg = str(info.get("yggdrasil_addr", info.get("ygg_addr", "")) or "").strip()
            update: Dict[str, Any] = {
                "node_id": node_id,
                "discovered_via": "gossip",
                "last_seen_utc": self._utc_now_iso(),
                "state": "active",
                "consecutive_failures": 0,
            }
            if ygg:
                update["yggdrasil_addr"] = ygg
            peer_id = str(info.get("peer_id", "") or "").strip()
            if peer_id:
                update["peer_id"] = peer_id
            lan_url = str(info.get("lan_url", "") or "").strip()
            if lan_url:
                update["lan_url"] = lan_url
            relay = info.get("relay")
            if relay is not None:
                update["relay"] = bool(relay)
            existing.update(update)
            node_path.write_text(
                json.dumps(existing, ensure_ascii=True, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as err:
            logger.warning(f"[aethernet_transport] _save_gossip_peer failed: {err}")

    def bootstrap_from_relay(self, relay_url: str) -> int:
        """Holt Peer-Liste + Relay-Pool von einem bekannten Relay-Knoten.

        Wird beim Start aufgerufen — so lernt ein neuer Knoten sofort viele
        andere Peers kennen, auch wenn er noch nie online war.
        Gibt Anzahl neu gelernter Peers zurück.
        """
        if not relay_url:
            return 0
        learned = 0
        try:
            with urllib.request.urlopen(
                relay_url.rstrip("/") + "/peers", timeout=10.0
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for peer in data.get("peers", []):
                if isinstance(peer, dict):
                    nid = str(peer.get("node_id", "")).strip()
                    if nid and nid != self.node_id:
                        self._save_peer_to_cache(peer)
                        # Auch in nodes_dir/ schreiben — so findet discover_from_nodes_dir()
                        # diesen Peer auch nach einem Neustart ohne Genesis-Kontakt.
                        self._save_gossip_peer(peer)
                        learned += 1
            # Lerne auch den Relay-Pool des anderen Knotens
            for rurl in data.get("relay_pool", []):
                self._learn_relay_url(str(rurl))
        except Exception:
            pass
        # Direkt auch /relay-pool abfragen
        try:
            with urllib.request.urlopen(
                relay_url.rstrip("/") + "/relay-pool", timeout=5.0
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for rurl in data.get("relay_urls", []):
                self._learn_relay_url(str(rurl))
        except Exception:
            pass
        return learned

    # ------------------------------------------------------------------ #
    #  Internet Relay                                                      #
    # ------------------------------------------------------------------ #

    def relay_gossip_push(self, relay_url: str, gossip_msg: Dict[str, Any]) -> bool:
        """Sendet vollständiges Gossip-Paket an einen Relay-Knoten via HTTP.

        Für Legacy-/kein-Yggdrasil-Nodes: Internet-HTTP-Kontakt zum Relay/Genesis.
        Kein LAN, kein Yggdrasil nötig — reines TCP/HTTP, funktioniert ab Python 2.7+
        (urllib-Fallback wird in legacy_bootstrap.py separat abgedeckt).
        """
        if not relay_url or not isinstance(gossip_msg, dict):
            return False
        try:
            msg = dict(gossip_msg)
            # Eigene Relay-Kenntnisse mitschicken → Peer lernt das Netz
            known = self._get_relay_pool()
            if relay_url not in known:
                known.append(relay_url)
            msg["known_relay_urls"] = known[:16]  # max 16, kein Flooding
            req = urllib.request.Request(
                relay_url.rstrip("/") + "/gossip",
                data=json.dumps(msg, ensure_ascii=True).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                return 200 <= int(resp.status) < 300
        except Exception as err:
            print(f"[AETHERNET] relay_gossip_push failed: {err}")
            return False

    def relay_gossip_pull(self, relay_url: str) -> List[Dict[str, Any]]:
        """Holt Gossip-Pakete vom Relay-Knoten (GET /gossip/latest).

        Legacy-/kein-Yggdrasil-Nodes empfangen so den Schwarmsstand ohne direkte
        Peer-Verbindung. Gibt leere Liste bei Fehler zurück.
        """
        if not relay_url:
            return []
        try:
            with urllib.request.urlopen(
                relay_url.rstrip("/") + "/gossip/latest", timeout=8.0
            ) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            msgs = [
                m for m in list(data.get("messages", []))
                if isinstance(m, dict)
                and str(m.get("schema", "")) == "aether.swarm.p2p.gossip.v1"
            ]
            # Lerne Relay-URLs aus empfangenen Gossip-Paketen
            for m in msgs:
                for rurl in list(m.get("known_relay_urls") or []):
                    self._learn_relay_url(str(rurl))
            return msgs
        except Exception as err:
            print(f"[AETHERNET] relay_gossip_pull failed: {err}")
            return []

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
            payload = self._sign_payload(payload)
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
        except Exception as e:
            logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
            return
        peer_urls = self.discover_lan_nodes()
        if not peer_urls:
            return
        try:
            local_anchors = list(get_consensus_anchors(db_path=consensus_db))
        except Exception as e:
            local_anchors = []
        for base_url in peer_urls:
            for anchor in local_anchors:
                try:
                    body = json.dumps(
                        self._sign_payload(
                        {
                            "ttd_hash": str(anchor.get("ttd_hash", "")),
                            "anchor_type": str(anchor.get("anchor_type", "consensus")),
                            "node_id": self.node_id,
                            "software_context": str(anchor.get("software_context", "aether")),
                            "metrics": dict(anchor.get("metrics", {})),
                        }
                        ),
                        ensure_ascii=True,
                    ).encode("utf-8")
                    req = urllib.request.Request(
                        base_url.rstrip("/") + "/consensus/candidate",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=2.0)
                except Exception as e:
                    logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
                    pass
            try:
                with urllib.request.urlopen(
                    base_url.rstrip("/") + "/consensus/candidates", timeout=2.0
                ) as resp:
                    remote = json.loads(resp.read().decode("utf-8"))
                for candidate in list(remote.get("candidates", [])):
                    try:
                        if not isinstance(candidate, dict):
                            continue
                        remote_node_id = self._normalized_candidate_node_id(candidate)
                        submit_candidate(
                            ttd_hash=str(candidate.get("ttd_hash", "")),
                            anchor_type=str(candidate.get("anchor_type", "remote")),
                            node_id=remote_node_id,
                            metrics=dict(candidate.get("metrics", {})),
                            software_context=str(candidate.get("software_context", "aether")),
                            db_path=consensus_db,
                        )
                    except Exception as e:
                        logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
                        pass
            except Exception as e:
                logger.warning(f"[aethernet_transport] Stiller Fehler: {e}")
                pass