from __future__ import annotations

import logging
logger = logging.getLogger(__name__)
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .aethernet_transport import AethernetTransport
from .ethics_engine import CodeEthicsEngine, EthicsEngine
from .swarm_health import get_swarm_status


KEY_PATH = Path("keys/node_secret.key")
NODE_DIR = Path("data/swarm/nodes")


class AethernetTemp:
    def __init__(self) -> None:
        self.node_id = self._load_local_node_id()
        self.transport = AethernetTransport(node_id=self.node_id)

    def _load_node_secret(self) -> bytes:
        if not KEY_PATH.exists():
            raise RuntimeError("Node nicht initialisiert. node_init.py ausfuehren.")
        return KEY_PATH.read_bytes()

    def _load_local_node_id(self) -> str:
        try:
            if not NODE_DIR.exists():
                return "local-node"
            for node_path in sorted(NODE_DIR.glob("*.json")):
                try:
                    payload = json.loads(node_path.read_text(encoding="utf-8"))
                except Exception as e:
                    continue
                node_id = str(payload.get("node_id", "")).strip()
                if node_id:
                    return node_id
        except Exception as e:
            return "local-node"
        return "local-node"

    def _canonical_json(self, obj: dict) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def _sign_anchor(self, anchor: dict) -> dict:
        secret = self._load_node_secret()
        canonical = self._canonical_json(anchor)
        anchor_id = hashlib.sha256(canonical).hexdigest()
        sig = hmac.new(secret, canonical, "sha256").hexdigest()
        return {"id": anchor_id, "sig": sig, "data": anchor}

    def _sign_pack(self, pack: dict) -> dict:
        return {**pack, "anchors": [self._sign_anchor(anchor) for anchor in pack.get("anchors", [])]}

    def generate_anchor_pack(self, anchors: list) -> dict:
        canonical = self._canonical_json({"anchors": anchors})
        return {
            "schema": "aether.anchor.pack.v1",
            "node_id": self.node_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "anchors": list(anchors or []),
            "pack_id": hashlib.sha256(canonical).hexdigest(),
        }

    def verify_consensus(self, anchor_id: str, verifications: list) -> bool:
        del anchor_id
        unique_nodes = set()
        for verification in list(verifications or []):
            if isinstance(verification, dict):
                node_id = str(verification.get("node_id", "")).strip()
                sig = str(verification.get("sig", "")).strip()
                if node_id and sig:
                    unique_nodes.add(node_id)
                continue
            token = str(verification).strip()
            if token:
                unique_nodes.add(token)
        return len(unique_nodes) >= 3

    def allow_solo_push(self, session) -> bool:
        if hasattr(session, "user_role"):
            return str(getattr(session, "user_role", "")).strip() in ("admin", "operator")
        session_value = str(session).strip().lower()
        return session_value in ("admin", "operator", "stillsilent22-spec")

    def get_transport_status(self) -> dict[str, Any]:
        try:
            return get_swarm_status()
        except Exception as e:
            return {}

    def push_to_github(self, pack: dict, session) -> bool:
        payload_str = json.dumps(pack, sort_keys=True, ensure_ascii=True)
        ethics_result = EthicsEngine().assess(payload_str)
        if ethics_result.integrity_state == "STRUCTURAL_ANOMALY":
            print(
                f"[ANCHOR BLOCKED] Ethics: {ethics_result.integrity_state} score={ethics_result.ethics_score:.3f}"
            )
            return False
        if ethics_result.integrity_state == "STRUCTURAL_TENSION":
            print(
                f"[ANCHOR WARN] Ethics: {ethics_result.integrity_state} score={ethics_result.ethics_score:.3f}"
            )
        code_result = CodeEthicsEngine().analyze(payload_str)
        if code_result.get("verdict") == "anomalous":
            print(f"[ANCHOR BLOCKED] CodeEthics: flags={code_result.get('flags', [])}")
            return False
        if code_result.get("verdict") == "suspicious":
            print(f"[ANCHOR WARN] CodeEthics: flags={code_result.get('flags', [])}")
        if not self.allow_solo_push(session):
            print("[ANCHOR BLOCKED] Unzureichende Session-Rolle.")
            return False
        signed = self._sign_pack(pack)
        transport_mode = self.transport.push_pack(signed)
        if transport_mode == "failed":
            print(f"[ANCHOR WARN] Push fehlgeschlagen (lokal gespeichert): {pack.get('pack_id', '')}")
            return False
        print(f"[AETHERNET] Pack {pack.get('pack_id', '')} ueber {transport_mode} transportiert")
        return True
