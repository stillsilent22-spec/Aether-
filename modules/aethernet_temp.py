import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path

from .ethics_engine import CodeEthicsEngine, EthicsEngine


KEY_PATH = Path("keys/node_secret.key")


class AethernetTemp:
    def _load_node_secret(self) -> bytes:
        if not KEY_PATH.exists():
            raise RuntimeError("Node nicht initialisiert. node_init.py ausfuehren.")
        return KEY_PATH.read_bytes()

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
        return {"anchors": anchors, "pack_id": hashlib.sha256(canonical).hexdigest()}

    def verify_consensus(self, anchor_id: str, verifications: list) -> bool:
        valid = 0
        for verification in verifications:
            node_id = str(verification.get("node_id", ""))
            sig = str(verification.get("sig", ""))
            node_path = Path(f"data/swarm/nodes/{node_id}.json")
            if not node_path.exists():
                continue
            try:
                node_data = json.loads(node_path.read_text(encoding="utf-8"))
                if node_data.get("node_id") == node_id and len(sig) == 64:
                    valid += 1
            except Exception:
                continue
        return valid >= 3

    def allow_solo_push(self, session) -> bool:
        return hasattr(session, "user_role") and session.user_role in ("admin", "operator")

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
        anchors_dir = "data/anchors"
        os.makedirs(anchors_dir, exist_ok=True)
        pack_path = os.path.join(anchors_dir, f"{pack['pack_id']}.pack")
        with open(pack_path, "w", encoding="utf-8") as handle:
            json.dump(signed, handle, ensure_ascii=True)
        try:
            subprocess.run(["git", "add", pack_path, "data/swarm/nodes/"], check=True)
            subprocess.run(["git", "commit", "-m", f"anchor: {pack['pack_id'][:12]}"], check=True)
            subprocess.run(["git", "push", "origin", "main"], check=True)
            return True
        except subprocess.CalledProcessError as err:
            print(f"[ANCHOR WARN] Push fehlgeschlagen (lokal gespeichert): {err}")
            return False
