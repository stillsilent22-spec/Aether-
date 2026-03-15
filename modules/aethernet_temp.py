import hashlib
import json
import os

class AethernetTemp:
    def generate_anchor_pack(self, ankers: list) -> dict:
        pack = {
            "anchors": [self._sign_anchor(a) for a in ankers],
            "pack_id": hashlib.sha256(json.dumps(ankers).encode()).hexdigest()
        }
        return pack

    def _sign_anchor(self, anchor: dict) -> dict:
        anchor_id = hashlib.sha256(json.dumps(anchor).encode()).hexdigest()
        return {"id": anchor_id, "sig": anchor_id[:16]}

    def verify_consensus(self, anker_id: str, verifications: list) -> bool:
        return len(set(verifications)) >= 3

    def allow_solo_push(self, user_id: str) -> bool:
        return user_id == "stillsilent22-spec"

    def push_to_github(self, pack: dict, user_id: str) -> bool:
        anchors_dir = "data/anchors"
        os.makedirs(anchors_dir, exist_ok=True)
        pack_path = os.path.join(anchors_dir, f"{pack['pack_id']}.pack")
        with open(pack_path, "w") as f:
            json.dump(pack, f)
        print(f"Anchor pack {pack['pack_id']} written by {user_id}")
        return True
