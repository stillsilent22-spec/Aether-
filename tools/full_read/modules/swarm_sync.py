from __future__ import annotations

import json
import subprocess
from pathlib import Path


ANCHOR_DIR = Path("data/anchors")
NODES_DIR = Path("data/swarm/nodes")


def _has_origin_remote() -> bool:
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and bool((result.stdout or "").strip())
    except Exception:
        return False


def pull_anchors() -> list[str]:
    known_before = {path.stem for path in ANCHOR_DIR.glob("*.pack")}
    if not _has_origin_remote():
        print("[SWARM] Pull uebersprungen: kein Git-Remote 'origin' konfiguriert")
        return []
    try:
        subprocess.run(["git", "pull", "origin", "main"], check=True, capture_output=True)
    except subprocess.CalledProcessError as err:
        print(f"[SWARM] Pull fehlgeschlagen: {err}")
        return []
    return list({path.stem for path in ANCHOR_DIR.glob("*.pack")} - known_before)


def push_anchor_pack(pack: dict) -> bool:
    ANCHOR_DIR.mkdir(parents=True, exist_ok=True)
    path = ANCHOR_DIR / f"{pack['pack_id']}.pack"
    path.write_text(json.dumps(pack, sort_keys=True, ensure_ascii=True), encoding="utf-8")
    if not _has_origin_remote():
        print("[SWARM] Push uebersprungen: kein Git-Remote 'origin' konfiguriert")
        return False
    try:
        subprocess.run(["git", "add", str(path)], check=True)
        subprocess.run(["git", "commit", "-m", f"anchor: {pack['pack_id'][:12]}"], check=True)
        subprocess.run(["git", "push", "origin", "main"], check=True)
        return True
    except subprocess.CalledProcessError as err:
        print(f"[SWARM] Push fehlgeschlagen: {err}")
        return False


def discover_nodes() -> dict[str, str]:
    nodes: dict[str, str] = {}
    for file_path in NODES_DIR.glob("*.json"):
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            node_id = str(data.get("node_id", ""))
            if node_id:
                nodes[node_id] = str(data.get("public_key_pem", ""))
        except Exception:
            continue
    return nodes


def build_kpi_report(node_id: str, kpis: dict[str, float]) -> dict:
    import time

    return {
        "schema_version": 1,
        "node_id": node_id,
        "epoch_minute": int(time.time() // 60),
        "kpis": {key: float(value) for key, value in kpis.items()},
        "rule_feedback": {},
    }


def verify_pack_basic(pack: dict, node_id: str) -> bool:
    if not (NODES_DIR / f"{node_id}.json").exists():
        return False
    return all(len(str(anchor.get("sig", ""))) == 64 for anchor in pack.get("anchors", []))


class SwarmSync:
    """Thin wrapper around swarm sync functions for object-oriented access."""

    def pull_anchors(self) -> list[str]:
        return pull_anchors()

    def push_anchor_pack(self, pack: dict) -> bool:
        return push_anchor_pack(pack)

    def discover_nodes(self) -> dict[str, str]:
        return discover_nodes()

    def build_kpi_report(self, node_id: str, kpis: dict) -> dict:
        return build_kpi_report(node_id, kpis)

    def verify_pack_basic(self, pack: dict, node_id: str) -> bool:
        return verify_pack_basic(pack, node_id)