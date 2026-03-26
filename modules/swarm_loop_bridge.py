"""
SwarmLoopBridge: submits CascadeResult KPIs to swarm_loop.rs via
the existing IPC channel (port 7387).

Enforces CASCADE_VERSION check before submission.
Genesis/Admin node can submit without quorum via role="genesis".
"""
from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path
from typing import Any

from modules.unified_cascade import CascadeResult, CASCADE_VERSION, cascade_to_swarm_kpi

NODE_ID_PATH = Path("data/swarm/nodes")
KEY_PATH     = Path("keys/node_private.key")
IPC_PORT     = 7387


def _load_node_id() -> str:
    files = list(NODE_ID_PATH.glob("*.json"))
    for f in files:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            if d.get("role") == "genesis":
                return str(d["node_id"])
        except Exception:
            pass
    return "unknown"


def _sign(payload: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        return key.sign(payload).hex()
    except Exception:
        return "unsigned"


def submit_cascade_result(
    result: CascadeResult,
    role: str = "peer",  # "genesis" = admin, skips quorum gate
) -> dict[str, Any]:
    """
    Submit a CascadeResult to the swarm as a signed KPI report.

    If role="genesis": anchor is promoted immediately without quorum.
    If role="peer": requires ≥3 matching run_ids from other nodes.

    Rejects submission if result.cascade_version != CASCADE_VERSION.
    """
    if result.cascade_version != CASCADE_VERSION:
        return {
            "ok": False,
            "error": f"cascade_version_mismatch: "
                     f"got {result.cascade_version}, need {CASCADE_VERSION}",
        }

    node_id  = _load_node_id()
    kpis     = cascade_to_swarm_kpi(result)
    import time
    report = {
        "schema_version":  1,
        "node_id":         node_id,
        "run_id":          result.run_id,
        "cascade_version": result.cascade_version,
        "epoch_minute":    int(time.time() // 60),
        "role":            role,
        "kpis":            kpis,
        "rule_feedback":   {},
        "source_type":     result.source_type,
        "trust_score":     result.trust_score,
        "anomaly_flags":   result.anomaly_flags,
        # delta_encrypted_hex intentionally NOT included — stays local
    }

    canonical = json.dumps(report, ensure_ascii=True,
                          sort_keys=True, separators=(",", ":")).encode()
    report["signature"] = _sign(canonical)

    # Genesis role = immediate anchor promotion without quorum
    if role == "genesis":
        return _promote_genesis_anchor(report, result)

    # Peer role = submit to swarm controller for quorum aggregation
    return _submit_to_ipc(report)


def _promote_genesis_anchor(
    report: dict[str, Any],
    result: CascadeResult,
) -> dict[str, Any]:
    """
    Genesis/Admin: write anchor pack directly to data/anchors/.
    No quorum needed — but the cascade MUST still pass.
    Genesis is NOT exempt from trust_score. The cascade is the proof of work.
    """
    from pathlib import Path
    import json
    from datetime import datetime, timezone

    # Hard gate — same threshold as quorum peers.
    # Genesis skips the vote, not the proof.
    TRUST_THRESHOLD = 0.65
    if result.trust_score < TRUST_THRESHOLD:
        return {
            "ok":            False,
            "promoted":      False,
            "reason":        (
                f"cascade_rejected: trust_score {result.trust_score:.3f} "
                f"< {TRUST_THRESHOLD} — genesis must pass the cascade too"
            ),
            "run_id":        result.run_id,
            "anomaly_flags": result.anomaly_flags,
            "trust_score":   result.trust_score,
        }

    ANCHOR_DIR = Path("data/anchors")
    ANCHOR_DIR.mkdir(parents=True, exist_ok=True)

    pack = {
        "schema":          "aether.anchor_pack.v1",
        "pack_id":         f"cascade_{result.run_id[:24]}",
        "node_id":         report["node_id"],
        "role":            "genesis",
        "cascade_version": CASCADE_VERSION,
        "run_id":          result.run_id,
        "promoted_by":     "genesis_no_quorum",
        "promoted_at":     datetime.now(timezone.utc).isoformat(),
        "source_type":     result.source_type,
        "kpis":            report["kpis"],
        "trust_score":     result.trust_score,
        "anomaly_flags":   result.anomaly_flags,
        "signature":       report["signature"],
        # delta never included
    }

    pack_path = ANCHOR_DIR / f"{pack['pack_id']}.pack"
    pack_path.write_text(
        json.dumps(pack, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    return {
        "ok":       True,
        "promoted": True,
        "pack_id":  pack["pack_id"],
        "run_id":   result.run_id,
        "role":     "genesis",
        "path":     str(pack_path),
    }


def _submit_to_ipc(report: dict[str, Any]) -> dict[str, Any]:
    """Submit KPI report to SwarmController IPC for quorum aggregation."""
    try:
        payload = (json.dumps({
            "cmd":    "submit_kpi",
            "report": report,
        }) + "\n").encode("utf-8")
        sock = socket.create_connection(("127.0.0.1", IPC_PORT), timeout=3.0)
        sock.sendall(payload)
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return json.loads(data.decode("utf-8").strip())
    except Exception as e:
        return {"ok": False, "error": str(e)}
