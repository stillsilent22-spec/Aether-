from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Lightweight bridge daemon for Rust <-> Python hybrid runtime.

This process is started by the Rust shell and keeps shared status files fresh.
It can also launch the Symbiont JSON-RPC server as a child process.
"""


import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.aethernet_transport import AethernetTransport
from modules.swarm_invite import accept_invite, generate_invite_pack, validate_invite_pack
from modules.swarm_health import get_swarm_status

SETTINGS_PATH = ROOT / "data" / "settings.json"
INTERBUS_DIR = ROOT / "data" / "interbus"
BACKEND_STATE_PATH = INTERBUS_DIR / "backend_state.json"
HYBRID_STATUS_PATH = INTERBUS_DIR / "hybrid_status.json"

DEFAULT_HYBRID: Dict[str, Any] = {
    "enabled": True,
    "python_path": "python",
    "poll_seconds": 2.0,
    "aethernet": {
        "enabled": True,
        "receiver_enabled": True,
        "require_signed_messages": True,
        "auto_pull": True,
        "pull_interval_seconds": 30.0,
        "peer_rejoin_interval_seconds": 45.0,
        "invites_enabled": True,
        "invite_auto_accept": True,
        "invite_emit_local": True,
        "invite_emit_interval_seconds": 900.0,
        "node_id": "",
        "lan_port": 7385,
        "relay_url": "",
        "anchor_dir": "data/anchors",
        "nodes_dir": "data/swarm/nodes",
    },
    "symbiont": {
        "enabled": True,
        "python_path": "python",
        "server_path": "aether-symbiont/server/symbiont_server.py",
        "host": "127.0.0.1",
        "port": 38571,
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_read_json(path: Path) -> Dict[str, Any]:
    try:
        if path.is_file():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return dict(raw)
    except Exception as e:
        return {}
    return {}


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _merge_hybrid(settings_raw: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(DEFAULT_HYBRID)
    hybrid_raw = settings_raw.get("hybrid")
    if isinstance(hybrid_raw, dict):
        merged.update({k: hybrid_raw.get(k) for k in ("enabled", "python_path", "poll_seconds") if k in hybrid_raw})
        aether_raw = hybrid_raw.get("aethernet")
        if isinstance(aether_raw, dict):
            aether = dict(DEFAULT_HYBRID["aethernet"])
            aether.update({
                k: aether_raw.get(k)
                for k in (
                    "enabled",
                    "receiver_enabled",
                    "require_signed_messages",
                    "auto_pull",
                    "pull_interval_seconds",
                    "peer_rejoin_interval_seconds",
                    "invites_enabled",
                    "invite_auto_accept",
                    "invite_emit_local",
                    "invite_emit_interval_seconds",
                    "node_id",
                    "lan_port",
                    "anchor_dir",
                    "nodes_dir",
                )
                if k in aether_raw
            })
            merged["aethernet"] = aether
        sym_raw = hybrid_raw.get("symbiont")
        if isinstance(sym_raw, dict):
            sym = dict(DEFAULT_HYBRID["symbiont"])
            sym.update({
                k: sym_raw.get(k)
                for k in ("enabled", "python_path", "server_path", "host", "port")
                if k in sym_raw
            })
            merged["symbiont"] = sym
    return merged


def _ensure_settings_defaults() -> Dict[str, Any]:
    settings = _safe_read_json(SETTINGS_PATH)
    hybrid = _merge_hybrid(settings)
    settings["hybrid"] = hybrid
    _write_json(SETTINGS_PATH, settings)
    return settings


def _resolve_local_node_id(nodes_dir: Path) -> str:
    try:
        for node_path in sorted(nodes_dir.glob("*.json")):
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


def _resolve_python(binary: str) -> str:
    value = str(binary or "").strip()
    if value:
        return value
    env_python = str(os.environ.get("AETHER_PYTHON", "")).strip()
    if env_python:
        return env_python
    return sys.executable or "python"


def _load_local_public_key() -> str:
    pub_key_path = ROOT / "keys" / "node_public.key"
    try:
        if pub_key_path.is_file():
            return str(pub_key_path.read_text(encoding="utf-8")).strip()
    except Exception as e:
        return ""
    return ""


def _process_swarm_invites(
    *,
    node_id: str,
    nodes_dir: Path,
    invites_root: Path,
    invite_auto_accept: bool,
    invite_emit_local: bool,
    invite_emit_interval_seconds: float,
    now_ts: float,
    last_emit_at: float,
) -> tuple[dict[str, Any], float]:
    """Verarbeitet Invite-Inbox und publiziert optional einen lokalen Invite fail-closed."""
    status: dict[str, Any] = {
        "invite_emitted": False,
        "invite_generated_path": "",
        "invite_received": 0,
        "invite_accepted": 0,
        "invite_rejected": 0,
        "invite_last_error": "",
    }
    private_key_path = ROOT / "keys" / "node_private.key"
    public_key_pem = _load_local_public_key()
    effective_last_emit = float(last_emit_at)

    try:
        incoming_dir = invites_root / "incoming"
        accepted_dir = invites_root / "accepted"
        rejected_dir = invites_root / "rejected"
        outgoing_dir = invites_root / "outgoing"
        incoming_dir.mkdir(parents=True, exist_ok=True)
        accepted_dir.mkdir(parents=True, exist_ok=True)
        rejected_dir.mkdir(parents=True, exist_ok=True)
        outgoing_dir.mkdir(parents=True, exist_ok=True)

        if invite_emit_local and private_key_path.is_file() and node_id:
            if (now_ts - effective_last_emit) >= max(60.0, float(invite_emit_interval_seconds)):
                pack = generate_invite_pack(
                    inviter_node_id=node_id,
                    inviter_private_key_path=str(private_key_path),
                )
                if isinstance(pack, dict) and str(pack.get("invite_id", "")).strip():
                    invite_id = str(pack.get("invite_id", "")).strip()
                    out_path = outgoing_dir / f"{invite_id}.json"
                    out_path.write_text(json.dumps(pack, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
                    latest_path = outgoing_dir / "latest_invite.json"
                    latest_path.write_text(json.dumps(pack, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
                    status["invite_emitted"] = True
                    status["invite_generated_path"] = str(out_path)
                    effective_last_emit = now_ts

        for invite_file in sorted(incoming_dir.glob("*.json")):
            status["invite_received"] = int(status.get("invite_received", 0) or 0) + 1
            accepted = False
            try:
                invite_pack = json.loads(invite_file.read_text(encoding="utf-8"))
                valid = validate_invite_pack(invite_pack, known_nodes_dir=str(nodes_dir))
                if valid and invite_auto_accept and public_key_pem and node_id:
                    accepted = accept_invite(
                        invite_pack,
                        my_node_id=node_id,
                        my_public_key_pem=public_key_pem,
                        known_nodes_dir=str(nodes_dir),
                    )
                elif valid:
                    accepted = True
                if accepted:
                    status["invite_accepted"] = int(status.get("invite_accepted", 0) or 0) + 1
                    target = accepted_dir / invite_file.name
                else:
                    status["invite_rejected"] = int(status.get("invite_rejected", 0) or 0) + 1
                    target = rejected_dir / invite_file.name
                if target.exists():
                    target = target.with_name(f"{target.stem}_{int(now_ts)}{target.suffix}")
                shutil.move(str(invite_file), str(target))
            except Exception as exc:
                status["invite_rejected"] = int(status.get("invite_rejected", 0) or 0) + 1
                status["invite_last_error"] = str(exc)
                try:
                    fallback_target = rejected_dir / invite_file.name
                    if fallback_target.exists():
                        fallback_target = fallback_target.with_name(
                            f"{fallback_target.stem}_{int(now_ts)}{fallback_target.suffix}"
                        )
                    shutil.move(str(invite_file), str(fallback_target))
                except Exception as e:
                    logger.warning(f"[hybrid_bridge] Fehler: {e}")
                    pass
    except Exception as exc:
        status["invite_last_error"] = str(exc)
    return status, effective_last_emit


def _start_symbiont(sym_cfg: Dict[str, Any]) -> subprocess.Popen[Any]:
    python_bin = _resolve_python(str(sym_cfg.get("python_path", "python") or "python"))
    server_rel = str(sym_cfg.get("server_path", "") or "").strip()
    if not server_rel:
        server_rel = "aether-symbiont/server/symbiont_server.py"
    server_path = ROOT / server_rel
    if not server_path.is_file():
        raise FileNotFoundError(f"Symbiont server not found: {server_path}")

    host = str(sym_cfg.get("host", "127.0.0.1") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(sym_cfg.get("port", 38571) or 38571)

    return subprocess.Popen(
        [python_bin, str(server_path), "--tcp-host", host, "--tcp-port", str(port)],
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _merge_backend_heartbeat(existing: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "vault_main": int(existing.get("vault_main", 0) or 0),
        "vault_sub": int(existing.get("vault_sub", 0) or 0),
        "entropy_mean": float(existing.get("entropy_mean", 0.0) or 0.0),
        "anchor_count": int(existing.get("anchor_count", 0) or 0),
        "cpu_pct": float(existing.get("cpu_pct", 0.0) or 0.0),
        "mem_used_gb": float(existing.get("mem_used_gb", 0.0) or 0.0),
        "assistant_last": str(existing.get("assistant_last", "") or ""),
        "swarm_node_count": int(existing.get("swarm_node_count", 0) or 0),
        "swarm_reachable_node_count": int(existing.get("swarm_reachable_node_count", 0) or 0),
        "swarm_pack_count": int(existing.get("swarm_pack_count", 0) or 0),
        "swarm_candidate_count": int(existing.get("swarm_candidate_count", 0) or 0),
        "swarm_consensus_count": int(existing.get("swarm_consensus_count", 0) or 0),
        "swarm_genesis_key_ok": bool(existing.get("swarm_genesis_key_ok", False)),
        "swarm_quorum_reachable": bool(existing.get("swarm_quorum_reachable", False)),
        "swarm_estimated_saving_percent": float(existing.get("swarm_estimated_saving_percent", 0.0) or 0.0),
        "swarm_summary": str(existing.get("swarm_summary", "") or ""),
    }
    return payload


def main() -> int:
    INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
    settings = _ensure_settings_defaults()

    sym_proc: Optional[subprocess.Popen[Any]] = None
    aether_transport: Optional[AethernetTransport] = None
    last_aether_pull_at = 0.0
    last_peer_rejoin_at = 0.0
    last_invite_emit_at = 0.0
    last_error = ""

    while True:
        try:
            settings = _safe_read_json(SETTINGS_PATH)
            hybrid = _merge_hybrid(settings)
            enabled = bool(hybrid.get("enabled", True))
            poll_seconds = float(hybrid.get("poll_seconds", 2.0) or 2.0)
            poll_seconds = max(0.5, min(10.0, poll_seconds))

            sym_cfg = hybrid.get("symbiont")
            sym_enabled = isinstance(sym_cfg, dict) and bool(sym_cfg.get("enabled", True))
            sym_host = str((sym_cfg or {}).get("host", "127.0.0.1") or "127.0.0.1")
            sym_port = int((sym_cfg or {}).get("port", 38571) or 38571)
            aether_cfg = hybrid.get("aethernet") if isinstance(hybrid.get("aethernet"), dict) else {}
            aether_enabled = bool((aether_cfg or {}).get("enabled", True))
            receiver_enabled = bool((aether_cfg or {}).get("receiver_enabled", True))
            require_signed_messages = bool((aether_cfg or {}).get("require_signed_messages", True))
            auto_pull = bool((aether_cfg or {}).get("auto_pull", True))
            pull_interval = float((aether_cfg or {}).get("pull_interval_seconds", 30.0) or 30.0)
            pull_interval = max(5.0, min(600.0, pull_interval))
            peer_rejoin_interval = float((aether_cfg or {}).get("peer_rejoin_interval_seconds", 45.0) or 45.0)
            peer_rejoin_interval = max(10.0, min(600.0, peer_rejoin_interval))
            invites_enabled = bool((aether_cfg or {}).get("invites_enabled", True))
            invite_auto_accept = bool((aether_cfg or {}).get("invite_auto_accept", True))
            invite_emit_local = bool((aether_cfg or {}).get("invite_emit_local", True))
            invite_emit_interval = float((aether_cfg or {}).get("invite_emit_interval_seconds", 900.0) or 900.0)
            invite_emit_interval = max(60.0, min(86400.0, invite_emit_interval))
            nodes_dir = ROOT / str((aether_cfg or {}).get("nodes_dir", "data/swarm/nodes") or "data/swarm/nodes")
            anchor_dir = ROOT / str((aether_cfg or {}).get("anchor_dir", "data/anchors") or "data/anchors")
            invites_root = ROOT / "data" / "swarm" / "invites"
            configured_node_id = str((aether_cfg or {}).get("node_id", "") or "").strip()
            aether_node_id = configured_node_id or _resolve_local_node_id(nodes_dir)
            aether_port = int((aether_cfg or {}).get("lan_port", 7385) or 7385)
            relay_url = str((aether_cfg or {}).get("relay_url", "") or "").strip()

            if enabled and sym_enabled:
                should_start = sym_proc is None or (sym_proc.poll() is not None)
                if should_start:
                    sym_proc = _start_symbiont(dict(sym_cfg or {}))
                    last_error = ""
            else:
                if sym_proc is not None and sym_proc.poll() is None:
                    sym_proc.terminate()
                    try:
                        sym_proc.wait(timeout=2.0)
                    except Exception as e:
                        sym_proc.kill()
                sym_proc = None

            swarm_status = get_swarm_status(
                nodes_dir=str(nodes_dir),
                anchor_dir=str(anchor_dir),
                consensus_db=str(ROOT / "data" / "consensus.db"),
            )
            if enabled and aether_enabled:
                if aether_transport is None or aether_transport.node_id != aether_node_id:
                    aether_transport = AethernetTransport(
                        node_id=aether_node_id,
                        anchor_dir=str(anchor_dir),
                        nodes_dir=str(nodes_dir),
                        lan_port=aether_port,
                        local_private_key_path=str(ROOT / "keys" / "node_private.key"),
                        require_signed_messages=require_signed_messages,
                    )
                if receiver_enabled:
                    aether_transport.start_lan_receiver()
                aether_transport.start_udp_discovery()
                now_ts = time.time()
                peer_probe = {"total": 0, "reachable": 0, "stalled": 0}
                if (now_ts - float(last_peer_rejoin_at)) >= peer_rejoin_interval:
                    peer_probe = aether_transport.refresh_peer_states()
                    last_peer_rejoin_at = now_ts
                if auto_pull:
                    if (now_ts - float(last_aether_pull_at)) >= pull_interval:
                        if relay_url:
                            aether_transport.relay_push(relay_url)
                            aether_transport.relay_pull(relay_url)
                        aether_transport.pull_packs()
                        aether_transport.sync_consensus_with_peers(
                            consensus_db=str(ROOT / "data" / "consensus.db")
                        )
                        last_aether_pull_at = now_ts
                        swarm_status = get_swarm_status(
                            nodes_dir=str(nodes_dir),
                            anchor_dir=str(anchor_dir),
                            consensus_db=str(ROOT / "data" / "consensus.db"),
                        )
                else:
                    peer_probe = aether_transport.refresh_peer_states()
                invite_status = {
                    "invite_emitted": False,
                    "invite_generated_path": "",
                    "invite_received": 0,
                    "invite_accepted": 0,
                    "invite_rejected": 0,
                    "invite_last_error": "",
                }
                if invites_enabled:
                    invite_status, last_invite_emit_at = _process_swarm_invites(
                        node_id=aether_node_id,
                        nodes_dir=nodes_dir,
                        invites_root=invites_root,
                        invite_auto_accept=invite_auto_accept,
                        invite_emit_local=invite_emit_local,
                        invite_emit_interval_seconds=invite_emit_interval,
                        now_ts=time.time(),
                        last_emit_at=last_invite_emit_at,
                    )
            else:
                aether_transport = None
                invite_status = {
                    "invite_emitted": False,
                    "invite_generated_path": "",
                    "invite_received": 0,
                    "invite_accepted": 0,
                    "invite_rejected": 0,
                    "invite_last_error": "",
                }
                peer_probe = {"total": 0, "reachable": 0, "stalled": 0}

            existing_backend = _safe_read_json(BACKEND_STATE_PATH)
            merged_backend = _merge_backend_heartbeat(existing_backend)

            # Live CPU + RAM via psutil (fail-safe: keep last value if unavailable)
            try:
                import psutil as _psutil  # optional dependency
                merged_backend["cpu_pct"] = round(float(_psutil.cpu_percent(interval=None)), 1)
                _mem = _psutil.virtual_memory()
                merged_backend["mem_used_gb"] = round(_mem.used / (1024 ** 3), 2)
                merged_backend["mem_total_gb"] = round(_mem.total / (1024 ** 3), 2)
            except Exception as e:
                pass  # keep values from existing_backend if psutil unavailable

            merged_backend.update(
                {
                    "swarm_node_count": int(swarm_status.get("node_count", 0) or 0),
                    "swarm_reachable_node_count": int(swarm_status.get("reachable_node_count", 0) or 0),
                    "swarm_pack_count": int(swarm_status.get("pack_count", 0) or 0),
                    "swarm_candidate_count": int(swarm_status.get("candidate_count", 0) or 0),
                    "swarm_consensus_count": int(swarm_status.get("consensus_count", 0) or 0),
                    "swarm_genesis_key_ok": bool(swarm_status.get("genesis_key_ok", False)),
                    "swarm_quorum_reachable": bool(swarm_status.get("quorum_reachable", False)),
                    "swarm_estimated_saving_percent": float(swarm_status.get("estimated_saving_percent", 0.0) or 0.0),
                    "swarm_summary": str(swarm_status.get("summary", "") or ""),
                    "swarm_alert_level": str(swarm_status.get("alert_level", "ok") or "ok"),
                    "swarm_alert_count": int(len(list(swarm_status.get("alerts", []) or []))),
                    "swarm_health_score": float(swarm_status.get("health_score", 0.0) or 0.0),
                    "swarm_peer_probe_total": int(peer_probe.get("total", 0) or 0),
                    "swarm_peer_probe_reachable": int(peer_probe.get("reachable", 0) or 0),
                    "swarm_peer_probe_stalled": int(peer_probe.get("stalled", 0) or 0),
                    "swarm_invite_received": int(invite_status.get("invite_received", 0) or 0),
                    "swarm_invite_accepted": int(invite_status.get("invite_accepted", 0) or 0),
                    "swarm_invite_rejected": int(invite_status.get("invite_rejected", 0) or 0),
                    "swarm_invite_emitted": bool(invite_status.get("invite_emitted", False)),
                }
            )
            _write_json(BACKEND_STATE_PATH, merged_backend)

            status_payload = {
                "bridge_running": bool(enabled),
                "symbiont_running": bool(sym_proc is not None and sym_proc.poll() is None),
                "bridge_pid": int(os.getpid()),
                "symbiont_pid": int(sym_proc.pid) if sym_proc is not None and sym_proc.poll() is None else -1,
                "symbiont_host": sym_host,
                "symbiont_port": sym_port,
                "aethernet_running": bool(enabled and aether_enabled),
                "aethernet_receiver_port": int(aether_port),
                "swarm_node_count": int(swarm_status.get("node_count", 0) or 0),
                "swarm_reachable_node_count": int(swarm_status.get("reachable_node_count", 0) or 0),
                "swarm_pack_count": int(swarm_status.get("pack_count", 0) or 0),
                "swarm_consensus_count": int(swarm_status.get("consensus_count", 0) or 0),
                "swarm_candidate_count": int(swarm_status.get("candidate_count", 0) or 0),
                "swarm_summary": str(swarm_status.get("summary", "") or ""),
                "swarm_alert_level": str(swarm_status.get("alert_level", "ok") or "ok"),
                "swarm_alert_count": int(len(list(swarm_status.get("alerts", []) or []))),
                "swarm_health_score": float(swarm_status.get("health_score", 0.0) or 0.0),
                "swarm_peer_probe_total": int(peer_probe.get("total", 0) or 0),
                "swarm_peer_probe_reachable": int(peer_probe.get("reachable", 0) or 0),
                "swarm_peer_probe_stalled": int(peer_probe.get("stalled", 0) or 0),
                "swarm_invite_received": int(invite_status.get("invite_received", 0) or 0),
                "swarm_invite_accepted": int(invite_status.get("invite_accepted", 0) or 0),
                "swarm_invite_rejected": int(invite_status.get("invite_rejected", 0) or 0),
                "swarm_invite_emitted": bool(invite_status.get("invite_emitted", False)),
                "swarm_invite_generated_path": str(invite_status.get("invite_generated_path", "") or ""),
                "swarm_invite_last_error": str(invite_status.get("invite_last_error", "") or ""),
                "last_error": str(last_error or ""),
                "last_tick": _utc_now(),
            }
            _write_json(HYBRID_STATUS_PATH, status_payload)
            time.sleep(poll_seconds)
        except KeyboardInterrupt as e:
            break
        except Exception as exc:
            last_error = str(exc)
            _write_json(
                HYBRID_STATUS_PATH,
                {
                    "bridge_running": False,
                    "symbiont_running": bool(sym_proc is not None and sym_proc.poll() is None),
                    "bridge_pid": int(os.getpid()),
                    "symbiont_pid": int(sym_proc.pid) if sym_proc is not None and sym_proc.poll() is None else -1,
                    "symbiont_host": str((sym_cfg or {}).get("host", "127.0.0.1") if isinstance(sym_cfg, dict) else "127.0.0.1"),
                    "symbiont_port": int((sym_cfg or {}).get("port", 38571) if isinstance(sym_cfg, dict) else 38571),
                    "aethernet_running": bool(aether_transport is not None),
                    "aethernet_receiver_port": int((aether_cfg or {}).get("lan_port", 7385) if isinstance(aether_cfg, dict) else 7385),
                    "last_error": str(last_error),
                    "last_tick": _utc_now(),
                },
            )
            time.sleep(1.0)

    if sym_proc is not None and sym_proc.poll() is None:
        sym_proc.terminate()
        try:
            sym_proc.wait(timeout=2.0)
        except Exception as e:
            sym_proc.kill()

    _write_json(
        HYBRID_STATUS_PATH,
        {
            "bridge_running": False,
            "symbiont_running": False,
            "bridge_pid": int(os.getpid()),
            "symbiont_pid": -1,
            "symbiont_host": "127.0.0.1",
            "symbiont_port": 38571,
            "aethernet_running": False,
            "aethernet_receiver_port": 7385,
            "last_error": "terminated",
            "last_tick": _utc_now(),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
