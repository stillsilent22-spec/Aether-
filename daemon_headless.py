"""daemon_headless.py — Aether Minimal Swarm Daemon.

Runs on old hardware where the full Rust + Python stack cannot start:
  - Windows Vista/7 era machines (32-bit, no wgpu GPU driver)
  - Raspberry Pi 1/2/Zero (ARM32, no Yggdrasil binary, 256 MB RAM)
  - Any system with Python 3.6+ but without numpy/scipy/opencv

What this daemon does:
  - Participates in the Aether swarm via gossip (swarm_p2p.py)
  - Broadcasts on the LAN via mDNS-style beacon (lan_beacon.py)
  - Writes a minimal data/interbus/backend_state.json every 10 s
  - Runs the capability_score probe once at startup
  - Respects swarm_consent.json — will NOT join if not consented

What it does NOT do:
  - No GUI (no iced, no tkinter, no webview)
  - No numpy / scipy / opencv / moviepy — imports never attempted
  - No Rust subprocess launch

Usage:
  python daemon_headless.py [--no-swarm] [--interval 10]

Requirements (stdlib only for core path):
  Python 3.6+  (asyncio, json, pathlib, socket, time)
  Optional: psutil (for RAM/CPU metrics in backend_state.json)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aether.daemon")

# ── Optional psutil ───────────────────────────────────────────────────────────

try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None  # type: ignore
    _HAS_PSUTIL = False

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent
INTERBUS_DIR = ROOT / "data" / "interbus"
BACKEND_STATE_PATH = INTERBUS_DIR / "backend_state.json"
CONSENT_PATH = ROOT / "data" / "swarm_consent.json"
GENESIS_KEY_PATH = ROOT / "data" / "keys" / "genesis_node.key"
HW_CAPABILITY_PATH = INTERBUS_DIR / "hw_capability.json"


def _linux_meminfo_mb() -> Tuple[int, int]:
    total_mb = 0
    available_mb = 0
    try:
        info = Path("/proc/meminfo").read_text(encoding="utf-8")
        for line in info.splitlines():
            if line.startswith("MemTotal:"):
                total_mb = int(line.split()[1]) // 1024
            elif line.startswith("MemAvailable:"):
                available_mb = int(line.split()[1]) // 1024
    except Exception:
        pass
    return total_mb, available_mb


def _memory_snapshot_mb() -> Tuple[int, int]:
    if _HAS_PSUTIL:
        try:
            mem = _psutil.virtual_memory()  # type: ignore[attr-defined]
            return int(mem.total // (1024 * 1024)), int(mem.available // (1024 * 1024))
        except Exception:
            pass
    return _linux_meminfo_mb()


def _is_raspberry_pi() -> bool:
    try:
        model = Path("/proc/device-tree/model").read_text(encoding="utf-8", errors="ignore")
        if "raspberry" in model.lower():
            return True
    except Exception:
        pass
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        lower = cpuinfo.lower()
        return "raspberry pi" in lower or "hardware\t: bcm" in lower or "hardware : bcm" in lower
    except Exception:
        return False


def _detect_os_platform() -> str:
    system = platform.system().lower()
    if system.startswith("win"):
        release = platform.release().strip().lower()
        version = platform.version().strip().lower()
        if release in {"95", "98", "me"} or version.startswith("4."):
            return "Win9x"
        if release in {"2000"}:
            return "Win2000"
        if release in {"xp", "2003server", "2003"}:
            return "WinXP"
        if release in {"vista", "7"}:
            return "WinVista7"
        return "WinModern"
    if system.startswith("linux"):
        if _is_raspberry_pi():
            return "RaspberryPi"
        try:
            kernel_major = int(platform.release().split(".", 1)[0])
            return "LinuxLegacy" if kernel_major < 4 else "LinuxModern"
        except Exception:
            return "LinuxModern"
    return "Unknown"


def _headless_network_tier(cores: int, ram_mb: int, os_platform: str, yggdrasil_ok: bool) -> Tuple[str, int, bool, bool, bool, bool]:
    # tier_label, rank, lan_beacon, lan_p2p, yggdrasil, dht
    if os_platform == "Win9x":
        return "LocalOnly", 0, False, False, False, False
    if os_platform == "Win2000":
        return "LanBeacon", 1, True, False, False, False
    if os_platform == "WinXP":
        if ram_mb < 512:
            return "LanBeacon", 1, True, False, False, False
        return "LanP2P", 2, True, True, False, False
    if os_platform == "WinVista7":
        return "LanP2P", 2, True, True, False, False
    if os_platform == "LinuxLegacy":
        if ram_mb < 256:
            return "LocalOnly", 0, False, False, False, False
        if ram_mb < 512:
            return "LanBeacon", 1, True, False, False, False
        return "LanP2P", 2, True, True, False, False
    if os_platform == "RaspberryPi":
        if cores <= 1 or ram_mb < 512:
            return "LanBeacon", 1, True, False, False, False
        if ram_mb < 2048:
            return "LanP2P", 2, True, True, False, False
        if yggdrasil_ok:
            return "YggdrasilP2P", 3, True, True, True, False
        return "LanP2P", 2, True, True, False, False

    # Moderne / unbekannte Systeme: headless darf trotzdem profitieren,
    # aber Yggdrasil nur wenn das Binary real vorhanden ist.
    if ram_mb < 1024:
        return "LanBeacon", 1, True, False, False, False
    if ram_mb < 4096 or cores <= 2:
        return "LanP2P", 2, True, True, False, False
    if yggdrasil_ok:
        if ram_mb >= 8192 and cores >= 4:
            return "FullDht", 4, True, True, True, True
        return "YggdrasilP2P", 3, True, True, True, False
    return "LanP2P", 2, True, True, False, False


def _write_headless_hw_capability(capability: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cores = int(os.cpu_count() or 1)
    ram_total_mb, ram_available_mb = _memory_snapshot_mb()
    os_platform = _detect_os_platform()
    capability = capability if isinstance(capability, dict) else {}
    yggdrasil_ok = False
    try:
        from modules.yggdrasil_install import is_yggdrasil_available

        yggdrasil_ok = bool(is_yggdrasil_available())
    except Exception:
        yggdrasil_ok = False

    tier_label, rank, lan_beacon, lan_p2p, yggdrasil, dht = _headless_network_tier(
        cores,
        ram_total_mb,
        os_platform,
        yggdrasil_ok,
    )
    note_map = {
        "LocalOnly": "Vault-first lokal — lernt offline, noch kein Netzbetrieb.",
        "LanBeacon": "Vault-first + LAN-Beacon — lokal lernen, im LAN sichtbar.",
        "LanP2P": "LAN-P2P aktiv — Gossip + Leader-Election ohne Yggdrasil.",
        "YggdrasilP2P": "Yggdrasil bereit — headless Overlay-P2P moeglich.",
        "FullDht": "Voller DHT — headless Relay + Peer-Tabelle aktiv.",
    }
    payload = {
        "os_platform": os_platform,
        "network_tier": tier_label,
        "native_network_tier": tier_label,
        "tier_rank": rank,
        "native_tier_rank": rank,
        "cpu_cores": cores,
        "ram_mb": ram_total_mb,
        "ram_available_mb": ram_available_mb,
        "is_raspberry_pi": os_platform == "RaspberryPi",
        "vault_bootstrap_only": tier_label in {"LocalOnly", "LanBeacon"},
        "lan_beacon": lan_beacon,
        "lan_p2p": lan_p2p,
        "yggdrasil": yggdrasil,
        "dht": dht,
        "note": note_map.get(tier_label, "Headless-Tier aktiv."),
        "runtime": "headless-python",
        "shell_capable": bool(capability.get("shell_ready", False)),
        "progressive_network_unlock": not bool(capability.get("shell_ready", False)),
        "capability_percent": float(capability.get("percent", 0.0) or 0.0),
        "capability_stage": str(capability.get("stage", "Basis-Daemon") or "Basis-Daemon"),
        "capability_stage_index": int(capability.get("stage_index", 0) or 0),
        "shell_ready": bool(capability.get("shell_ready", False)),
        "overlay_ready": bool(capability.get("overlay_ready", False)),
        "full_member_ready": bool(capability.get("full_member_ready", False)),
        "swarm_learning_active": bool(capability.get("swarm_learning_active", False)),
        "startup_mode": str(capability.get("startup_mode", "headless") or "headless"),
        "startup_reason": str(capability.get("startup_reason", "legacy_headless") or "legacy_headless"),
        "requirements_profile": str(capability.get("requirements_profile", "legacy") or "legacy"),
        "recommended_entrypoint": str(capability.get("recommended_entrypoint", "daemon_headless.py") or "daemon_headless.py"),
        "progression_track": str(capability.get("progression_track", "legacy-headless") or "legacy-headless"),
        "base_progression_mode": str(capability.get("base_progression_mode", capability.get("progression_mode", "vault-first")) or "vault-first"),
        "progression_mode": str(capability.get("progression_mode", "vault-first") or "vault-first"),
        "next_goal": str(capability.get("next_goal", "") or ""),
        "fair_inclusion_path": bool(capability.get("fair_inclusion_path", True)),
        "network_end_goal": str(capability.get("network_end_goal", "RelayBridgeToAethernet") or "RelayBridgeToAethernet"),
        "overlay_path": str(capability.get("overlay_path", "relay-bridge") or "relay-bridge"),
        "relay_bridge_required": bool(capability.get("relay_bridge_required", True)),
        "symbiont_role": str(capability.get("symbiont_role", "relay-compatible-symbiont") or "relay-compatible-symbiont"),
        "emergent_network_role": str(capability.get("emergent_network_role", "relay-bridge-candidate") or "relay-bridge-candidate"),
        "aethernet_goal_message": str(capability.get("aethernet_goal_message", "LAN ist nur Zwischenstufe; Ziel ist echte Aufnahme ins P2P-Aethernet.") or "LAN ist nur Zwischenstufe; Ziel ist echte Aufnahme ins P2P-Aethernet."),
    }
    try:
        INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
        HW_CAPABILITY_PATH.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning("hw_capability write failed: %s", exc)
    return payload


# ── Genesis-Node Prüfung ──────────────────────────────────────────────────────

def _check_genesis_key_local() -> bool:
    """True nur wenn data/keys/genesis_node.key lokal vorhanden ist UND
    die daraus abgeleitete Yggdrasil-Adresse zur Genesis-Adresse passt.

    Diese Datei besitzt ausschliesslich der Ersteller (HANNEMANN).
    Alle anderen Knoten geben False zurück — unabhängig von der Rolle.
    """
    try:
        if not GENESIS_KEY_PATH.is_file():
            return False
        raw = GENESIS_KEY_PATH.read_bytes()
        if len(raw) != 32:
            return False
        from modules.swarm_p2p import _get_genesis_ygg_addr
        # _get_genesis_ygg_addr() leitet die Adresse aus dem Key ab —
        # kein hardkodierter Wert im Code, kein Tracking durch Dritte.
        return bool(_get_genesis_ygg_addr())
    except Exception:
        return False


# ── Consent check ─────────────────────────────────────────────────────────────

def _is_consented() -> bool:
    try:
        if not CONSENT_PATH.exists():
            return False
        data = json.loads(CONSENT_PATH.read_text(encoding="utf-8"))
        if "consented" in data:
            return bool(data.get("consented"))
        if "consent_ok" in data:
            return bool(data.get("consent_ok"))
        if "approved" in data:
            return bool(data.get("approved"))
        return False
    except Exception:
        return False


# ── Capability score (lightweight, runs once) ─────────────────────────────────

def _run_capability_probe() -> dict:
    try:
        from modules.capability_score import probe_and_write
        result = probe_and_write()
        log.info(
            "Capability: %d%% — %s",
            result.get("percent_int", 0),
            result.get("stage", "?"),
        )
        return result
    except Exception as exc:
        log.warning("Capability probe failed: %s", exc)
        return {}


# ── System metrics (psutil or fallback) ──────────────────────────────────────

def _system_metrics() -> Dict[str, float]:
    cpu_pct: float = 0.0
    mem_used_gb: float = 0.0

    if _HAS_PSUTIL:
        try:
            cpu_pct = float(_psutil.cpu_percent(interval=None))  # type: ignore
        except Exception:
            pass
        try:
            mem = _psutil.virtual_memory()  # type: ignore
            mem_used_gb = (mem.total - mem.available) / (1024 ** 3)
        except Exception:
            pass
    else:
        # Linux fallback via /proc
        try:
            lines = Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
            vals: Dict[str, int] = {}
            for ln in lines:
                if ":" in ln:
                    k, v_str = ln.split(":", 1)
                    try:
                        vals[k.strip()] = int(v_str.strip().split()[0])
                    except (ValueError, IndexError):
                        pass
            total_kb = vals.get("MemTotal", 0)
            avail_kb = vals.get("MemAvailable", 0)
            used_kb = total_kb - avail_kb
            mem_used_gb = used_kb / (1024 * 1024)
        except Exception:
            pass

    return {"cpu_pct": cpu_pct, "mem_used_gb": round(mem_used_gb, 3)}


# ── backend_state.json writer ─────────────────────────────────────────────────

def _write_backend_state(
    swarm_node_count: int = 0,
    swarm_reachable: int = 0,
    capability_score: float = 0.0,
    capability_stage: str = "",
    vault_main: int = 0,
    anchor_count: int = 0,
    capability: Optional[Dict[str, Any]] = None,
    hw_capability: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
        metrics = _system_metrics()
        capability = capability if isinstance(capability, dict) else {}
        hw_capability = hw_capability if isinstance(hw_capability, dict) else {}
        startup_mode = str(capability.get("startup_mode", hw_capability.get("startup_mode", "headless")) or "headless")
        startup_reason = str(capability.get("startup_reason", hw_capability.get("startup_reason", "legacy_headless")) or "legacy_headless")
        requirements_profile = str(capability.get("requirements_profile", hw_capability.get("requirements_profile", "legacy")) or "legacy")
        progression_track = str(capability.get("progression_track", hw_capability.get("progression_track", "legacy-headless")) or "legacy-headless")
        base_progression_mode = str(capability.get("base_progression_mode", hw_capability.get("base_progression_mode", "vault-first")) or "vault-first")
        progression_mode = str(capability.get("progression_mode", hw_capability.get("progression_mode", "vault-first")) or "vault-first")
        next_goal = str(capability.get("next_goal", hw_capability.get("next_goal", "")) or "")
        network_tier = str(hw_capability.get("network_tier", "LanBeacon") or "LanBeacon")
        network_end_goal = str(capability.get("network_end_goal", hw_capability.get("network_end_goal", "RelayBridgeToAethernet")) or "RelayBridgeToAethernet")
        overlay_path = str(capability.get("overlay_path", hw_capability.get("overlay_path", "relay-bridge")) or "relay-bridge")
        symbiont_role = str(capability.get("symbiont_role", hw_capability.get("symbiont_role", "relay-compatible-symbiont")) or "relay-compatible-symbiont")
        emergent_network_role = str(capability.get("emergent_network_role", hw_capability.get("emergent_network_role", "relay-bridge-candidate")) or "relay-bridge-candidate")
        aethernet_goal_message = str(capability.get("aethernet_goal_message", hw_capability.get("aethernet_goal_message", "LAN ist nur Zwischenstufe; Ziel ist echte Aufnahme ins P2P-Aethernet.")) or "LAN ist nur Zwischenstufe; Ziel ist echte Aufnahme ins P2P-Aethernet.")
        payload = {
            "vault_main":                      vault_main,
            "vault_sub":                       0,
            "entropy_mean":                    0.0,
            "anchor_count":                    anchor_count,
            "cpu_pct":                         metrics["cpu_pct"],
            "mem_used_gb":                     metrics["mem_used_gb"],
            "swarm_node_count":                swarm_node_count,
            "swarm_reachable_node_count":      swarm_reachable,
            "swarm_pack_count":                0,
            "swarm_candidate_count":           0,
            "swarm_consensus_count":           0,
            "swarm_genesis_key_ok":            _check_genesis_key_local(),
            "swarm_quorum_reachable":          swarm_reachable > 0,
            "swarm_estimated_saving_percent":  0.0,
            "swarm_summary":                   f"Headless daemon | {network_tier} | {progression_mode} | {swarm_node_count} nodes",
            "capability_score":                capability_score,
            "capability_stage":                capability_stage,
            "daemon_mode":                     "headless",
            "startup_mode":                    startup_mode,
            "startup_reason":                  startup_reason,
            "requirements_profile":            requirements_profile,
            "progression_track":               progression_track,
            "base_progression_mode":           base_progression_mode,
            "progression_mode":                progression_mode,
            "next_goal":                       next_goal,
            "network_tier":                    network_tier,
            "fair_inclusion_path":             bool(capability.get("fair_inclusion_path", hw_capability.get("fair_inclusion_path", True))),
            "network_end_goal":                network_end_goal,
            "overlay_path":                    overlay_path,
            "relay_bridge_required":           bool(capability.get("relay_bridge_required", hw_capability.get("relay_bridge_required", True))),
            "symbiont_role":                   symbiont_role,
            "emergent_network_role":           emergent_network_role,
            "aethernet_goal_message":          aethernet_goal_message,
            "updated_at":                      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        BACKEND_STATE_PATH.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning("backend_state write failed: %s", exc)


# ── Swarm integration ─────────────────────────────────────────────────────────

def _ensure_bootstrap() -> str:
    """Stellt sicher dass node_private.key + node.json existieren.

    Ruft solo_bootstrap.run_bootstrap() auf wenn nötig — idempotent.
    Gibt die stabile node_id zurück (aus Ed25519-Public-Key abgeleitet,
    Hardware-eindeutig via device_lock nach dem ersten Start).
    Fällt auf temporäre ID zurück nur wenn bootstrap komplett fehlschlägt.
    """
    node_json_path = ROOT / "data" / "swarm" / "node.json"
    private_key_path = ROOT / "data" / "keys" / "node_private.key"

    # Bereits vorhanden — nur auslesen
    if node_json_path.is_file() and private_key_path.is_file():
        try:
            node_id = str(json.loads(node_json_path.read_text(encoding="utf-8")).get("node_id", "") or "").strip()
            if node_id:
                return node_id
        except Exception:
            pass

    # Bootstrap nötig
    try:
        import solo_bootstrap
        result = solo_bootstrap.run_bootstrap()
        node_id = str(result.get("node_id", "") or "").strip()
        if node_id:
            log.info("[bootstrap] Node initialisiert: %s", node_id)
            return node_id
    except Exception as exc:
        log.warning("[bootstrap] solo_bootstrap fehlgeschlagen: %s — nutze temporäre ID", exc)

    # Letzter Fallback: stabile UUID aus Hostname + Pfad (besser als timestamp)
    import hashlib
    import socket
    seed = f"{socket.gethostname()}|{str(ROOT)}"
    return "tmp-" + hashlib.sha256(seed.encode()).hexdigest()[:12]


async def _run_swarm() -> None:
    """Start the P2P swarm layer if consented."""
    p2p = None
    try:
        from modules.swarm_p2p import make_p2p_layer

        node_id = _ensure_bootstrap()

        p2p = make_p2p_layer(node_id=node_id)
        p2p.start()
        log.info("Swarm P2P layer started.")
        # Keep alive — P2PLayer runs its own internal tasks
        while True:
            await asyncio.sleep(60)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.warning("Swarm P2P not started: %s", exc)
    finally:
        if p2p is not None:
            try:
                p2p.stop()
            except Exception:
                pass


async def _run_lan_beacon() -> None:
    """Start the LAN beacon for local peer discovery."""
    try:
        from modules.lan_beacon import start as beacon_start
        beacon_start()
        log.info("LAN beacon started.")
    except Exception as exc:
        log.warning("LAN beacon not started: %s", exc)


# ── Main loop ─────────────────────────────────────────────────────────────────

async def _main_loop(interval: int, no_swarm: bool) -> None:
    log.info("Aether headless daemon starting — Python %d.%d",
             sys.version_info.major, sys.version_info.minor)

    # Initial capability probe
    cap = _run_capability_probe()
    cap_score = float(cap.get("percent", 0.0))
    cap_stage = str(cap.get("stage", "Basis-Daemon"))
    hw_capability = _write_headless_hw_capability(cap)

    log.info(
        "Headless-Tier: %s (%s) | LAN=%s | Yggdrasil=%s | Shell=%s | Mode=%s",
        hw_capability.get("network_tier", "?"),
        hw_capability.get("os_platform", "?"),
        hw_capability.get("lan_p2p", False),
        hw_capability.get("yggdrasil", False),
        hw_capability.get("shell_ready", False),
        hw_capability.get("progression_mode", "vault-first"),
    )

    # Write initial state immediately
    _write_backend_state(
        capability_score=cap_score,
        capability_stage=cap_stage,
        capability=cap,
        hw_capability=hw_capability,
    )

    # Start subsystems
    tasks: List[asyncio.Task] = []

    await _run_lan_beacon()  # fire-and-forget sync call

    if not no_swarm:
        if _is_consented():
            tasks.append(asyncio.create_task(_run_swarm()))
            log.info("Swarm task created.")
        else:
            log.info("Swarm consent not given — running in local-only mode.")

    # Periodic state writer
    tick = 0
    try:
        while True:
            await asyncio.sleep(interval)
            tick += 1

            # Re-probe capability every 5 min
            if tick % (300 // interval) == 0:
                cap = _run_capability_probe()
                cap_score = float(cap.get("percent", cap_score))
                cap_stage = str(cap.get("stage", cap_stage))
                hw_capability = _write_headless_hw_capability(cap)

            _write_backend_state(
                capability_score=cap_score,
                capability_stage=cap_stage,
                capability=cap,
                hw_capability=hw_capability,
            )

            log.debug("Tick %d — capability %.0f%%", tick, cap_score * 100)
    except asyncio.CancelledError:
        pass
    finally:
        for task in tasks:
            task.cancel()
        log.info("Aether headless daemon stopped.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aether Minimal Headless Daemon — swarm + LAN beacon, no GUI."
    )
    parser.add_argument(
        "--no-swarm", action="store_true",
        help="Do not start the swarm P2P layer (local-only mode).",
    )
    parser.add_argument(
        "--interval", type=int, default=10,
        metavar="SECONDS",
        help="Interval in seconds for backend_state.json refresh (default: 10).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Graceful shutdown on SIGINT/SIGTERM
    def _handle_stop() -> None:
        for task in asyncio.all_tasks(loop):
            task.cancel()

    try:
        loop.add_signal_handler(signal.SIGINT, _handle_stop)
        loop.add_signal_handler(signal.SIGTERM, _handle_stop)
    except (NotImplementedError, AttributeError):
        # Windows — signal handlers in asyncio are limited
        pass

    try:
        loop.run_until_complete(_main_loop(args.interval, args.no_swarm))
    except KeyboardInterrupt:
        log.info("Keyboard interrupt — shutting down.")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
