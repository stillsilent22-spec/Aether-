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
import signal
import sys
import time
from pathlib import Path

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


# ── Consent check ─────────────────────────────────────────────────────────────

def _is_consented() -> bool:
    try:
        if not CONSENT_PATH.exists():
            return False
        data = json.loads(CONSENT_PATH.read_text(encoding="utf-8"))
        return bool(data.get("consented", False))
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

def _system_metrics() -> dict:
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
            vals: dict[str, int] = {}
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
) -> None:
    try:
        INTERBUS_DIR.mkdir(parents=True, exist_ok=True)
        metrics = _system_metrics()
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
            "swarm_genesis_key_ok":            False,
            "swarm_quorum_reachable":          swarm_reachable > 0,
            "swarm_estimated_saving_percent":  0.0,
            "swarm_summary":                   f"Headless daemon | {swarm_node_count} nodes",
            "capability_score":                capability_score,
            "capability_stage":                capability_stage,
            "daemon_mode":                     "headless",
            "updated_at":                      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        BACKEND_STATE_PATH.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning("backend_state write failed: %s", exc)


# ── Swarm integration ─────────────────────────────────────────────────────────

async def _run_swarm() -> None:
    """Start the P2P swarm layer if consented."""
    try:
        from modules.swarm_p2p import P2PLayer
        p2p = P2PLayer()
        await p2p.start()
        log.info("Swarm P2P layer started.")
        # Keep alive — P2PLayer runs its own internal tasks
        while True:
            await asyncio.sleep(60)
    except Exception as exc:
        log.warning("Swarm P2P not started: %s", exc)


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

    # Write initial state immediately
    _write_backend_state(
        capability_score=cap_score,
        capability_stage=cap_stage,
    )

    # Start subsystems
    tasks: list[asyncio.Task] = []

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

            _write_backend_state(
                capability_score=cap_score,
                capability_stage=cap_stage,
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
