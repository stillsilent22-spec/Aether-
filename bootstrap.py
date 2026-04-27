"""
bootstrap.py -- Aether node bootstrap orchestrator.

Boot sequence:
  1. Read data/interbus/bootstrap_status.json  (written by aether_node_bootstrap.c)
  2. Run solo_bootstrap.run_bootstrap() to ensure node identity is present.
  3. Dispatch based on mode:
       full            -> exec aether_iced (Rust shell, only full-mode entry)
       learn           -> Python-only daemon, no Rust shell
       linux_fallback  -> Python-only daemon, no Rust shell

Genesis invariant: GENESIS_NODE_ID = "7a280b7e3ab3e042" must never be issued here.
Rust shell (aether_iced) is the ONLY authorised full-mode entry point.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

BOOTSTRAP_STATUS_PATH = ROOT / "data" / "interbus" / "bootstrap_status.json"
GENESIS_NODE_ID = "7a280b7e3ab3e042"

# Rust-shell executable names (searched on PATH and in bin/)
_ICED_NAMES = ["aether_iced", "aether_iced.exe"]


def _read_bootstrap_status() -> dict:
    """Return the status dict written by aether_node_bootstrap.c, or defaults."""
    try:
        return json.loads(BOOTSTRAP_STATUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"mode": "learn", "capability": 0}


def _find_iced_binary() -> str | None:
    """Return path to aether_iced executable, or None if not found."""
    # 1. Adjacent bin/ directory
    for name in _ICED_NAMES:
        candidate = ROOT / "bin" / name
        if candidate.is_file():
            return str(candidate)
    # 2. PATH
    for name in _ICED_NAMES:
        found = _which(name)
        if found:
            return found
    return None


def _which(name: str) -> str | None:
    """Minimal shutil.which replacement (avoids import at module level)."""
    import shutil
    return shutil.which(name)


def _ensure_node_identity() -> dict:
    """Run solo_bootstrap.run_bootstrap() idempotently."""
    from solo_bootstrap import run_bootstrap
    return run_bootstrap(dry_run=False)


def _guard_genesis(node_info: dict) -> None:
    """Abort if bootstrap accidentally issued the genesis node id."""
    nid = str(node_info.get("node_id", ""))
    if nid == GENESIS_NODE_ID:
        sys.exit(
            "bootstrap: FATAL — genesis node id issued outside solo_bootstrap. "
            "Halting to preserve genesis invariant."
        )


def _maybe_install_service(status: dict) -> None:
    """Install the system service if the user confirmed in the C bootstrap dialog.

    Reads install_service + service_asked from bootstrap_status.json (written by
    aether_node_bootstrap.c).  Only acts when both flags are set and the service
    is not yet active.  Never prompts the user again — that already happened in C.
    """
    if not int(status.get("service_asked", 0)):
        return
    if not int(status.get("install_service", 0)):
        print("bootstrap: service install deferred by user (dialog choice)", flush=True)
        return
    try:
        from modules.service_installer import install, status as svc_status
        current = svc_status()
        if current.get("active") or current.get("enabled"):
            print("bootstrap: system service already active — skipping install", flush=True)
            return
        print("bootstrap: installing system service (confirmed in setup dialog)…", flush=True)
        ok = install(dry_run=False)
        if ok:
            print("bootstrap: system service installed successfully", flush=True)
        else:
            print("bootstrap: service install returned False — check permissions", flush=True)
    except Exception as exc:
        print(f"bootstrap: service_installer unavailable ({exc})", flush=True)


def _launch_full_mode(iced_bin: str) -> None:
    """Hand control to the Rust shell (replaces current process on POSIX)."""
    print(f"bootstrap: full mode — launching {iced_bin}", flush=True)
    args = [iced_bin, "--bootstrap-mode", "full"]
    if hasattr(os, "execv"):
        os.execv(iced_bin, args)
    else:
        # Windows fallback: subprocess (no execv)
        result = subprocess.run(args)
        sys.exit(result.returncode)


def _launch_learn_mode() -> None:
    """Start Python-only daemon in learn mode."""
    print("bootstrap: learn mode — starting Python daemon", flush=True)
    try:
        from modules.agent_loop import run_agent_loop
        run_agent_loop(mode="learn")
    except Exception as exc:
        print(f"bootstrap: agent_loop unavailable ({exc}), exiting cleanly", flush=True)
        sys.exit(0)


def _launch_linux_fallback_mode() -> None:
    """Start Python-only daemon in linux_fallback mode."""
    print("bootstrap: linux_fallback mode — starting Python daemon", flush=True)
    try:
        from modules.agent_loop import run_agent_loop
        run_agent_loop(mode="linux_fallback")
    except Exception as exc:
        print(f"bootstrap: agent_loop unavailable ({exc}), exiting cleanly", flush=True)
        sys.exit(0)


def main() -> None:
    status = _read_bootstrap_status()
    mode: str = status.get("mode", "learn")
    capability: int = int(status.get("capability", 0))

    print(f"bootstrap: status mode={mode} capability={capability}", flush=True)

    node_info = _ensure_node_identity()
    _guard_genesis(node_info)
    _maybe_install_service(status)

    if mode == "full" and capability == 1:
        iced_bin = _find_iced_binary()
        if iced_bin:
            _launch_full_mode(iced_bin)
        else:
            print(
                "bootstrap: aether_iced not found; falling back to learn mode",
                flush=True,
            )
            _launch_learn_mode()
    elif mode == "linux_fallback":
        _launch_linux_fallback_mode()
    else:
        _launch_learn_mode()


if __name__ == "__main__":
    main()
