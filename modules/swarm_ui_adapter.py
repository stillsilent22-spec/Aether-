from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""UI Adapter for Aether Swarm Mode.

Provides lightweight UI clients that send IPC commands to SwarmController:
  - CLI adapter (primary): command-line interface
  - Status display: ON/OFF, sampling rate, CPU/GPU load, consent state
  - File-based adapter: writes swarm_cmd.json (no socket required)

Usage (CLI):
    python -m modules.swarm_ui_adapter enable_swarm
    python -m modules.swarm_ui_adapter disable_swarm
    python -m modules.swarm_ui_adapter status
    python -m modules.swarm_ui_adapter health
    python -m modules.swarm_ui_adapter consent
    python -m modules.swarm_ui_adapter revoke
"""


import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.registry import get_module
from modules.swarm_controller import IPC_HOST, IPC_PORT, send_command, send_command_via_file


# --------------------------------------------------------------------------- #
#  Status formatting                                                          #
# --------------------------------------------------------------------------- #

def format_status(status: Dict[str, Any]) -> str:
    """Format status dict into a human-readable string."""
    lines: list[str] = []
    mode = status.get("mode", "unknown")
    swarm = status.get("swarm_mode", False)
    indicator = "ON" if swarm else "OFF"
    lines.append("+-- AETHER SWARM STATUS ----------------------------------------+")
    lines.append(f"|  Mode:          {mode.upper():<46s}|")
    lines.append(f"|  Swarm Active:  {indicator:<46s}|")
    if "health_score" in status:
        score = float(status["health_score"])
        bar_len = int(score * 20)
        bar = "#" * bar_len + "." * (20 - bar_len)
        score_str = f"[{bar}] {score:.2f}"
        lines.append(f"|  Health:        {score_str:<46s}|")
    if "alert_level" in status:
        al = str(status["alert_level"]).upper()
        lines.append(f"|  Alert Level:   {al:<46s}|")
    if "node_count" in status:
        lines.append(f"|  Nodes:         {str(status['node_count']):<46s}|")
    if "reachable_node_count" in status:
        lines.append(f"|  Reachable:     {str(status['reachable_node_count']):<46s}|")

    # Agent health from interbus file
    agent_path = ROOT / "data" / "interbus" / "swarm_agent_health.json"
    if agent_path.is_file():
        try:
            ah = json.loads(agent_path.read_text(encoding="utf-8"))
            fps_str = f"{ah.get('max_fps', '?')} fps max"
            cpu_str = f"{ah.get('cpu_percent', '?')}% CPU"
            frames_str = str(ah.get("frame_count", "?"))
            adapter_str = str(ah.get("adapter_type", "?"))
            lines.append(f"|  Adapter:       {adapter_str:<46s}|")
            lines.append(f"|  Sampling:      {fps_str:<46s}|")
            lines.append(f"|  CPU Load:      {cpu_str:<46s}|")
            lines.append(f"|  Frames:        {frames_str:<46s}|")
        except Exception as e:
            logger.warning(f"[swarm_ui_adapter] Fehler: {e}")
            pass

    # Consent state
    try:
        from modules.swarm_consent import get_consent_state
        cs = get_consent_state()
        consent_str = "GRANTED" if cs.get("consented") else "NOT GIVEN"
        if cs.get("revoked"):
            consent_str = "REVOKED"
        lines.append(f"|  Consent:       {consent_str:<46s}|")
    except Exception as e:
        logger.warning(f"[swarm_ui_adapter] Fehler: {e}")
        pass

    lines.append(f"|  IPC:           {IPC_HOST}:{IPC_PORT:<41s}|")
    ts = status.get("updated_at", "")
    if ts:
        lines.append(f"|  Updated:       {str(ts)[:46]:<46s}|")
    lines.append("+---------------------------------------------------------------+")
    return "\n".join(lines)


def format_alerts(status: Dict[str, Any]) -> str:
    """Format alert list."""
    alerts = status.get("alerts", [])
    if not alerts:
        return "No active alerts."
    lines = []
    for a in alerts:
        sev = str(a.get("severity", "?")).upper()
        code = str(a.get("code", "?"))
        msg = str(a.get("message", ""))
        lines.append(f"  [{sev}] {code}: {msg}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  CLI commands                                                               #
# --------------------------------------------------------------------------- #

def _send(cmd: str, verbose: bool = True) -> Dict[str, Any]:
    """Send command via IPC socket, fall back to file-based IPC."""
    result = send_command(cmd)
    if not result.get("ok") and result.get("fallback") == "file":
        result = send_command_via_file(cmd)
    if verbose:
        _print_result(cmd, result)
    return result


def _print_result(cmd: str, result: Dict[str, Any]) -> None:
    if cmd in ("status", "health"):
        print(format_status(result))
        alerts = format_alerts(result)
        if alerts != "No active alerts.":
            print("\nAlerts:")
            print(alerts)
    else:
        ok = result.get("ok", False)
        event = result.get("event", "")
        err = result.get("error", "")
        if ok:
            print(f"✓ {cmd}: {event or 'OK'}")
        else:
            print(f"✗ {cmd} failed: {err}")


def cli_enable(interactive: bool = True) -> Dict[str, Any]:
    """Enable swarm via CLI (runs consent flow if needed)."""
    from modules.swarm_consent import gated_enable_swarm
    from modules.swarm_controller import get_controller

    controller_module = get_module("swarm_controller")
    if controller_module is not None:
        try:
            controller = controller_module.get_controller()
        except Exception:
            controller = get_controller()
    else:
        controller = get_controller()

    result = gated_enable_swarm(controller, actor="cli", interactive=interactive)
    if not result.get("ok") and result.get("error") == "consent_required":
        print("✗ Consent required. Run: python -m modules.swarm_ui_adapter consent")
    return result


def cli_disable() -> Dict[str, Any]:
    from modules.swarm_consent import gated_disable_swarm
    from modules.swarm_controller import get_controller

    controller_module = get_module("swarm_controller")
    if controller_module is not None:
        try:
            controller = controller_module.get_controller()
        except Exception:
            controller = get_controller()
    else:
        controller = get_controller()

    return gated_disable_swarm(controller, actor="cli")


def cli_status() -> Dict[str, Any]:
    # Try live IPC first; fall back to cached status file
    result = send_command("status")
    if not result.get("ok"):
        from modules.swarm_controller import read_status
        result = read_status()
        result["ok"] = True
        result["_source"] = "cached"
    _print_result("status", result)
    return result


def cli_health() -> Dict[str, Any]:
    result = send_command("health")
    if not result.get("ok"):
        result["_source"] = "unavailable"
    _print_result("health", result)
    return result


def cli_consent() -> None:
    from modules.swarm_consent import interactive_consent_flow
    interactive_consent_flow(actor="cli")


def cli_revoke() -> None:
    from modules.swarm_consent import revoke_consent
    confirm = input("Revoke consent and purge all frame metrics? [yes/no]: ").strip().lower()
    if confirm in ("yes", "y", "ja", "j"):
        result = revoke_consent(actor="cli")
        print(f"✓ Consent revoked at {result.get('revoked_at')}")
        _send("disable_swarm", verbose=False)
        print("✓ Swarm Mode disabled.")
    else:
        print("Revocation cancelled.")


# --------------------------------------------------------------------------- #
#  Entry point                                                                #
# --------------------------------------------------------------------------- #

_COMMANDS = {
    "enable_swarm": "Enable Swarm Mode (runs consent flow if needed)",
    "disable_swarm": "Disable Swarm Mode",
    "status": "Show current Swarm status",
    "health": "Show detailed Swarm health",
    "consent": "Run consent flow",
    "revoke": "Revoke consent and purge frame metrics",
}


def _usage() -> None:
    print("Usage: python -m modules.swarm_ui_adapter <command>")
    print("\nCommands:")
    for cmd, desc in _COMMANDS.items():
        print(f"  {cmd:20s}  {desc}")


def main(args: Optional[list[str]] = None) -> int:
    argv = args if args is not None else sys.argv[1:]
    if not argv:
        _usage()
        return 1
    cmd = argv[0].strip().lower()
    if cmd == "enable_swarm":
        cli_enable(interactive=True)
    elif cmd == "disable_swarm":
        cli_disable()
    elif cmd == "status":
        cli_status()
    elif cmd == "health":
        cli_health()
    elif cmd == "consent":
        cli_consent()
    elif cmd == "revoke":
        cli_revoke()
    else:
        print(f"Unknown command: {cmd!r}")
        _usage()
        return 1
    return 0


if __name__ == "__main__":
    from modules.session_guard import require_session
    require_session()
    sys.exit(main())
