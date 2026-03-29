from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .swarm_relay import RelayConfig, get_relay_nodes
except ImportError:
    from modules.swarm_relay import RelayConfig, get_relay_nodes  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_NODE_JSON_PATH = ROOT / "data" / "swarm" / "node.json"
DEFAULT_NODES_DIR = ROOT / "data" / "swarm" / "nodes"


def _run_runtime() -> int:
    from runtime_core import init_runtime
    from runtime_loop import run_loop, simple_delta_provider
    from renderer_visual import render_state_summary, render_timeline
    from monitoring_engine import monitor_runtime

    runtime = init_runtime()
    print("Aether Runtime gestartet")
    runtime = run_loop(runtime, max_ticks=10, delta_provider=simple_delta_provider)
    print(render_state_summary(runtime["state"]))
    print(render_timeline(runtime["history"]))
    print(monitor_runtime(runtime))
    return 0


def _sync_discovery_copy(node_json_path: Path) -> None:
    if not node_json_path.is_file():
        return
    payload = json.loads(node_json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return
    node_id = str(payload.get("node_id", "") or "").strip()
    if not node_id:
        return
    target = DEFAULT_NODES_DIR / f"{node_id}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _relay_enable(node_json_path: Path) -> int:
    RelayConfig().enable(str(node_json_path))
    _sync_discovery_copy(node_json_path)
    print(f"[relay] aktiviert: {node_json_path}")
    print("[relay] Empfehlung: git add data/swarm/nodes/ && git push")
    return 0


def _relay_disable(node_json_path: Path) -> int:
    RelayConfig().disable(str(node_json_path))
    _sync_discovery_copy(node_json_path)
    print(f"[relay] deaktiviert: {node_json_path}")
    return 0


def _relay_list(nodes_dir: Path) -> int:
    relays = get_relay_nodes(str(nodes_dir))
    print(json.dumps(relays, ensure_ascii=True, indent=2))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aether CLI")
    subparsers = parser.add_subparsers(dest="command")

    relay_parser = subparsers.add_parser("relay", help="Relay-Status fuer den lokalen Node verwalten")
    relay_subparsers = relay_parser.add_subparsers(dest="relay_command")

    relay_enable = relay_subparsers.add_parser("enable", help="Setzt relay=true in node.json")
    relay_enable.add_argument("--node-json", default=str(DEFAULT_NODE_JSON_PATH))

    relay_disable = relay_subparsers.add_parser("disable", help="Setzt relay=false in node.json")
    relay_disable.add_argument("--node-json", default=str(DEFAULT_NODE_JSON_PATH))

    relay_list = relay_subparsers.add_parser("list", help="Zeigt alle bekannten Relay-Nodes")
    relay_list.add_argument("--nodes-dir", default=str(DEFAULT_NODES_DIR))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return _run_runtime()
    if args.command == "relay" and args.relay_command == "enable":
        return _relay_enable(Path(args.node_json))
    if args.command == "relay" and args.relay_command == "disable":
        return _relay_disable(Path(args.node_json))
    if args.command == "relay" and args.relay_command == "list":
        return _relay_list(Path(args.nodes_dir))
    parser.print_help()
    return 1


if __name__ == "__main__":
    from modules.session_guard import require_session
    require_session()
    raise SystemExit(main(sys.argv[1:]))
