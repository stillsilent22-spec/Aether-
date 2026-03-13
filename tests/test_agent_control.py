from modules.agent_control import AgentControlEngine


def _snapshot(
    *,
    pid: int = 2001,
    cpu_percent: float = 6.0,
    io_read_bytes: int = 0,
    io_write_bytes: int = 0,
    open_connections: int = 2,
    thread_count: int = 8,
    interval_regularity: float = 0.2,
) -> dict[str, object]:
    return {
        "process_signals": [
            {
                "pid": pid,
                "name": "background_worker.exe",
                "cpu_percent": cpu_percent,
                "memory_mb": 320.0,
                "io_read_bytes": io_read_bytes,
                "io_write_bytes": io_write_bytes,
                "thread_count": thread_count,
                "open_connections": open_connections,
                "start_time_iso": "",
                "is_system": False,
                "has_window": False,
                "snapshot_ts": "",
            }
        ],
        "network_signals": [
            {
                "remote_domain": "example.net",
                "remote_port": 443,
                "local_port": 41000,
                "protocol": "TCP",
                "process_name": "background_worker.exe",
                "pid": pid,
                "packet_size_bucket": "medium",
                "connection_count_last_min": max(1, open_connections),
                "interval_regularity": interval_regularity,
                "snapshot_ts": "",
            }
        ],
    }


def test_manual_disable_requests_pause_for_background_candidate() -> None:
    engine = AgentControlEngine(apply_os_controls=False)
    report = engine.evaluate_snapshot(
        _snapshot(cpu_percent=14.0, open_connections=4, interval_regularity=0.78),
        agents_enabled=False,
        automatic_policies=True,
    )
    assert report.decisions
    assert report.decisions[0].applied_action == "pause"
    assert "manual_disable" in report.decisions[0].policy_hits


def test_auto_policy_deprioritizes_unstable_cpu_drift() -> None:
    engine = AgentControlEngine(apply_os_controls=False)
    engine.evaluate_snapshot(
        _snapshot(cpu_percent=1.0, open_connections=3, interval_regularity=0.10),
        agents_enabled=True,
        automatic_policies=True,
    )
    report = engine.evaluate_snapshot(
        _snapshot(cpu_percent=28.0, open_connections=3, interval_regularity=0.10),
        agents_enabled=True,
        automatic_policies=True,
    )
    assert report.decisions
    assert report.decisions[0].applied_action in {"deprioritize", "isolate", "network_block", "pause"}
    assert "cpu_drift" in report.decisions[0].policy_hits


def test_auto_policy_blocks_highly_regular_network_pattern() -> None:
    engine = AgentControlEngine(apply_os_controls=False)
    report = engine.evaluate_snapshot(
        _snapshot(cpu_percent=7.0, open_connections=5, interval_regularity=0.94),
        agents_enabled=True,
        automatic_policies=True,
    )
    assert report.decisions
    assert report.decisions[0].applied_action == "network_block"
    assert "network_rhythm" in report.decisions[0].policy_hits
