"""Unit tests for task_broker.py."""

from __future__ import annotations

from modules import task_broker as tb_mod
from modules.task_broker import TaskRequest
import modules.blindspot_engine as bs_mod


def test_execute_task_failure_registers_blindspot_gap(monkeypatch):
    """A failed execution should produce a blindspot gap for swarm assistance."""
    # Reset singleton state for isolation.
    tb_mod.TaskBroker._instance = None
    bs_mod.BlindspotEngine._instance = None

    broker = tb_mod.TaskBroker.instance()
    blindspot = bs_mod.BlindspotEngine.instance()

    request = TaskRequest(
        task_id='task-test-1',
        task_type='invariant_analysis',
        payload_fingerprint='f',
        invariant_vector=[0.0] * 9,
        requirements=['numpy'],
        bounty_priority=5,
        requester_node_id='node-x',
        expires_ts=1e12,
    )

    monkeypatch.setattr(
        tb_mod,
        '_compute_structural_fingerprints',
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('simulated failure')),
    )

    result = broker.execute_task(request, executor_node_id='local', local_score_pct=100.0)
    assert result is None
    assert any(
        gap.metadata.get('task_id') == request.task_id
        for gap in blindspot._active_gaps.values()
    )
