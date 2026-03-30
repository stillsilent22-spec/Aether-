from __future__ import annotations


def test_p2p_starts_and_stops_managed_yggdrasil(monkeypatch):
    from modules.swarm_p2p import P2PLayer

    events = []

    monkeypatch.setattr("modules.swarm_p2p.is_yggdrasil_managed_running", lambda: False)
    monkeypatch.setattr(
        "modules.swarm_p2p.start_yggdrasil_subprocess",
        lambda config_path="data/yggdrasil.conf": events.append(("start", config_path)),
    )
    monkeypatch.setattr("modules.swarm_p2p.stop_yggdrasil_subprocess", lambda: events.append(("stop", None)))

    layer = P2PLayer(node_id="node-1", config={"enabled": True, "gossip_interval_seconds": 3600.0})
    layer.start()
    layer.stop()

    assert events == [("start", "data/yggdrasil.conf"), ("stop", None)]