from __future__ import annotations

from modules.swarm_p2p import _effective_swarm_scope


def test_shell_capable_modern_machine_keeps_native_network_scope() -> None:
    hw = {"tier_rank": 4, "network_tier": "FullDht", "shell_capable": True, "progressive_network_unlock": False}
    cap = {
        "stage_index": 0,
        "progression_mode": "vault-first",
        "shell_ready": False,
        "overlay_ready": False,
        "full_member_ready": False,
    }

    scope = _effective_swarm_scope(hw, cap)

    assert scope["native_network_tier"] == "FullDht"
    assert scope["effective_network_tier"] == "FullDht"
    assert scope["lan_beacon"] is True
    assert scope["lan_p2p"] is True
    assert scope["yggdrasil"] is True


def test_headless_node_starts_beacon_first_until_locally_ready() -> None:
    hw = {
        "tier_rank": 4,
        "network_tier": "FullDht",
        "runtime": "headless-python",
        "shell_capable": False,
        "progressive_network_unlock": True,
    }
    cap = {
        "stage_index": 0,
        "progression_mode": "vault-first",
        "shell_ready": False,
        "overlay_ready": False,
        "full_member_ready": False,
    }

    scope = _effective_swarm_scope(hw, cap)

    assert scope["native_network_tier"] == "FullDht"
    assert scope["effective_network_tier"] == "LanBeacon"
    assert scope["lan_beacon"] is True
    assert scope["lan_p2p"] is False
    assert scope["yggdrasil"] is False


def test_headless_progression_can_unlock_lan_p2p_before_overlay() -> None:
    hw = {
        "tier_rank": 3,
        "network_tier": "YggdrasilP2P",
        "runtime": "headless-python",
        "shell_capable": False,
        "progressive_network_unlock": True,
    }
    cap = {
        "stage_index": 2,
        "progression_mode": "lan-p2p-ready",
        "shell_ready": False,
        "overlay_ready": False,
        "full_member_ready": False,
    }

    scope = _effective_swarm_scope(hw, cap)

    assert scope["effective_network_tier"] == "LanP2P"
    assert scope["lan_p2p"] is True
    assert scope["yggdrasil"] is False
    assert scope["dht"] is False


def test_full_member_ready_unlocks_full_dht_when_hardware_allows_it() -> None:
    hw = {"tier_rank": 4, "network_tier": "FullDht"}
    cap = {
        "stage_index": 4,
        "progression_mode": "full-member",
        "shell_ready": True,
        "overlay_ready": True,
        "full_member_ready": True,
    }

    scope = _effective_swarm_scope(hw, cap)

    assert scope["effective_network_tier"] == "FullDht"
    assert scope["yggdrasil"] is True
    assert scope["dht"] is True


def test_hardware_ceiling_still_limits_the_upgrade() -> None:
    hw = {"tier_rank": 1, "network_tier": "LanBeacon"}
    cap = {
        "stage_index": 4,
        "progression_mode": "full-member",
        "shell_ready": True,
        "overlay_ready": True,
        "full_member_ready": True,
    }

    scope = _effective_swarm_scope(hw, cap)

    assert scope["effective_network_tier"] == "LanBeacon"
    assert scope["lan_beacon"] is True
    assert scope["lan_p2p"] is False
    assert scope["yggdrasil"] is False