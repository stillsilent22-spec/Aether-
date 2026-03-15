import pytest
from modules.aethernet_temp import AethernetTemp

def test_consensus_verify():
    at = AethernetTemp()
    assert at.verify_consensus("id", ["u1", "u2", "u3"])
    assert not at.verify_consensus("id", ["u1", "u2"])

def test_solo_push():
    at = AethernetTemp()
    assert at.allow_solo_push("stillsilent22-spec")
    assert not at.allow_solo_push("otheruser")
