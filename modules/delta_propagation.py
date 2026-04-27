import logging
logger = logging.getLogger(__name__)

def propagate_delta(state: dict, delta: dict) -> dict:
    new_state = dict(state)
    new_state.update(delta)
    state_hash = compute_delta_hash(new_state)
    delta_hash = compute_delta_hash(delta)
    return {"new_state": new_state, "state_hash": state_hash, "delta_hash": delta_hash}

def compute_delta_hash(delta: dict) -> str:
    """XOR-based rolling fingerprint of a delta dict (no SHA, no crypto)."""
    items = sorted(delta.items())
    s = "".join(f"{k}:{str(v)};" for k, v in items).encode("utf-8")
    acc = 0x5A5A5A5A
    for b in s:
        acc = ((acc << 5) | (acc >> 27)) ^ b
        acc &= 0xFFFFFFFF
    return format(acc, "08x")
