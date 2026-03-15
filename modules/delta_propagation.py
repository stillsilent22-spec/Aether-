import hashlib

def propagate_delta(state: dict, delta: dict) -> dict:
    new_state = dict(state)
    new_state.update(delta)
    state_hash = compute_delta_hash(new_state)
    delta_hash = compute_delta_hash(delta)
    return {"new_state": new_state, "state_hash": state_hash, "delta_hash": delta_hash}

def compute_delta_hash(delta: dict) -> str:
    items = sorted(delta.items())
    s = "".join(f"{k}:{str(v)};" for k, v in items)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
