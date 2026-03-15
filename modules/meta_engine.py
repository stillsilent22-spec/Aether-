import hashlib

def meta_validate_state(state: dict) -> bool:
    if not isinstance(state, dict):
        return False
    forbidden = {"__meta__", "__system__"}
    for k, v in state.items():
        if not isinstance(k, str):
            return False
        if k in forbidden:
            return False
        if not (isinstance(v, (int, float, bytes, dict))):
            return False
        if isinstance(v, dict):
            # keine Rekursion
            return False
    return True

def meta_compute_delta(old: dict, new: dict) -> dict:
    delta = {}
    for k in new:
        if k not in old or old[k] != new[k]:
            delta[k] = new[k]
    return delta

def meta_apply_delta(state: dict, delta: dict) -> dict:
    out = dict(state)
    out.update(delta)
    return out

def meta_hash_state(state: dict) -> str:
    items = sorted(state.items())
    s = "".join(f"{k}:{str(v)};" for k, v in items)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
