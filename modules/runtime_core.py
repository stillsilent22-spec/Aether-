from state_machine import state_init, state_step
from meta_engine import meta_hash_state

def init_runtime() -> dict:
    return {"state": state_init(), "history": [], "running": False, "tick": 0}

def runtime_step(runtime: dict, delta: dict) -> dict:
    state = state_step(runtime["state"], delta)
    state_hash = meta_hash_state(state)
    history = list(runtime["history"]) + [state_hash]
    tick = int(runtime["tick"]) + 1
    return {"state": state, "history": history, "running": runtime["running"], "tick": tick}

def runtime_set_running(runtime: dict, flag: bool) -> dict:
    out = dict(runtime)
    out["running"] = bool(flag)
    return out
