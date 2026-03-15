import time

def state_init() -> dict:
    return {"version": 1, "timestamp": int(time.time()), "data": {}}

def state_step(state: dict, delta: dict) -> dict:
    new_state = dict(state)
    new_state.update(delta)
    new_state["version"] = int(state.get("version", 0)) + 1
    new_state["timestamp"] = int(time.time())
    return new_state
