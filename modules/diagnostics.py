from meta_engine import meta_hash_state
from delta_propagation import compute_delta_hash

def diag_state_summary(state: dict) -> dict:
    return {"keys": len(state), "hash": meta_hash_state(state), "version": state.get("version", 0)}

def diag_delta_summary(delta: dict) -> dict:
    return {"keys_changed": len(delta), "hash": compute_delta_hash(delta)}
