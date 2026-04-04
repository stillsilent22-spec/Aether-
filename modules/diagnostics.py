import logging
logger = logging.getLogger(__name__)
from modules.meta_engine import meta_hash_state
from modules.delta_propagation import compute_delta_hash

def diag_state_summary(state: dict) -> dict:
    return {"keys": len(state), "hash": meta_hash_state(state), "version": state.get("version", 0)}

def diag_delta_summary(delta: dict) -> dict:
    return {"keys_changed": len(delta), "hash": compute_delta_hash(delta)}
