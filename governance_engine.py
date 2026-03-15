def governance_engine(state):
    trace = {
        "invariants_touched": [],
        "justifications": [],
        "entropy_changes": [],
        "delta_events": [],
        "fail_closed_events": []
    }
    if "fail_closed" in state:
        trace["fail_closed_events"].append(state["fail_closed"])
    return {"G": trace}
