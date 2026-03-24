def governance_engine(state):
    trace = {
        "invariants_touched": [],
        "justifications": [],
        "entropy_changes": [],
        "delta_events": [],
        "fail_closed_events": [],
        "governance_status": "ok",
    }

    # Fail-closed: invalid inputs are never treated as successful governance.
    if not isinstance(state, dict):
        trace["governance_status"] = "fail_closed"
        trace["fail_closed_events"].append(
            {
                "reason": "invalid_state_type",
                "expected": "dict",
                "received": type(state).__name__,
            }
        )
        return {"G": trace}

    try:
        if "fail_closed" in state:
            trace["governance_status"] = "fail_closed"
            trace["fail_closed_events"].append(state["fail_closed"])
    except Exception as err:
        trace["governance_status"] = "fail_closed"
        trace["fail_closed_events"].append(
            {
                "reason": "governance_exception",
                "detail": str(err),
            }
        )
    return {"G": trace}
