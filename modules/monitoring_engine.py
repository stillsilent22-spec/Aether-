def monitor_runtime(runtime: dict) -> dict:
    return {"running": bool(runtime.get("running", False)), "tick": int(runtime.get("tick", 0)), "history_length": len(runtime.get("history", []))}

def monitor_anomalies(runtime: dict) -> list:
    history_length = len(runtime.get("history", []))
    tick = int(runtime.get("tick", 0))
    if history_length == 0:
        return ["no_history"]
    if tick > history_length:
        return ["tick_history_mismatch"]
    return []
