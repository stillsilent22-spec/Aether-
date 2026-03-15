def attractor_signature(state_hash: str) -> str:
    return state_hash[:12]

def attractor_track(history: list[str]) -> dict:
    counts = {}
    for h in history:
        counts[h] = counts.get(h, 0) + 1
    attractors = [k for k, v in counts.items() if v > 1]
    return {"attractors": attractors, "counts": counts}
