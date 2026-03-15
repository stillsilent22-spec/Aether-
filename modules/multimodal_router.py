import os
from analysis_engine import entropy, gini
from shanway_engine import shanway_normalize, shanway_reduce

def route_text_input(text: str) -> dict:
    norm = shanway_normalize(text)
    features = shanway_reduce(text)
    return {"type": "text", "normalized": norm, "features": features}

def route_file_input(path: str) -> dict:
    if not os.path.exists(path):
        return {"type": "file", "path": path, "entropy": 0.0, "gini": 0.0}
    with open(path, "rb") as f:
        data = f.read()
    return {"type": "file", "path": path, "entropy": float(entropy(data)), "gini": float(gini(data))}

def route_observation(event: dict) -> dict:
    return {"type": "observation", "source": event.get("source", ""), "payload": event.get("payload")}
