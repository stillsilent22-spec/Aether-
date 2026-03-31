import math
import os
from collections import Counter


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def gini(data: bytes) -> float:
    if not data:
        return 0.0
    vals = sorted(Counter(data).values())
    n = len(data)
    cumsum = sum((2 * (i + 1) - len(vals) - 1) * v for i, v in enumerate(vals))
    return cumsum / (len(vals) * n)

from modules.text_utils import text_normalize, text_reduce

def route_text_input(text: str) -> dict:
    norm = text_normalize(text)
    features = text_reduce(text)
    return {"type": "text", "normalized": norm, "features": features}

def route_file_input(path: str) -> dict:
    if not os.path.exists(path):
        return {"type": "file", "path": path, "entropy": 0.0, "gini": 0.0}
    with open(path, "rb") as f:
        data = f.read()
    return {"type": "file", "path": path, "entropy": float(entropy(data)), "gini": float(gini(data))}

def route_observation(event: dict) -> dict:
    return {"type": "observation", "source": event.get("source", ""), "payload": event.get("payload")}
