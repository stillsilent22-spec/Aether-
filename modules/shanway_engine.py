import hashlib
import unicodedata

def shanway_normalize(text: str) -> str:
    text = " ".join(text.split())
    text = "".join(c for c in text if c.isprintable())
    text = unicodedata.normalize("NFKC", text)
    return text

def shanway_interference_score(a: str, b: str) -> float:
    ba = a.encode("utf-8")
    bb = b.encode("utf-8")
    length = min(len(ba), len(bb))
    if length == 0:
        return 0.0
    score = sum(abs(ba[i] ^ bb[i]) for i in range(length)) / length
    return float(score)

def shanway_reduce(text: str) -> dict:
    b = text.encode("utf-8")
    length = len(b)
    entropy = 0.0
    if length > 0:
        from collections import Counter
        import math
        counts = Counter(b)
        total = float(length)
        entropy = -sum((c/total) * math.log2(c/total) for c in counts.values())
    signature = hashlib.sha256(b).hexdigest()
    return {"length": length, "entropy": float(entropy), "signature": signature}
