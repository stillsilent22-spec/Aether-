import numpy as np
import hashlib
import time

class RenderCoordinator:
    def __init__(self):
        self.last_snapshot = None

    def capture_pixel_data(self, pixel_bytes: bytes) -> dict:
        # Strukturelle Analyse: alles als Bytes, label-frei
        entropy = self._shannon_entropy(pixel_bytes)
        symmetry = self._symmetry(pixel_bytes)
        resonance = self._resonance(pixel_bytes)
        fingerprint = hashlib.sha256(pixel_bytes).hexdigest()
        timestamp = time.time()
        return {
            "entropy": entropy,
            "symmetry": symmetry,
            "resonance": resonance,
            "fingerprint": fingerprint,
            "timestamp": timestamp
        }

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr)
        probs = counts / arr.size
        return float(-np.sum([p * np.log2(p) for p in probs if p > 0]))

    def _symmetry(self, data: bytes) -> float:
        arr = np.frombuffer(data, dtype=np.uint8)
        if arr.size < 2:
            return 1.0
        half = arr.size // 2
        return float(np.sum(arr[:half] == arr[-half:][::-1]) / half)

    def _resonance(self, data: bytes) -> float:
        arr = np.frombuffer(data, dtype=np.uint8)
        if arr.size == 0:
            return 0.0
        return float(np.std(arr))
