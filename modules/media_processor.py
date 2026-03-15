import numpy as np
import hashlib
from typing import Dict, Any

class MediaProcessor:
    def process_mp3(self, data: bytes) -> Dict[str, Any]:
        entropy = self._shannon_entropy(data)
        symmetry = self._byte_symmetry(data)
        return {"entropy": entropy, "symmetry": symmetry}

    def process_mp4(self, frames: list) -> Dict[str, Any]:
        arr = np.array(frames)
        entropy = self._shannon_entropy(arr.tobytes())
        symmetry = self._byte_symmetry(arr.tobytes())
        return {"entropy": entropy, "symmetry": symmetry}

    def process_image(self, pixels: np.ndarray) -> Dict[str, Any]:
        entropy = self._shannon_entropy(pixels.tobytes())
        symmetry = self._byte_symmetry(pixels.tobytes())
        return {"entropy": entropy, "symmetry": symmetry}

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
        probs = counts / len(data)
        return -np.sum([p * np.log2(p) for p in probs if p > 0])

    def _byte_symmetry(self, data: bytes) -> float:
        if len(data) < 2:
            return 1.0
        pairs = zip(data[:len(data)//2], reversed(data[len(data)//2:]))
        return sum(1 for a, b in pairs if a == b) / (len(data)//2)
