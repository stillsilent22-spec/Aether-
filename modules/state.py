from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Authoritative State API for Aether.

Thread-safe, monotone-version state store.  Every write increments the
logical clock ``t`` so callers can detect stale reads.
"""

import copy
import threading
from typing import Any, Dict


class State:
    """Centralised Aether runtime state with snapshot/update semantics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.t: int = 0
        self._storage: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """Return a deep copy of the current state together with the
        logical timestamp ``t``."""
        with self._lock:
            return {"t": self.t, "storage": copy.deepcopy(self._storage)}

    def update(self, key: str, value: Any) -> None:
        """Write *value* under *key* and advance the logical clock."""
        with self._lock:
            self._storage[key] = value
            self.t += 1

    def get(self, key: str, default: Any = None) -> Any:
        """Return the stored value for *key* or *default*."""
        with self._lock:
            return self._storage.get(key, default)

    def delete(self, key: str) -> bool:
        """Remove *key*.  Returns True if the key existed."""
        with self._lock:
            if key in self._storage:
                del self._storage[key]
                self.t += 1
                return True
            return False

    def keys(self):
        """Return a snapshot of current keys."""
        with self._lock:
            return list(self._storage.keys())

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._storage

    def __repr__(self) -> str:  # pragma: no cover
        return f"State(t={self.t}, keys={list(self._storage.keys())})"
