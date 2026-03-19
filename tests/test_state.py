"""Unit tests for modules/state.py."""
from __future__ import annotations

import threading

import pytest

from modules.state import State


class TestStateBasic:
    def test_initial_snapshot(self):
        s = State()
        snap = s.snapshot()
        assert snap["t"] == 0
        assert snap["storage"] == {}

    def test_update_increments_t(self):
        s = State()
        s.update("key", "value")
        assert s.snapshot()["t"] == 1
        s.update("key", "value2")
        assert s.snapshot()["t"] == 2

    def test_get_returns_value(self):
        s = State()
        s.update("alpha", 42)
        assert s.get("alpha") == 42

    def test_get_missing_returns_default(self):
        s = State()
        assert s.get("missing") is None
        assert s.get("missing", 99) == 99

    def test_snapshot_is_copy(self):
        s = State()
        s.update("x", [1, 2, 3])
        snap = s.snapshot()
        snap["storage"]["x"].append(99)
        # Original must be unaffected
        assert s.get("x") == [1, 2, 3]

    def test_delete_removes_key(self):
        s = State()
        s.update("a", 1)
        removed = s.delete("a")
        assert removed is True
        assert s.get("a") is None
        assert "a" not in s

    def test_delete_increments_t(self):
        s = State()
        s.update("b", 2)
        t_before = s.snapshot()["t"]
        s.delete("b")
        assert s.snapshot()["t"] == t_before + 1

    def test_delete_nonexistent_returns_false(self):
        s = State()
        assert s.delete("nope") is False

    def test_contains(self):
        s = State()
        s.update("present", True)
        assert "present" in s
        assert "absent" not in s

    def test_keys(self):
        s = State()
        s.update("one", 1)
        s.update("two", 2)
        assert set(s.keys()) == {"one", "two"}


class TestStateConcurrency:
    def test_concurrent_updates(self):
        s = State()
        errors = []

        def writer(n: int):
            try:
                for i in range(50):
                    s.update(f"key_{n}_{i}", i)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Each thread writes 50 keys → at least 200 increments
        assert s.snapshot()["t"] >= 200

    def test_snapshot_consistency(self):
        """Snapshot must never expose partial writes."""
        s = State()
        s.update("counter", 0)
        stop = threading.Event()
        inconsistencies = []

        def continuous_writer():
            v = 0
            while not stop.is_set():
                v += 1
                s.update("counter", v)

        def continuous_reader():
            while not stop.is_set():
                snap = s.snapshot()
                if not isinstance(snap["storage"].get("counter", 0), int):
                    inconsistencies.append(snap)

        w = threading.Thread(target=continuous_writer)
        r = threading.Thread(target=continuous_reader)
        w.start()
        r.start()

        import time
        time.sleep(0.05)
        stop.set()
        w.join()
        r.join()

        assert not inconsistencies
