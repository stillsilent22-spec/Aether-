"""Unit tests for modules/vault_orchestrator.py."""
from __future__ import annotations

import random
import time

import pytest

from modules.vault_orchestrator import (
    Candidate,
    CandidateStatus,
    PROMOTE_THRESHOLD,
    Subvault,
    hybridize,
    mutate,
    orchestrate_cycle,
)
from modules.rule_engine import RuleEngine
from modules.state import State


# ---------------------------------------------------------------------------
# Candidate
# ---------------------------------------------------------------------------

class TestCandidate:
    def test_default_status(self):
        c = Candidate(id="x", data=b"hello")
        assert c.status == CandidateStatus.DRAFT

    def test_age_grows(self):
        c = Candidate(id="y", data=b"test")
        time.sleep(0.01)
        assert c.age() > 0


# ---------------------------------------------------------------------------
# Subvault
# ---------------------------------------------------------------------------

class TestSubvault:
    def _filled(self, n=10):
        sv = Subvault()
        for i in range(n):
            sv.store(Candidate(id=str(i), data=bytes([i % 256])))
        return sv

    def test_store_and_len(self):
        sv = Subvault()
        assert len(sv) == 0
        sv.store(Candidate(id="a", data=b"aa"))
        assert len(sv) == 1

    def test_sample_returns_at_most_n(self):
        sv = self._filled(5)
        assert len(sv.sample(3)) == 3
        assert len(sv.sample(100)) == 5

    def test_sample_empty_vault(self):
        sv = Subvault()
        assert sv.sample(5) == []

    def test_random_returns_candidate(self):
        sv = self._filled(3)
        c = sv.random()
        assert isinstance(c, Candidate)

    def test_random_empty_returns_none(self):
        sv = Subvault()
        assert sv.random() is None

    def test_context_bytes_only_promoted(self):
        sv = Subvault()
        draft = Candidate(id="d", data=b"draft")
        promoted = Candidate(id="p", data=b"promoted", status=CandidateStatus.PROMOTED)
        sv.store(draft)
        sv.store(promoted)
        ctx = sv.context_bytes()
        assert b"promoted" in ctx
        assert b"draft" not in ctx

    def test_eviction_on_full_pool(self):
        sv = Subvault(max_size=5)
        for i in range(5):
            sv.store(Candidate(id=str(i), data=b"x"))
        retired = sv._pool[2]
        retired.status = CandidateStatus.RETIRED
        sv.store(Candidate(id="new", data=b"new"))
        ids = [c.id for c in sv._pool]
        # RETIRED candidate should have been evicted first
        assert retired.id not in ids
        assert "new" in ids

    def test_by_status(self):
        sv = self._filled(4)
        promoted = sv._pool[0]
        promoted.status = CandidateStatus.PROMOTED
        assert len(sv.by_status(CandidateStatus.PROMOTED)) == 1
        assert len(sv.by_status(CandidateStatus.DRAFT)) == 3


# ---------------------------------------------------------------------------
# Genetic operators
# ---------------------------------------------------------------------------

class TestMutate:
    def test_returns_new_candidate(self):
        parent = Candidate(id="p", data=b"AAAA")
        child = mutate(parent, rng=random.Random(42))
        assert isinstance(child, Candidate)
        assert child.id != parent.id

    def test_metadata_tracks_parent(self):
        parent = Candidate(id="parent", data=b"data")
        child = mutate(parent, rng=random.Random(0))
        assert child.metadata.get("parent_id") == "parent"
        assert child.metadata.get("op") == "mutate"

    def test_empty_data_survives(self):
        parent = Candidate(id="e", data=b"")
        child = mutate(parent, rng=random.Random(7))
        assert len(child.data) >= 1

    def test_data_differs_from_parent(self):
        rng = random.Random(1)
        different = False
        parent = Candidate(id="p", data=b"hello world test data")
        for _ in range(20):
            child = mutate(parent, rng=rng)
            if child.data != parent.data:
                different = True
                break
        assert different

    def test_various_ops(self):
        """All three mutation ops (bit-flip, insert, delete) must run without crashing."""
        parent = Candidate(id="p", data=b"test data bytes here")
        for seed in range(30):
            child = mutate(parent, rng=random.Random(seed))
            assert isinstance(child.data, bytes)


class TestHybridize:
    def test_returns_new_candidate(self):
        a = Candidate(id="a", data=b"AAAA")
        b = Candidate(id="b", data=b"BBBB")
        child = hybridize(a, b)
        assert child.id not in ("a", "b")

    def test_data_is_splice_of_parents(self):
        a = Candidate(id="a", data=b"ABCDEF")
        b = Candidate(id="b", data=b"GHIJKL")
        child = hybridize(a, b)
        # first half of a ([:3] = b"ABC") + second half of b ([3:] = b"JKL")
        assert child.data == b"ABC" + b"JKL"

    def test_metadata_tracks_parents(self):
        a = Candidate(id="a", data=b"AA")
        b = Candidate(id="b", data=b"BB")
        child = hybridize(a, b)
        assert "a" in child.metadata.get("parent_ids", [])
        assert "b" in child.metadata.get("parent_ids", [])
        assert child.metadata.get("op") == "hybridize"

    def test_empty_data_fallback(self):
        a = Candidate(id="a", data=b"")
        b = Candidate(id="b", data=b"")
        child = hybridize(a, b)
        assert child.data == b""


# ---------------------------------------------------------------------------
# orchestrate_cycle()
# ---------------------------------------------------------------------------

class TestOrchestrateCycle:
    def _make_vault(self, n=10):
        sv = Subvault(rng=random.Random(42))
        for i in range(n):
            # Highly compressible data to ensure some candidates score >= threshold
            sv.store(Candidate(id=f"c{i}", data=b"\x00" * 200))
        return sv

    def test_returns_summary(self):
        sv = self._make_vault()
        summary = orchestrate_cycle(sv, rng=random.Random(1))
        for key in ("evaluated", "promoted", "retired", "flagged", "pool_size"):
            assert key in summary

    def test_updates_state(self):
        sv = self._make_vault()
        state = State()
        orchestrate_cycle(sv, state=state, rng=random.Random(2))
        assert state.get("vault_pool_size") is not None

    def test_with_rule_engine(self, tmp_path):
        sv = self._make_vault()
        rules = [{
            "id": "large-data",
            "priority": 1,
            "conditions": [{"metric": "data_size", "op": ">=", "value": 100.0}],
            "action": "promote",
            "ttl_seconds": None,
        }]
        engine = RuleEngine(rules, log_path=tmp_path / "decisions.jsonl")
        summary = orchestrate_cycle(sv, rule_engine=engine, rng=random.Random(3))
        # All candidates have 200 bytes so rule should promote them
        assert summary["promoted"] > 0

    def test_candidates_change_status(self):
        sv = self._make_vault(5)
        orchestrate_cycle(sv, rng=random.Random(99))
        statuses = {c.status for c in sv._pool}
        assert statuses - {CandidateStatus.DRAFT}  # at least one status changed

    def test_promote_threshold_constant(self):
        assert PROMOTE_THRESHOLD == 1.0
