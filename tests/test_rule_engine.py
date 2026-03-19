"""Unit tests for modules/rule_engine.py."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from modules.rule_engine import (
    RuleEngine,
    compare,
    load_rules_from_file,
    write_decision_log,
)


# ---------------------------------------------------------------------------
# compare()
# ---------------------------------------------------------------------------

class TestCompare:
    @pytest.mark.parametrize("a, op, b, expected", [
        (5.0, "<",  6.0, True),
        (5.0, "<",  5.0, False),
        (5.0, "<=", 5.0, True),
        (5.0, ">",  4.0, True),
        (5.0, ">=", 5.0, True),
        (5.0, "==", 5.0, True),
        (5.0, "==", 4.9, False),
        (5.0, "!=", 4.9, True),
        (5.0, "!=", 5.0, False),
    ])
    def test_operators(self, a, op, b, expected):
        assert compare(a, op, b) is expected

    def test_unknown_op_raises(self):
        with pytest.raises(ValueError, match="Unknown operator"):
            compare(1.0, "??", 2.0)


# ---------------------------------------------------------------------------
# RuleEngine construction
# ---------------------------------------------------------------------------

RULE_FLAG = {
    "id": "high-entropy",
    "priority": 10,
    "conditions": [{"metric": "entropy_mean", "op": ">", "value": 7.0}],
    "action": "flag",
    "ttl_seconds": None,
}

RULE_QUARANTINE = {
    "id": "low-symmetry",
    "priority": 5,
    "conditions": [{"metric": "symmetry_phi", "op": "<", "value": 0.1}],
    "action": "quarantine",
    "ttl_seconds": 60,
}

RULE_PROMOTE = {
    "id": "high-coherence",
    "priority": 20,
    "conditions": [{"metric": "coherence_score", "op": ">=", "value": 0.9}],
    "action": "promote",
    "ttl_seconds": None,
}


class TestRuleEngineConstruction:
    def test_empty_rules(self):
        engine = RuleEngine([])
        assert len(engine) == 0

    def test_single_rule(self):
        engine = RuleEngine([RULE_FLAG])
        assert len(engine) == 1

    def test_invalid_action_raises(self):
        bad = {**RULE_FLAG, "action": "self_destruct"}
        with pytest.raises(ValueError, match="invalid action"):
            RuleEngine([bad])

    def test_missing_id_raises(self):
        bad = {**RULE_FLAG}
        del bad["id"]
        with pytest.raises(ValueError, match="missing 'id'"):
            RuleEngine([bad])

    def test_missing_condition_field_raises(self):
        bad = {
            "id": "x",
            "priority": 1,
            "conditions": [{"metric": "entropy_mean", "op": ">"}],  # no value
            "action": "flag",
        }
        with pytest.raises(ValueError, match="malformed condition"):
            RuleEngine([bad])

    def test_unknown_op_in_conditions_raises(self):
        bad = {
            "id": "x",
            "priority": 1,
            "conditions": [{"metric": "entropy_mean", "op": "<<", "value": 1.0}],
            "action": "flag",
        }
        with pytest.raises(ValueError, match="unknown op"):
            RuleEngine([bad])

    def test_priority_ordering(self):
        engine = RuleEngine([RULE_FLAG, RULE_QUARANTINE, RULE_PROMOTE])
        priorities = [r.get("priority", 0) for r in engine._rules]
        assert priorities == sorted(priorities)


# ---------------------------------------------------------------------------
# RuleEngine.evaluate()
# ---------------------------------------------------------------------------

class TestRuleEngineEvaluate:
    def _engine(self, log_path=None):
        return RuleEngine([RULE_FLAG, RULE_QUARANTINE, RULE_PROMOTE], log_path=log_path)

    def test_first_match_returned(self):
        engine = self._engine()
        result = engine.evaluate(
            {"entropy_mean": 7.5, "symmetry_phi": 0.05},
            candidate_id="c1",
            write_log=False,
        )
        # RULE_QUARANTINE (priority=5) sorts before RULE_FLAG (priority=10)
        assert result is not None
        assert result["action"] == "quarantine"
        assert result["candidate_id"] == "c1"

    def test_no_match_returns_none(self):
        engine = self._engine()
        result = engine.evaluate(
            {"entropy_mean": 3.0, "symmetry_phi": 0.9, "coherence_score": 0.5},
            write_log=False,
        )
        assert result is None

    def test_result_contains_required_fields(self):
        engine = self._engine()
        result = engine.evaluate(
            {"entropy_mean": 7.5},
            candidate_id="test-99",
            write_log=False,
        )
        for key in ("timestamp", "candidate_id", "metrics", "rule_ids", "action", "actor"):
            assert key in result

    def test_missing_metric_does_not_match(self):
        engine = self._engine()
        # entropy_mean is absent — RULE_FLAG must not fire
        result = engine.evaluate(
            {"symmetry_phi": 0.9, "coherence_score": 0.5},
            write_log=False,
        )
        assert result is None

    def test_evaluate_all_returns_multiple(self):
        engine = self._engine()
        # Feed metrics that satisfy both RULE_FLAG and RULE_PROMOTE
        results = engine.evaluate_all(
            {"entropy_mean": 7.5, "coherence_score": 0.95},
            write_log=False,
        )
        actions = {r["action"] for r in results}
        assert "flag" in actions
        assert "promote" in actions

    def test_write_log_appends_to_file(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        engine = self._engine(log_path=log_file)
        engine.evaluate(
            {"entropy_mean": 7.5},
            candidate_id="log-test",
            write_log=True,
        )
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["candidate_id"] == "log-test"
        assert entry["action"] == "flag"


# ---------------------------------------------------------------------------
# load_rules_from_file()
# ---------------------------------------------------------------------------

class TestLoadRulesFromFile:
    def test_round_trip(self, tmp_path):
        rules = [RULE_FLAG, RULE_QUARANTINE]
        path = tmp_path / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        loaded = load_rules_from_file(str(path))
        assert len(loaded) == 2
        assert loaded[0]["id"] == "high-entropy"

    def test_not_a_list_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"id": "x"}), encoding="utf-8")
        with pytest.raises(ValueError, match="JSON array"):
            load_rules_from_file(str(path))


# ---------------------------------------------------------------------------
# write_decision_log()
# ---------------------------------------------------------------------------

class TestWriteDecisionLog:
    def test_creates_file(self, tmp_path):
        log_path = tmp_path / "sub" / "decisions.jsonl"
        entry = {"timestamp": "now", "candidate_id": "x", "action": "flag"}
        write_decision_log(entry, log_path=log_path)
        assert log_path.exists()
        loaded = json.loads(log_path.read_text())
        assert loaded["action"] == "flag"

    def test_appends(self, tmp_path):
        log_path = tmp_path / "decisions.jsonl"
        for i in range(3):
            write_decision_log({"n": i}, log_path=log_path)
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 3
