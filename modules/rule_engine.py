import logging
logger = logging.getLogger(__name__)
"""Deterministic JSON-rule evaluator for Aether metrics.

Rules are plain dicts with the schema::

    {
        "id":         str,          # unique rule identifier
        "priority":   int,          # lower number = higher priority
        "conditions": [             # ALL must be true (conjunction)
            {"metric": str, "op": str, "value": float}
        ],
        "action":     str,          # quarantine | dampen | persist | flag | mutate | promote
        "ttl_seconds": int | None   # optional expiry hint
    }

Supported operators: ``<  <=  >  >=  ==  !=``

Example::

    rules = [
        {"id": "high-entropy", "priority": 10,
         "conditions": [{"metric": "entropy_mean", "op": ">", "value": 7.0}],
         "action": "flag", "ttl_seconds": None},
    ]
    engine = RuleEngine(rules)
    result = engine.evaluate({"entropy_mean": 7.5}, candidate_id="abc123")
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OPS = {
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}

_VALID_ACTIONS = frozenset(
    {"quarantine", "dampen", "persist", "flag", "mutate", "promote"}
)

# Path where decision entries are appended.
_DEFAULT_LOG_PATH = Path(__file__).parent.parent / "logs" / "decisions.jsonl"


def compare(a: float, op: str, b: float) -> bool:
    """Evaluate ``a <op> b``.  Raises ``ValueError`` for unknown operators."""
    fn = _OPS.get(op)
    if fn is None:
        raise ValueError(f"Unknown operator: {op!r}")
    return fn(float(a), float(b))


def _validate_rule(rule: Dict[str, Any]) -> None:
    """Raise ``ValueError`` when *rule* is malformed."""
    if "id" not in rule:
        raise ValueError("Rule missing 'id'")
    if "action" not in rule or rule["action"] not in _VALID_ACTIONS:
        raise ValueError(f"Rule {rule.get('id')!r}: invalid action {rule.get('action')!r}")
    for cond in rule.get("conditions", []):
        if "metric" not in cond or "op" not in cond or "value" not in cond:
            raise ValueError(f"Rule {rule['id']!r}: malformed condition {cond!r}")
        if cond["op"] not in _OPS:
            raise ValueError(f"Rule {rule['id']!r}: unknown op {cond['op']!r}")


# ---------------------------------------------------------------------------
# Decision log
# ---------------------------------------------------------------------------

def write_decision_log(entry: Dict[str, Any], log_path: Path = None) -> None:
    """Append *entry* as a single JSON line to the decision log.

    Creates parent directories and the file if they do not exist.
    Non-blocking best-effort: IO errors are silently swallowed so a logging
    failure never crashes the analysis pipeline.
    """
    path = log_path if log_path is not None else _DEFAULT_LOG_PATH
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # pragma: no cover
        logger.warning(f"[rule_engine] Fehler: {e}")
        pass


def load_rules_from_file(path: str) -> List[Dict[str, Any]]:
    """Load and validate a JSON array of rules from *path*."""
    with open(path, encoding="utf-8") as fh:
        rules = json.load(fh)
    if not isinstance(rules, list):
        raise ValueError("Rules file must contain a JSON array")
    for rule in rules:
        _validate_rule(rule)
    return rules


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Evaluates a sorted set of rules against a metric dict.

    Rules are sorted by priority ascending (lower = evaluated first).
    Evaluation stops at the first matching rule (first-match semantics).
    """

    def __init__(self, rules: List[Dict[str, Any]], log_path: Path = None) -> None:
        for r in rules:
            _validate_rule(r)
        self._rules: List[Dict[str, Any]] = sorted(rules, key=lambda r: r.get("priority", 0))
        self._log_path: Optional[Path] = log_path

    # ------------------------------------------------------------------

    def evaluate(
        self,
        metrics: Dict[str, float],
        candidate_id: str = "",
        actor: str = "rule_engine_v1",
        evidence_refs: List[str] = None,
        write_log: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Match *metrics* against the rule set.

        Returns the matching rule's evaluation record or ``None`` if no rule
        fires.  If *write_log* is True, appends an entry to the decision log.
        """
        matched_rule = self._first_match(metrics)
        if matched_rule is None:
            return None

        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "candidate_id": candidate_id,
            "metrics": {k: float(v) for k, v in metrics.items()},
            "rule_ids": [matched_rule["id"]],
            "action": matched_rule["action"],
            "actor": actor,
            "evidence_refs": list(evidence_refs or []),
        }
        if write_log:
            write_decision_log(entry, log_path=self._log_path)
        return entry

    def evaluate_all(
        self,
        metrics: Dict[str, float],
        candidate_id: str = "",
        actor: str = "rule_engine_v1",
        evidence_refs: List[str] = None,
        write_log: bool = True,
    ) -> List[Dict[str, Any]]:
        """Like :meth:`evaluate` but collects ALL matching rules, not just the first."""
        results = []
        for rule in self._rules:
            if self._rule_matches(rule, metrics):
                entry: Dict[str, Any] = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "candidate_id": candidate_id,
                    "metrics": {k: float(v) for k, v in metrics.items()},
                    "rule_ids": [rule["id"]],
                    "action": rule["action"],
                    "actor": actor,
                    "evidence_refs": list(evidence_refs or []),
                }
                if write_log:
                    write_decision_log(entry, log_path=self._log_path)
                results.append(entry)
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _first_match(self, metrics: Dict[str, float]) -> Optional[Dict[str, Any]]:
        for rule in self._rules:
            if self._rule_matches(rule, metrics):
                return rule
        return None

    @staticmethod
    def _rule_matches(rule: Dict[str, Any], metrics: Dict[str, float]) -> bool:
        for cond in rule.get("conditions", []):
            metric_val = metrics.get(cond["metric"])
            if metric_val is None:
                return False
            if not compare(metric_val, cond["op"], cond["value"]):
                return False
        return True

    def __len__(self) -> int:
        return len(self._rules)

    def __repr__(self) -> str:  # pragma: no cover
        return f"RuleEngine(rules={len(self._rules)})"
