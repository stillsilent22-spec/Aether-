import logging
logger = logging.getLogger(__name__)
"""Subvault Genpool — evolutionary candidate lifecycle for Aether.

Architecture
------------
A :class:`Subvault` holds a pool of :class:`Candidate` objects.  Candidates
move through a deterministic lifecycle::

    DRAFT ──► EVALUATE ──► PROMOTE ──► (retain / age out)
                    │
                    └──► RETIRED  (score too low or TTL exceeded)

:func:`mutate` and :func:`hybridize` produce new candidates from existing
ones.  :func:`orchestrate_cycle` ties everything together: it samples
candidates, scores them via :mod:`mdl`, applies rules, and advances the
lifecycle.
"""
from __future__ import annotations

import hashlib
import os
import random as _random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .mdl import mdl_score
from .rule_engine import RuleEngine
from .state import State

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROMOTE_THRESHOLD = 1.0   # minimum mdl_score to advance to PROMOTED
MAX_POOL_SIZE = 256        # hard cap per Subvault


# ---------------------------------------------------------------------------
# Candidate
# ---------------------------------------------------------------------------

class CandidateStatus(Enum):
    DRAFT = "draft"
    EVALUATED = "evaluated"
    PROMOTED = "promoted"
    RETIRED = "retired"


@dataclass
class Candidate:
    """A single evolutionary candidate in the genpool."""

    id: str
    data: bytes
    status: CandidateStatus = CandidateStatus.DRAFT
    mdl_score_val: float = 0.0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def age(self, now: float = None) -> float:
        """Seconds since creation."""
        return (now if now is not None else time.time()) - self.created_at


# ---------------------------------------------------------------------------
# Subvault
# ---------------------------------------------------------------------------

class Subvault:
    """Fixed-capacity pool of :class:`Candidate` objects."""

    def __init__(self, max_size: int = MAX_POOL_SIZE, rng: _random.Random = None) -> None:
        self._pool: List[Candidate] = []
        self._max_size = max_size
        self._rng = rng or _random.Random()

    # ------------------------------------------------------------------
    # Mutating operations
    # ------------------------------------------------------------------

    def store(self, candidate: Candidate) -> None:
        """Add *candidate* to the pool, evicting the oldest RETIRED entry if
        the pool is at capacity, or the oldest DRAFT as a fallback."""
        if len(self._pool) >= self._max_size:
            self._evict()
        self._pool.append(candidate)

    def _evict(self) -> None:
        """Remove one candidate to make room — prefer RETIRED, then oldest DRAFT."""
        for status in (CandidateStatus.RETIRED, CandidateStatus.DRAFT):
            for i, c in enumerate(self._pool):
                if c.status == status:
                    self._pool.pop(i)
                    return
        # Last resort: remove the oldest entry of any status
        if self._pool:
            self._pool.pop(0)

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def sample(self, n: int) -> List[Candidate]:
        """Return up to *n* random candidates (without replacement)."""
        size = min(n, len(self._pool))
        return self._rng.sample(self._pool, size)

    def random(self) -> Optional[Candidate]:
        """Return a single random candidate or ``None`` if the pool is empty."""
        return self._rng.choice(self._pool) if self._pool else None

    def context_bytes(self) -> bytes:
        """Concatenate data from all PROMOTED candidates as context."""
        out = bytearray()
        for c in self._pool:
            if c.status == CandidateStatus.PROMOTED:
                out.extend(c.data)
        return bytes(out)

    def by_status(self, status: CandidateStatus) -> List[Candidate]:
        return [c for c in self._pool if c.status == status]

    def __len__(self) -> int:
        return len(self._pool)


# ---------------------------------------------------------------------------
# Genetic operators
# ---------------------------------------------------------------------------

def _make_id(data: bytes) -> str:
    """Deterministic short ID from data hash + timestamp suffix."""
    digest = hashlib.sha1(data, usedforsecurity=False).hexdigest()[:12]
    suffix = format(int(time.time() * 1e3) & 0xFFFF, "04x")
    return f"{digest}-{suffix}"


def mutate(candidate: Candidate, rng: _random.Random = None) -> Candidate:
    """Return a new :class:`Candidate` derived from *candidate* by applying
    one of three structural edits chosen at random:

    * **bit-flip** — flip a random byte
    * **insert** — insert one random byte at a random position
    * **delete** — remove one byte at a random position (noop if empty)
    """
    rng = rng or _random.Random()
    data = bytearray(candidate.data)
    op = rng.randint(0, 2)
    if not data:
        data = bytes([rng.randint(0, 255)])
    elif op == 0 and data:
        # bit-flip
        idx = rng.randrange(len(data))
        data[idx] ^= rng.randint(1, 255)
        data = bytes(data)
    elif op == 1:
        # insert
        idx = rng.randrange(len(data) + 1)
        data.insert(idx, rng.randint(0, 255))
        data = bytes(data)
    else:
        # delete
        if len(data) > 1:
            idx = rng.randrange(len(data))
            del data[idx]
        data = bytes(data)
    new_data = bytes(data) if not isinstance(data, bytes) else data
    return Candidate(
        id=_make_id(new_data),
        data=new_data,
        metadata={**candidate.metadata, "parent_id": candidate.id, "op": "mutate"},
    )


def hybridize(a: Candidate, b: Candidate, rng: _random.Random = None) -> Candidate:
    """Return a new :class:`Candidate` by splicing *a* and *b* at their
    midpoints and concatenating the halves::

        new_data = a.data[:len(a)//2] + b.data[len(b)//2:]
    """
    rng = rng or _random.Random()
    half_a = len(a.data) // 2
    half_b = len(b.data) // 2
    new_data = a.data[:half_a] + b.data[half_b:]
    # Fallback: if splice produces empty bytes use full concatenation
    if not new_data:
        new_data = a.data + b.data
    return Candidate(
        id=_make_id(new_data),
        data=new_data,
        metadata={
            **a.metadata,
            "parent_ids": [a.id, b.id],
            "op": "hybridize",
        },
    )


# ---------------------------------------------------------------------------
# Lifecycle orchestration
# ---------------------------------------------------------------------------

def orchestrate_cycle(
    subvault: Subvault,
    rule_engine: Optional[RuleEngine] = None,
    state: Optional[State] = None,
    *,
    sample_n: int = 8,
    rng: _random.Random = None,
    log_path=None,
) -> Dict[str, Any]:
    """Run one generation of the evolutionary lifecycle.

    Steps:
    1. Sample *sample_n* DRAFT candidates.
    2. Score each via MDL against the current context.
    3. Run rules (if provided) and advance lifecycle state.
    4. Persist promoted count into *state* (if provided).

    Returns a summary dict with counts for each status transition.
    """
    rng = rng or _random.Random()
    context = subvault.context_bytes()
    candidates = subvault.sample(sample_n)
    # Filter to drafts only
    drafts = [c for c in candidates if c.status == CandidateStatus.DRAFT]

    promoted = 0
    retired = 0
    flagged = 0

    for candidate in drafts:
        score = mdl_score(candidate.data, context_bytes=context)
        candidate.mdl_score_val = score
        candidate.status = CandidateStatus.EVALUATED

        # Run rule engine on candidate metrics
        if rule_engine is not None:
            metrics = {
                "mdl_score": score,
                "data_size": float(len(candidate.data)),
                "age_seconds": candidate.age(),
            }
            result = rule_engine.evaluate(
                metrics,
                candidate_id=candidate.id,
                write_log=True,
            )
            if result is not None:
                action = result.get("action", "")
                if action == "promote":
                    candidate.status = CandidateStatus.PROMOTED
                    promoted += 1
                    continue
                elif action == "quarantine":
                    candidate.status = CandidateStatus.RETIRED
                    retired += 1
                    continue
                elif action == "flag":
                    candidate.metadata["flagged"] = True
                    flagged += 1

        # Default lifecycle: promote if above threshold
        if score >= PROMOTE_THRESHOLD:
            candidate.status = CandidateStatus.PROMOTED
            promoted += 1
        elif score < 0:
            candidate.status = CandidateStatus.RETIRED
            retired += 1

    # Optionally seed new diversity via mutation
    promoted_pool = subvault.by_status(CandidateStatus.PROMOTED)
    if promoted_pool and len(subvault) < subvault._max_size:
        parent = rng.choice(promoted_pool)
        child = mutate(parent, rng=rng)
        subvault.store(child)

    summary = {
        "evaluated": len(drafts),
        "promoted": promoted,
        "retired": retired,
        "flagged": flagged,
        "pool_size": len(subvault),
    }

    if state is not None:
        state.update("vault_promoted_total", state.get("vault_promoted_total", 0) + promoted)
        state.update("vault_pool_size", len(subvault))

    return summary


class VaultOrchestrator:
    """Thin wrapper around vault orchestration functions for object-oriented access."""

    def __init__(self, max_size: int = MAX_POOL_SIZE) -> None:
        self._subvault = Subvault(max_size=max_size)

    def orchestrate_cycle(self, *args, **kwargs):
        return orchestrate_cycle(*args, **kwargs)

    @property
    def subvault(self) -> Subvault:
        return self._subvault

    def store(self, candidate: "Candidate") -> None:
        self._subvault.store(candidate)
