from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Minimum Description Length (MDL) scorer for Aether candidates.

The MDL principle favours hypotheses that compress data well.  Here we
implement a practical approximation:

    mdl_score = gain - alpha * complexity

where

    gain        = compress_size(context) - compress_size(context + candidate)
    complexity  = compress_size(candidate)
    alpha       = 0.001   (regularisation weight, configurable)

Compression is computed with *both* zlib and lzma and the **average** of the
two compression sizes is used so the metric is robust against pathological
inputs that happen to compress well with one algorithm but not the other.

A positive score means the candidate *reduces* the compressed description
length of the context — i.e. it is a useful addition.
"""

import lzma
import zlib
from typing import Literal

_ZLIB_LEVEL = 9
_LZMA_PRESET = 6

# Default regularisation weight on model complexity.
DEFAULT_ALPHA = 0.001


# ---------------------------------------------------------------------------
# Low-level compression helpers
# ---------------------------------------------------------------------------

def _compress_zlib(data: bytes) -> int:
    """Return compressed byte-count using zlib (level 9)."""
    return len(zlib.compress(data, _ZLIB_LEVEL))


def _compress_lzma(data: bytes) -> int:
    """Return compressed byte-count using lzma (preset 6)."""
    return len(lzma.compress(data, preset=_LZMA_PRESET))


def compress_size(data: bytes, method: Literal["zlib", "lzma", "avg"] = "avg") -> float:
    """Return the compressed size of *data* in bytes.

    Args:
        data:   Raw bytes to compress.
        method: Compression backend to use.
                ``"avg"`` averages zlib and lzma (default).

    Returns:
        Compressed byte-count as a float (may be fractional for ``"avg"``).
    """
    if not data:
        return 0.0
    if method == "zlib":
        return float(_compress_zlib(data))
    if method == "lzma":
        return float(_compress_lzma(data))
    if method == "avg":
        return (_compress_zlib(data) + _compress_lzma(data)) / 2.0
    raise ValueError(f"Unknown compression method: {method!r}. Use 'zlib', 'lzma', or 'avg'")


# ---------------------------------------------------------------------------
# MDL scoring
# ---------------------------------------------------------------------------

def mdl_score(
    candidate_bytes: bytes,
    context_bytes: bytes = b"",
    alpha: float = DEFAULT_ALPHA,
) -> float:
    """Compute the MDL score of *candidate_bytes* given *context_bytes*.

    A higher positive score means the candidate is a better fit for the
    context (it compresses the joint corpus more than it costs to describe).

    Args:
        candidate_bytes: The candidate data to evaluate.
        context_bytes:   Background / prior context (may be empty).
        alpha:           Complexity penalty weight.  Default 0.001.

    Returns:
        MDL score as a float.  Positive = useful; negative = harmful.
    """
    c_ctx = compress_size(context_bytes)
    c_joint = compress_size(context_bytes + candidate_bytes)
    c_cand = compress_size(candidate_bytes)
    gain = c_ctx - c_joint
    complexity = c_cand
    return gain - alpha * complexity


def normalize_score(score: float, context_size: int) -> float:
    """Normalize *score* by the uncompressed *context_size* (bytes).

    Returns a value in roughly [-1, 1] when context is non-trivial.
    Returns 0.0 for empty contexts to avoid division by zero.
    """
    if context_size <= 0:
        return 0.0
    return score / float(context_size)
