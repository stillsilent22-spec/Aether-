"""Compatibility shim for legacy imports.

Canonical implementation lives in ``modules.persist``.
"""

from modules.persist import build_aef, build_dna

__all__ = ["build_dna", "build_aef"]
