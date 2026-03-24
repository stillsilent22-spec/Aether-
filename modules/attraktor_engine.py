"""Compatibility wrapper for legacy `attraktor` naming.

Canonical module: ``modules.attractor_engine``.
"""

from .attractor_engine import attractor_signature, attractor_track


# Backwards-compatible aliases
attraktor_signature = attractor_signature
attraktor_track = attractor_track

__all__ = [
    "attractor_signature",
    "attractor_track",
    "attraktor_signature",
    "attraktor_track",
]
