import logging
logger = logging.getLogger(__name__)
"""Compatibility wrapper for legacy `attraktor` naming.

Canonical module: ``modules.attractor_engine``.
"""

from .attractor_engine import attractor_signature, attractor_track, perm_entropy


# Backwards-compatible aliases
attraktor_signature = attractor_signature
attraktor_track = attractor_track

__all__ = [
    "attractor_signature",
    "attractor_track",
    "perm_entropy",
    "attraktor_signature",
    "attraktor_track",
]
