from __future__ import annotations

from pathlib import Path

import pytest

from aether_dropper import _detect_anchor, _safe_child_path


def test_detect_anchor_matches_fractional_constant() -> None:
    assert _detect_anchor(0.618, tolerance=0.02) == "phi"


def test_safe_child_path_rejects_archive_traversal() -> None:
    with pytest.raises(ValueError):
        _safe_child_path(Path.cwd(), "../escape.txt")
