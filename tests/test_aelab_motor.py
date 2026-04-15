"""tests/test_aelab_motor.py — Legacy hardware rate-limit tests for AEEvolver.

Verifies that the vault evolution engine adapts iterations for low-tier hardware.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.aelab_motor import AEEvolver


def test_aeevolver_legacy_hardware_tier_scales_down() -> None:
    data = bytes([i & 0xFF for i in range(16)])
    evolver = AEEvolver(data=data, seed=123)
    tree, fit = evolver.run(pop=12, gens=8, hardware_tier=0)

    assert tree is not None
    assert isinstance(fit, float)
    assert len(evolver.history) == 2
    assert fit >= 0.0


def test_aeevolver_standard_hardware_uses_full_iterations() -> None:
    data = bytes([((i * 3) + 7) & 0xFF for i in range(16)])
    evolver = AEEvolver(data=data, seed=456)
    tree, fit = evolver.run(pop=10, gens=6, hardware_tier=4)

    assert tree is not None
    assert isinstance(fit, float)
    assert len(evolver.history) == 6
    assert fit >= 0.0
