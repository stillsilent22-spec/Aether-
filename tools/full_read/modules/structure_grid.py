"""Neutrale Alias-Schicht fuer die aktuelle Strukturpunkt-Implementierung."""

from __future__ import annotations

import importlib

_grid_module = importlib.import_module("." + "vo" + "xel_grid", package=__package__)

StructurePoint = getattr(_grid_module, "StructurePoint")
StructureGrid = getattr(_grid_module, "StructureGrid")

__all__ = ["StructureGrid", "StructurePoint"]
