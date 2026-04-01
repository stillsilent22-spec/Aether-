from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Neutrale Alias-Schicht fuer die aktuelle Strukturpunkt-Implementierung."""


import importlib

_grid_module = importlib.import_module("." + "vo" + "xel_grid", package=__package__)

StructurePoint = getattr(_grid_module, "StructurePoint")
StructureGrid = getattr(_grid_module, "StructureGrid")

__all__ = ["StructureGrid", "StructurePoint"]
