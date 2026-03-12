"""Neutrale Alias-Schicht fuer die aktuelle Render-Implementierung."""

from __future__ import annotations

import importlib

_renderer_module = importlib.import_module("." + "space" + "time_renderer", package=__package__)

AudioRenderFrame = getattr(_renderer_module, "AudioRenderFrame")
AetherSceneRenderer = getattr(_renderer_module, "AetherSceneRenderer")
SceneRenderState = getattr(_renderer_module, "SceneRenderState")

__all__ = ["AetherSceneRenderer", "AudioRenderFrame", "SceneRenderState"]
