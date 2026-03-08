"""Kontinuierlicher Conway-Ableger fuer Aether-Beobachtungsfelder."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .observer_engine import AnchorPoint


@dataclass
class ConwaySnapshot:
    """Momentaufnahme des Conway-Feldes inklusive H_obs und Phi."""

    grid: np.ndarray
    h_obs: float
    phi: float


def _histogram_entropy(values: np.ndarray, bins: int = 32) -> float:
    """Berechnet Histogrammentropie fuer kontinuierliche Zellaktivierungen."""
    if values.size == 0:
        return 0.0
    histogram, _ = np.histogram(values, bins=bins, range=(0.0, 1.0), density=False)
    probs = histogram.astype(np.float64)
    probs = probs[probs > 0.0]
    if probs.size == 0:
        return 0.0
    probs = probs / float(np.sum(probs))
    return float(-np.sum(probs * np.log2(probs)))


class ContinuousConway:
    """Berechnet ein kontinuierliches 60x60-Feld aus Ankern und Nachbarschaftskernen."""

    def __init__(self, size: int = 60) -> None:
        self.size = max(20, int(size))
        self.grid = np.zeros((self.size, self.size), dtype=np.float64)
        self.kernel = self._build_kernel(radius=5)

    @staticmethod
    def _build_kernel(radius: int) -> np.ndarray:
        """Erzeugt K(d)=d^(-1.5) ohne Singulaeritaet im Zentrum."""
        size = radius * 2 + 1
        kernel = np.zeros((size, size), dtype=np.float64)
        for y_pos in range(size):
            for x_pos in range(size):
                dx = x_pos - radius
                dy = y_pos - radius
                if dx == 0 and dy == 0:
                    continue
                distance = math.sqrt(dx * dx + dy * dy)
                kernel[y_pos, x_pos] = distance ** (-1.5)
        kernel /= float(np.sum(kernel)) if float(np.sum(kernel)) > 1e-9 else 1.0
        return kernel

    @staticmethod
    def _sigmoid(values: np.ndarray) -> np.ndarray:
        """Numerisch stabile Sigmoidfunktion."""
        clipped = np.clip(values, -16.0, 16.0)
        return 1.0 / (1.0 + np.exp(-clipped))

    def reset(self) -> None:
        """Setzt das Conway-Feld zurueck."""
        self.grid.fill(0.0)

    def seed_from_anchors(
        self,
        anchors: Sequence[AnchorPoint],
        ghost_anchors: Sequence[AnchorPoint] = (),
    ) -> None:
        """Impft das Feld mit extrahierten und vorhergesagten Ankern."""
        self.grid *= 0.92
        combined = list(ghost_anchors[:6]) + list(anchors)
        for anchor in combined:
            x_pos = int(round(float(anchor.x) * (self.size - 1)))
            y_pos = int(round(float(anchor.y) * (self.size - 1)))
            x_pos = max(0, min(self.size - 1, x_pos))
            y_pos = max(0, min(self.size - 1, y_pos))
            radius = 2 if anchor.predicted else 1
            weight = 0.24 * float(anchor.strength) if anchor.predicted else 0.55 * float(anchor.strength)
            for y_delta in range(-radius, radius + 1):
                for x_delta in range(-radius, radius + 1):
                    px = max(0, min(self.size - 1, x_pos + x_delta))
                    py = max(0, min(self.size - 1, y_pos + y_delta))
                    falloff = 1.0 / max(1.0, math.sqrt((x_delta * x_delta) + (y_delta * y_delta) + 1.0))
                    self.grid[py, px] = min(1.0, self.grid[py, px] + (weight * falloff))

    def step(self) -> ConwaySnapshot:
        """Fuehrt einen kontinuierlichen Conway-Schritt aus."""
        influence = np.zeros_like(self.grid, dtype=np.float64)
        radius = self.kernel.shape[0] // 2
        for y_shift in range(-radius, radius + 1):
            for x_shift in range(-radius, radius + 1):
                weight = float(self.kernel[y_shift + radius, x_shift + radius])
                if weight <= 0.0:
                    continue
                influence += np.roll(np.roll(self.grid, y_shift, axis=0), x_shift, axis=1) * weight

        updated = self._sigmoid((influence * 9.5) - 2.8)
        self.grid = np.clip((self.grid * 0.18) + (updated * 0.82), 0.0, 1.0)

        whole_entropy = _histogram_entropy(self.grid)
        half = self.size // 2
        quadrants = [
            self.grid[:half, :half],
            self.grid[:half, half:],
            self.grid[half:, :half],
            self.grid[half:, half:],
        ]
        phi = float(whole_entropy - sum(_histogram_entropy(quadrant) for quadrant in quadrants))
        return ConwaySnapshot(
            grid=np.array(self.grid, copy=True),
            h_obs=float(whole_entropy),
            phi=float(phi),
        )

    def render_rgb(self, snapshot: ConwaySnapshot) -> np.ndarray:
        """Rendert das Aktivierungsfeld als RGB-Bild fuer Tk-Canvas oder PIL."""
        grid = np.clip(snapshot.grid, 0.0, 1.0)
        red = np.clip(grid * 255.0, 0.0, 255.0).astype(np.uint8)
        green = np.clip((0.35 + 0.65 * grid) * 200.0, 0.0, 255.0).astype(np.uint8)
        blue = np.clip((1.0 - np.abs(grid - 0.5) * 1.6) * 255.0, 0.0, 255.0).astype(np.uint8)
        return np.dstack([red, green, blue]).astype(np.uint8)
