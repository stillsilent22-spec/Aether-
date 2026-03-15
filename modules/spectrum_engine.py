"""Lichtspektrum-Analyse fuer Bild- und Frame-Daten."""

from __future__ import annotations

import hashlib
import math
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from .analysis_engine import AetherFingerprint
from .session_engine import SessionContext


def _shannon_entropy(values: np.ndarray) -> float:
    """Berechnet die Shannon-Entropie einer eindimensionalen Byte-Sequenz."""
    if values.size == 0:
        return 0.0
    counts = np.bincount(values.astype(np.uint8), minlength=256).astype(np.float64)
    probs = counts[counts > 0.0] / float(values.size)
    if probs.size == 0:
        return 0.0
    return float(-np.sum(probs * np.log2(probs)))


@dataclass
class SpectrumFingerprint:
    """Enthaelt das analysierte Lichtspektrum einer Bildquelle."""

    session_id: str
    source_type: str
    source_path: str
    timestamp: str
    image_hash: str
    file_size: int
    width: int
    height: int
    entropy_red: float
    entropy_green: float
    entropy_blue: float
    entropy_total: float
    entropy_blocks: list[float]
    dominant_wavelength_nm: float
    dominant_color_rgb: tuple[int, int, int]
    mean_red: float
    mean_green: float
    mean_blue: float
    delta: bytes
    delta_ratio: float
    noise_seed: int
    anomaly_coordinates: list[tuple[int, int]]
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert den Spektrums-Fingerprint als JSON-kompatibles Dictionary."""
        return {
            "session_id": self.session_id,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "timestamp": self.timestamp,
            "image_hash": self.image_hash,
            "file_size": int(self.file_size),
            "width": int(self.width),
            "height": int(self.height),
            "entropy_red": float(self.entropy_red),
            "entropy_green": float(self.entropy_green),
            "entropy_blue": float(self.entropy_blue),
            "entropy_total": float(self.entropy_total),
            "entropy_blocks": [float(x) for x in self.entropy_blocks],
            "dominant_wavelength_nm": float(self.dominant_wavelength_nm),
            "dominant_color_rgb": [int(self.dominant_color_rgb[0]), int(self.dominant_color_rgb[1]), int(self.dominant_color_rgb[2])],
            "mean_red": float(self.mean_red),
            "mean_green": float(self.mean_green),
            "mean_blue": float(self.mean_blue),
            "delta": self.delta.hex(),
            "delta_ratio": float(self.delta_ratio),
            "noise_seed": int(self.noise_seed),
            "anomaly_coordinates": [[int(x), int(y)] for x, y in self.anomaly_coordinates],
            "verdict": self.verdict,
        }

    def to_aether_fingerprint(self) -> AetherFingerprint:
        """Konvertiert das Spektrum in ein kompatibles AetherFingerprint-Objekt fuer Renderer und Logging."""
        gray_distribution = {int(k): int(v) for k, v in Counter(self.dominant_color_rgb).items()}
        symmetry_score = float(max(0.0, 100.0 - (self.entropy_total / 8.0) * 100.0))
        return AetherFingerprint(
            session_id=self.session_id,
            file_hash=self.image_hash,
            file_size=self.file_size,
            entropy_blocks=self.entropy_blocks,
            entropy_mean=float(np.mean(self.entropy_blocks) if self.entropy_blocks else 0.0),
            fourier_peaks=[
                {"frequency": float(self.mean_red), "magnitude": float(self.entropy_red)},
                {"frequency": float(self.mean_green), "magnitude": float(self.entropy_green)},
                {"frequency": float(self.mean_blue), "magnitude": float(self.entropy_blue)},
                {"frequency": float(self.dominant_wavelength_nm), "magnitude": float(self.entropy_total)},
                {"frequency": 0.0, "magnitude": 0.0},
            ],
            byte_distribution=gray_distribution,
            periodicity=0,
            symmetry_score=symmetry_score,
            delta=self.delta,
            delta_ratio=self.delta_ratio,
            anomaly_coordinates=list(self.anomaly_coordinates),
            verdict=self.verdict,
            timestamp=self.timestamp,
            source_type=self.source_type,
            source_label=self.source_path,
        )


class SpectrumEngine:
    """Analysiert elektromagnetische Spektralstruktur in Bilddaten."""

    def __init__(self, session_context: SessionContext, block_size: int = 256) -> None:
        """
        Initialisiert die Spektrum-Engine.

        Args:
            session_context: Aktiver Session-Kontext inklusive Seed.
            block_size: Blockgroesse fuer lokale Entropieauswertung.
        """
        self.session_context = session_context
        self.block_size = block_size

    @staticmethod
    def wavelength_to_rgb(wavelength_nm: float) -> tuple[int, int, int]:
        """
        Konvertiert eine Wellenlaenge in eine approximierte RGB-Farbe.

        Args:
            wavelength_nm: Wellenlaenge in Nanometern.
        """
        wl = float(max(380.0, min(780.0, wavelength_nm)))
        if wl < 440:
            r, g, b = -(wl - 440) / (440 - 380), 0.0, 1.0
        elif wl < 490:
            r, g, b = 0.0, (wl - 440) / (490 - 440), 1.0
        elif wl < 510:
            r, g, b = 0.0, 1.0, -(wl - 510) / (510 - 490)
        elif wl < 580:
            r, g, b = (wl - 510) / (580 - 510), 1.0, 0.0
        elif wl < 645:
            r, g, b = 1.0, -(wl - 645) / (645 - 580), 0.0
        else:
            r, g, b = 1.0, 0.0, 0.0

        if wl < 420:
            factor = 0.3 + 0.7 * (wl - 380) / (420 - 380)
        elif wl > 700:
            factor = 0.3 + 0.7 * (780 - wl) / (780 - 700)
        else:
            factor = 1.0
        gamma = 0.8
        red = int(round((max(0.0, r) * factor) ** gamma * 255))
        green = int(round((max(0.0, g) * factor) ** gamma * 255))
        blue = int(round((max(0.0, b) * factor) ** gamma * 255))
        return red, green, blue

    def _dominant_wavelength(self, mean_red: float, mean_green: float, mean_blue: float) -> float:
        """Berechnet die dominante Wellenlaenge aus den RGB-Mittelwerten."""
        weights = np.array([mean_red, mean_green, mean_blue], dtype=np.float64)
        total = float(weights.sum())
        if total <= 1e-9:
            return 550.0
        wavelengths = np.array([700.0, 550.0, 450.0], dtype=np.float64)
        return float(np.dot(weights / total, wavelengths))

    def _entropy_blocks(self, gray_values: np.ndarray) -> list[float]:
        """Berechnet blockweise Entropie aus Grauwerten."""
        values = gray_values.astype(np.uint8).flatten()
        blocks: list[float] = []
        for idx in range(0, values.size, self.block_size):
            block = values[idx : idx + self.block_size]
            blocks.append(_shannon_entropy(block))
        return blocks

    def _anomaly_coordinates(self, entropy_blocks: list[float]) -> list[tuple[int, int]]:
        """Ermittelt entropische Ausreisser als Koordinaten auf einem 16x16-Gitter."""
        if not entropy_blocks:
            return []
        arr = np.array(entropy_blocks, dtype=np.float64)
        mean = float(arr.mean())
        std = float(arr.std())
        threshold = max(0.6, 1.35 * std)
        coords: list[tuple[int, int]] = []
        for index, value in enumerate(entropy_blocks):
            if abs(value - mean) > threshold:
                coords.append((index % 16, index // 16))
        return coords

    def _classify(self, entropy_total: float) -> str:
        """Leitet ein Urteil aus der kombinierten Entropie ab."""
        if entropy_total < 2.4:
            return "CLEAN"
        if entropy_total < 5.8:
            return "SUSPICIOUS"
        return "CRITICAL"

    def _build_aether_delta(
        self,
        raw_rgb: np.ndarray,
        entropy_vector: tuple[float, float, float, float],
        dominant_color: tuple[int, int, int],
    ) -> tuple[bytes, float, int]:
        """
        Erstellt ein verlustfreies Delta, in das Spektrums-Entropie direkt einfliesst.

        Das Modell orientiert sich am dominanten Farbvektor; bei nahezu monochromatischen Bildern
        bleibt das Delta typischerweise klein und gut komprimierbar.
        """
        flat = raw_rgb.astype(np.uint8).flatten()
        if flat.size == 0:
            return b"", 0.0, int(self.session_context.seed)

        entropy_payload = (
            f"{entropy_vector[0]:.6f}|{entropy_vector[1]:.6f}|"
            f"{entropy_vector[2]:.6f}|{entropy_vector[3]:.6f}|"
            f"{dominant_color[0]}|{dominant_color[1]}|{dominant_color[2]}"
        ).encode("utf-8")
        entropy_hash = int(hashlib.sha256(entropy_payload).hexdigest()[:8], 16)
        noise_seed = (int(self.session_context.seed) ^ entropy_hash) & 0xFFFFFFFF

        pattern = np.array(dominant_color, dtype=np.uint8)
        repeats = int(math.ceil(flat.size / 3.0))
        base_model = np.tile(pattern, repeats)[: flat.size]

        modulation = float(max(0.0, min(1.0, entropy_vector[3] / 8.0)))
        rng = np.random.default_rng(noise_seed)
        rand_stream = rng.integers(0, 256, size=flat.size, dtype=np.uint8)
        dynamic_mask = np.uint8(int(modulation * 255.0))
        model = np.bitwise_xor(base_model, np.bitwise_and(rand_stream, dynamic_mask))

        delta = np.bitwise_xor(flat, model).tobytes()
        compressed_size = len(zlib.compress(delta, level=9))
        ratio = float(max(0.0, min(1.0, compressed_size / max(1, flat.size))))
        return delta, ratio, noise_seed

    def analyze_array(self, rgb_array: np.ndarray, source_label: str = "frame") -> SpectrumFingerprint:
        """
        Analysiert ein bereits geladenes RGB-Array als elektromagnetisches Spektrum.

        Args:
            rgb_array: Bilddaten im RGB-Format.
            source_label: Textuelle Quellenbezeichnung fuer Logging.
        """
        if rgb_array.ndim != 3 or rgb_array.shape[2] != 3:
            raise RuntimeError("Ungueltiges Bildformat: RGB-Array erwartet.")

        rgb = np.asarray(rgb_array, dtype=np.uint8)
        height, width, _ = rgb.shape
        red = rgb[:, :, 0].flatten()
        green = rgb[:, :, 1].flatten()
        blue = rgb[:, :, 2].flatten()
        joined = rgb.flatten()

        entropy_red = _shannon_entropy(red)
        entropy_green = _shannon_entropy(green)
        entropy_blue = _shannon_entropy(blue)
        entropy_total = _shannon_entropy(joined)

        mean_red = float(np.mean(red)) if red.size else 0.0
        mean_green = float(np.mean(green)) if green.size else 0.0
        mean_blue = float(np.mean(blue)) if blue.size else 0.0
        dominant_wavelength = self._dominant_wavelength(mean_red, mean_green, mean_blue)
        dominant_color = (
            int(round(mean_red)),
            int(round(mean_green)),
            int(round(mean_blue)),
        )

        gray = np.clip(0.299 * rgb[:, :, 0] + 0.587 * rgb[:, :, 1] + 0.114 * rgb[:, :, 2], 0, 255).astype(np.uint8)
        entropy_blocks = self._entropy_blocks(gray)
        anomaly_coordinates = self._anomaly_coordinates(entropy_blocks)
        verdict = self._classify(entropy_total)

        delta, delta_ratio, noise_seed = self._build_aether_delta(
            raw_rgb=rgb,
            entropy_vector=(entropy_red, entropy_green, entropy_blue, entropy_total),
            dominant_color=dominant_color,
        )

        raw_bytes = rgb.tobytes()
        timestamp = datetime.now(timezone.utc).isoformat()
        image_hash = hashlib.sha256(raw_bytes).hexdigest()
        return SpectrumFingerprint(
            session_id=self.session_context.session_id,
            source_type="frame",
            source_path=source_label,
            timestamp=timestamp,
            image_hash=image_hash,
            file_size=len(raw_bytes),
            width=int(width),
            height=int(height),
            entropy_red=float(entropy_red),
            entropy_green=float(entropy_green),
            entropy_blue=float(entropy_blue),
            entropy_total=float(entropy_total),
            entropy_blocks=entropy_blocks,
            dominant_wavelength_nm=float(dominant_wavelength),
            dominant_color_rgb=dominant_color,
            mean_red=mean_red,
            mean_green=mean_green,
            mean_blue=mean_blue,
            delta=delta,
            delta_ratio=delta_ratio,
            noise_seed=noise_seed,
            anomaly_coordinates=anomaly_coordinates,
            verdict=verdict,
        )

    def analyze_image(self, image_path: str) -> SpectrumFingerprint:
        """
        Analysiert eine Bilddatei ueber PIL als Lichtspektrum.

        Args:
            image_path: Pfad zur Bilddatei.
        """
        path = Path(image_path)
        if not path.is_file():
            raise RuntimeError("Bilddatei nicht gefunden.")
        try:
            with Image.open(path) as image:
                rgb = np.array(image.convert("RGB"), dtype=np.uint8)
        except OSError as exc:
            raise RuntimeError(f"Bild konnte nicht gelesen werden: {exc}") from exc

        spectrum = self.analyze_array(rgb, source_label=str(path))
        spectrum.source_type = "image"
        spectrum.source_path = str(path)
        return spectrum
