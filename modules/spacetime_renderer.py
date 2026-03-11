"""3D-Raumzeit-Visualisierung fuer AetherFingerprints."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from matplotlib import cm, pyplot as plt
from matplotlib.figure import Figure
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401

from .analysis_engine import AetherFingerprint


@dataclass
class AudioVisualVoxel:
    """Ein einzelner synaesthetischer Voxelpunkt fuer Bild und Ton."""

    x: float
    y: float
    z: float
    t_norm: float
    pan: float
    base_frequency: float
    volume: float
    reverb_depth: float
    anomaly_flash: float
    confidence: float
    interference: float
    inside_boundary: bool
    overtone_mode: str
    noise_mode: str
    strobe: float
    is_anchor_star: bool = False
    anchor_type: str = ""
    pulse_scale: float = 1.0


@dataclass
class AudioVisualFrame:
    """Verdichteter synchroner Frame fuer Renderer und Audioengine."""

    phase: float
    pulse_hz: float
    bpm: float
    alpha_1f: float
    mandelbrot_d: float
    symmetry_phi: float
    heisenberg_confidence: float
    noether_alarm: bool
    pink_noise_mix: float
    white_noise_mix: float
    left_right_divergence: float
    boundary_threshold: float
    threshold_plane_z: float
    points: list[AudioVisualVoxel] = field(default_factory=list)
    anchor_stars: list[AudioVisualVoxel] = field(default_factory=list)
    file_category: str = "binary"
    screen_mode: str = ""
    visual_entropy: float = 0.0
    process_cpu: float = 0.0
    process_threads: int = 0
    observer_intensity: float = 0.0
    emergence_intensity: float = 0.0


@dataclass
class RenderScene:
    """Enthaelt den dynamischen Zustand einer gerenderten Raumzeit-Szene."""

    figure: Figure
    ax: Any
    grid_x: np.ndarray
    grid_y: np.ndarray
    base_z: np.ndarray
    entropy_norm: np.ndarray
    anomaly_coordinates: list[tuple[int, int]]
    verdict: str
    raw_points: np.ndarray | None = None
    storage_layer: str = "Heatmap"
    frame_index: int = 0
    fingerprint: AetherFingerprint | None = None
    audiovisual_frame: AudioVisualFrame | None = None


class SpacetimeRenderer:
    """Rendert Entropieinformationen als plastisches, animierbares 3D-Feld."""

    def __init__(self) -> None:
        """Initialisiert den Renderer mit Farb- und Stilprofilen."""
        self.storage_layer = "Heatmap"
        self.verdict_colors = {
            "CLEAN": "#2DE2E6",
            "SUSPICIOUS": "#FF8C42",
            "CRITICAL": "#FF355E",
            "RECURSIVE": "#F2C14E",
        }
        self.verdict_colormaps = {
            "CLEAN": "winter",
            "SUSPICIOUS": "autumn",
            "CRITICAL": "inferno",
            "RECURSIVE": "Wistia",
        }
        self.anomaly_color = "#FFE45E"

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        """Begrenzt Werte robust auf einen Zielbereich."""
        return float(max(low, min(high, value)))

    def set_storage_layer(self, layer_name: str) -> str:
        """Schaltet zwischen Heatmap- und Raw-Delta-Darstellung um."""
        normalized = str(layer_name or "").strip().lower()
        self.storage_layer = "Raw Deltas" if normalized.startswith("raw") else "Heatmap"
        return self.storage_layer

    @staticmethod
    def _normalize(values: np.ndarray, out_max: float) -> np.ndarray:
        """Normiert Werte robust auf einen Zielbereich."""
        if values.size == 0:
            return np.zeros(0, dtype=np.float64)
        low = float(np.min(values))
        high = float(np.max(values))
        span = high - low
        if span <= 1e-9:
            return np.full(values.shape, out_max / 2.0, dtype=np.float64)
        return ((values - low) / span) * float(out_max)

    def _prepare_grid(self, fingerprint: AetherFingerprint) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Bereitet 16x16-Gitter und normalisierte Entropiedaten vor."""
        entropy_values = list(fingerprint.entropy_blocks[:256])
        if len(entropy_values) < 256:
            fill = fingerprint.entropy_mean if fingerprint.entropy_blocks else 0.0
            entropy_values.extend([fill] * (256 - len(entropy_values)))

        entropy_grid = np.array(entropy_values, dtype=np.float64).reshape(16, 16)
        grid_x, grid_y = np.meshgrid(np.arange(16), np.arange(16))
        base_z = -entropy_grid

        min_entropy = float(np.min(entropy_grid))
        max_entropy = float(np.max(entropy_grid))
        span = max_entropy - min_entropy
        if span <= 1e-9:
            entropy_norm = np.zeros_like(entropy_grid, dtype=np.float64)
        else:
            entropy_norm = (entropy_grid - min_entropy) / span
        return grid_x, grid_y, base_z, entropy_norm

    def _prepare_raw_points(self, fingerprint: AetherFingerprint) -> np.ndarray | None:
        """Bereitet rohe 4D-Voxel-Deltas fuer die Weltlinienansicht auf."""
        points = getattr(fingerprint, "voxel_points", None)
        if not points:
            return None

        raw = np.array(points, dtype=np.float64)
        if raw.ndim != 2 or raw.shape[1] < 7:
            return None

        prepared = np.zeros((raw.shape[0], 8), dtype=np.float64)
        prepared[:, 0] = self._normalize(raw[:, 0], 15.0)
        prepared[:, 1] = self._normalize(raw[:, 1], 15.0)
        prepared[:, 2] = self._normalize(raw[:, 2], 15.0)
        prepared[:, 3] = self._normalize(raw[:, 3], 1.0)
        prepared[:, 4] = self._normalize(np.abs(raw[:, 4]), 1.0)
        prepared[:, 5] = self._normalize(np.abs(raw[:, 5]), 1.0)
        prepared[:, 6] = self._normalize(np.abs(raw[:, 6]), 1.0)
        prepared[:, 7] = np.clip(raw[:, 7], -1.0, 1.0) if raw.shape[1] > 7 else 0.0
        return prepared

    def _beauty_metrics(self, fingerprint: AetherFingerprint | None) -> dict[str, float | bool]:
        """Leitet synaesthetische Steuerwerte aus Beauty- und Beobachtermetriken ab."""
        beauty = dict(getattr(fingerprint, "beauty_signature", {}) or {}) if fingerprint is not None else {}
        alpha_1f = float(beauty.get("alpha_1f", 1.0) or 1.0)
        mandelbrot_d = float(beauty.get("mandelbrot_d", 1.5) or 1.5)
        symmetry_phi = float(
            beauty.get(
                "symmetry_phi",
                self._clamp(float(getattr(fingerprint, "symmetry_score", 100.0) or 100.0) / 100.0, 0.0, 1.0)
                if fingerprint is not None else 1.0,
            )
            or 1.0
        )
        knowledge_ratio = float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0) if fingerprint is not None else 0.0
        h_lambda = float(getattr(fingerprint, "h_lambda", 0.0) or 0.0) if fingerprint is not None else 0.0
        if knowledge_ratio > 0.0:
            observer_confidence = self._clamp(knowledge_ratio, 0.0, 1.0)
        else:
            observer_confidence = self._clamp(1.0 - (h_lambda / 8.0), 0.0, 1.0)
        deviation = self._clamp(abs(mandelbrot_d - 1.5) / 0.9, 0.0, 1.0)
        pink_noise_mix = self._clamp(1.0 - (abs(alpha_1f - 1.0) / 0.7), 0.0, 1.0)
        if alpha_1f < 0.3:
            pink_noise_mix = min(pink_noise_mix, 0.15)
        white_noise_mix = self._clamp(1.0 - pink_noise_mix, 0.0, 1.0)
        noether_alarm = bool(
            (fingerprint is not None and list(getattr(fingerprint, "anomaly_coordinates", []) or []))
            or symmetry_phi < 0.35
            or (fingerprint is not None and str(getattr(fingerprint, "verdict", "")) == "CRITICAL")
        )
        pulse_hz = 0.618 + (self._clamp(abs(alpha_1f - 1.0), 0.0, 1.2) * 2.8) + (1.2 if noether_alarm else 0.0)
        return {
            "alpha_1f": float(alpha_1f),
            "mandelbrot_d": float(mandelbrot_d),
            "symmetry_phi": float(symmetry_phi),
            "heisenberg_confidence": float(observer_confidence),
            "pink_noise_mix": float(pink_noise_mix),
            "white_noise_mix": float(white_noise_mix),
            "left_right_divergence": float(self._clamp((0.35 - symmetry_phi) / 0.35, 0.0, 1.0)),
            "noether_alarm": bool(noether_alarm),
            "pulse_hz": float(self._clamp(pulse_hz, 0.618, 4.8)),
            "mandelbrot_deviation": float(deviation),
        }

    def _observer_frame_metrics(self, fingerprint: AetherFingerprint | None) -> dict[str, float | int | str]:
        """Verdichtet Screen-/Observer-Zustaende fuer Render- und Audio-Frames."""
        if fingerprint is None:
            return {
                "file_category": "binary",
                "screen_mode": "",
                "visual_entropy": 0.0,
                "process_cpu": 0.0,
                "process_threads": 0,
                "observer_intensity": 0.0,
                "emergence_intensity": 0.0,
            }
        file_profile = dict(getattr(fingerprint, "file_profile", {}) or {})
        observer_payload = dict(getattr(fingerprint, "observer_payload", {}) or {})
        visual_state = dict(observer_payload.get("visual_state", {}) or {})
        process_state = dict(observer_payload.get("process_state", {}) or {})
        emergence_layers = list(getattr(fingerprint, "emergence_layers", []) or [])
        screen_payload = dict(getattr(fingerprint, "screen_vision_payload", {}) or {})
        visual_entropy = float(visual_state.get("visual_entropy", 0.0) or 0.0)
        process_cpu = float(process_state.get("cpu_percent", 0.0) or 0.0)
        process_threads = int(process_state.get("threads", 0) or 0)
        screen_mode = str(
            visual_state.get("mode", "")
            or observer_payload.get("screen_vision_mode", "")
            or screen_payload.get("SCREEN_VISION", screen_payload.get("screen_vision", ""))
            or ""
        )
        observer_intensity = self._clamp(
            (
                self._clamp(visual_entropy / 8.0, 0.0, 1.0)
                + self._clamp(process_cpu / 100.0, 0.0, 1.0)
                + self._clamp(process_threads / 32.0, 0.0, 1.0)
            ) / 3.0,
            0.0,
            1.0,
        )
        emergence_intensity = self._clamp(len(emergence_layers) / 4.0, 0.0, 1.0)
        return {
            "file_category": str(file_profile.get("category", "binary") or "binary"),
            "screen_mode": screen_mode,
            "visual_entropy": float(visual_entropy),
            "process_cpu": float(process_cpu),
            "process_threads": int(process_threads),
            "observer_intensity": float(observer_intensity),
            "emergence_intensity": float(emergence_intensity),
        }

    def _boundary_threshold(self, mandelbrot_d: float) -> float:
        """Leitet eine sichtbare Mandelbrot-Grenze im Raster ab."""
        return self._clamp(0.52 + ((float(mandelbrot_d) - 1.5) * 0.28), 0.18, 0.82)

    def _base_rgb(self, mandelbrot_d: float) -> np.ndarray:
        """Mappt die fraktale Abweichung von Blau nach Orange."""
        blue = np.array([0.18, 0.46, 0.98], dtype=np.float64)
        orange = np.array([1.0, 0.56, 0.14], dtype=np.float64)
        deviation = self._clamp(abs(float(mandelbrot_d) - 1.5) / 0.9, 0.0, 1.0)
        return (blue * (1.0 - deviation)) + (orange * deviation)

    def _draw_observer_overlay(self, ax: Any, av_frame: AudioVisualFrame) -> None:
        """Schreibt kompaktes Observer-/Emergenz-Feedback direkt in die Szene."""
        overlay = (
            f"{str(av_frame.file_category or 'binary').upper()} | "
            f"Screen {str(av_frame.screen_mode or 'off')} | "
            f"Hvis {float(av_frame.visual_entropy):.2f} | "
            f"CPU {float(av_frame.process_cpu):.1f}% | "
            f"Threads {int(av_frame.process_threads)} | "
            f"L4 {float(av_frame.emergence_intensity):.2f}"
        )
        ax.text2D(
            0.02,
            0.97,
            overlay,
            transform=ax.transAxes,
            color="#D6E8FF",
            fontsize=8,
            bbox={"facecolor": "#091426", "edgecolor": "#28466F", "alpha": 0.76, "boxstyle": "round,pad=0.28"},
        )

    def _build_audiovisual_frame(
        self,
        scene: RenderScene,
        phase: float,
        dynamic_z: np.ndarray,
    ) -> AudioVisualFrame:
        """Berechnet den gemeinsamen Bild-/Ton-Frame aus exakt demselben Datenstrom."""
        fingerprint = scene.fingerprint
        metrics = self._beauty_metrics(fingerprint)
        observer_metrics = self._observer_frame_metrics(fingerprint)
        boundary_threshold = self._boundary_threshold(float(metrics["mandelbrot_d"]))
        min_z = float(np.min(dynamic_z))
        max_z = float(np.max(dynamic_z))
        threshold_plane_z = min_z + (boundary_threshold * max(1e-6, max_z - min_z))
        anomaly_set = {
            (int(x_pos), int(y_pos))
            for x_pos, y_pos in list(scene.anomaly_coordinates or [])
            if 0 <= int(x_pos) < 16 and 0 <= int(y_pos) < 16
        }
        overtone_mode = "harmonic"
        if float(metrics["mandelbrot_d"]) < 1.2:
            overtone_mode = "unison"
        elif float(metrics["mandelbrot_d"]) > 2.1:
            overtone_mode = "inharmonic"
        noise_mode = "pink" if float(metrics["alpha_1f"]) >= 0.3 else "white"

        points: list[AudioVisualVoxel] = []
        if scene.raw_points is not None and scene.raw_points.size > 0:
            ordered = scene.raw_points[np.argsort(scene.raw_points[:, 3])]
            for row in ordered:
                x_norm = self._clamp(float(row[0]) / 15.0, 0.0, 1.0)
                y_norm = self._clamp(float(row[1]) / 15.0, 0.0, 1.0)
                z_norm = self._clamp(float(row[2]) / 15.0, 0.0, 1.0)
                t_norm = self._clamp(float(row[3]), 0.0, 1.0)
                delta_norm = self._clamp(float(row[4]), 0.0, 1.0)
                amp_norm = self._clamp(float(row[6]), 0.0, 1.0)
                interference = self._clamp(float(row[7]) if row.shape[0] > 7 else 0.0, -1.0, 1.0)
                cell = (int(round(float(row[0]))), int(round(float(row[1]))))
                inside_boundary = ((0.42 * delta_norm) + (0.38 * amp_norm) + (0.20 * z_norm)) <= boundary_threshold
                anomaly_flash = 1.0 if cell in anomaly_set and bool(metrics["noether_alarm"]) else 0.0
                points.append(
                    AudioVisualVoxel(
                        x=x_norm,
                        y=y_norm,
                        z=z_norm,
                        t_norm=t_norm,
                        pan=(x_norm * 2.0) - 1.0,
                        base_frequency=220.0 * (1.0 + y_norm),
                        volume=self._clamp((0.12 + (0.74 * amp_norm) + (0.18 * delta_norm)) * (0.55 + 0.45 * float(metrics["heisenberg_confidence"])), 0.0, 1.0),
                        reverb_depth=self._clamp((0.55 * z_norm) + (0.45 * (1.0 - float(metrics["mandelbrot_deviation"]))), 0.0, 1.0),
                        anomaly_flash=anomaly_flash,
                        confidence=float(metrics["heisenberg_confidence"]),
                        interference=interference,
                        inside_boundary=inside_boundary,
                        overtone_mode=overtone_mode,
                        noise_mode=noise_mode,
                        strobe=0.0 if inside_boundary else 1.0,
                    )
                )
        else:
            for y_idx in range(scene.entropy_norm.shape[0]):
                for x_idx in range(scene.entropy_norm.shape[1]):
                    energy = self._clamp(float(scene.entropy_norm[y_idx, x_idx]), 0.0, 1.0)
                    z_norm = self._clamp((float(dynamic_z[y_idx, x_idx]) - min_z) / max(1e-6, max_z - min_z), 0.0, 1.0)
                    inside_boundary = energy <= boundary_threshold
                    anomaly_flash = 1.0 if (x_idx, y_idx) in anomaly_set and bool(metrics["noether_alarm"]) else 0.0
                    points.append(
                        AudioVisualVoxel(
                            x=float(x_idx) / 15.0,
                            y=float(y_idx) / 15.0,
                            z=z_norm,
                            t_norm=self._clamp(phase % 1.0, 0.0, 1.0),
                            pan=(float(x_idx) / 7.5) - 1.0,
                            base_frequency=220.0 * (1.0 + (float(y_idx) / 15.0)),
                            volume=self._clamp((0.08 + (0.82 * energy)) * (0.55 + 0.45 * float(metrics["heisenberg_confidence"])), 0.0, 1.0),
                            reverb_depth=self._clamp((0.55 * z_norm) + (0.45 * (1.0 - float(metrics["mandelbrot_deviation"]))), 0.0, 1.0),
                            anomaly_flash=anomaly_flash,
                            confidence=float(metrics["heisenberg_confidence"]),
                            interference=0.0,
                            inside_boundary=inside_boundary,
                            overtone_mode=overtone_mode,
                            noise_mode=noise_mode,
                            strobe=0.0 if inside_boundary else 1.0,
                        )
                    )

        anchor_stars = self._build_anchor_stars(fingerprint, dynamic_z, phase)
        pulse_hz = self._clamp(
            float(metrics["pulse_hz"])
            * (
                1.0
                + (0.12 * float(observer_metrics["observer_intensity"]))
                + (0.08 * float(observer_metrics["emergence_intensity"]))
            ),
            0.618,
            5.4,
        )
        pink_noise_mix = self._clamp(
            float(metrics["pink_noise_mix"]) * (1.0 - (0.18 * float(observer_metrics["observer_intensity"]))),
            0.0,
            1.0,
        )
        white_noise_mix = self._clamp(
            float(metrics["white_noise_mix"])
            + (0.18 * float(observer_metrics["observer_intensity"]))
            + (0.08 * float(observer_metrics["emergence_intensity"])),
            0.0,
            1.0,
        )
        mix_total = max(1e-6, pink_noise_mix + white_noise_mix)
        pink_noise_mix = pink_noise_mix / mix_total
        white_noise_mix = white_noise_mix / mix_total

        return AudioVisualFrame(
            phase=float(phase),
            pulse_hz=float(pulse_hz),
            bpm=float(pulse_hz) * 60.0,
            alpha_1f=float(metrics["alpha_1f"]),
            mandelbrot_d=float(metrics["mandelbrot_d"]),
            symmetry_phi=float(metrics["symmetry_phi"]),
            heisenberg_confidence=float(metrics["heisenberg_confidence"]),
            noether_alarm=bool(metrics["noether_alarm"]),
            pink_noise_mix=float(pink_noise_mix),
            white_noise_mix=float(white_noise_mix),
            left_right_divergence=float(metrics["left_right_divergence"]),
            boundary_threshold=float(boundary_threshold),
            threshold_plane_z=float(threshold_plane_z),
            points=points,
            anchor_stars=anchor_stars,
            file_category=str(observer_metrics["file_category"]),
            screen_mode=str(observer_metrics["screen_mode"]),
            visual_entropy=float(observer_metrics["visual_entropy"]),
            process_cpu=float(observer_metrics["process_cpu"]),
            process_threads=int(observer_metrics["process_threads"]),
            observer_intensity=float(observer_metrics["observer_intensity"]),
            emergence_intensity=float(observer_metrics["emergence_intensity"]),
        )

    def _build_anchor_stars(
        self,
        fingerprint: AetherFingerprint | None,
        dynamic_z: np.ndarray,
        phase: float,
    ) -> list[AudioVisualVoxel]:
        """Leitet AE-Anker als visuell getrennte Sternpunkte fuer das Raster ab."""
        if fingerprint is None:
            return []
        stars: list[AudioVisualVoxel] = []
        for raw_star in list(getattr(fingerprint, "ae_anchor_stars", []) or [])[:24]:
            if not isinstance(raw_star, dict):
                continue
            x_norm = self._clamp(float(raw_star.get("x", 0.5) or 0.5), 0.0, 1.0)
            y_norm = self._clamp(float(raw_star.get("y", 0.5) or 0.5), 0.0, 1.0)
            x_idx = int(round(x_norm * 15.0))
            y_idx = int(round(y_norm * 15.0))
            base_z = float(dynamic_z[y_idx, x_idx]) if 0 <= y_idx < 16 and 0 <= x_idx < 16 else 0.0
            z_norm = self._clamp(float(raw_star.get("z", 0.78) or 0.78), 0.0, 1.0)
            stars.append(
                AudioVisualVoxel(
                    x=x_norm,
                    y=y_norm,
                    z=self._clamp((base_z + (1.1 + (1.5 * z_norm))) / 15.0, 0.0, 1.0),
                    t_norm=self._clamp(float(raw_star.get("t_norm", phase % 1.0) or (phase % 1.0)), 0.0, 1.0),
                    pan=(x_norm * 2.0) - 1.0,
                    base_frequency=float(raw_star.get("base_frequency", 440.0) or 440.0),
                    volume=self._clamp(float(raw_star.get("volume", 0.9) or 0.9), 0.0, 1.0),
                    reverb_depth=self._clamp(float(raw_star.get("reverb_depth", 0.12) or 0.12), 0.0, 1.0),
                    anomaly_flash=0.0,
                    confidence=self._clamp(float(raw_star.get("confidence", 0.95) or 0.95), 0.0, 1.0),
                    interference=0.0,
                    inside_boundary=True,
                    overtone_mode="unison",
                    noise_mode="pink",
                    strobe=0.0,
                    is_anchor_star=True,
                    anchor_type=str(raw_star.get("type_label", "")),
                    pulse_scale=self._clamp(float(raw_star.get("pulse_scale", 1.0) or 1.0), 0.6, 2.4),
                )
            )
        return stars

    def _setup_axis_style(self, ax: Any) -> None:
        """Setzt dunkles Raumzeit-Styling mit kontrastreichen Achsen."""
        ax.set_facecolor("#0A0F2E")
        ax.xaxis.set_pane_color((0.06, 0.08, 0.20, 0.9))
        ax.yaxis.set_pane_color((0.06, 0.08, 0.20, 0.9))
        ax.zaxis.set_pane_color((0.03, 0.05, 0.12, 0.9))
        ax.grid(True, color="#4F6FD6", alpha=0.42, linewidth=0.9)
        ax.set_xlabel("X", color="#C5D4FF")
        ax.set_ylabel("Y", color="#C5D4FF")
        ax.set_zlabel("Raumzeit-Kruemmung", color="#C5D4FF")
        ax.set_xticks(np.arange(0, 16, 1))
        ax.set_yticks(np.arange(0, 16, 1))
        ax.tick_params(colors="#A7B7E2", labelsize=8)

    def _dynamic_z(self, scene: RenderScene, phase: float) -> np.ndarray:
        """Berechnet eine plastische Wellenverformung fuer fluessige Bewegung."""
        radial = np.sqrt((scene.grid_x - 7.5) ** 2 + (scene.grid_y - 7.5) ** 2)
        wave_primary = np.sin(radial * 0.9 - phase * 1.2) * (0.10 + 0.32 * scene.entropy_norm)
        wave_secondary = np.cos((scene.grid_x * 0.45 + scene.grid_y * 0.55) + phase * 0.8) * 0.12
        return scene.base_z - wave_primary - wave_secondary

    def _dynamic_facecolors(self, scene: RenderScene, phase: float, av_frame: AudioVisualFrame) -> np.ndarray:
        """Erzeugt synaesthetische Verlauf-Farben passend zu Mandelbrot, Symmetrie und Alarmen."""
        base_rgb = self._base_rgb(av_frame.mandelbrot_d)
        inside_mask = scene.entropy_norm <= float(av_frame.boundary_threshold)
        breathe = 0.62 + 0.38 * np.sin(
            (phase * av_frame.pulse_hz * 2.0 * np.pi)
            + (scene.grid_x * 0.17)
            + (scene.grid_y * 0.11)
        )
        strobe = np.where(
            np.sin((phase * (1.8 + av_frame.pulse_hz) * 2.0 * np.pi) + (scene.grid_x * 0.23)) > 0.1,
            1.0,
            0.18,
        )
        pulse = np.where(inside_mask, breathe, strobe)
        intensity = np.clip((0.32 + (0.68 * scene.entropy_norm)) * pulse, 0.0, 1.0)
        colors = np.zeros(scene.entropy_norm.shape + (4,), dtype=np.float64)
        colors[..., :3] = np.clip(base_rgb.reshape(1, 1, 3) * intensity[..., None], 0.0, 1.0)
        colors[..., 3] = np.clip(0.18 + (0.74 * av_frame.heisenberg_confidence) + (0.08 * scene.entropy_norm), 0.18, 0.98)
        if av_frame.noether_alarm and scene.anomaly_coordinates:
            flash = 0.55 + 0.45 * np.sin((phase * (2.2 + av_frame.pulse_hz) * 2.0 * np.pi))
            for x_pos, y_pos in scene.anomaly_coordinates:
                if 0 <= int(x_pos) < 16 and 0 <= int(y_pos) < 16:
                    colors[int(y_pos), int(x_pos), :3] = np.array([1.0, 0.12 + 0.18 * flash, 0.22 + 0.14 * flash], dtype=np.float64)
                    colors[int(y_pos), int(x_pos), 3] = 0.96
        return colors

    def _draw_boundary_plane(self, ax: Any, scene: RenderScene, av_frame: AudioVisualFrame) -> None:
        """Zeichnet die sichtbare Mandelbrot-Grenzebene im 3D-Feld."""
        plane = np.full(scene.grid_x.shape, float(av_frame.threshold_plane_z), dtype=np.float64)
        plane_rgb = self._base_rgb(av_frame.mandelbrot_d)
        plane_color = tuple(float(value) for value in plane_rgb.tolist())
        ax.plot_surface(
            scene.grid_x,
            scene.grid_y,
            plane,
            color=plane_color,
            linewidth=0.0,
            antialiased=False,
            shade=False,
            alpha=0.10 + (0.05 * (1.0 - av_frame.white_noise_mix)),
        )
        ax.plot_wireframe(
            scene.grid_x,
            scene.grid_y,
            plane,
            color="#7AB6FF" if av_frame.mandelbrot_d <= 2.1 else "#FF8C42",
            linewidth=0.25,
            alpha=0.28,
        )

    def _draw_detection_raster(
        self,
        ax: Any,
        scene: RenderScene,
        dynamic_z: np.ndarray,
        av_frame: AudioVisualFrame,
    ) -> None:
        """Zeichnet ein deutlich sichtbares Diagnose-Raster fuer schnelle Malware- und Anomaliepruefung."""
        floor_z = float(np.min(dynamic_z)) - 0.55
        for index in range(16):
            is_major = index % 4 == 0
            color = "#A8C9FF" if is_major else "#3656B2"
            width = 1.45 if is_major else 0.7
            alpha = 0.62 if is_major else 0.34
            ax.plot(
                [index, index],
                [0, 15],
                [floor_z, floor_z],
                color=color,
                linewidth=width,
                alpha=alpha,
                zorder=0,
            )
            ax.plot(
                [0, 15],
                [index, index],
                [floor_z, floor_z],
                color=color,
                linewidth=width,
                alpha=alpha,
                zorder=0,
            )

        suspicious_cells: set[tuple[int, int]] = set()
        for x_pos, y_pos in list(scene.anomaly_coordinates or []):
            if 0 <= int(x_pos) < 16 and 0 <= int(y_pos) < 16:
                suspicious_cells.add((int(x_pos), int(y_pos)))

        entropy_threshold = 0.78 if scene.verdict in {"SUSPICIOUS", "CRITICAL"} else 0.9
        hot_y, hot_x = np.where(scene.entropy_norm >= entropy_threshold)
        for y_pos, x_pos in zip(hot_y.tolist(), hot_x.tolist()):
            suspicious_cells.add((int(x_pos), int(y_pos)))

        outline_color = "#FF6B57" if scene.verdict == "CRITICAL" else "#FFB347"
        for x_pos, y_pos in sorted(suspicious_cells):
            x0 = max(0.0, float(x_pos) - 0.48)
            x1 = min(15.0, float(x_pos) + 0.48)
            y0 = max(0.0, float(y_pos) - 0.48)
            y1 = min(15.0, float(y_pos) + 0.48)
            ax.plot(
                [x0, x1, x1, x0, x0],
                [y0, y0, y1, y1, y0],
                [floor_z + 0.02] * 5,
                color=outline_color,
                linewidth=2.0,
                alpha=0.92,
            )

        ax.text2D(
            0.02,
            0.965,
            "Rasterdiagnose: helle Linien = Hauptzellen | orange/rot = auffaellige Felder",
            transform=ax.transAxes,
            color="#F6D58E",
            fontsize=9,
            fontweight="bold",
        )

    def _voxel_rgba(self, point: AudioVisualVoxel, av_frame: AudioVisualFrame, phase: float) -> np.ndarray:
        """Leitet die synaesthetische RGBA-Farbe eines Voxels ab."""
        if point.is_anchor_star:
            pulse = 0.68 + 0.32 * math.sin(
                (phase * av_frame.pulse_hz * point.pulse_scale * 2.0 * math.pi)
                + (point.t_norm * math.pi)
            )
            flash = 0.78 + 0.22 * max(0.0, pulse)
            return np.array([flash, flash, 1.0, 0.96], dtype=np.float64)
        base_rgb = self._base_rgb(av_frame.mandelbrot_d)
        if point.inside_boundary:
            pulse = 0.58 + 0.42 * math.sin((phase * av_frame.pulse_hz * 2.0 * math.pi) + (point.t_norm * math.pi))
        else:
            pulse = 1.0 if math.sin((phase * (1.7 + av_frame.pulse_hz) * 2.0 * math.pi) + (point.x * math.pi)) > 0.1 else 0.16
        rgb = np.clip(base_rgb * (0.34 + (0.66 * point.volume)) * pulse, 0.0, 1.0)
        if point.anomaly_flash > 0.0 and av_frame.noether_alarm:
            flash = 0.55 + 0.45 * math.sin((phase * (2.2 + av_frame.pulse_hz) * 2.0 * math.pi))
            rgb = np.array([1.0, 0.14 + (0.18 * flash), 0.24 + (0.12 * flash)], dtype=np.float64)
        alpha = self._clamp(0.22 + (0.62 * point.confidence) + (0.18 * point.volume), 0.22, 0.98)
        return np.array([rgb[0], rgb[1], rgb[2], alpha], dtype=np.float64)

    def _draw_anchor_stars(self, ax: Any, av_frame: AudioVisualFrame, phase: float) -> tuple[float, float] | None:
        """Zeichnet AE-Anker als helle pulsierende Sterne ueber dem Raster."""
        stars = list(av_frame.anchor_stars or [])
        if not stars:
            return None
        x_points = [point.x * 15.0 for point in stars]
        y_points = [point.y * 15.0 for point in stars]
        z_points = [1.2 + (point.z * 14.5) for point in stars]
        colors = np.array([self._voxel_rgba(point, av_frame, phase) for point in stars], dtype=np.float64)
        sizes = np.array(
            [
                120.0
                + (110.0 * point.volume)
                + (34.0 * (1.0 + math.sin((phase * av_frame.pulse_hz * point.pulse_scale * 2.0 * math.pi))))
                for point in stars
            ],
            dtype=np.float64,
        )
        ax.scatter(
            x_points,
            y_points,
            z_points,
            c=colors,
            s=sizes,
            marker="*",
            edgecolors="#FFF8D6",
            linewidths=0.7,
            depthshade=False,
            alpha=0.98,
        )
        return float(min(z_points)), float(max(z_points))

    def _draw_frame(self, scene: RenderScene, phase: float) -> None:
        """Zeichnet einen kompletten dynamischen Render-Frame."""
        ax = scene.ax
        ax.cla()
        self._setup_axis_style(ax)
        dynamic_z = self._dynamic_z(scene, phase)
        av_frame = self._build_audiovisual_frame(scene, phase, dynamic_z)
        scene.audiovisual_frame = av_frame

        if scene.storage_layer == "Raw Deltas" and scene.raw_points is not None and scene.raw_points.size > 0:
            self._draw_raw_delta_layer(scene, phase, av_frame)
            self._draw_observer_overlay(ax, av_frame)
            return

        facecolors = self._dynamic_facecolors(scene, phase, av_frame)
        wire_color = self.verdict_colors.get(scene.verdict, "#2DE2E6")
        self._draw_boundary_plane(ax, scene, av_frame)
        self._draw_detection_raster(ax, scene, dynamic_z, av_frame)

        ax.plot_surface(
            scene.grid_x,
            scene.grid_y,
            dynamic_z,
            rcount=16,
            ccount=16,
            facecolors=facecolors,
            linewidth=0.0,
            antialiased=True,
            shade=False,
            alpha=0.94,
        )

        wire_width = 0.55 + (0.14 * (1.0 + np.sin(phase)))
        ax.plot_wireframe(
            scene.grid_x,
            scene.grid_y,
            dynamic_z,
            color=wire_color,
            linewidth=wire_width,
            alpha=0.62,
        )

        point_sizes = 12.0 + (78.0 * scene.entropy_norm)
        ax.scatter(
            scene.grid_x.flatten(),
            scene.grid_y.flatten(),
            dynamic_z.flatten(),
            c=facecolors.reshape(-1, 4),
            s=point_sizes.flatten(),
            marker="o",
            alpha=0.72,
            edgecolors="none",
            depthshade=False,
        )

        if av_frame.points:
            overlay = sorted(av_frame.points, key=lambda item: item.volume + (0.35 * item.anomaly_flash), reverse=True)[:180]
            if overlay:
                x_points = [point.x * 15.0 for point in overlay]
                y_points = [point.y * 15.0 for point in overlay]
                z_points = [float(dynamic_z[int(round(point.y * 15.0)), int(round(point.x * 15.0))]) + (point.z * 2.8) - 0.8 for point in overlay]
                rgba = np.array([self._voxel_rgba(point, av_frame, phase) for point in overlay], dtype=np.float64)
                sizes = np.array([26.0 + (92.0 * point.volume) + (28.0 * point.anomaly_flash) for point in overlay], dtype=np.float64)
                ax.scatter(
                    x_points,
                    y_points,
                    z_points,
                    c=rgba,
                    s=sizes,
                    marker="o",
                    edgecolors="none",
                    depthshade=False,
                )

        star_bounds = self._draw_anchor_stars(ax, av_frame, phase)

        if scene.anomaly_coordinates:
            pulse = 105.0 + 55.0 * (1.0 + np.sin(phase * 2.0))
            anomaly_x: list[int] = []
            anomaly_y: list[int] = []
            anomaly_z: list[float] = []
            for x_pos, y_pos in scene.anomaly_coordinates:
                if 0 <= x_pos < 16 and 0 <= y_pos < 16:
                    anomaly_x.append(x_pos)
                    anomaly_y.append(y_pos)
                    anomaly_z.append(float(dynamic_z[y_pos, x_pos]))
            if anomaly_x:
                ax.scatter(
                    anomaly_x,
                    anomaly_y,
                    anomaly_z,
                    c=self.anomaly_color,
                    s=pulse,
                    marker="o",
                    edgecolors="#151515",
                    linewidths=0.8,
                    alpha=0.95,
                    depthshade=True,
                )

        min_z = float(np.min(scene.base_z)) - 0.9
        max_z = float(np.max(scene.base_z)) + 0.8
        if star_bounds is not None:
            min_z = min(min_z, float(star_bounds[0]) - 0.8)
            max_z = max(max_z, float(star_bounds[1]) + 0.8)
        if min_z == max_z:
            max_z += 1.0
        ax.set_xlim(0, 15)
        ax.set_ylim(0, 15)
        ax.set_zlim(min_z, max_z)

        azim = (35.0 + (phase * 15.0)) % 360.0
        elev = 26.0 + (5.0 * np.sin(phase * 0.45))
        ax.view_init(elev=elev, azim=azim)
        ax.set_title("Aether Rasterdiagnose - Malware und Strukturfeld", color="#DDF9FF", pad=14)
        self._draw_observer_overlay(ax, av_frame)

    def _draw_raw_delta_layer(self, scene: RenderScene, phase: float, av_frame: AudioVisualFrame) -> None:
        """Zeichnet rohe 4D-Deltas als Weltlinien ueber einem leichten Heatmap-Feld."""
        ax = scene.ax
        dynamic_z = self._dynamic_z(scene, phase)
        backdrop = self._dynamic_facecolors(scene, phase, av_frame)
        ax.plot_surface(
            scene.grid_x,
            scene.grid_y,
            dynamic_z,
            rcount=16,
            ccount=16,
            facecolors=backdrop,
            linewidth=0.0,
            antialiased=True,
            shade=False,
            alpha=0.16,
        )
        self._draw_boundary_plane(ax, scene, av_frame)
        self._draw_detection_raster(ax, scene, dynamic_z, av_frame)

        wire_color = self.verdict_colors.get(scene.verdict, "#2DE2E6")
        raw = scene.raw_points
        assert raw is not None
        order = np.argsort(raw[:, 3])
        ordered = raw[order]
        ordered_points = sorted(av_frame.points, key=lambda item: item.t_norm)
        x_points = np.array([point.x * 15.0 for point in ordered_points], dtype=np.float64)
        y_points = np.array([point.y * 15.0 for point in ordered_points], dtype=np.float64)
        z_points = np.array(
            [(0.68 * point.z * 15.0) + (point.t_norm * 6.0) - 2.0 for point in ordered_points],
            dtype=np.float64,
        )
        colors = np.array([self._voxel_rgba(point, av_frame, phase) for point in ordered_points], dtype=np.float64)
        sizes = np.array(
            [20.0 + (120.0 * point.volume) + (40.0 * max(0.0, point.anomaly_flash)) for point in ordered_points],
            dtype=np.float64,
        )

        ax.scatter(
            x_points,
            y_points,
            z_points,
            c=colors,
            s=sizes,
            marker="o",
            edgecolors="none",
            depthshade=False,
        )
        if ordered.shape[0] > 1:
            ax.plot(
                x_points,
                y_points,
                z_points,
                color=wire_color,
                linewidth=1.1 + 0.4 * np.sin(phase),
                alpha=0.46,
            )

        if scene.anomaly_coordinates:
            highlight_x = []
            highlight_y = []
            highlight_z = []
            for x_pos, y_pos in scene.anomaly_coordinates:
                if 0 <= x_pos < 16 and 0 <= y_pos < 16:
                    highlight_x.append(x_pos)
                    highlight_y.append(y_pos)
                    highlight_z.append(float(dynamic_z[y_pos, x_pos]))
            if highlight_x:
                ax.scatter(
                    highlight_x,
                    highlight_y,
                    highlight_z,
                    c=self.anomaly_color,
                    s=92.0 + 34.0 * (1.0 + np.sin(phase * 1.8)),
                    marker="o",
                    edgecolors="#111111",
                    linewidths=0.8,
                    alpha=0.92,
                    depthshade=True,
                )

        star_bounds = self._draw_anchor_stars(ax, av_frame, phase)

        min_z = min(float(np.min(scene.base_z)) - 1.0, float(np.min(z_points)) - 1.0)
        max_z = max(float(np.max(scene.base_z)) + 1.0, float(np.max(z_points)) + 1.0)
        if star_bounds is not None:
            min_z = min(min_z, float(star_bounds[0]) - 0.8)
            max_z = max(max_z, float(star_bounds[1]) + 0.8)
        if min_z == max_z:
            max_z += 1.0
        ax.set_xlim(0, 15)
        ax.set_ylim(0, 15)
        ax.set_zlim(min_z, max_z)
        ax.set_zlabel("Z / Zeit-Offset", color="#C5D4FF")

        azim = (48.0 + (phase * 18.0)) % 360.0
        elev = 24.0 + (6.0 * np.sin(phase * 0.35))
        ax.view_init(elev=elev, azim=azim)
        ax.set_title("Aether Rasterdiagnose - 4D Weltlinien und Delta-Spuren", color="#DDF9FF", pad=14)

    def create_dynamic_scene(self, fingerprint: AetherFingerprint) -> RenderScene:
        """
        Erzeugt eine animierbare 3D-Szene mit plastischer Oberflaeche.

        Args:
            fingerprint: Ergebnisobjekt der Analyse.
        """
        figure = plt.Figure(figsize=(8, 6), facecolor="#050816")
        ax = figure.add_subplot(111, projection="3d")
        grid_x, grid_y, base_z, entropy_norm = self._prepare_grid(fingerprint)
        scene = RenderScene(
            figure=figure,
            ax=ax,
            grid_x=grid_x,
            grid_y=grid_y,
            base_z=base_z,
            entropy_norm=entropy_norm,
            anomaly_coordinates=list(fingerprint.anomaly_coordinates),
            verdict=fingerprint.verdict,
            raw_points=self._prepare_raw_points(fingerprint),
            storage_layer=self.storage_layer,
            fingerprint=fingerprint,
        )
        self._draw_frame(scene, phase=0.0)
        return scene

    def apply_fingerprint_to_scene(self, scene: RenderScene, fingerprint: AetherFingerprint) -> None:
        """
        Aktualisiert eine bestehende Szene mit neuen Fingerprint-Daten ohne Figure-Neuaufbau.

        Args:
            scene: Bereits aktive Szene.
            fingerprint: Neuer Analysezustand.
        """
        grid_x, grid_y, base_z, entropy_norm = self._prepare_grid(fingerprint)
        scene.grid_x = grid_x
        scene.grid_y = grid_y
        scene.base_z = base_z
        scene.entropy_norm = entropy_norm
        scene.anomaly_coordinates = list(fingerprint.anomaly_coordinates)
        scene.verdict = fingerprint.verdict
        scene.raw_points = self._prepare_raw_points(fingerprint)
        scene.storage_layer = self.storage_layer
        scene.fingerprint = fingerprint

    def update_dynamic_scene(self, scene: RenderScene) -> None:
        """
        Aktualisiert eine bestehende Szene um einen Animationsschritt.

        Args:
            scene: Bereits erzeugter dynamischer Szenenzustand.
        """
        scene.frame_index += 1
        phase = scene.frame_index * 0.09
        self._draw_frame(scene, phase=phase)

    def render(self, fingerprint: AetherFingerprint) -> Figure:
        """
        Rendert eine statische Momentaufnahme der dynamischen Szene.

        Args:
            fingerprint: Ergebnisobjekt der Analyse.
        """
        return self.create_dynamic_scene(fingerprint).figure

    def get_state_description(self, fingerprint: AetherFingerprint) -> str:
        """
        Liefert eine deutsche Statusbeschreibung fuer den aktuellen Analysezustand.

        Args:
            fingerprint: Ergebnisobjekt der Analyse.
        """
        if fingerprint.verdict == "RECURSIVE":
            return "Rekursive Selbstbeobachtung aktiv - Goldresonanz stabil"
        if fingerprint.verdict == "CRITICAL":
            return "Kritische Raumzeit-Kruemmung - Anomalie bestaetigt"
        if fingerprint.verdict == "SUSPICIOUS" or fingerprint.anomaly_coordinates:
            return "Lokale Verwerfungen erkannt - Analyse empfohlen"
        return "Symmetrisches Feld - keine Anomalien erkannt"
