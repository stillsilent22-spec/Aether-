"""Echtzeit-Theremin-Engine fuer Webcam-basierte Spektrumsynthese."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import cv2
import numpy as np

from .analysis_engine import AetherFingerprint
from .audio_engine import AudioEngine
from .ethics_engine import EthicsEngine
from .registry import AetherRegistry
from .session_engine import SessionContext
from .spectrum_engine import SpectrumEngine, SpectrumFingerprint
from .voxel_grid import VoxelDelta

try:
    import sounddevice as sd
except Exception:
    sd = None


@dataclass
class ThereminFrameState:
    """Beschreibt den Zustand eines einzelnen Theremin-Frames."""

    session_id: str
    timestamp: str
    frame_index: int
    entropy_red: float
    entropy_green: float
    entropy_blue: float
    entropy_total: float
    dominant_wavelength_nm: float
    dominant_color_rgb: tuple[int, int, int]
    bass_freq: float
    mid_freq: float
    high_freq: float
    volume: float
    dissonance: float
    hand_detected: bool
    hand_proximity: float
    recursive_state: bool
    recursion_collapsed: bool
    anomaly_detected: bool
    delta: bytes
    delta_ratio: float
    noise_seed: int
    verdict: str
    mic_peak_freq: float
    mic_peak_level: float
    voxel_x: float
    voxel_y: float
    voxel_z: float
    voxel_t: float
    voxel_delta: float
    voxel_freq: float
    voxel_amp: float
    symmetry_score: float
    coherence_score: float
    resonance_score: float
    ethics_score: float
    integrity_state: str
    integrity_text: str

    def to_dict(self) -> dict[str, object]:
        """Serialisiert den Frame-Zustand fuer Persistenz und Logging."""
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "frame_index": int(self.frame_index),
            "entropy_red": float(self.entropy_red),
            "entropy_green": float(self.entropy_green),
            "entropy_blue": float(self.entropy_blue),
            "entropy_total": float(self.entropy_total),
            "dominant_wavelength_nm": float(self.dominant_wavelength_nm),
            "dominant_color_rgb": [int(self.dominant_color_rgb[0]), int(self.dominant_color_rgb[1]), int(self.dominant_color_rgb[2])],
            "bass_freq": float(self.bass_freq),
            "mid_freq": float(self.mid_freq),
            "high_freq": float(self.high_freq),
            "volume": float(self.volume),
            "dissonance": float(self.dissonance),
            "hand_detected": bool(self.hand_detected),
            "hand_proximity": float(self.hand_proximity),
            "recursive_state": bool(self.recursive_state),
            "recursion_collapsed": bool(self.recursion_collapsed),
            "anomaly_detected": bool(self.anomaly_detected),
            "delta": self.delta.hex(),
            "delta_ratio": float(self.delta_ratio),
            "noise_seed": int(self.noise_seed),
            "verdict": self.verdict,
            "mic_peak_freq": float(self.mic_peak_freq),
            "mic_peak_level": float(self.mic_peak_level),
            "voxel_x": float(self.voxel_x),
            "voxel_y": float(self.voxel_y),
            "voxel_z": float(self.voxel_z),
            "voxel_t": float(self.voxel_t),
            "voxel_delta": float(self.voxel_delta),
            "voxel_freq": float(self.voxel_freq),
            "voxel_amp": float(self.voxel_amp),
            "symmetry_score": float(self.symmetry_score),
            "coherence_score": float(self.coherence_score),
            "resonance_score": float(self.resonance_score),
            "ethics_score": float(self.ethics_score),
            "integrity_state": self.integrity_state,
            "integrity_text": self.integrity_text,
        }


class ThereminEngine:
    """Fuehrt Echtzeit-Webcam-Analyse mit Klang- und Gitterrueckkopplung aus."""

    def __init__(
        self,
        session_context: SessionContext,
        spectrum_engine: SpectrumEngine,
        registry: AetherRegistry,
        audio_engine: AudioEngine,
        target_fps: int = 14,
        camera_index: int = 0,
    ) -> None:
        """
        Initialisiert die Theremin-Engine.

        Args:
            session_context: Aktive Session fuer Delta-Deterministik.
            spectrum_engine: Spektrumanalyse-Modul fuer Frames.
            registry: Persistente Registry fuer Frame-Metriken.
            audio_engine: Audioausgabe fuer Echtzeitsynthese.
            target_fps: Zielrate fuer Frame-Verarbeitung.
            camera_index: Index der zu oeffnenden Webcam.
        """
        self.session_context = session_context
        self.spectrum_engine = spectrum_engine
        self.registry = registry
        self.audio_engine = audio_engine
        self.ethics_engine = EthicsEngine()
        self.target_fps = max(4, int(target_fps))
        self.camera_index = camera_index

        self._running = threading.Event()
        self._thread: threading.Thread | None = None
        self._capture: cv2.VideoCapture | None = None
        self._frame_callback: Callable[[ThereminFrameState, AetherFingerprint], None] | None = None
        self._status_callback: Callable[[str], None] | None = None
        self._sensitivity_getter: Callable[[], float] | None = None
        self._blend_getter: Callable[[], float] | None = None
        self._frame_index = 0
        self._entropy_history: deque[float] = deque(maxlen=420)
        self._recursive_last = False
        self._last_error = ""
        self._mic_stream: Any | None = None
        self._mic_sample_rate = 16_000
        self._mic_lock = threading.Lock()
        self._mic_bins = np.zeros(128, dtype=np.float32)
        self._mic_peak_freq = 0.0
        self._mic_peak_level = 0.0

    @property
    def is_running(self) -> bool:
        """Liefert True, wenn die Theremin-Schleife aktiv ist."""
        return self._running.is_set()

    @property
    def last_error(self) -> str:
        """Liefert die letzte bekannte Fehlermeldung der Theremin-Schleife."""
        return self._last_error

    def start(
        self,
        frame_callback: Callable[[ThereminFrameState, AetherFingerprint], None],
        status_callback: Callable[[str], None],
        sensitivity_getter: Callable[[], float],
        blend_getter: Callable[[], float],
    ) -> bool:
        """
        Startet Webcam-Analyse und Echtzeit-Synthese in einem Hintergrund-Thread.

        Args:
            frame_callback: Callback fuer GUI-Updates pro Frame.
            status_callback: Callback fuer Statusmeldungen.
            sensitivity_getter: Callback fuer Entropie-Sensitivitaet.
            blend_getter: Callback fuer Harmonie-Dissonanz-Mischung.
        """
        if self.is_running:
            status_callback("Kamera-Raster laeuft bereits.")
            return True

        self._frame_callback = frame_callback
        self._status_callback = status_callback
        self._sensitivity_getter = sensitivity_getter
        self._blend_getter = blend_getter
        self._frame_index = 0
        self._entropy_history.clear()
        self._recursive_last = False
        self._last_error = ""

        try:
            self._capture = cv2.VideoCapture(self.camera_index, cv2.CAP_DSHOW)
            if not self._capture.isOpened():
                self._capture = cv2.VideoCapture(self.camera_index)
            if not self._capture.isOpened():
                status_callback("Kamera-Raster konnte nicht starten: Keine Webcam gefunden.")
                return False
            self._capture.set(cv2.CAP_PROP_FRAME_WIDTH, 960)
            self._capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 540)
            self._capture.set(cv2.CAP_PROP_FPS, float(self.target_fps))
        except Exception as exc:
            self._last_error = str(exc)
            status_callback(f"Kamera-Raster-Fehler beim Webcam-Start: {exc}")
            return False

        if not self.audio_engine.start_theremin_stream():
            status_callback("Kamera-Raster startet im visuellen Modus ohne Audio-Stream.")
        if not self._start_mic_input():
            status_callback("Kamera-Raster startet ohne Mikrofon-FFT (kein Eingabegeraet verfuegbar).")

        self._running.set()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        status_callback("Kamera-Raster aktiv. Webcam-Analyse laeuft.")
        return True

    def stop(self) -> None:
        """Stoppt Webcam-Schleife und Audio-Stream sauber."""
        self._running.clear()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.5)
        self._thread = None
        if self._capture is not None:
            try:
                self._capture.release()
            except Exception:
                self._last_error = "Webcam-Ressource konnte nicht sauber freigegeben werden."
        self._capture = None
        self._stop_mic_input()
        self.audio_engine.stop_theremin_stream()
        if self._status_callback is not None:
            self._status_callback("Kamera-Raster gestoppt.")

    def _start_mic_input(self) -> bool:
        """Startet einen Mikrofon-Stream fuer Live-FFT."""
        if sd is None:
            return False
        with self._mic_lock:
            self._mic_bins = np.zeros(128, dtype=np.float32)
            self._mic_peak_freq = 0.0
            self._mic_peak_level = 0.0
            if self._mic_stream is not None:
                return True
            try:
                self._mic_stream = sd.InputStream(
                    samplerate=self._mic_sample_rate,
                    channels=1,
                    dtype="float32",
                    callback=self._audio_input_callback,
                    blocksize=256,
                )
                self._mic_stream.start()
                return True
            except Exception:
                self._mic_stream = None
                return False

    def _stop_mic_input(self) -> None:
        """Stoppt den Mikrofon-Stream sauber."""
        with self._mic_lock:
            if self._mic_stream is None:
                return
            try:
                self._mic_stream.stop()
                self._mic_stream.close()
            except Exception:
                self._last_error = "Mikrofon-Ressource konnte nicht sauber freigegeben werden."
            self._mic_stream = None

    def _audio_input_callback(self, indata: np.ndarray, _frames: int, _time_info: Any, status: Any) -> None:
        """Extrahiert Mikrofon-Level und dominante Frequenz aus dem Eingangssignal."""
        if status or indata is None:
            return
        samples = np.asarray(indata[:, 0], dtype=np.float32)
        if samples.size == 0:
            return

        level = float(np.sqrt(np.mean(np.square(samples))))
        window = np.hanning(samples.size).astype(np.float32)
        spectrum = np.abs(np.fft.rfft(samples * window))
        if spectrum.size <= 1:
            peak_freq = 0.0
        else:
            freqs = np.fft.rfftfreq(samples.size, d=1.0 / float(self._mic_sample_rate))
            peak_index = int(np.argmax(spectrum[1:]) + 1)
            peak_freq = float(freqs[peak_index])

        if spectrum.size == 0:
            binned = np.zeros(128, dtype=np.float32)
        else:
            positions = np.linspace(0, spectrum.size - 1, 128, dtype=np.float32)
            binned = np.interp(positions, np.arange(spectrum.size, dtype=np.float32), spectrum).astype(np.float32)
            peak = float(np.max(binned))
            if peak > 1e-9:
                binned = binned / peak

        with self._mic_lock:
            self._mic_bins = binned
            self._mic_peak_freq = float(peak_freq)
            self._mic_peak_level = float(level)

    def _mic_snapshot(self) -> tuple[np.ndarray, float, float]:
        """Liefert einen threadsicheren Snapshot der letzten Mikrofon-FFT."""
        with self._mic_lock:
            return np.array(self._mic_bins, copy=True), float(self._mic_peak_freq), float(self._mic_peak_level)

    def _loop(self) -> None:
        """Verarbeitet Frames in Echtzeit, mappt Spektrum auf Klang und meldet Ergebnisse."""
        assert self._capture is not None
        while self._running.is_set():
            frame_interval = 1.0 / float(max(4, self.target_fps))
            loop_start = time.perf_counter()
            ok, frame_bgr = self._capture.read()
            if not ok or frame_bgr is None:
                if self._status_callback is not None:
                    self._status_callback("Webcam liefert keine Frames. Kamera-Raster wartet auf Signal.")
                time.sleep(0.12)
                continue
            try:
                frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                spectrum = self.spectrum_engine.analyze_array(
                    frame_rgb,
                    source_label=f"theremin_frame_{self._frame_index}",
                )
                sensitivity = float(max(0.3, min(3.0, self._sensitivity_getter() if self._sensitivity_getter else 1.0)))
                harmonic_blend = float(max(0.0, min(1.0, self._blend_getter() if self._blend_getter else 0.65)))
                _mic_bins, mic_peak_freq, mic_peak_level = self._mic_snapshot()
                hand_detected, hand_proximity, hand_center = self._detect_hand(frame_rgb, sensitivity)
                recursive_state = self._detect_recursive_state(frame_rgb, hand_detected)
                recursion_collapsed = bool(self._recursive_last and hand_detected and not recursive_state)
                self._recursive_last = recursive_state

                bass, mid, high, volume, dissonance = self._map_audio_params(
                    spectrum=spectrum,
                    sensitivity=sensitivity,
                    harmonic_blend=harmonic_blend,
                    hand_proximity=hand_proximity,
                    recursive_state=recursive_state,
                    mic_peak_freq=mic_peak_freq,
                    mic_peak_level=mic_peak_level,
                )

                anomaly_detected = self._detect_session_anomaly(spectrum.entropy_total, sensitivity)
                fingerprint = spectrum.to_aether_fingerprint()
                try:
                    healthy_refs = self.registry.get_resonance_reference_vectors(limit=180)
                except Exception:
                    healthy_refs = []

                ethics = self.ethics_engine.evaluate(
                    symmetry_score=float(fingerprint.symmetry_score),
                    entropy_blocks=list(self._entropy_history)[-128:] or [float(spectrum.entropy_total)],
                    entropy_mean=float(np.mean(spectrum.entropy_blocks) if spectrum.entropy_blocks else spectrum.entropy_total),
                    periodicity=int(round(max(0.0, mic_peak_freq))),
                    delta_ratio=float(spectrum.delta_ratio),
                    healthy_references=healthy_refs,
                )

                verdict = "RECURSIVE" if recursive_state else spectrum.verdict
                if ethics.integrity_state == "STRUCTURAL_ANOMALY" and not recursive_state:
                    verdict = "CRITICAL"
                elif ethics.integrity_state == "STRUCTURAL_TENSION" and verdict == "CLEAN":
                    verdict = "SUSPICIOUS"
                if anomaly_detected and verdict == "CLEAN":
                    verdict = "SUSPICIOUS"

                voxel_t = time.time() * 1000.0
                voxel_x = float(hand_center[0] * 15.0)
                voxel_y = float((1.0 - hand_center[1]) * 15.0)
                voxel_z = float(max(0.0, min(15.0, (hand_proximity * 10.5) + min(4.5, mic_peak_level * 52.0))))
                voxel_delta = float(
                    max(
                        -12.0,
                        min(
                            12.0,
                            ((spectrum.entropy_total / 8.0) - 0.5) * 12.0
                            + (mic_peak_level * 10.0)
                            + (0.9 if anomaly_detected else 0.0)
                            - (0.6 if recursive_state else 0.0),
                        ),
                    )
                )
                voxel_freq = float(mic_peak_freq if mic_peak_freq > 0.0 else mid)
                voxel_amp = float(max(volume, min(1.0, mic_peak_level * 11.0)))

                if recursive_state:
                    self.audio_engine.trigger_recursive_resonance()

                self.audio_engine.update_theremin_state(
                    bass_freq=bass,
                    mid_freq=mid,
                    high_freq=high,
                    volume=volume,
                    dissonance=dissonance,
                    harmonic_blend=harmonic_blend,
                    recursive_state=recursive_state,
                    hand_proximity=hand_proximity,
                )

                frame_state = ThereminFrameState(
                    session_id=self.session_context.session_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    frame_index=self._frame_index,
                    entropy_red=spectrum.entropy_red,
                    entropy_green=spectrum.entropy_green,
                    entropy_blue=spectrum.entropy_blue,
                    entropy_total=spectrum.entropy_total,
                    dominant_wavelength_nm=spectrum.dominant_wavelength_nm,
                    dominant_color_rgb=spectrum.dominant_color_rgb,
                    bass_freq=bass,
                    mid_freq=mid,
                    high_freq=high,
                    volume=volume,
                    dissonance=dissonance,
                    hand_detected=hand_detected,
                    hand_proximity=hand_proximity,
                    recursive_state=recursive_state,
                    recursion_collapsed=recursion_collapsed,
                    anomaly_detected=anomaly_detected,
                    delta=spectrum.delta,
                    delta_ratio=spectrum.delta_ratio,
                    noise_seed=spectrum.noise_seed,
                    verdict=verdict,
                    mic_peak_freq=mic_peak_freq,
                    mic_peak_level=mic_peak_level,
                    voxel_x=voxel_x,
                    voxel_y=voxel_y,
                    voxel_z=voxel_z,
                    voxel_t=voxel_t,
                    voxel_delta=voxel_delta,
                    voxel_freq=voxel_freq,
                    voxel_amp=voxel_amp,
                    symmetry_score=float(ethics.symmetry_component),
                    coherence_score=float(ethics.coherence_score),
                    resonance_score=float(ethics.resonance_score),
                    ethics_score=float(ethics.ethics_score),
                    integrity_state=ethics.integrity_state,
                    integrity_text=ethics.integrity_text,
                )

                fingerprint.verdict = verdict
                fingerprint.source_type = "theremin"
                fingerprint.source_label = f"theremin_frame_{self._frame_index}"
                fingerprint.symmetry_component = float(ethics.symmetry_component)
                fingerprint.coherence_score = float(ethics.coherence_score)
                fingerprint.resonance_score = float(ethics.resonance_score)
                fingerprint.ethics_score = float(ethics.ethics_score)
                fingerprint.integrity_state = ethics.integrity_state
                fingerprint.integrity_text = ethics.integrity_text
                if hand_detected:
                    fingerprint.voxel_points = [
                        (
                            float(voxel_x),
                            float(voxel_y),
                            float(voxel_z),
                            float(voxel_t),
                            float(voxel_delta),
                            float(voxel_freq),
                            float(voxel_amp),
                        )
                    ]
                if recursive_state:
                    fingerprint.anomaly_coordinates = [(7, 7), (8, 7), (7, 8), (8, 8)]

                try:
                    self.registry.save_theremin_frame(frame_state)
                    if hand_detected:
                        self.registry.save_voxel_events(
                            session_id=self.session_context.session_id,
                            source_type="theremin",
                            source_label=f"theremin_frame_{self._frame_index}",
                            voxels=[
                                VoxelDelta(
                                    x=voxel_x,
                                    y=voxel_y,
                                    z=voxel_z,
                                    t=voxel_t,
                                    delta=voxel_delta,
                                    freq=voxel_freq,
                                    amp=voxel_amp,
                                )
                            ],
                        )
                except Exception:
                    if self._status_callback is not None:
                        self._status_callback("Warnung: Kamera-Raster-Frame konnte nicht in Registry gespeichert werden.")

                if self._frame_callback is not None:
                    self._frame_callback(frame_state, fingerprint)
            except Exception as exc:
                self._last_error = str(exc)
                if self._status_callback is not None:
                    self._status_callback(f"Kamera-Raster-Verarbeitung fehlgeschlagen: {exc}")

            self._frame_index += 1
            elapsed = time.perf_counter() - loop_start
            remaining = frame_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)

    def _detect_hand(self, frame_rgb: np.ndarray, sensitivity: float) -> tuple[bool, float, tuple[float, float]]:
        """
        Erkennt Handpraesenz ueber Hautmaske und lokale Texturentropie.

        Args:
            frame_rgb: Aktueller RGB-Frame.
            sensitivity: Entropie-Sensitivitaet aus GUI.
        """
        frame_uint8 = np.asarray(frame_rgb, dtype=np.uint8)
        ycrcb = cv2.cvtColor(frame_uint8, cv2.COLOR_RGB2YCrCb)
        lower = np.array([0, 133, 77], dtype=np.uint8)
        upper = np.array([255, 173, 127], dtype=np.uint8)
        skin_mask = cv2.inRange(ycrcb, lower, upper)
        skin_ratio = float(np.count_nonzero(skin_mask)) / float(max(1, skin_mask.size))

        kernel = np.ones((3, 3), dtype=np.uint8)
        skin_mask = cv2.morphologyEx(skin_mask, cv2.MORPH_OPEN, kernel, iterations=1)
        skin_mask = cv2.morphologyEx(skin_mask, cv2.MORPH_DILATE, kernel, iterations=1)

        contours, _ = cv2.findContours(skin_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        max_area = 0.0
        best_contour = None
        for contour in contours:
            area = cv2.contourArea(contour)
            if area > max_area:
                max_area = area
                best_contour = contour
        frame_area = float(frame_uint8.shape[0] * frame_uint8.shape[1])
        area_ratio = max_area / max(1.0, frame_area)

        gray = cv2.cvtColor(frame_uint8, cv2.COLOR_RGB2GRAY)
        lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())

        hand_detected = bool(skin_ratio > (0.012 / max(0.3, sensitivity)) and (area_ratio > 0.018 or lap_var > 55.0))
        proximity = float(max(0.0, min(1.0, area_ratio * 5.5)))
        center = (0.5, 0.5)
        if best_contour is not None:
            moments = cv2.moments(best_contour)
            if moments["m00"]:
                width = float(max(1, frame_uint8.shape[1]))
                height = float(max(1, frame_uint8.shape[0]))
                center = (
                    float(moments["m10"] / moments["m00"] / width),
                    float(moments["m01"] / moments["m00"] / height),
                )
        return hand_detected, proximity, center

    def _detect_recursive_state(self, frame_rgb: np.ndarray, hand_detected: bool) -> bool:
        """
        Erkennt rekursive Selbstbeobachtung ueber cyan-dominante Bildanteile.

        Args:
            frame_rgb: Aktueller RGB-Frame.
            hand_detected: Bereits erkannte Handpraesenz.
        """
        frame = np.asarray(frame_rgb, dtype=np.uint8)
        red = frame[:, :, 0].astype(np.int16)
        green = frame[:, :, 1].astype(np.int16)
        blue = frame[:, :, 2].astype(np.int16)
        cyan_mask = (green > 120) & (blue > 120) & (red < 120) & (np.abs(green - blue) < 55)
        cyan_ratio = float(np.count_nonzero(cyan_mask)) / float(max(1, cyan_mask.size))

        edge = cv2.Canny(frame, 70, 140)
        edge_density = float(np.count_nonzero(edge)) / float(max(1, edge.size))
        recursive_state = bool(cyan_ratio > 0.16 and edge_density > 0.05 and not hand_detected)
        return recursive_state

    def _map_audio_params(
        self,
        spectrum: SpectrumFingerprint,
        sensitivity: float,
        harmonic_blend: float,
        hand_proximity: float,
        recursive_state: bool,
        mic_peak_freq: float,
        mic_peak_level: float,
    ) -> tuple[float, float, float, float, float]:
        """
        Mappt Spektralwerte auf Theremin-Frequenzen, Lautstaerke und Dissonanz.

        Args:
            spectrum: Aktueller Spektrum-Fingerprint.
            sensitivity: Entropie-Sensitivitaet aus GUI.
            harmonic_blend: Regler fuer harmonischen Grundton.
            hand_proximity: Geschaetzte Handnaehe.
            recursive_state: Kennzeichen fuer Spiegel-Rekursion.
        """
        bass = 60.0 + (spectrum.mean_red / 255.0) * 130.0
        mid = 200.0 + (spectrum.mean_green / 255.0) * 1800.0
        high = 2000.0 + (spectrum.mean_blue / 255.0) * 3200.0

        entropy_norm = float(max(0.0, min(1.0, spectrum.entropy_total / 8.0)))
        bass *= (1.0 - 0.42 * hand_proximity)
        if mic_peak_freq > 0.0:
            mid = max(mid, 180.0 + min(1820.0, mic_peak_freq))
            high = max(high, 1600.0 + min(3600.0, mic_peak_freq * 2.1))
        volume = 0.15 + (entropy_norm * 0.6 * sensitivity) + (0.28 * hand_proximity) + min(0.32, mic_peak_level * 7.5)
        dissonance = (entropy_norm * sensitivity * (1.0 - harmonic_blend)) + (0.35 * hand_proximity)
        dissonance += min(0.28, abs(mid - max(1.0, mic_peak_freq)) / 4000.0) if mic_peak_freq > 0.0 else 0.0

        if recursive_state:
            volume = 0.48
            dissonance = 0.05
            bass = 118.0
            mid = 472.0
            high = 2830.0

        bass = float(max(35.0, min(199.0, bass)))
        mid = float(max(200.0, min(2000.0, mid)))
        high = float(max(2000.0, min(5200.0, high)))
        volume = float(max(0.0, min(1.0, volume)))
        dissonance = float(max(0.0, min(1.0, dissonance)))
        return bass, mid, high, volume, dissonance

    def _detect_session_anomaly(self, entropy_total: float, sensitivity: float) -> bool:
        """
        Erkennt Abweichungen gegen das akkumulierte Session-Entropieprofil.

        Args:
            entropy_total: Entropie des aktuellen Frames.
            sensitivity: Entropie-Sensitivitaet aus GUI.
        """
        self._entropy_history.append(float(entropy_total))
        if len(self._entropy_history) < 25:
            return False
        values = np.array(self._entropy_history, dtype=np.float64)
        mean = float(values.mean())
        std = float(values.std())
        threshold = max(0.28, (1.45 / max(0.35, sensitivity)) * max(0.18, std))
        return bool(abs(float(entropy_total) - mean) > threshold)
