"""Audio-Synaesthesie und Echtzeit-Theremin fuer Aether."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from typing import TYPE_CHECKING, Any

import numpy as np

from .analysis_engine import AetherFingerprint

if TYPE_CHECKING:
    from .spacetime_renderer import AudioVisualFrame

try:
    import sounddevice as sd
except Exception:
    sd = None


class AudioEngine:
    """Generiert statische Analysekloenge und kontinuierliche Theremin-Synthese."""

    def __init__(self, sample_rate: int = 44_100, duration: float = 2.2) -> None:
        """
        Konfiguriert die Audioengine.

        Args:
            sample_rate: Abtastrate in Hertz.
            duration: Tonlaenge fuer Einzelklang in Sekunden.
        """
        self.sample_rate = sample_rate
        self.duration = duration

        self._theremin_lock = threading.Lock()
        self._theremin_stream: Any | None = None
        self._theremin_state: dict[str, Any] = {
            "bass_freq": 120.0,
            "mid_freq": 640.0,
            "high_freq": 2600.0,
            "volume": 0.0,
            "dissonance": 0.0,
            "harmonic_blend": 0.65,
            "recursive_state": False,
            "hand_proximity": 0.0,
            "resonance_freqs": (701.0, 933.0, 1477.0),
            "resonance_gain": 0.0,
        }
        self._phase = {
            "bass": 0.0,
            "mid": 0.0,
            "high": 0.0,
            "dis1": 0.0,
            "dis2": 0.0,
            "res1": 0.0,
            "res2": 0.0,
            "res3": 0.0,
            "brown": 0.0,
        }
        self._rng = np.random.default_rng(int(time.time_ns() & 0xFFFFFFFF))

        self._aether_lock = threading.Lock()
        self._aether_stream: Any | None = None
        self._aether_state: dict[str, Any] = {
            "frequency": 110.0,
            "detune": 0.0,
            "volume": 0.0,
            "active": False,
        }
        self._aether_phase = {
            "main": 0.0,
            "detuned": 0.0,
        }

        self._audiovisual_lock = threading.Lock()
        self._audiovisual_stream: Any | None = None
        self._audiovisual_state: dict[str, Any] = {
            "active": False,
            "frame": None,
            "sample_index": 0,
            "anchor_pings": [],
        }
        self._audiovisual_reverb_left = np.zeros(max(2048, sample_rate // 3), dtype=np.float32)
        self._audiovisual_reverb_right = np.zeros(max(2048, sample_rate // 3), dtype=np.float32)
        self._audiovisual_reverb_index = 0

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        """Begrenzt Audiowerte robust auf einen sicheren Bereich."""
        return float(max(low, min(high, value)))

    def _apply_fade(self, signal: np.ndarray) -> np.ndarray:
        """Wendet weiches Fade-In und Fade-Out an."""
        fade_len = max(1, int(0.05 * self.sample_rate))
        fade_in = np.linspace(0.0, 1.0, fade_len, dtype=np.float32)
        fade_out = np.linspace(1.0, 0.0, fade_len, dtype=np.float32)
        signal[:fade_len] *= fade_in
        signal[-fade_len:] *= fade_out
        return signal

    def _brownian_noise(self, length: int, amplitude: float, rng: np.random.Generator | None = None) -> np.ndarray:
        """Erzeugt normalisiertes Brownian Noise aus weissem Rauschen."""
        generator = rng if rng is not None else self._rng
        white = generator.normal(0.0, 1.0, length).astype(np.float32)
        brown = np.cumsum(white)
        max_abs = np.max(np.abs(brown)) if length > 0 else 1.0
        normalized = (brown / max_abs) if max_abs else brown
        return normalized.astype(np.float32) * float(max(0.0, amplitude))

    def _base_chord(self, frequencies: list[float]) -> np.ndarray:
        """Mischt mehrere Sinuswellen zu einem Akkord."""
        samples = int(self.sample_rate * self.duration)
        t = np.linspace(0, self.duration, samples, endpoint=False, dtype=np.float32)
        waves = [np.sin(2.0 * np.pi * freq * t).astype(np.float32) for freq in frequencies]
        chord = np.sum(waves, axis=0) / max(1, len(waves))
        return chord.astype(np.float32)

    @staticmethod
    def _fingerprint_seed(fingerprint: AetherFingerprint) -> int:
        """Leitet einen stabilen Audio-Seed nur aus Fingerprint-Zustaenden ab."""
        base = (
            f"{getattr(fingerprint, 'file_hash', '')}|"
            f"{getattr(fingerprint, 'scan_hash', '')}|"
            f"{getattr(fingerprint, 'source_label', '')}|"
            f"{getattr(fingerprint, 'verdict', '')}"
        ).encode("utf-8", errors="ignore")
        return int.from_bytes(hashlib.sha256(base).digest()[:8], "big", signed=False)

    def _fingerprint_rng(self, fingerprint: AetherFingerprint) -> np.random.Generator:
        """Erzeugt pro Fingerprint einen reproduzierbaren Zufallsstrom."""
        return np.random.default_rng(self._fingerprint_seed(fingerprint))

    @staticmethod
    def _category_frequencies(category: str) -> list[float]:
        """Ordnet Dateikategorien stabile Akkordzentren zu."""
        palette = {
            "audio": [196.0, 392.0, 784.0],
            "video": [174.61, 261.63, 523.25],
            "image": [329.63, 493.88, 659.25],
            "document": [220.0, 277.18, 440.0],
            "font": [246.94, 369.99, 493.88],
            "archive": [110.0, 164.81, 220.0],
            "code": [146.83, 220.0, 293.66],
            "data": [164.81, 329.63, 659.25],
            "binary": [220.0, 330.0, 440.0],
        }
        return list(palette.get(str(category or "binary").lower(), palette["binary"]))

    def generate_tone(self, fingerprint: AetherFingerprint) -> np.ndarray:
        """
        Generiert einen Audio-Array passend zum Analyseurteil.

        Args:
            fingerprint: Ergebnisobjekt der Analyse.
        """
        file_profile = dict(getattr(fingerprint, "file_profile", {}) or {})
        observer_payload = dict(getattr(fingerprint, "observer_payload", {}) or {})
        visual_state = dict(observer_payload.get("visual_state", {}) or {})
        process_state = dict(observer_payload.get("process_state", {}) or {})
        emergence_layers = list(getattr(fingerprint, "emergence_layers", []) or [])
        category = str(file_profile.get("category", "binary") or "binary")
        category_frequencies = self._category_frequencies(category)
        observer_entropy = float(visual_state.get("visual_entropy", 0.0) or 0.0)
        process_cpu = float(process_state.get("cpu_percent", 0.0) or 0.0)
        observer_drive = self._clamp(
            (
                self._clamp(observer_entropy / 8.0, 0.0, 1.0)
                + self._clamp(process_cpu / 100.0, 0.0, 1.0)
            ) / 2.0,
            0.0,
            1.0,
        )
        emergence_drive = self._clamp(len(emergence_layers) / 4.0, 0.0, 1.0)
        rng = self._fingerprint_rng(fingerprint)
        if fingerprint.verdict == "RECURSIVE":
            recursive_base = [freq * 1.333 for freq in category_frequencies]
            base = self._base_chord(recursive_base)
            shimmer = self._base_chord([freq * 1.414 for freq in recursive_base]) * (0.32 + (0.22 * emergence_drive))
            tone = base + shimmer + self._brownian_noise(len(base), amplitude=0.06 + (0.06 * observer_drive), rng=rng)
        elif fingerprint.verdict == "CRITICAL":
            critical_base = [category_frequencies[0] * 0.92, category_frequencies[1] * 0.94, category_frequencies[2] * 1.06]
            tone = self._base_chord(critical_base)
            tone += self._brownian_noise(len(tone), amplitude=0.45 + (0.45 * observer_drive), rng=rng)
            click_len = min(220, len(tone))
            if click_len > 0:
                tone[:click_len] += np.hanning(click_len).astype(np.float32) * 0.95
        elif fingerprint.verdict == "SUSPICIOUS":
            tone = self._base_chord(category_frequencies)
            anomaly_degree = max(0.0, min(1.0, (100.0 - fingerprint.symmetry_score) / 100.0))
            anomaly_degree = max(anomaly_degree, min(1.0, len(fingerprint.anomaly_coordinates) / 24.0))
            tone += self._brownian_noise(
                len(tone),
                amplitude=0.12 + (anomaly_degree * 0.38) + (observer_drive * 0.22),
                rng=rng,
            )
        else:
            tone = self._base_chord(category_frequencies)
            if observer_drive > 0.05 or emergence_drive > 0.05:
                overtone = self._base_chord([freq * (1.0 + (0.08 * emergence_drive)) for freq in category_frequencies])
                tone = tone + (overtone * np.float32(0.12 + (0.18 * observer_drive)))

        if observer_drive > 0.01:
            shimmer = self._base_chord([freq * (1.0 + (0.04 * observer_drive)) for freq in category_frequencies])
            tone = tone + (shimmer * np.float32(0.05 + (0.12 * emergence_drive)))

        tone = self._apply_fade(tone)
        peak = np.max(np.abs(tone)) if len(tone) else 1.0
        if peak > 0:
            tone = tone / peak
        return tone.astype(np.float32)

    def play(self, fingerprint: AetherFingerprint) -> None:
        """
        Spielt den generierten Ton asynchron ab.

        Fehler bei fehlendem Audiogeraet oder fehlender Bibliothek werden abgefangen.
        """
        if sd is None:
            print("Warnung: Soundausgabe nicht verfuegbar (sounddevice fehlt).")
            return
        try:
            tone = self.generate_tone(fingerprint)
            sd.play(tone, self.sample_rate, blocking=False)
        except Exception:
            print("Warnung: Audiogeraet nicht verfuegbar, Analyse laeuft ohne Sound weiter.")

    def start_audiovisual_stream(self) -> bool:
        """Startet den kontinuierlichen Stereo-Stream fuer synaesthetisches AV-Feedback."""
        if sd is None:
            return False
        with self._audiovisual_lock:
            if self._audiovisual_stream is not None:
                self._audiovisual_state["active"] = True
                return True
            try:
                self._audiovisual_stream = sd.OutputStream(
                    samplerate=self.sample_rate,
                    channels=2,
                    dtype="float32",
                    callback=self._audiovisual_callback,
                    blocksize=0,
                )
                self._audiovisual_stream.start()
                self._audiovisual_state["active"] = True
                return True
            except Exception:
                self._audiovisual_stream = None
                self._audiovisual_state["active"] = False
                return False

    def stop_audiovisual_stream(self) -> None:
        """Stoppt den synchronen Stereo-Stream sauber."""
        with self._audiovisual_lock:
            self._audiovisual_state["active"] = False
            self._audiovisual_state["frame"] = None
            self._audiovisual_state["sample_index"] = 0
            self._audiovisual_reverb_left.fill(0.0)
            self._audiovisual_reverb_right.fill(0.0)
            self._audiovisual_reverb_index = 0
            if self._audiovisual_stream is None:
                return
            try:
                self._audiovisual_stream.stop()
                self._audiovisual_stream.close()
            except Exception:
                self._audiovisual_stream = None
            self._audiovisual_stream = None

    def update_audiovisual_frame(self, frame: AudioVisualFrame | None) -> None:
        """Aktualisiert den gemeinsamen Bild-/Ton-Frame fuer die synaesthetische Ausgabe."""
        if frame is None or not getattr(frame, "points", None):
            with self._audiovisual_lock:
                self._audiovisual_state["frame"] = None
                self._audiovisual_state["active"] = False
                self._audiovisual_state["sample_index"] = 0
                self._audiovisual_state["anchor_pings"] = []
            return

        if sd is None:
            return

        start_needed = False
        with self._audiovisual_lock:
            self._audiovisual_state["frame"] = frame
            self._audiovisual_state["active"] = True
            start_needed = self._audiovisual_stream is None
        if start_needed:
            self.start_audiovisual_stream()

    def trigger_anchor_pings(self, anchor_values: list[float]) -> None:
        """Spielt neu gefundene AE-Anker als reine harmonische Pings."""
        if sd is None:
            return
        frequencies = [
            float(max(55.0, min(3520.0, abs(float(value)) * 110.0)))
            for value in list(anchor_values or [])
            if math.isfinite(float(value)) and abs(float(value)) > 1e-12
        ][:12]
        if not frequencies:
            return

        with self._audiovisual_lock:
            frame = self._audiovisual_state.get("frame")
            stream_active = bool(self._audiovisual_state.get("active", False)) and self._audiovisual_stream is not None
            if stream_active and frame is not None:
                pending = list(self._audiovisual_state.get("anchor_pings", []) or [])
                gap_samples = int(self.sample_rate * 0.045)
                duration_samples = int(self.sample_rate * 0.18)
                offset = 0
                for frequency in frequencies:
                    pending.append(
                        {
                            "frequency": float(frequency),
                            "remaining": int(duration_samples),
                            "total": int(duration_samples),
                            "phase": 0.0,
                            "position": 0,
                            "start_delay": int(offset),
                            "amplitude": 0.22,
                        }
                    )
                    offset += gap_samples
                self._audiovisual_state["anchor_pings"] = pending
                return

        duration = 0.18
        gap = 0.045
        segments: list[np.ndarray] = []
        for frequency in frequencies:
            samples = max(1, int(self.sample_rate * duration))
            time_axis = np.linspace(0.0, duration, samples, endpoint=False, dtype=np.float32)
            envelope = np.hanning(samples).astype(np.float32) if samples > 2 else np.ones(samples, dtype=np.float32)
            segment = (np.sin(2.0 * np.pi * frequency * time_axis).astype(np.float32) * envelope * 0.24).astype(np.float32)
            segments.append(segment)
            segments.append(np.zeros(int(self.sample_rate * gap), dtype=np.float32))
        signal = np.concatenate(segments).astype(np.float32) if segments else np.zeros(1, dtype=np.float32)
        try:
            sd.play(signal, self.sample_rate, blocking=False)
        except Exception:
            return

    def start_aether_oscillator(self) -> bool:
        """Startet einen einzelnen kontinuierlichen Aether-Oszillator."""
        if sd is None:
            return False
        with self._aether_lock:
            if self._aether_stream is not None:
                self._aether_state["active"] = True
                return True
            try:
                self._aether_stream = sd.OutputStream(
                    samplerate=self.sample_rate,
                    channels=1,
                    dtype="float32",
                    callback=self._aether_callback,
                    blocksize=0,
                )
                self._aether_stream.start()
                self._aether_state["active"] = True
                return True
            except Exception:
                self._aether_stream = None
                return False

    def stop_aether_oscillator(self) -> None:
        """Stoppt den kontinuierlichen Aether-Oszillator."""
        with self._aether_lock:
            self._aether_state["active"] = False
            self._aether_state["volume"] = 0.0
            if self._aether_stream is None:
                return
            try:
                self._aether_stream.stop()
                self._aether_stream.close()
            except Exception:
                self._aether_stream = None
            self._aether_stream = None

    def update_aether_state(self, frequency: float, detune: float, volume: float = 0.18) -> None:
        """Aktualisiert Frequenz und Detune des kontinuierlichen Aether-Oszillators."""
        with self._aether_lock:
            self._aether_state["frequency"] = float(max(40.0, min(1600.0, frequency)))
            self._aether_state["detune"] = float(max(-2400.0, min(2400.0, detune)))
            self._aether_state["volume"] = float(max(0.0, min(0.7, volume)))

    def play_alarm_burst(self, duration_ms: int = 200) -> None:
        """Spielt einen kurzen dissonanten Alarmburst."""
        if sd is None:
            return
        duration = max(0.08, min(0.4, duration_ms / 1000.0))
        samples = int(self.sample_rate * duration)
        t = np.linspace(0, duration, samples, endpoint=False, dtype=np.float32)
        signal = (
            np.sin(2.0 * np.pi * 233.0 * t)
            + 0.9 * np.sin(2.0 * np.pi * 277.0 * t)
            + 0.4 * np.sin(2.0 * np.pi * 421.0 * t)
        ).astype(np.float32)
        envelope = np.hanning(samples).astype(np.float32) if samples > 2 else np.ones(samples, dtype=np.float32)
        burst = signal * envelope * 0.35
        try:
            sd.play(burst, self.sample_rate, blocking=False)
        except Exception:
            return

    def start_theremin_stream(self) -> bool:
        """Startet den kontinuierlichen Echtzeit-Output fuer das Theremin."""
        if sd is None:
            return False
        with self._theremin_lock:
            if self._theremin_stream is not None:
                return True
            try:
                self._theremin_stream = sd.OutputStream(
                    samplerate=self.sample_rate,
                    channels=1,
                    dtype="float32",
                    callback=self._theremin_callback,
                    blocksize=0,
                )
                self._theremin_stream.start()
                return True
            except Exception:
                self._theremin_stream = None
                return False

    def stop_theremin_stream(self) -> None:
        """Stoppt den Echtzeit-Stream sauber."""
        with self._theremin_lock:
            if self._theremin_stream is None:
                return
            try:
                self._theremin_stream.stop()
                self._theremin_stream.close()
            except Exception:
                self._theremin_stream = None
            self._theremin_stream = None

    def update_theremin_state(
        self,
        bass_freq: float,
        mid_freq: float,
        high_freq: float,
        volume: float,
        dissonance: float,
        harmonic_blend: float,
        recursive_state: bool,
        hand_proximity: float,
    ) -> None:
        """
        Aktualisiert Zielparameter der Echtzeit-Synthese.

        Args:
            bass_freq: Bassfrequenz < 200 Hz.
            mid_freq: Mittenfrequenz zwischen 200 und 2000 Hz.
            high_freq: Hoehenfrequenz > 2000 Hz.
            volume: Lautstaerke zwischen 0 und 1.
            dissonance: Dissonanzanteil zwischen 0 und 1.
            harmonic_blend: Gewichtung harmonischer Komponenten.
            recursive_state: Kennzeichen fuer Selbstbeobachtung.
            hand_proximity: Geschaetzte Handnaehe zwischen 0 und 1.
        """
        with self._theremin_lock:
            self._theremin_state["bass_freq"] = float(max(20.0, min(199.0, bass_freq)))
            self._theremin_state["mid_freq"] = float(max(200.0, min(2000.0, mid_freq)))
            self._theremin_state["high_freq"] = float(max(2000.0, min(6000.0, high_freq)))
            self._theremin_state["volume"] = float(max(0.0, min(1.0, volume)))
            self._theremin_state["dissonance"] = float(max(0.0, min(1.0, dissonance)))
            self._theremin_state["harmonic_blend"] = float(max(0.0, min(1.0, harmonic_blend)))
            self._theremin_state["recursive_state"] = bool(recursive_state)
            self._theremin_state["hand_proximity"] = float(max(0.0, min(1.0, hand_proximity)))

            current_gain = float(self._theremin_state.get("resonance_gain", 0.0))
            if recursive_state:
                self._theremin_state["resonance_gain"] = min(1.0, current_gain + 0.03)
            else:
                self._theremin_state["resonance_gain"] = max(0.0, current_gain - 0.02)

    def trigger_recursive_resonance(self) -> None:
        """Aktiviert einen einzigartigen Resonanzton fuer Selbstbeobachtung."""
        seed = int(time.time_ns() & 0xFFFFFFFF)
        rng = np.random.default_rng(seed)
        f1 = float(rng.uniform(520.0, 760.0))
        f2 = float(rng.uniform(880.0, 1340.0))
        f3 = float(rng.uniform(1680.0, 2460.0))
        with self._theremin_lock:
            self._theremin_state["resonance_freqs"] = (f1, f2, f3)
            self._theremin_state["resonance_gain"] = max(0.62, float(self._theremin_state.get("resonance_gain", 0.0)))

    def _osc(self, freq: float, frames: int, phase_key: str) -> np.ndarray:
        """Erzeugt eine Oszillatorwelle mit persistenter Phase."""
        phase = float(self._phase[phase_key])
        omega = (2.0 * np.pi * float(freq)) / float(self.sample_rate)
        idx = np.arange(frames, dtype=np.float32)
        wave = np.sin(phase + idx * omega, dtype=np.float32)
        self._phase[phase_key] = float((phase + frames * omega) % (2.0 * np.pi))
        return wave

    def _theremin_callback(self, outdata: np.ndarray, frames: int, _time: Any, status: Any) -> None:
        """Synthese-Callback des kontinuierlichen Sounddevice-Streams."""
        if status:
            outdata[:] = 0.0
            return

        with self._theremin_lock:
            state = dict(self._theremin_state)

        bass = self._osc(state["bass_freq"], frames, "bass")
        mid = self._osc(state["mid_freq"], frames, "mid")
        high = self._osc(state["high_freq"], frames, "high")

        harmonic = (bass + 0.62 * mid + 0.44 * high) / 2.06
        dis1 = self._osc(state["mid_freq"] * 1.618, frames, "dis1")
        dis2 = self._osc(state["high_freq"] * 0.707, frames, "dis2")

        white = self._rng.normal(0.0, 1.0, frames).astype(np.float32)
        brown = np.cumsum(white) + float(self._phase["brown"])
        self._phase["brown"] = float(brown[-1] if brown.size else self._phase["brown"])
        max_abs = float(np.max(np.abs(brown))) if frames > 0 else 1.0
        if max_abs > 0:
            brown = brown / max_abs

        dissonant = (0.56 * dis1 + 0.34 * dis2 + 0.25 * brown.astype(np.float32)) / 1.15
        blend = float(state["harmonic_blend"])
        dissonance = float(state["dissonance"])
        signal = (blend * harmonic) + ((1.0 - blend) * dissonance * dissonant)

        proximity_weight = 0.95 - 0.28 * float(state["hand_proximity"])
        signal *= max(0.25, proximity_weight)

        if float(state["resonance_gain"]) > 0.001:
            f1, f2, f3 = state["resonance_freqs"]
            res = (
                self._osc(f1, frames, "res1")
                + 0.74 * self._osc(f2, frames, "res2")
                + 0.51 * self._osc(f3, frames, "res3")
            ) / 2.25
            signal += res * float(state["resonance_gain"]) * 0.35

        signal = signal * float(state["volume"])
        peak = float(np.max(np.abs(signal))) if frames > 0 else 1.0
        if peak > 1.0:
            signal = signal / peak
        outdata[:] = signal.reshape(-1, 1).astype(np.float32)

    def _aether_callback(self, outdata: np.ndarray, frames: int, _time: Any, status: Any) -> None:
        """Callback fuer den kontinuierlichen Einzeloszillator."""
        if status:
            outdata[:] = 0.0
            return

        with self._aether_lock:
            state = dict(self._aether_state)

        if not state.get("active", False) or float(state.get("volume", 0.0)) <= 1e-4:
            outdata[:] = 0.0
            return

        frequency = float(state.get("frequency", 110.0))
        detune = float(state.get("detune", 0.0))
        detuned_frequency = frequency * float(2.0 ** (detune / 1200.0))
        base = self._osc_simple(frequency, frames, "main")
        detuned = self._osc_simple(detuned_frequency, frames, "detuned")
        signal = ((0.72 * base) + (0.48 * detuned)) * float(state.get("volume", 0.0))
        peak = float(np.max(np.abs(signal))) if frames > 0 else 1.0
        if peak > 1.0:
            signal = signal / peak
        outdata[:] = signal.reshape(-1, 1).astype(np.float32)

    def _osc_simple(self, freq: float, frames: int, phase_key: str) -> np.ndarray:
        """Erzeugt eine einfache Sinuswelle fuer den Aether-Oszillator."""
        phase = float(self._aether_phase[phase_key])
        omega = (2.0 * np.pi * float(freq)) / float(self.sample_rate)
        idx = np.arange(frames, dtype=np.float32)
        wave = np.sin(phase + idx * omega, dtype=np.float32)
        self._aether_phase[phase_key] = float((phase + frames * omega) % (2.0 * np.pi))
        return wave

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        """Begrenzt Werte robust auf einen Zielbereich."""
        return float(max(low, min(high, value)))

    def _pinkish_noise(self, frames: int) -> np.ndarray:
        """Erzeugt geglaettetes Rauschen als leichte Pink-Noise-Approximation."""
        white = self._rng.normal(0.0, 1.0, frames).astype(np.float32)
        if frames <= 2:
            return white
        kernel = np.array([0.18, 0.27, 0.32, 0.23], dtype=np.float32)
        pink = np.convolve(white, kernel, mode="same").astype(np.float32)
        peak = float(np.max(np.abs(pink))) if frames > 0 else 1.0
        if peak > 0.0:
            pink = pink / peak
        return pink

    def _pan_gains(self, pan: float) -> tuple[float, float]:
        """Berechnet Equal-Power-Pan fuer einen Stereo-Ort."""
        angle = (self._clamp(pan, -1.0, 1.0) + 1.0) * (math.pi / 4.0)
        return float(math.cos(angle)), float(math.sin(angle))

    def _overtone_partials(self, base_frequency: float, mode: str) -> list[tuple[float, float]]:
        """Leitet die Obertonstruktur aus Mandelbrot- bzw. Chaoslage ab."""
        phi = 1.61803398875
        if mode == "unison":
            multipliers = [(1.0, 0.78), (1.0, 0.16), (1.0, 0.08)]
        elif mode == "inharmonic":
            multipliers = [(1.0, 0.52), (1.414, 0.28), (2.297, 0.18), (3.113, 0.14)]
        else:
            multipliers = [(1.0, 0.58), (phi, 0.24), (phi * phi, 0.14), (phi * phi * phi, 0.09)]
        partials: list[tuple[float, float]] = []
        for multiplier, gain in multipliers:
            frequency = self._clamp(float(base_frequency) * float(multiplier), 40.0, 7800.0)
            partials.append((frequency, float(gain)))
        return partials

    def _apply_audiovisual_reverb(
        self,
        left: np.ndarray,
        right: np.ndarray,
        depth: float,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Wendet einen leichten Raumhall mit Tiefe auf den Stereo-Block an."""
        wetness = self._clamp(depth, 0.0, 1.0)
        if wetness <= 0.001:
            return left, right

        buffer_len = len(self._audiovisual_reverb_left)
        delay = max(64, min(buffer_len - 1, int(160 + wetness * (buffer_len * 0.72))))
        feedback = 0.18 + (0.54 * wetness)
        mix = 0.14 + (0.42 * wetness)
        out_left = left.astype(np.float32, copy=True)
        out_right = right.astype(np.float32, copy=True)
        index = int(self._audiovisual_reverb_index)

        for sample_index in range(left.size):
            tap = (index - delay) % buffer_len
            delayed_left = float(self._audiovisual_reverb_left[tap])
            delayed_right = float(self._audiovisual_reverb_right[tap])
            dry_left = float(out_left[sample_index])
            dry_right = float(out_right[sample_index])
            out_left[sample_index] = float((dry_left * (1.0 - mix)) + (delayed_left * mix))
            out_right[sample_index] = float((dry_right * (1.0 - mix)) + (delayed_right * mix))
            self._audiovisual_reverb_left[index] = dry_left + (delayed_left * feedback)
            self._audiovisual_reverb_right[index] = dry_right + (delayed_right * feedback)
            index = (index + 1) % buffer_len

        self._audiovisual_reverb_index = index
        return out_left, out_right

    def _audiovisual_callback(self, outdata: np.ndarray, frames: int, _time: Any, status: Any) -> None:
        """Synthese-Callback fuer das synchrone Stereo-Bild/Ton-Feld."""
        if status:
            outdata[:] = 0.0
            return

        with self._audiovisual_lock:
            state = dict(self._audiovisual_state)
            queued_pings = [dict(item) for item in list(self._audiovisual_state.get("anchor_pings", []) or [])]
            self._audiovisual_state["anchor_pings"] = []

        frame = state.get("frame")
        if not state.get("active", False) or frame is None or not getattr(frame, "points", None):
            outdata[:] = 0.0
            return

        sample_index = int(state.get("sample_index", 0) or 0)
        time_axis = (sample_index + np.arange(frames, dtype=np.float32)) / float(self.sample_rate)
        left = np.zeros(frames, dtype=np.float32)
        right = np.zeros(frames, dtype=np.float32)

        ordered_points = sorted(
            list(getattr(frame, "points", []) or []),
            key=lambda point: float(getattr(point, "volume", 0.0)) + (0.7 * float(getattr(point, "anomaly_flash", 0.0))),
            reverse=True,
        )[:24]

        depth_total = 0.0
        depth_weight = 0.0
        pink_noise = self._pinkish_noise(frames)
        white_noise = self._rng.normal(0.0, 1.0, frames).astype(np.float32)
        white_peak = float(np.max(np.abs(white_noise))) if frames > 0 else 1.0
        if white_peak > 0.0:
            white_noise = white_noise / white_peak

        pulse_hz = float(getattr(frame, "pulse_hz", 0.618) or 0.618)
        divergence = float(getattr(frame, "left_right_divergence", 0.0) or 0.0)
        observer_intensity = self._clamp(float(getattr(frame, "observer_intensity", 0.0) or 0.0), 0.0, 1.0)
        emergence_intensity = self._clamp(float(getattr(frame, "emergence_intensity", 0.0) or 0.0), 0.0, 1.0)
        process_cpu = self._clamp(float(getattr(frame, "process_cpu", 0.0) or 0.0) / 100.0, 0.0, 1.0)
        pulse_hz = float(pulse_hz * (1.0 + (0.08 * emergence_intensity) + (0.04 * observer_intensity)))
        divergence = float(self._clamp(divergence + (0.22 * observer_intensity), 0.0, 1.0))
        pink_mix = float(getattr(frame, "pink_noise_mix", 0.0) or 0.0)
        white_mix = float(getattr(frame, "white_noise_mix", 0.0) or 0.0)
        pink_mix = self._clamp(pink_mix * (1.0 - (0.20 * observer_intensity)), 0.0, 1.0)
        white_mix = self._clamp(white_mix + (0.18 * observer_intensity) + (0.10 * emergence_intensity), 0.0, 1.0)
        noise_total = max(1e-6, pink_mix + white_mix)
        pink_mix /= noise_total
        white_mix /= noise_total

        for point in ordered_points:
            left_gain, right_gain = self._pan_gains(float(getattr(point, "pan", 0.0) or 0.0))
            point_volume = self._clamp(
                float(getattr(point, "volume", 0.0) or 0.0) * (0.42 + (0.58 * float(getattr(point, "confidence", 0.0) or 0.0))),
                0.0,
                1.0,
            )
            if point_volume <= 0.001:
                continue

            harmonic = np.zeros(frames, dtype=np.float32)
            for frequency, gain in self._overtone_partials(
                float(getattr(point, "base_frequency", 220.0) or 220.0),
                str(getattr(point, "overtone_mode", "harmonic") or "harmonic"),
            ):
                harmonic += (np.sin((2.0 * np.pi * frequency * time_axis), dtype=np.float32) * np.float32(gain)).astype(np.float32)

            carrier_noise = (
                (pink_noise * np.float32(pink_mix))
                + (white_noise * np.float32(white_mix))
            ).astype(np.float32)
            if str(getattr(point, "noise_mode", "pink")) == "white":
                carrier_noise = ((0.25 * pink_noise) + (0.75 * white_noise)).astype(np.float32)

            rhythm = 0.5 + 0.5 * np.sin(
                (2.0 * np.pi * pulse_hz * time_axis)
                + (float(getattr(point, "t_norm", 0.0) or 0.0) * np.pi)
            )
            if float(getattr(point, "strobe", 0.0) or 0.0) > 0.5:
                rhythm = np.where(rhythm > 0.55, 1.0, 0.12).astype(np.float32)
            else:
                rhythm = rhythm.astype(np.float32)

            anomaly_flash = float(getattr(point, "anomaly_flash", 0.0) or 0.0)
            anomaly_burst = np.zeros(frames, dtype=np.float32)
            if anomaly_flash > 0.0:
                envelope = np.exp(-np.linspace(0.0, 4.5, frames, dtype=np.float32))
                anomaly_burst = (white_noise * envelope * np.float32(0.85 * anomaly_flash)).astype(np.float32)

            signal = (
                (0.72 * harmonic)
                + (
                    0.28
                    + (0.24 * float(getattr(point, "strobe", 0.0) or 0.0))
                    + (0.12 * observer_intensity)
                    + (0.08 * process_cpu)
                ) * carrier_noise
                + anomaly_burst
            ).astype(np.float32)
            signal *= (rhythm * np.float32(point_volume)).astype(np.float32)

            pan = float(getattr(point, "pan", 0.0) or 0.0)
            left_bias = 1.0 + (divergence * max(0.0, -pan) * 0.6)
            right_bias = 1.0 + (divergence * max(0.0, pan) * 0.6)
            left += signal * np.float32(left_gain * left_bias)
            right += signal * np.float32(right_gain * right_bias)

            point_depth = float(getattr(point, "reverb_depth", 0.0) or 0.0)
            depth_total += point_depth * point_volume
            depth_weight += point_volume

        if divergence > 0.001:
            drift_left = self._pinkish_noise(frames) * np.float32((0.025 + (0.015 * emergence_intensity)) * divergence)
            drift_right = self._rng.normal(0.0, 1.0, frames).astype(np.float32)
            drift_peak = float(np.max(np.abs(drift_right))) if frames > 0 else 1.0
            if drift_peak > 0.0:
                drift_right = (drift_right / drift_peak).astype(np.float32)
            right += drift_right * np.float32((0.025 + (0.018 * observer_intensity)) * divergence)
            left += drift_left

        reverb_depth = float(depth_total / depth_weight) if depth_weight > 0.0 else 0.0
        left, right = self._apply_audiovisual_reverb(left, right, reverb_depth)

        updated_pings: list[dict[str, Any]] = []
        for ping in queued_pings:
            start_delay = int(ping.get("start_delay", 0) or 0)
            if start_delay >= frames:
                ping["start_delay"] = start_delay - frames
                updated_pings.append(ping)
                continue

            offset = max(0, start_delay)
            remaining = int(ping.get("remaining", 0) or 0)
            total = max(1, int(ping.get("total", remaining or 1) or 1))
            active_frames = min(frames - offset, remaining)
            if active_frames <= 0:
                continue

            phase = float(ping.get("phase", 0.0) or 0.0)
            frequency = float(ping.get("frequency", 440.0) or 440.0)
            amplitude = float(ping.get("amplitude", 0.22) or 0.22)
            position = int(ping.get("position", 0) or 0)
            omega = (2.0 * np.pi * frequency) / float(self.sample_rate)
            idx = np.arange(active_frames, dtype=np.float32)
            wave = np.sin(phase + (idx * omega), dtype=np.float32).astype(np.float32)
            progress = (position + idx) / float(total)
            envelope = np.sin(np.pi * np.clip(progress, 0.0, 1.0)).astype(np.float32)
            segment = (wave * envelope * np.float32(amplitude)).astype(np.float32)
            left[offset : offset + active_frames] += segment
            right[offset : offset + active_frames] += segment

            ping["phase"] = float((phase + (active_frames * omega)) % (2.0 * np.pi))
            ping["remaining"] = int(remaining - active_frames)
            ping["position"] = int(position + active_frames)
            ping["start_delay"] = 0
            if int(ping["remaining"]) > 0:
                updated_pings.append(ping)

        peak = float(max(np.max(np.abs(left)), np.max(np.abs(right)))) if frames > 0 else 1.0
        if peak > 0.98:
            scale = np.float32(0.98 / peak)
            left *= scale
            right *= scale

        outdata[:] = np.column_stack((left, right)).astype(np.float32)

        with self._audiovisual_lock:
            self._audiovisual_state["sample_index"] = sample_index + frames
            self._audiovisual_state["anchor_pings"] = updated_pings + list(self._audiovisual_state.get("anchor_pings", []) or [])
