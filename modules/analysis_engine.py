"""Dateianalyse fuer Aether."""

from __future__ import annotations

import hashlib
import json
import math
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np
from scipy.fft import rfft, rfftfreq

from .blockchain_interface import AetherChain
from .ethics_engine import EthicsAssessment, EthicsEngine
from .session_engine import SessionContext
from .voxel_grid import VoxelGrid4D

if TYPE_CHECKING:
    from .registry import AetherRegistry


@dataclass
class AetherFingerprint:
    """Enthaelt alle Analysemetriken einer untersuchten Datei."""

    session_id: str
    file_hash: str
    file_size: int
    entropy_blocks: list[float]
    entropy_mean: float
    fourier_peaks: list[dict[str, float]]
    byte_distribution: dict[int, int]
    periodicity: int
    symmetry_score: float
    delta: bytes
    delta_ratio: float
    anomaly_coordinates: list[tuple[int, int]]
    verdict: str
    timestamp: str
    symmetry_component: float = 0.0
    coherence_score: float = 0.0
    resonance_score: float = 0.0
    ethics_score: float = 0.0
    integrity_state: str = "STRUCTURAL_TENSION"
    integrity_text: str = "Strukturelle Spannung erkannt"
    source_type: str = "file"
    source_label: str = ""
    observer_mutual_info: float = 0.0
    observer_knowledge_ratio: float = 0.0
    h_lambda: float = 0.0
    observer_state: str = "OFFEN"
    beauty_signature: dict[str, float] | None = None
    ae_lab_summary: dict[str, Any] | None = None
    voxel_points: list[tuple[float, float, float, float, float, float, float, float]] | None = None
    anchor_coverage_ratio: float = 0.0
    unresolved_residual_ratio: float = 1.0
    residual_hash: str = ""
    coverage_verified: bool = False
    local_chain_tx_hash: str = ""
    local_chain_prev_hash: str = ""
    local_chain_endpoint: str = ""
    local_chain_attested_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert den Fingerprint als JSON-taugliches Dictionary."""
        return {
            "session_id": self.session_id,
            "source_type": self.source_type,
            "source_label": self.source_label,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "entropy_blocks": [float(value) for value in self.entropy_blocks],
            "entropy_mean": float(self.entropy_mean),
            "fourier_peaks": self.fourier_peaks,
            "byte_distribution": {str(key): int(value) for key, value in self.byte_distribution.items()},
            "periodicity": int(self.periodicity),
            "symmetry_score": float(self.symmetry_score),
            "symmetry_component": float(self.symmetry_component),
            "coherence_score": float(self.coherence_score),
            "resonance_score": float(self.resonance_score),
            "ethics_score": float(self.ethics_score),
            "integrity_state": self.integrity_state,
            "integrity_text": self.integrity_text,
            "observer_mutual_info": float(self.observer_mutual_info),
            "observer_knowledge_ratio": float(self.observer_knowledge_ratio),
            "h_lambda": float(self.h_lambda),
            "observer_state": str(self.observer_state),
            "anchor_coverage_ratio": float(self.anchor_coverage_ratio),
            "unresolved_residual_ratio": float(self.unresolved_residual_ratio),
            "residual_hash": str(self.residual_hash),
            "coverage_verified": bool(self.coverage_verified),
            "beauty_signature": {
                str(key): float(value) for key, value in dict(self.beauty_signature or {}).items()
            },
            "ae_lab_summary": dict(self.ae_lab_summary or {}),
            "local_chain_tx_hash": str(self.local_chain_tx_hash),
            "local_chain_prev_hash": str(self.local_chain_prev_hash),
            "local_chain_endpoint": str(self.local_chain_endpoint),
            "local_chain_attested_at": str(self.local_chain_attested_at),
            "delta": self.delta.hex(),
            "delta_ratio": float(self.delta_ratio),
            "anomaly_coordinates": [[int(x), int(y)] for x, y in self.anomaly_coordinates],
            "voxel_count": int(len(self.voxel_points) if self.voxel_points else 0),
            "verdict": self.verdict,
            "timestamp": self.timestamp,
        }

    def submit_to_chain(self, chain: AetherChain | None = None) -> bool:
        """
        Reicht den Fingerprint bei aktiver Chain-Verbindung ein.

        Args:
            chain: Optional bereits initialisierte AetherChain-Instanz.
        """
        chain_client = chain if chain is not None else AetherChain()
        if not chain_client.connected:
            return False
        try:
            receipt = chain_client.submit_fingerprint(self.to_dict())
            if isinstance(receipt, dict):
                if receipt.get("accepted") is False:
                    return False
                self.local_chain_tx_hash = str(receipt.get("tx_hash", ""))
                self.local_chain_prev_hash = str(receipt.get("prev_hash", ""))
                self.local_chain_endpoint = str(receipt.get("endpoint", ""))
                self.local_chain_attested_at = str(receipt.get("submitted_at", ""))
                return bool(self.local_chain_tx_hash)
            return False
        except Exception:
            print("Warnung: Blockchain-Uebertragung konnte nicht abgeschlossen werden.")
            return False


class AnalysisEngine:
    """Analysiert Dateien, berechnet Ethik-Integritaet und erzeugt AetherFingerprints."""

    def __init__(
        self,
        session_context: SessionContext,
        chain: AetherChain | None = None,
        block_size: int = 256,
        registry: AetherRegistry | None = None,
        ethics_engine: EthicsEngine | None = None,
    ) -> None:
        """
        Initialisiert die Analyse-Engine.

        Args:
            session_context: Aktiver Session-Kontext inklusive Seed.
            chain: Optionaler Blockchain-Connector.
            block_size: Blockgroesse fuer Entropieanalyse.
            registry: Optionale Registry fuer Resonanz-Referenzen.
            ethics_engine: Optionale externe Ethik-Engine.
        """
        self.session_context = session_context
        self.chain = chain if chain is not None else AetherChain()
        self.block_size = block_size
        self.registry = registry
        self.ethics_engine = ethics_engine if ethics_engine is not None else EthicsEngine()

    def set_registry(self, registry: AetherRegistry | None) -> None:
        """
        Verknuepft eine Registry nachtraeglich fuer Resonanz-Berechnung.

        Args:
            registry: Registry-Instanz oder None.
        """
        self.registry = registry

    def _shannon_entropy(self, block: bytes) -> float:
        """Berechnet die Shannon-Entropie eines Byteblocks."""
        if not block:
            return 0.0
        counts = Counter(block)
        length = len(block)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    def _periodicity(self, data: bytes) -> int:
        """Schaetzt die dominante Periodizitaet ueber Musterabstaende."""
        if len(data) < 4:
            return 0
        last_seen: dict[bytes, int] = {}
        distances: list[int] = []
        for idx in range(len(data) - 1):
            pattern = data[idx : idx + 2]
            if pattern in last_seen:
                distance = idx - last_seen[pattern]
                if distance > 0:
                    distances.append(distance)
            last_seen[pattern] = idx
        if not distances:
            return 0
        return Counter(distances).most_common(1)[0][0]

    def _symmetry_score(self, distribution: dict[int, int]) -> float:
        """Berechnet den Symmetrie-Score als 100 minus normalisierter Gini-Wert."""
        values = np.array([distribution.get(byte, 0) for byte in range(256)], dtype=np.float64)
        if float(values.sum()) <= 0.0:
            return 100.0

        sorted_values = np.sort(values)
        n = len(sorted_values)
        cumulative = np.cumsum(sorted_values, dtype=np.float64)
        gini = (n + 1 - 2 * np.sum(cumulative) / cumulative[-1]) / n
        max_gini = (n - 1) / n
        normalized_gini = float(gini / max_gini) if max_gini else 0.0
        normalized_gini = max(0.0, min(1.0, normalized_gini))
        symmetry = 100.0 - (normalized_gini * 100.0)
        return float(max(0.0, min(100.0, symmetry)))

    def _anomaly_coordinates(self, entropy_blocks: list[float]) -> list[tuple[int, int]]:
        """Ermittelt Ausreisserpositionen als Raumzeit-Koordinaten."""
        if not entropy_blocks:
            return []
        arr = np.array(entropy_blocks, dtype=np.float64)
        mean = float(arr.mean())
        std = float(arr.std())
        threshold = max(0.75, 1.5 * std)
        coords: list[tuple[int, int]] = []
        for index, value in enumerate(entropy_blocks):
            if abs(value - mean) > threshold:
                coords.append((index % 16, index // 16))
        return coords

    def _verdict_from_integrity(self, integrity_state: str) -> str:
        """Leitet Rendering-/Audio-Verhalten aus dem Integritaetszustand ab."""
        if integrity_state == "STRUCTURAL_ANOMALY":
            return "CRITICAL"
        if integrity_state == "STRUCTURAL_TENSION":
            return "SUSPICIOUS"
        return "CLEAN"

    def _healthy_references(self) -> list[dict[str, float | int]]:
        """Liest gesunde Referenzvektoren fuer Resonanz aus der Registry."""
        if self.registry is None:
            return []
        try:
            return self.registry.get_resonance_reference_vectors(limit=320)
        except Exception:
            return []

    def _compute_ethics(
        self,
        symmetry_score: float,
        entropy_blocks: list[float],
        entropy_mean: float,
        periodicity: int,
        delta_ratio: float,
    ) -> EthicsAssessment:
        """Berechnet die Ethikkomponenten inklusive kombiniertem Integritaets-Score."""
        return self.ethics_engine.evaluate(
            symmetry_score=symmetry_score,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            periodicity=periodicity,
            delta_ratio=delta_ratio,
            healthy_references=self._healthy_references(),
        )

    def _fourier_peaks(self, raw: bytes) -> list[dict[str, float]]:
        """Berechnet die dominantesten Frequenzspitzen aus einem Byte-Strom."""
        data_array = np.frombuffer(raw, dtype=np.uint8).astype(np.float64)
        if data_array.size == 0:
            return [{"frequency": 0.0, "magnitude": 0.0} for _ in range(5)]

        spectrum = np.abs(rfft(data_array))
        freqs = rfftfreq(data_array.size, d=1.0)
        if spectrum.size > 0:
            spectrum[0] = 0.0
        peak_count = min(5, spectrum.size)
        peak_indices = np.argsort(spectrum)[-peak_count:][::-1] if peak_count else np.array([], dtype=int)
        peaks = [
            {"frequency": float(freqs[idx]), "magnitude": float(spectrum[idx])}
            for idx in peak_indices
        ]
        while len(peaks) < 5:
            peaks.append({"frequency": 0.0, "magnitude": 0.0})
        return peaks

    def _build_delta(self, raw: bytes) -> tuple[bytes, float]:
        """Erzeugt das session-abhaengige Delta und seine Kompressionsrate."""
        file_size = len(raw)
        noise = self.session_context.generate_aether_noise(file_size)
        delta = bytes(a ^ b for a, b in zip(raw, noise))
        if file_size == 0:
            return delta, 0.0
        compressed_size = len(zlib.compress(delta, level=9))
        delta_ratio = float(max(0.0, min(1.0, compressed_size / file_size)))
        return delta, delta_ratio

    def _power_law_alpha(self, raw: bytes) -> float:
        """Schaetzt die 1/f-Steigung des Spektrums als additive Schoenheitsdimension."""
        if len(raw) < 64:
            return 0.0
        data_array = np.frombuffer(raw, dtype=np.uint8).astype(np.float64)
        centered = data_array - float(np.mean(data_array))
        spectrum = np.abs(rfft(centered)) ** 2
        freqs = rfftfreq(centered.size, d=1.0)
        mask = (freqs > 0.0) & (spectrum > 0.0)
        if int(np.sum(mask)) < 8:
            return 0.0
        slope, _ = np.polyfit(np.log(freqs[mask]), np.log(spectrum[mask]), 1)
        return float(max(0.0, min(3.0, -float(slope))))

    def _lyapunov_proxy(self, entropy_blocks: list[float]) -> float:
        """Misst lokale Entropie-Divergenz als Chaos-Proxy."""
        if len(entropy_blocks) < 3:
            return 0.0
        arr = np.array(entropy_blocks, dtype=np.float64)
        first = np.abs(np.diff(arr))
        second = np.abs(np.diff(first))
        baseline = float(np.mean(first)) + 1e-9
        value = float(np.mean(np.log1p(second / baseline)))
        return float(max(0.0, min(3.0, value)))

    def _katz_fractal_dimension(self, values: list[float]) -> float:
        """Schaetzt eine fraktale Rauheit der Entropiekurve mit Katz-FD."""
        if len(values) < 2:
            return 1.0
        arr = np.array(values, dtype=np.float64)
        distances = np.hypot(1.0, np.diff(arr))
        curve_length = float(np.sum(distances))
        if curve_length <= 0.0:
            return 1.0
        steps = np.arange(arr.size, dtype=np.float64)
        diameter = float(np.max(np.hypot(steps - steps[0], arr - arr[0])))
        if diameter <= 0.0:
            return 1.0
        n = float(arr.size)
        fd = math.log10(n) / (math.log10(diameter / curve_length) + math.log10(n))
        return float(max(1.0, min(2.5, fd)))

    def _compressibility_proxy(self, raw: bytes) -> float:
        """Leitet eine Kolmogorov-nahe Komprimierbarkeit aus zlib ab."""
        if not raw:
            return 0.0
        ratio = float(len(zlib.compress(raw, level=9)) / max(1, len(raw)))
        return float(max(0.0, min(1.0, 1.0 - ratio)))

    def _benford_similarity(self, delta: bytes) -> float:
        """Vergleicht die erste Ziffer des Deltas mit der Benford-Verteilung."""
        digits = [int(str(value)[0]) for value in delta if int(value) > 0]
        if len(digits) < 12:
            return 0.0
        counts = Counter(digits)
        total = float(len(digits))
        l1_distance = 0.0
        for digit in range(1, 10):
            observed = float(counts.get(digit, 0)) / total
            expected = math.log10(1.0 + (1.0 / float(digit)))
            l1_distance += abs(observed - expected)
        return float(max(0.0, min(1.0, 1.0 - (l1_distance / 2.0))))

    @staticmethod
    def _first_significant_digit(value: float) -> int:
        """Liefert die erste signifikante Ziffer einer positiven Zahl."""
        number = abs(float(value))
        if number <= 0.0:
            return 0
        while number >= 10.0:
            number /= 10.0
        while 0.0 < number < 1.0:
            number *= 10.0
        digit = int(number)
        return digit if 1 <= digit <= 9 else 0

    @staticmethod
    def _metric_band(value: float, width: int = 10) -> int:
        """Quantisiert eine Metrik in grobe, stabile Banden."""
        return int(max(0, min(100, round(float(value) / max(1, int(width))) * int(width))))

    def vault_noether_profile(
        self,
        fingerprint: AetherFingerprint,
        anchor_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Leitet eine strenge Invarianzsignatur fuer Vault-Orbits ab."""
        anchors = [dict(item) for item in list(anchor_details or []) if isinstance(item, dict)]
        anchor_types = sorted(
            {
                str(item.get("type_label", "")).strip()
                for item in anchors
                if str(item.get("type_label", "")).strip()
            }
        )[:4]
        invariant_core = {
            "source_type": str(getattr(fingerprint, "source_type", "file") or "file"),
            "integrity_state": str(getattr(fingerprint, "integrity_state", "") or ""),
            "observer_state": str(getattr(fingerprint, "observer_state", "") or ""),
            "symmetry_band": self._metric_band(float(getattr(fingerprint, "symmetry_score", 0.0) or 0.0), 10),
            "coherence_band": self._metric_band(float(getattr(fingerprint, "coherence_score", 0.0) or 0.0), 10),
            "resonance_band": self._metric_band(float(getattr(fingerprint, "resonance_score", 0.0) or 0.0), 10),
            "ethics_band": self._metric_band(float(getattr(fingerprint, "ethics_score", 0.0) or 0.0), 10),
            "entropy_band": round(float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0), 1),
            "periodicity_bucket": int(
                min(12, math.log2(int(getattr(fingerprint, "periodicity", 0) or 0) + 1))
            ) if int(getattr(fingerprint, "periodicity", 0) or 0) > 0 else 0,
            "anchor_types": anchor_types,
            "anchor_count_band": min(24, int(len(anchors))),
        }
        canonical = json.dumps(invariant_core, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        invariant_signature = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        orbit_seed = {
            "source_type": invariant_core["source_type"],
            "integrity_state": invariant_core["integrity_state"],
            "symmetry_band": invariant_core["symmetry_band"],
            "coherence_band": invariant_core["coherence_band"],
            "anchor_types": anchor_types[:2],
        }
        orbit_id = hashlib.sha256(
            json.dumps(orbit_seed, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:12].upper()
        symmetry_class = (
            f"{invariant_core['source_type']}|"
            f"{invariant_core['integrity_state']}|"
            f"S{invariant_core['symmetry_band']}|"
            f"C{invariant_core['coherence_band']}|"
            f"{'+'.join(anchor_types or ['NONE'])}"
        )
        return {
            "invariant_signature": str(invariant_signature),
            "orbit_id": str(orbit_id),
            "symmetry_class": str(symmetry_class),
            "invariants": invariant_core,
        }

    def vault_benford_profile(
        self,
        fingerprint: AetherFingerprint,
        anchor_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Bewertet Benford nur dort, wo fuer Vault-Anker genug Zahlenmaterial vorliegt."""
        anchors = [dict(item) for item in list(anchor_details or []) if isinstance(item, dict)]
        digits = [
            self._first_significant_digit(float(item.get("value", 0.0) or 0.0))
            for item in anchors
            if abs(float(item.get("value", 0.0) or 0.0)) > 1e-12
        ]
        digits = [digit for digit in digits if 1 <= digit <= 9]
        auxiliary = float(dict(getattr(fingerprint, "beauty_signature", {}) or {}).get("benford_b", 0.0) or 0.0)
        if len(digits) < 12:
            return {
                "score": float(auxiliary),
                "sample_count": int(len(digits)),
                "informative": False,
                "mode": "beauty_aux",
                "deviation": float(1.0 - auxiliary),
            }
        counts = Counter(digits)
        total = float(len(digits))
        l1_distance = 0.0
        for digit in range(1, 10):
            observed = float(counts.get(digit, 0)) / total
            expected = math.log10(1.0 + (1.0 / float(digit)))
            l1_distance += abs(observed - expected)
        score = float(max(0.0, min(1.0, 1.0 - (l1_distance / 2.0))))
        return {
            "score": float(score),
            "sample_count": int(len(digits)),
            "informative": True,
            "mode": "anchor_values",
            "deviation": float(l1_distance),
        }

    def _zipf_alpha(self, distribution: dict[int, int]) -> float:
        """Schaetzt die Zipf-Steigung der Byte-Rangfolge."""
        frequencies = np.array(sorted((count for count in distribution.values() if count > 0), reverse=True), dtype=np.float64)
        if frequencies.size < 4:
            return 0.0
        ranks = np.arange(1, frequencies.size + 1, dtype=np.float64)
        slope, _ = np.polyfit(np.log(ranks), np.log(frequencies), 1)
        return float(max(0.0, min(3.0, -float(slope))))

    def _beauty_signature(
        self,
        raw: bytes,
        entropy_blocks: list[float],
        distribution: dict[int, int],
        delta: bytes,
        delta_ratio: float,
        symmetry_score: float,
    ) -> dict[str, float]:
        """Berechnet eine additive 7D-Schoenheitssignatur fuer Diagnose und Visualisierung."""
        alpha_1f = self._power_law_alpha(raw)
        lyapunov = self._lyapunov_proxy(entropy_blocks)
        mandelbrot_d = self._katz_fractal_dimension(entropy_blocks)
        kolmogorov_k = self._compressibility_proxy(raw)
        benford_b = self._benford_similarity(delta)
        zipf_z = self._zipf_alpha(distribution)
        symmetry_phi = float(max(0.0, min(1.0, symmetry_score / 100.0)))

        alpha_score = max(0.0, 1.0 - (abs(alpha_1f - 1.0) / 1.5))
        lyapunov_score = max(0.0, 1.0 - (lyapunov / 2.0))
        mandelbrot_score = max(0.0, 1.0 - (abs(mandelbrot_d - 1.5) / 0.8))
        zipf_score = max(0.0, 1.0 - (abs(zipf_z - 1.0) / 1.2))
        delta_stability = max(0.0, min(1.0, 1.0 - delta_ratio))
        beauty_score = 100.0 * (
            (0.15 * alpha_score)
            + (0.10 * lyapunov_score)
            + (0.18 * mandelbrot_score)
            + (0.17 * kolmogorov_k)
            + (0.12 * benford_b)
            + (0.13 * zipf_score)
            + (0.15 * symmetry_phi)
        )
        return {
            "alpha_1f": float(alpha_1f),
            "lyapunov": float(lyapunov),
            "mandelbrot_d": float(mandelbrot_d),
            "kolmogorov_k": float(kolmogorov_k),
            "benford_b": float(benford_b),
            "zipf_z": float(zipf_z),
            "symmetry_phi": float(symmetry_phi),
            "delta_stability": float(delta_stability),
            "beauty_score": float(max(0.0, min(100.0, beauty_score))),
        }

    def _observer_knowledge_state(
        self,
        entropy_mean: float,
        delta_ratio: float,
        coherence_score: float,
        resonance_score: float,
    ) -> tuple[float, float, float, str]:
        """Schaetzt Beobachterwissen und verbleibende Restunsicherheit H_lambda additiv."""
        user_id = int(getattr(self.session_context, "user_id", 0) or 0)
        scoped_user = user_id if user_id > 0 else None
        depth_ratio = 0.0
        familiarity = 0.0
        learning_score = 0.35
        if self.registry is not None:
            try:
                depth_report = self.registry.get_model_depth_report(user_id=scoped_user)
                learning_curve = self.registry.get_delta_learning_curve(user_id=scoped_user)
                depth_ratio = float(depth_report.get("depth_score", 0.0) or 0.0) / 100.0
                familiarity = min(1.0, float(depth_report.get("samples", 0) or 0.0) / 64.0)
                learning_ratio = float(learning_curve.get("improvement_ratio", 0.0) or 0.0)
                learning_score = max(0.0, min(1.0, 0.5 + (learning_ratio * 2.5)))
            except Exception:
                depth_ratio = 0.0
                familiarity = 0.0
                learning_score = 0.35

        compression_affinity = max(0.0, min(1.0, 1.0 - float(delta_ratio)))
        coherence_affinity = max(0.0, min(1.0, float(coherence_score) / 100.0))
        resonance_affinity = max(0.0, min(1.0, float(resonance_score) / 100.0))
        knowledge_ratio = (
            (0.30 * depth_ratio)
            + (0.16 * familiarity)
            + (0.20 * compression_affinity)
            + (0.17 * coherence_affinity)
            + (0.09 * resonance_affinity)
            + (0.08 * learning_score)
        )
        knowledge_ratio = float(max(0.0, min(1.0, knowledge_ratio)))
        observer_information = float(max(0.0, entropy_mean * knowledge_ratio))
        h_lambda = float(max(0.0, entropy_mean - observer_information))
        if h_lambda <= 1.0:
            label = "LOSSLESS_NAH"
        elif h_lambda <= 2.8:
            label = "VERTRAUT"
        elif h_lambda <= 4.8:
            label = "LERNBAR"
        else:
            label = "OFFEN"
        return observer_information, knowledge_ratio, h_lambda, label

    def _build_fingerprint(
        self,
        raw: bytes,
        entropy_blocks: list[float],
        entropy_mean: float,
        periodicity: int,
        anomaly_coordinates: list[tuple[int, int]],
        source_type: str,
        source_label: str,
        voxel_points: list[tuple[float, float, float, float, float, float, float, float]] | None = None,
    ) -> AetherFingerprint:
        """Baut einen AetherFingerprint aus vorbereiteten Metriken."""
        file_size = len(raw)
        distribution = dict(Counter(raw))
        symmetry_score = self._symmetry_score(distribution)
        fourier_peaks = self._fourier_peaks(raw)
        delta, delta_ratio = self._build_delta(raw)
        beauty_signature = self._beauty_signature(
            raw=raw,
            entropy_blocks=entropy_blocks,
            distribution=distribution,
            delta=delta,
            delta_ratio=delta_ratio,
            symmetry_score=symmetry_score,
        )
        ethics = self._compute_ethics(
            symmetry_score=symmetry_score,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            periodicity=periodicity,
            delta_ratio=delta_ratio,
        )
        observer_information, knowledge_ratio, h_lambda, observer_state = self._observer_knowledge_state(
            entropy_mean=entropy_mean,
            delta_ratio=delta_ratio,
            coherence_score=ethics.coherence_score,
            resonance_score=ethics.resonance_score,
        )
        verdict = self._verdict_from_integrity(ethics.integrity_state)

        fingerprint = AetherFingerprint(
            session_id=self.session_context.session_id,
            file_hash=hashlib.sha256(raw).hexdigest(),
            file_size=file_size,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            fourier_peaks=fourier_peaks,
            byte_distribution=distribution,
            periodicity=periodicity,
            symmetry_score=symmetry_score,
            delta=delta,
            delta_ratio=delta_ratio,
            anomaly_coordinates=anomaly_coordinates,
            verdict=verdict,
            timestamp=datetime.now(timezone.utc).isoformat(),
            symmetry_component=ethics.symmetry_component,
            coherence_score=ethics.coherence_score,
            resonance_score=ethics.resonance_score,
            ethics_score=ethics.ethics_score,
            integrity_state=ethics.integrity_state,
            integrity_text=ethics.integrity_text,
            source_type=source_type,
            source_label=source_label,
            observer_mutual_info=observer_information,
            observer_knowledge_ratio=knowledge_ratio,
            h_lambda=h_lambda,
            observer_state=observer_state,
            beauty_signature=beauty_signature,
            voxel_points=voxel_points,
        )

        return fingerprint

    def analyze_bytes(
        self,
        raw: bytes,
        source_label: str = "memory",
        source_type: str = "memory",
        callback: callable = None,
    ) -> AetherFingerprint:
        """Analysiert einen Byte-Strom direkt ohne Dateizugriff."""
        file_size = len(raw)
        entropy_blocks = [
            self._shannon_entropy(raw[idx : idx + self.block_size])
            for idx in range(0, file_size, self.block_size)
        ]
        entropy_mean = float(np.mean(entropy_blocks)) if entropy_blocks else 0.0
        periodicity = self._periodicity(raw)
        anomaly_coordinates = self._anomaly_coordinates(entropy_blocks)
        fingerprint = self._build_fingerprint(
            raw=raw,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            periodicity=periodicity,
            anomaly_coordinates=anomaly_coordinates,
            source_type=source_type,
            source_label=source_label,
        )
        if callback is not None:
            callback(fingerprint)
        return fingerprint

    def analyze_voxel_grid(
        self,
        voxel_grid: VoxelGrid4D,
        source_label: str = "voxel_grid",
    ) -> AetherFingerprint:
        """Analysiert ein 4D-Voxel-Gitter inklusive Ethik- und Resonanzbewertung."""
        raw = voxel_grid.serialize()
        entropy_blocks = voxel_grid.build_entropy_blocks(size=16)
        entropy_mean = float(np.mean(entropy_blocks)) if entropy_blocks else 0.0
        periodicity = voxel_grid.estimate_periodicity()
        anomaly_coordinates = voxel_grid.anomaly_coordinates(size=16)
        return self._build_fingerprint(
            raw=raw,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            periodicity=periodicity,
            anomaly_coordinates=anomaly_coordinates,
            source_type="voxel",
            source_label=source_label,
            voxel_points=voxel_grid.render_points(limit=900),
        )

    def analyze(self, file_path: str) -> AetherFingerprint:
        """
        Fuehrt die vollstaendige Analyse einer Datei durch und erzeugt einen AetherFingerprint.

        Args:
            file_path: Pfad zur Zieldatei.
        """
        try:
            raw = Path(file_path).read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Datei konnte nicht gelesen werden: {exc}") from exc
        return self.analyze_bytes(raw, source_label=str(Path(file_path)), source_type="file")
