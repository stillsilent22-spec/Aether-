"""Dateianalyse fuer Aether."""

from __future__ import annotations

import hashlib
import io
import json
import math
import mimetypes
import re
import sqlite3
import struct
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import numpy as np
from scipy.fft import rfft, rfftfreq

try:
    import magic
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    magic = None

try:
    import cv2
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    cv2 = None

try:
    import fitz
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    fitz = None

try:
    from PIL import Image, ImageStat
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    Image = None
    ImageStat = None

try:
    from pydub import AudioSegment
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    AudioSegment = None

try:
    from fontTools.ttLib import TTFont
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    TTFont = None

try:
    from moviepy import VideoFileClip
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    VideoFileClip = None

from .ae_evolution_core import normalize_anchor_entries
from .blockchain_interface import AetherChain
from .ethics_engine import EthicsAssessment, EthicsEngine
from .reconstruction_engine import LosslessReconstructionEngine
from .session_engine import SessionContext
from .voxel_grid import VoxelGrid4D

if TYPE_CHECKING:
    from .registry import AetherRegistry


MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"%PDF-", "application/pdf", "document"),
    (b"PK\x03\x04", "application/zip", "archive"),
    (b"PK\x05\x06", "application/zip", "archive"),
    (b"PK\x07\x08", "application/zip", "archive"),
    (b"Rar!\x1a\x07", "application/vnd.rar", "archive"),
    (b"7z\xbc\xaf'\x1c", "application/x-7z-compressed", "archive"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "image"),
    (b"\xff\xd8\xff", "image/jpeg", "image"),
    (b"GIF87a", "image/gif", "image"),
    (b"GIF89a", "image/gif", "image"),
    (b"RIFF", "application/riff", "container"),
    (b"ID3", "audio/mpeg", "audio"),
    (b"OggS", "application/ogg", "audio"),
    (b"fLaC", "audio/flac", "audio"),
    (b"MZ", "application/x-msdownload", "executable"),
    (b"\x7fELF", "application/x-elf", "executable"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3", "data"),
    (b"\x00\x00\x01\xba", "video/mpeg", "video"),
)

TEXTUAL_SUFFIXES = {
    ".txt", ".md", ".rst", ".py", ".js", ".ts", ".json", ".csv", ".html", ".htm",
    ".css", ".xml", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".log", ".bat", ".ps1",
}

IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff"}
VIDEO_SUFFIXES = {".mp4", ".mkv", ".avi", ".mov", ".webm", ".wmv", ".m4v"}
AUDIO_SUFFIXES = {".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".wma"}
FONT_SUFFIXES = {".ttf", ".otf", ".woff", ".woff2"}
ARCHIVE_SUFFIXES = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso"}
DOC_SUFFIXES = {".pdf", ".docx", ".txt", ".md", ".html", ".htm"}
CODE_SUFFIXES = {".py", ".js", ".dll", ".exe", ".so", ".bin", ".ps1", ".sh"}
DATA_SUFFIXES = {".csv", ".json", ".sqlite", ".db", ".bin", ".iso"}


def _safe_decode_text(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except Exception:
            continue
    return raw.decode("utf-8", errors="ignore")


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True).encode("utf-8")


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
    scan_hash: str = ""
    scan_payload: dict[str, Any] | None = None
    screen_vision_payload: dict[str, Any] | None = None
    file_profile: dict[str, Any] | None = None
    observer_payload: dict[str, Any] | None = None
    emergence_layers: list[dict[str, Any]] | None = None
    delta_session_seed: int = 0
    reconstruction_verification: dict[str, Any] | None = None
    verdict_reconstruction: str = ""
    verdict_reconstruction_reason: str = ""

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
            "scan_hash": str(self.scan_hash),
            "scan_payload": dict(self.scan_payload or {}),
            "screen_vision_payload": dict(self.screen_vision_payload or {}),
            "file_profile": dict(self.file_profile or {}),
            "observer_payload": dict(self.observer_payload or {}),
            "emergence_layers": [dict(item) for item in list(self.emergence_layers or [])],
            "delta_session_seed": int(self.delta_session_seed),
            "reconstruction_verification": dict(self.reconstruction_verification or {}),
            "verdict_reconstruction": str(self.verdict_reconstruction),
            "verdict_reconstruction_reason": str(self.verdict_reconstruction_reason),
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

    DEFAULT_CHUNK_SIZE = 512 * 1024
    LOW_POWER_CHUNK_SIZE = 256 * 1024

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
        self.reconstruction_engine = LosslessReconstructionEngine(chunk_size=max(64, int(block_size)))

    def set_registry(self, registry: AetherRegistry | None) -> None:
        """
        Verknuepft eine Registry nachtraeglich fuer Resonanz-Berechnung.

        Args:
            registry: Registry-Instanz oder None.
        """
        self.registry = registry

    @staticmethod
    def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
        return float(max(low, min(high, value)))

    def _resolve_chunk_size(self, chunk_size: int | None = None, low_power: bool = False) -> int:
        """Leitet eine CPU-freundliche Analyse-Chunk-Groesse ab."""
        requested = int(chunk_size or (self.LOW_POWER_CHUNK_SIZE if low_power else self.DEFAULT_CHUNK_SIZE))
        return int(max(self.LOW_POWER_CHUNK_SIZE, min(self.DEFAULT_CHUNK_SIZE, requested)))

    def _report_progress(
        self,
        progress_callback: Callable[[str, float, str], None] | None,
        stage: str,
        progress: float,
        detail: str = "",
    ) -> None:
        """Meldet Analysefortschritt robust als normierte 0..1-Spanne."""
        if progress_callback is None:
            return
        try:
            progress_callback(str(stage), self._clamp(float(progress), 0.0, 1.0), str(detail or ""))
        except Exception:
            return

    def _progress_scope(
        self,
        progress_callback: Callable[[str, float, str], None] | None,
        start: float,
        end: float,
    ) -> Callable[[str, float, str], None]:
        """Skaliert Teilfortschritte in einen globalen Analysebereich."""
        low = self._clamp(float(start), 0.0, 1.0)
        high = self._clamp(float(end), low, 1.0)

        def scoped(stage: str, progress: float, detail: str = "") -> None:
            scaled = low + ((high - low) * self._clamp(float(progress), 0.0, 1.0))
            self._report_progress(progress_callback, stage, scaled, detail)

        return scoped

    def _iter_chunk_windows(self, size: int, chunk_size: int) -> list[tuple[int, int]]:
        """Teilt eine Datenmenge deterministisch in Analysefenster auf."""
        if size <= 0:
            return [(0, 0)]
        resolved_chunk = max(1, int(chunk_size))
        return [
            (offset, min(size, offset + resolved_chunk))
            for offset in range(0, size, resolved_chunk)
        ]

    def _read_file_bytes_chunked(
        self,
        file_path: Path,
        chunk_size: int,
        progress_callback: Callable[[str, float, str], None] | None = None,
    ) -> bytes:
        """Liest Dateien sequenziell in 256-512-KB-Fenstern fuer niedrige RAM-Spitzen."""
        total_size = int(file_path.stat().st_size if file_path.exists() else 0)
        if total_size <= 0:
            self._report_progress(progress_callback, "read", 1.0, f"{file_path.name} leer")
            return b""
        windows = self._iter_chunk_windows(total_size, chunk_size)
        buffer = bytearray()
        with file_path.open("rb") as handle:
            for index, (_start, _end) in enumerate(windows, start=1):
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                buffer.extend(chunk)
                self._report_progress(
                    progress_callback,
                    "read",
                    index / max(1, len(windows)),
                    f"{file_path.name} lesen | Chunk {index}/{len(windows)}",
                )
        return bytes(buffer)

    def _chunked_entropy_distribution(
        self,
        raw: bytes,
        chunk_size: int,
        progress_callback: Callable[[str, float, str], None] | None = None,
    ) -> tuple[list[float], dict[int, int]]:
        """Berechnet Entropiebloecke und Byte-Verteilung sequentiell pro Chunk."""
        file_size = len(raw)
        if file_size <= 0:
            self._report_progress(progress_callback, "metrics", 1.0, "Leerer Byte-Strom")
            return [], {}
        windows = self._iter_chunk_windows(file_size, chunk_size)
        entropy_blocks: list[float] = []
        distribution_counter: Counter[int] = Counter()
        for index, (start, end) in enumerate(windows, start=1):
            chunk = raw[start:end]
            if chunk:
                distribution_counter.update(chunk)
                for block_start in range(0, len(chunk), self.block_size):
                    block = chunk[block_start : block_start + self.block_size]
                    entropy_blocks.append(self._shannon_entropy(block))
            self._report_progress(
                progress_callback,
                "metrics",
                index / max(1, len(windows)),
                f"Grundmetriken | Chunk {index}/{len(windows)}",
            )
        return entropy_blocks, dict(distribution_counter)

    def _periodicity_sample(self, raw: bytes, chunk_size: int, low_power: bool = False) -> bytes:
        """Begrenzt die Periodizitaetsanalyse auf reprasentative Byteausschnitte."""
        if not raw:
            return b""
        sample_limit = int(chunk_size if low_power else (chunk_size * 2))
        if len(raw) <= sample_limit:
            return raw
        half = max(1, sample_limit // 2)
        head = raw[:half]
        tail = raw[-half:]
        return bytes(head + tail)

    def _stream_entry(self, label: str, data: bytes, kind: str = "derived") -> dict[str, Any]:
        return {
            "label": str(label),
            "kind": str(kind),
            "size": int(len(data)),
            "bytes": bytes(data),
        }

    def _guess_magic_mime(self, raw: bytes, file_path: Path) -> str:
        if magic is not None:
            try:
                detector = magic.Magic(mime=True)
                return str(detector.from_buffer(raw[:65536]))
            except Exception:
                pass
        for signature, mime_type, _family in MAGIC_SIGNATURES:
            if raw.startswith(signature):
                return str(mime_type)
        guessed, _encoding = mimetypes.guess_type(str(file_path))
        return str(guessed or "application/octet-stream")

    def _classify_file_family(self, raw: bytes, file_path: Path, mime_type: str) -> dict[str, str]:
        suffix = str(file_path.suffix.lower())
        lowered_mime = str(mime_type or "").lower()
        category = "binary"
        subtype = "opaque"
        if suffix in AUDIO_SUFFIXES or lowered_mime.startswith("audio/"):
            category, subtype = "audio", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in VIDEO_SUFFIXES or lowered_mime.startswith("video/"):
            category, subtype = "video", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in IMAGE_SUFFIXES or lowered_mime.startswith("image/"):
            category, subtype = "image", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in FONT_SUFFIXES or "font" in lowered_mime:
            category, subtype = "font", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in ARCHIVE_SUFFIXES or "zip" in lowered_mime or "rar" in lowered_mime or "7z" in lowered_mime:
            category, subtype = "archive", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in DOC_SUFFIXES or lowered_mime.startswith("text/") or lowered_mime == "application/pdf":
            category, subtype = "document", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in DATA_SUFFIXES or lowered_mime in {"application/json", "text/csv", "application/vnd.sqlite3"}:
            category, subtype = "data", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in CODE_SUFFIXES or lowered_mime in {"application/x-msdownload", "application/x-elf"}:
            category, subtype = "code", suffix.lstrip(".") or lowered_mime.replace("/", "_")
        elif suffix in TEXTUAL_SUFFIXES:
            category, subtype = "document", suffix.lstrip(".")
        return {
            "mime_type": str(lowered_mime or "application/octet-stream"),
            "category": str(category),
            "subtype": str(subtype or "opaque"),
            "suffix": suffix,
        }

    def _stream_metrics(self, streams: list[dict[str, Any]]) -> dict[str, Any]:
        metrics: list[dict[str, Any]] = []
        entropies: list[float] = []
        symmetries: list[float] = []
        for stream in streams:
            raw = bytes(stream.get("bytes", b""))
            if not raw:
                continue
            entropy = self._shannon_entropy(raw[: min(len(raw), 4096)])
            symmetry = self._symmetry_score(dict(Counter(raw[: min(len(raw), 4096)])))
            entropies.append(float(entropy))
            symmetries.append(float(symmetry))
            metrics.append(
                {
                    "label": str(stream.get("label", "")),
                    "kind": str(stream.get("kind", "")),
                    "size": int(stream.get("size", 0) or 0),
                    "entropy": round(float(entropy), 12),
                    "symmetry": round(float(symmetry), 12),
                }
            )
        entropy_mean = float(np.mean(entropies)) if entropies else 0.0
        symmetry_mean = float(np.mean(symmetries)) if symmetries else 100.0
        stream_count = int(len(metrics))
        observer_boost = self._clamp(
            (math.log2(1.0 + float(stream_count)) / math.log2(9.0)) * (float(entropy_mean) / 8.0),
            0.0,
            1.0,
        )
        return {
            "stream_count": stream_count,
            "stream_metrics": metrics,
            "type_entropy_mean": round(float(entropy_mean), 12),
            "type_symmetry_mean": round(float(symmetry_mean), 12),
            "type_information_gain": round(float(observer_boost), 12),
        }

    def _parser_missing(self, dependency: str, category: str, subtype: str, raw: bytes) -> dict[str, Any]:
        return {
            "category": str(category),
            "subtype": str(subtype),
            "summary": {},
            "streams": [self._stream_entry("raw_bytes", raw[: min(len(raw), 65536)], kind="raw")],
            "missing_dependencies": [str(dependency)],
            "missing_data": [],
        }

    def _parse_image_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        if Image is None or ImageStat is None:
            return self._parser_missing("pillow", category, subtype, raw)
        with Image.open(io.BytesIO(raw)) as image:
            rgb = image.convert("RGB")
            stats = ImageStat.Stat(rgb)
            summary = {
                "width": int(rgb.width),
                "height": int(rgb.height),
                "mode": str(image.mode),
                "mean": [round(float(value), 6) for value in list(stats.mean)],
                "stddev": [round(float(value), 6) for value in list(stats.stddev)],
            }
            thumbnail = rgb.copy()
            thumbnail.thumbnail((128, 128))
            streams = [
                self._stream_entry("pixel_bytes", rgb.tobytes(), kind="pixel"),
                self._stream_entry("thumbnail_bytes", thumbnail.tobytes(), kind="pixel"),
                self._stream_entry("image_summary", _json_bytes(summary), kind="metadata"),
            ]
            return {
                "category": category,
                "subtype": subtype,
                "summary": summary,
                "streams": streams,
                "missing_dependencies": [],
                "missing_data": [],
            }

    def _parse_audio_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        if AudioSegment is None:
            return self._parser_missing("pydub", category, subtype, raw)
        segment = AudioSegment.from_file(str(file_path))
        sample_array = np.array(segment.get_array_of_samples())
        if int(segment.channels) > 1 and sample_array.size >= int(segment.channels):
            sample_array = sample_array.reshape((-1, int(segment.channels)))
        chunk_count = min(64, max(1, int(math.ceil(len(segment) / 100.0))))
        rms_values: list[float] = []
        for index in range(chunk_count):
            start = int(index * len(segment) / chunk_count)
            end = int((index + 1) * len(segment) / chunk_count)
            slice_segment = segment[start:end]
            rms_values.append(float(slice_segment.rms))
        summary = {
            "duration_ms": int(len(segment)),
            "frame_rate": int(segment.frame_rate),
            "channels": int(segment.channels),
            "sample_width": int(segment.sample_width),
            "sample_count": int(sample_array.size),
        }
        rms_stream = np.array(rms_values, dtype=np.float64).tobytes()
        sample_bytes = sample_array[: min(sample_array.size, 65536)].tobytes()
        streams = [
            self._stream_entry("audio_samples", sample_bytes, kind="audio"),
            self._stream_entry("audio_waveform_rms", rms_stream, kind="waveform"),
            self._stream_entry("audio_summary", _json_bytes(summary), kind="metadata"),
        ]
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": [],
        }

    def _parse_video_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        missing_dependencies: list[str] = []
        if cv2 is None:
            return self._parser_missing("opencv-python", category, subtype, raw)
        capture = cv2.VideoCapture(str(file_path))
        if not capture.isOpened():
            return {
                "category": category,
                "subtype": subtype,
                "summary": {"opened": False},
                "streams": [self._stream_entry("raw_bytes", raw[: min(len(raw), 65536)], kind="raw")],
                "missing_dependencies": [],
                "missing_data": ["video_frames_unavailable"],
            }
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        fps = float(capture.get(cv2.CAP_PROP_FPS) or 0.0)
        width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        sample_targets = list(sorted({0, max(0, frame_count // 4), max(0, frame_count // 2), max(0, frame_count - 1)}))
        sampled_frames: list[bytes] = []
        frame_entropies: list[float] = []
        for target in sample_targets:
            capture.set(cv2.CAP_PROP_POS_FRAMES, float(target))
            ok, frame = capture.read()
            if not ok or frame is None:
                continue
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            resized = cv2.resize(rgb, (min(128, rgb.shape[1]), min(128, rgb.shape[0])), interpolation=cv2.INTER_AREA)
            frame_bytes = resized.tobytes()
            sampled_frames.append(frame_bytes)
            frame_entropies.append(self._shannon_entropy(frame_bytes[: min(len(frame_bytes), 4096)]))
        capture.release()
        if VideoFileClip is None:
            missing_dependencies.append("moviepy")
            audio_summary: dict[str, Any] = {"audio_track_inspected": False}
        else:
            audio_summary = {"audio_track_inspected": False}
            try:
                clip = VideoFileClip(str(file_path))
                audio_summary = {
                    "audio_track_inspected": bool(clip.audio is not None),
                    "duration_s": round(float(clip.duration or 0.0), 6),
                }
                try:
                    clip.close()
                except Exception:
                    pass
            except Exception:
                missing_dependencies.append("moviepy")
        summary = {
            "frame_count": int(frame_count),
            "fps": round(float(fps), 6),
            "width": int(width),
            "height": int(height),
            "sampled_frame_count": int(len(sampled_frames)),
            "frame_entropy_mean": round(float(np.mean(frame_entropies)) if frame_entropies else 0.0, 12),
            "audio": audio_summary,
        }
        streams = [self._stream_entry(f"video_frame_{index}", frame, kind="frame") for index, frame in enumerate(sampled_frames)]
        streams.append(self._stream_entry("video_summary", _json_bytes(summary), kind="metadata"))
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": sorted(set(missing_dependencies)),
            "missing_data": [] if sampled_frames else ["video_frames_unavailable"],
        }

    def _parse_pdf_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        if fitz is None:
            return self._parser_missing("pymupdf", category, subtype, raw)
        document = fitz.open(stream=raw, filetype="pdf")
        page_texts: list[str] = []
        page_lengths: list[int] = []
        for page in document:
            text = page.get_text("text")
            page_texts.append(text)
            page_lengths.append(len(text))
        summary = {
            "page_count": int(document.page_count),
            "text_length": int(sum(page_lengths)),
            "metadata": {str(key): str(value) for key, value in dict(document.metadata or {}).items()},
            "page_text_lengths": page_lengths[:32],
        }
        streams = [
            self._stream_entry("pdf_text", "\n".join(page_texts).encode("utf-8", errors="ignore"), kind="text"),
            self._stream_entry("pdf_summary", _json_bytes(summary), kind="metadata"),
        ]
        document.close()
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": [] if page_texts else ["pdf_text_unavailable"],
        }

    def _parse_docx_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        text_payload = ""
        entry_names: list[str] = []
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entry_names = sorted(archive.namelist())
            if "word/document.xml" in entry_names:
                xml_bytes = archive.read("word/document.xml")
                text_payload = " ".join(re.findall(r">([^<]+)<", _safe_decode_text(xml_bytes)))
        summary = {
            "entry_count": int(len(entry_names)),
            "entries": entry_names[:24],
            "text_length": int(len(text_payload)),
        }
        streams = [
            self._stream_entry("docx_text", text_payload.encode("utf-8", errors="ignore"), kind="text"),
            self._stream_entry("docx_manifest", "\n".join(entry_names).encode("utf-8"), kind="metadata"),
            self._stream_entry("docx_summary", _json_bytes(summary), kind="metadata"),
        ]
        missing_data = [] if text_payload else ["docx_text_unavailable"]
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": missing_data,
        }

    def _parse_text_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        text = _safe_decode_text(raw)
        lines = text.splitlines()
        tokens = re.findall(r"[A-Za-z0-9_]+", text)
        summary = {
            "line_count": int(len(lines)),
            "token_count": int(len(tokens)),
            "character_count": int(len(text)),
        }
        streams = [
            self._stream_entry("text_content", text.encode("utf-8", errors="ignore"), kind="text"),
            self._stream_entry("text_summary", _json_bytes(summary), kind="metadata"),
        ]
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": [],
        }

    def _parse_font_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        if TTFont is None:
            return self._parser_missing("fonttools", category, subtype, raw)
        font = TTFont(str(file_path), recalcBBoxes=False, recalcTimestamp=False)
        glyph_order = list(font.getGlyphOrder())
        widths: list[int] = []
        if "hmtx" in font:
            widths = [int(width) for _name, (width, _lsb) in list(font["hmtx"].metrics.items())[:512]]
        summary = {
            "glyph_count": int(len(glyph_order)),
            "units_per_em": int(getattr(font["head"], "unitsPerEm", 0) if "head" in font else 0),
            "family_name": str(font["name"].getDebugName(1) if "name" in font else ""),
        }
        streams = [
            self._stream_entry("font_glyph_order", "\n".join(glyph_order[:512]).encode("utf-8"), kind="metadata"),
            self._stream_entry("font_widths", np.array(widths, dtype=np.int32).tobytes(), kind="geometry"),
            self._stream_entry("font_summary", _json_bytes(summary), kind="metadata"),
        ]
        try:
            font.close()
        except Exception:
            pass
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": [],
        }

    def _parse_archive_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        suffix = str(file_path.suffix.lower())
        if suffix == ".zip" or raw.startswith(b"PK"):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                names = sorted(archive.namelist())
                preview_entries: list[bytes] = []
                for name in names[:8]:
                    try:
                        preview_entries.append(archive.read(name)[:4096])
                    except Exception:
                        continue
            summary = {"entry_count": int(len(names)), "entries": names[:32]}
            streams = [self._stream_entry("archive_manifest", "\n".join(names).encode("utf-8"), kind="metadata")]
            streams.extend(self._stream_entry(f"archive_entry_{index}", entry, kind="payload") for index, entry in enumerate(preview_entries))
            streams.append(self._stream_entry("archive_summary", _json_bytes(summary), kind="metadata"))
            return {
                "category": category,
                "subtype": subtype,
                "summary": summary,
                "streams": streams,
                "missing_dependencies": [],
                "missing_data": [],
            }
        missing = []
        if suffix == ".rar":
            missing.append("rar support unavailable")
        if suffix == ".7z":
            missing.append("7z support unavailable")
        if suffix == ".iso":
            missing.append("iso filesystem parsing unavailable")
        return {
            "category": category,
            "subtype": subtype,
            "summary": {"entry_count": 0},
            "streams": [self._stream_entry("archive_header", raw[: min(len(raw), 65536)], kind="raw")],
            "missing_dependencies": [],
            "missing_data": missing,
        }

    def _parse_data_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        suffix = str(file_path.suffix.lower())
        summary: dict[str, Any] = {}
        streams: list[dict[str, Any]] = []
        missing_data: list[str] = []
        if suffix == ".json":
            try:
                payload = json.loads(_safe_decode_text(raw))
                canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2)
                summary = {"root_type": type(payload).__name__, "size": int(len(canonical))}
                streams.append(self._stream_entry("json_canonical", canonical.encode("utf-8"), kind="text"))
            except Exception:
                missing_data.append("json_parse_failed")
        elif suffix in {".sqlite", ".db"}:
            try:
                connection = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
                cursor = connection.cursor()
                tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                counts = {}
                for table in tables[:16]:
                    try:
                        counts[str(table)] = int(cursor.execute(f"SELECT COUNT(*) FROM \"{table}\"").fetchone()[0])
                    except Exception:
                        counts[str(table)] = 0
                summary = {"tables": tables[:32], "table_counts": counts}
                streams.append(self._stream_entry("sqlite_schema", _json_bytes(summary), kind="metadata"))
                connection.close()
            except Exception:
                missing_data.append("sqlite_parse_failed")
        elif suffix == ".csv":
            text = _safe_decode_text(raw)
            lines = text.splitlines()
            header = lines[0].split(",") if lines else []
            summary = {"row_count": int(max(0, len(lines) - 1)), "column_count": int(len(header))}
            streams.append(self._stream_entry("csv_text", text.encode("utf-8"), kind="text"))
        elif suffix == ".iso":
            summary = {"header_bytes": int(min(65536, len(raw)))}
            streams.append(self._stream_entry("iso_header", raw[: min(len(raw), 65536)], kind="raw"))
        else:
            summary = {"binary_size": int(len(raw))}
            streams.append(self._stream_entry("data_bytes", raw[: min(len(raw), 65536)], kind="raw"))
        streams.append(self._stream_entry("data_summary", _json_bytes(summary), kind="metadata"))
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": missing_data,
        }

    def _parse_code_profile(self, file_path: Path, raw: bytes, category: str, subtype: str) -> dict[str, Any]:
        suffix = str(file_path.suffix.lower())
        if suffix in TEXTUAL_SUFFIXES:
            text = _safe_decode_text(raw)
            lines = text.splitlines()
            summary = {"line_count": int(len(lines)), "char_count": int(len(text))}
            streams = [
                self._stream_entry("code_text", text.encode("utf-8", errors="ignore"), kind="text"),
                self._stream_entry("code_summary", _json_bytes(summary), kind="metadata"),
            ]
            return {
                "category": category,
                "subtype": subtype,
                "summary": summary,
                "streams": streams,
                "missing_dependencies": [],
                "missing_data": [],
            }
        summary = {
            "mz_header": bool(raw.startswith(b"MZ")),
            "elf_header": bool(raw.startswith(b"\x7fELF")),
            "header_size": int(min(len(raw), 1024)),
        }
        streams = [
            self._stream_entry("binary_header", raw[: min(len(raw), 4096)], kind="raw"),
            self._stream_entry("binary_summary", _json_bytes(summary), kind="metadata"),
        ]
        return {
            "category": category,
            "subtype": subtype,
            "summary": summary,
            "streams": streams,
            "missing_dependencies": [],
            "missing_data": [],
        }

    def detect_and_parse_file(
        self,
        file_path: str,
        chunk_size: int | None = None,
        low_power: bool = False,
        progress_callback: Callable[[str, float, str], None] | None = None,
    ) -> dict[str, Any]:
        """Erkennt Dateityp, extrahiert typspezifische Streams und meldet fehlende Abhaengigkeiten."""
        path = Path(file_path)
        resolved_chunk_size = self._resolve_chunk_size(chunk_size=chunk_size, low_power=low_power)
        raw = self._read_file_bytes_chunked(path, resolved_chunk_size, progress_callback=progress_callback)
        self._report_progress(progress_callback, "type_detect", 0.40, f"{path.suffix.lower() or '.bin'} erkennen")
        mime_type = self._guess_magic_mime(raw, path)
        classification = self._classify_file_family(raw, path, mime_type)
        category = str(classification["category"])
        subtype = str(classification["subtype"])
        try:
            if category == "image":
                parsed = self._parse_image_profile(path, raw, category, subtype)
            elif category == "audio":
                parsed = self._parse_audio_profile(path, raw, category, subtype)
            elif category == "video":
                parsed = self._parse_video_profile(path, raw, category, subtype)
            elif category == "font":
                parsed = self._parse_font_profile(path, raw, category, subtype)
            elif category == "archive":
                parsed = self._parse_archive_profile(path, raw, category, subtype)
            elif category == "data":
                parsed = self._parse_data_profile(path, raw, category, subtype)
            elif category == "code":
                parsed = self._parse_code_profile(path, raw, category, subtype)
            elif category == "document" and subtype == "pdf":
                parsed = self._parse_pdf_profile(path, raw, category, subtype)
            elif category == "document" and subtype == "docx":
                parsed = self._parse_docx_profile(path, raw, category, subtype)
            else:
                parsed = self._parse_text_profile(path, raw, category, subtype) if category == "document" else {
                    "category": category,
                    "subtype": subtype,
                    "summary": {"binary_size": int(len(raw))},
                    "streams": [self._stream_entry("raw_bytes", raw[: min(len(raw), 65536)], kind="raw")],
                    "missing_dependencies": [],
                    "missing_data": [],
                }
        except Exception as exc:
            parsed = {
                "category": category,
                "subtype": subtype,
                "summary": {"parser_error": str(exc)},
                "streams": [self._stream_entry("raw_bytes", raw[: min(len(raw), 65536)], kind="raw")],
                "missing_dependencies": [],
                "missing_data": ["parser_failed"],
            }

        streams = [dict(item) for item in list(parsed.get("streams", []) or [])]
        self._report_progress(progress_callback, "type_parse", 0.82, f"{category}/{subtype} parsen")
        stream_metrics = self._stream_metrics(streams)
        public_streams = [
            {
                "label": str(stream.get("label", "")),
                "kind": str(stream.get("kind", "")),
                "size": int(stream.get("size", 0) or 0),
            }
            for stream in streams
        ]
        parser_confidence = self._clamp(
            1.0
            - (float(len(parsed.get("missing_dependencies", []) or [])) * 0.25)
            - (float(len(parsed.get("missing_data", []) or [])) * 0.15),
            0.0,
            1.0,
        )
        missing_dependencies = sorted(set(str(item) for item in list(parsed.get("missing_dependencies", []) or [])))
        if magic is None:
            missing_dependencies.append("python-magic")
            missing_dependencies = sorted(set(missing_dependencies))
        self._report_progress(progress_callback, "type_ready", 1.0, f"{path.name} vorbereitet")
        return {
            "path": str(path),
            "file_name": str(path.name),
            "suffix": str(path.suffix.lower()),
            "file_size": int(len(raw)),
            "mime_type": str(mime_type),
            "category": category,
            "subtype": subtype,
            "raw_bytes": raw,
            "streams": streams,
            "feature_streams": public_streams,
            "summary": dict(parsed.get("summary", {}) or {}),
            "missing_dependencies": missing_dependencies,
            "missing_data": sorted(set(str(item) for item in list(parsed.get("missing_data", []) or []))),
            "parser_confidence": round(float(parser_confidence), 12),
            "type_metrics": stream_metrics,
            "analysis_chunk_size": int(resolved_chunk_size),
            "low_power_mode": bool(low_power),
        }

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
        counts = Counter(distances)
        best_count = max(counts.values())
        return min(distance for distance, count in counts.items() if count == best_count)

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
        ranked_peaks = sorted(
            (
                (float(spectrum[index]), float(freqs[index]), int(index))
                for index in range(int(spectrum.size))
                if float(spectrum[index]) > 0.0
            ),
            key=lambda item: (-item[0], item[1], item[2]),
        )
        peaks = [
            {"frequency": float(frequency), "magnitude": float(magnitude)}
            for magnitude, frequency, _index in ranked_peaks[:5]
        ]
        while len(peaks) < 5:
            peaks.append({"frequency": 0.0, "magnitude": 0.0})
        return peaks

    def _build_delta(self, raw: bytes) -> tuple[bytes, float, int]:
        """Erzeugt das session-abhaengige Delta und seine Kompressionsrate."""
        file_size = len(raw)
        session_seed = int(self.session_context.get_seed())
        noise = SessionContext.noise_from_seed(session_seed, file_size)
        delta = bytes(a ^ b for a, b in zip(raw, noise))
        if file_size == 0:
            return delta, 0.0, session_seed
        compressed_size = len(zlib.compress(delta, level=9))
        delta_ratio = float(max(0.0, min(1.0, compressed_size / file_size)))
        return delta, delta_ratio, session_seed

    @staticmethod
    def _reconstruct_delta_bytes(delta: bytes, session_seed: int) -> bytes:
        """Hebt ein sessionbasiertes XOR-Delta wieder in Originalbytes auf."""
        noise = SessionContext.noise_from_seed(int(session_seed) & 0xFFFFFFFF, len(delta))
        return bytes(value ^ mask for value, mask in zip(delta, noise))

    def _reconstruction_verdict(
        self,
        verification: dict[str, Any],
        delta_session_seed: int,
    ) -> tuple[str, str]:
        """Leitet einen klaren Rekonstruktionsbefund samt Fehlergrund ab."""
        failures: list[str] = []
        if not bool(verification.get("verified", False)):
            if not bool(verification.get("byte_match", False)):
                failures.append("byte_match failed")
            if not bool(verification.get("size_match", False)):
                failures.append("size_match failed")
        anchor_ratio = float(verification.get("anchor_coverage_ratio", 0.0) or 0.0)
        residual_ratio = float(
            verification.get("unresolved_residual_ratio", 1.0)
            if verification.get("unresolved_residual_ratio", None) is not None
            else 1.0
        )
        if anchor_ratio <= 0.85:
            failures.append(f"anchor_coverage_ratio {anchor_ratio:.3f} <= 0.850")
        if residual_ratio >= 0.15:
            failures.append(f"unresolved_residual_ratio {residual_ratio:.3f} >= 0.150")
        session_seed_match = bool(int(delta_session_seed) == int(self.session_context.get_seed()))
        if not session_seed_match:
            failures.append("delta_session_seed mismatch")
        if not failures:
            return "CONFIRMED", ""
        return "FAILED", "; ".join(failures)

    def _apply_reconstruction_verification(
        self,
        fingerprint: AetherFingerprint,
        raw: bytes,
    ) -> AetherFingerprint:
        """Prueft die Delta-Rekonstruktion direkt im Analysepfad und schreibt den Befund in den Fingerprint."""
        reconstructed = self._reconstruct_delta_bytes(
            bytes(getattr(fingerprint, "delta", b"") or b""),
            int(getattr(fingerprint, "delta_session_seed", 0) or 0),
        )
        verification = dict(self.reconstruction_engine.verify_lossless(raw, reconstructed))
        verification["delta_session_seed"] = int(getattr(fingerprint, "delta_session_seed", 0) or 0)
        verification["session_seed_match"] = bool(
            int(getattr(fingerprint, "delta_session_seed", 0) or 0) == int(self.session_context.get_seed())
        )
        verdict_reconstruction, reason = self._reconstruction_verdict(
            verification=verification,
            delta_session_seed=int(getattr(fingerprint, "delta_session_seed", 0) or 0),
        )
        verification["verdict_reconstruction"] = str(verdict_reconstruction)
        verification["reason"] = str(reason)
        fingerprint.reconstruction_verification = verification
        fingerprint.verdict_reconstruction = str(verdict_reconstruction)
        fingerprint.verdict_reconstruction_reason = str(reason)
        fingerprint.anchor_coverage_ratio = float(verification.get("anchor_coverage_ratio", 0.0) or 0.0)
        fingerprint.unresolved_residual_ratio = float(
            verification.get("unresolved_residual_ratio", 1.0)
            if verification.get("unresolved_residual_ratio", None) is not None
            else 1.0
        )
        fingerprint.coverage_verified = bool(
            float(verification.get("anchor_coverage_ratio", 0.0) or 0.0) > 0.85
            and float(
                verification.get("unresolved_residual_ratio", 1.0)
                if verification.get("unresolved_residual_ratio", None) is not None
                else 1.0
            ) < 0.15
        )
        return fingerprint

    @staticmethod
    def _scan_hash(raw: bytes) -> str:
        """Liefert einen rein bytebasierten Hash fuer deterministische DNA-Scans."""
        return hashlib.sha256(raw).hexdigest()

    def _build_scan_delta(self, raw: bytes, scan_hash: str) -> tuple[bytes, float]:
        """Erzeugt ein bytebasiertes Delta ohne Session-Einfluss."""
        file_size = len(raw)
        if file_size == 0:
            return b"", 0.0
        seed = int(str(scan_hash or "0")[:16], 16) & 0xFFFFFFFF
        noise = SessionContext.noise_from_seed(seed, file_size)
        delta = bytes(a ^ b for a, b in zip(raw, noise))
        compressed_size = len(zlib.compress(delta, level=9))
        delta_ratio = float(max(0.0, min(1.0, compressed_size / file_size)))
        return delta, delta_ratio

    def _build_scan_anchor_entries(
        self,
        entropy_blocks: list[float],
        fourier_peaks: list[dict[str, float]],
        periodicity: int,
        symmetry_score: float,
        scan_delta_ratio: float,
        beauty_signature: dict[str, float],
        file_size: int,
    ) -> list[dict[str, Any]]:
        """Leitet eine stabile, rein bytebasierte Anchor-Menge fuer DNA-Exports ab."""
        raw_entries: list[dict[str, Any]] = []
        ranked_entropy = sorted(
            (
                (int(index), float(value))
                for index, value in enumerate(entropy_blocks)
                if abs(float(value)) > 1e-12
            ),
            key=lambda item: (-round(item[1], 12), item[0]),
        )
        for index, value in ranked_entropy[:8]:
            raw_entries.append(
                {
                    "index": int(index),
                    "value": round(float(value), 12),
                    "origin": "scan_entropy",
                    "type": "SCAN_ENTROPY",
                    "stability": True,
                    "reproducible": True,
                }
            )

        ranked_peaks = sorted(
            (
                (
                    int(index),
                    float(peak.get("frequency", 0.0) or 0.0),
                    float(peak.get("magnitude", 0.0) or 0.0),
                )
                for index, peak in enumerate(fourier_peaks)
            ),
            key=lambda item: (-round(item[2], 12), item[1], item[0]),
        )
        for index, frequency, magnitude in ranked_peaks[:4]:
            if abs(frequency) > 1e-12:
                raw_entries.append(
                    {
                        "index": int(1000 + index),
                        "value": round(float(frequency), 12),
                        "origin": "scan_fourier_frequency",
                        "type": "SCAN_FREQUENCY",
                        "stability": True,
                        "reproducible": True,
                    }
                )
            magnitude_norm = float(magnitude / max(1.0, float(file_size)))
            if abs(magnitude_norm) > 1e-12:
                raw_entries.append(
                    {
                        "index": int(1100 + index),
                        "value": round(float(magnitude_norm), 12),
                        "origin": "scan_fourier_magnitude",
                        "type": "SCAN_MAGNITUDE",
                        "stability": True,
                        "reproducible": True,
                    }
                )

        scalar_entries = [
            ("scan_periodicity", "SCAN_PERIODICITY", 2000, float(periodicity)),
            ("scan_symmetry", "SCAN_SYMMETRY", 2001, float(symmetry_score) / 100.0),
            ("scan_delta_ratio", "SCAN_DELTA_RATIO", 2002, float(scan_delta_ratio)),
            (
                "scan_beauty_score",
                "SCAN_BEAUTY",
                2003,
                float(dict(beauty_signature or {}).get("beauty_score", 0.0) or 0.0) / 100.0,
            ),
        ]
        for origin, anchor_type, index, value in scalar_entries:
            if abs(float(value)) <= 1e-12:
                continue
            raw_entries.append(
                {
                    "index": int(index),
                    "value": round(float(value), 12),
                    "origin": str(origin),
                    "type": str(anchor_type),
                    "stability": True,
                    "reproducible": True,
                }
            )

        raw_entries.sort(
            key=lambda item: (
                int(item.get("index", 0) or 0),
                float(item.get("value", 0.0) or 0.0),
                str(item.get("type", "")),
                str(item.get("origin", "")),
            )
        )
        return normalize_anchor_entries(raw_entries)

    def _build_scan_payload(
        self,
        raw: bytes,
        file_size: int,
        entropy_blocks: list[float],
        entropy_mean: float,
        periodicity: int,
        anomaly_coordinates: list[tuple[int, int]],
        symmetry_score: float,
        fourier_peaks: list[dict[str, float]],
    ) -> tuple[str, dict[str, Any]]:
        """Baut einen deterministischen AELAB-Scanpayload ausschliesslich aus Input-Bytes."""
        scan_hash = self._scan_hash(raw)
        scan_delta, scan_delta_ratio = self._build_scan_delta(raw, scan_hash)
        scan_beauty_signature = self._beauty_signature(
            raw=raw,
            entropy_blocks=entropy_blocks,
            distribution=dict(Counter(raw)),
            delta=scan_delta,
            delta_ratio=scan_delta_ratio,
            symmetry_score=symmetry_score,
        )
        scan_anchor_entries = self._build_scan_anchor_entries(
            entropy_blocks=entropy_blocks,
            fourier_peaks=fourier_peaks,
            periodicity=periodicity,
            symmetry_score=symmetry_score,
            scan_delta_ratio=scan_delta_ratio,
            beauty_signature=scan_beauty_signature,
            file_size=file_size,
        )
        payload = {
            "scan_hash": str(scan_hash),
            "file_hash": str(scan_hash),
            "file_size": int(file_size),
            "entropy_mean": round(float(entropy_mean), 12),
            "entropy_blocks": [round(float(value), 12) for value in entropy_blocks[:64]],
            "periodicity": int(periodicity),
            "symmetry_score": round(float(symmetry_score), 12),
            "delta_ratio": round(float(scan_delta_ratio), 12),
            "beauty_signature": {
                str(key): round(float(value), 12)
                for key, value in sorted(dict(scan_beauty_signature or {}).items(), key=lambda item: item[0])
            },
            "fourier_peaks": [
                {
                    "frequency": round(float(item.get("frequency", 0.0) or 0.0), 12),
                    "magnitude": round(float(item.get("magnitude", 0.0) or 0.0), 12),
                }
                for item in fourier_peaks[:5]
            ],
            "anomaly_coordinates": [
                [int(x_pos), int(y_pos)]
                for x_pos, y_pos in sorted((int(x), int(y)) for x, y in anomaly_coordinates)
            ],
            "scan_anchor_entries": [dict(item) for item in scan_anchor_entries],
        }
        return str(scan_hash), payload

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
        low_power: bool = False,
    ) -> dict[str, float]:
        """Berechnet eine additive 7D-Schoenheitssignatur fuer Diagnose und Visualisierung."""
        alpha_1f = self._power_law_alpha(raw)
        lyapunov = self._lyapunov_proxy(entropy_blocks)
        fractal_source = list(entropy_blocks)
        if low_power and len(fractal_source) > 32:
            step = max(2, int(math.ceil(len(fractal_source) / 32.0)))
            fractal_source = fractal_source[::step]
        mandelbrot_d = self._katz_fractal_dimension(fractal_source)
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
            "low_power_mode": float(1.0 if low_power else 0.0),
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

    def _apply_file_profile(
        self,
        fingerprint: AetherFingerprint,
        file_profile: dict[str, Any] | None = None,
    ) -> AetherFingerprint:
        profile = dict(file_profile or {})
        if not profile:
            return fingerprint
        type_metrics = dict(profile.get("type_metrics", {}) or {})
        type_entropy_mean = float(type_metrics.get("type_entropy_mean", 0.0) or 0.0)
        type_information_gain = float(type_metrics.get("type_information_gain", 0.0) or 0.0)
        parser_confidence = float(profile.get("parser_confidence", 0.0) or 0.0)
        observer_boost = float(
            min(
                float(fingerprint.entropy_mean),
                (type_entropy_mean / 8.0) * math.log2(1.0 + float(type_metrics.get("stream_count", 0) or 0)) * parser_confidence,
            )
        )
        if observer_boost > 0.0:
            fingerprint.observer_mutual_info = float(
                min(float(fingerprint.entropy_mean), float(fingerprint.observer_mutual_info) + observer_boost)
            )
            fingerprint.observer_knowledge_ratio = self._clamp(
                float(fingerprint.observer_mutual_info) / max(1e-9, float(fingerprint.entropy_mean))
            )
            fingerprint.h_lambda = float(max(0.0, float(fingerprint.entropy_mean) - float(fingerprint.observer_mutual_info)))
            if float(fingerprint.h_lambda) <= 1.0:
                fingerprint.observer_state = "LOSSLESS_NAH"
            elif float(fingerprint.h_lambda) <= 2.8:
                fingerprint.observer_state = "VERTRAUT"
            elif float(fingerprint.h_lambda) <= 4.8:
                fingerprint.observer_state = "LERNBAR"
            else:
                fingerprint.observer_state = "OFFEN"
        profile["type_observer_boost"] = round(float(observer_boost), 12)
        fingerprint.file_profile = profile
        return fingerprint

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
        file_profile: dict[str, Any] | None = None,
        distribution: dict[int, int] | None = None,
        low_power: bool = False,
    ) -> AetherFingerprint:
        """Baut einen AetherFingerprint aus vorbereiteten Metriken."""
        file_size = len(raw)
        distribution = dict(distribution or Counter(raw))
        symmetry_score = self._symmetry_score(distribution)
        fourier_peaks = self._fourier_peaks(raw)
        delta, delta_ratio, delta_session_seed = self._build_delta(raw)
        beauty_signature = self._beauty_signature(
            raw=raw,
            entropy_blocks=entropy_blocks,
            distribution=distribution,
            delta=delta,
            delta_ratio=delta_ratio,
            symmetry_score=symmetry_score,
            low_power=low_power,
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
        file_hash = self._scan_hash(raw)
        scan_hash, scan_payload = self._build_scan_payload(
            raw=raw,
            file_size=file_size,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            periodicity=periodicity,
            anomaly_coordinates=anomaly_coordinates,
            symmetry_score=symmetry_score,
            fourier_peaks=fourier_peaks,
        )

        fingerprint = AetherFingerprint(
            session_id=self.session_context.session_id,
            file_hash=file_hash,
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
            scan_hash=scan_hash,
            scan_payload=scan_payload,
            file_profile=dict(file_profile or {}),
            delta_session_seed=int(delta_session_seed),
        )
        fingerprint = self._apply_file_profile(fingerprint, file_profile=file_profile)
        return self._apply_reconstruction_verification(fingerprint, raw=raw)

    def analyze_bytes(
        self,
        raw: bytes,
        source_label: str = "memory",
        source_type: str = "memory",
        callback: callable = None,
        file_profile: dict[str, Any] | None = None,
        low_power: bool = False,
        chunk_size: int | None = None,
        progress_callback: Callable[[str, float, str], None] | None = None,
    ) -> AetherFingerprint:
        """Analysiert einen Byte-Strom direkt ohne Dateizugriff."""
        file_size = len(raw)
        resolved_chunk_size = self._resolve_chunk_size(chunk_size=chunk_size, low_power=low_power)
        self._report_progress(progress_callback, "metrics", 0.0, f"{source_label} vorbereiten")
        entropy_blocks, distribution = self._chunked_entropy_distribution(
            raw,
            resolved_chunk_size,
            progress_callback=self._progress_scope(progress_callback, 0.0, 0.58),
        )
        entropy_mean = float(np.mean(entropy_blocks)) if entropy_blocks else 0.0
        self._report_progress(progress_callback, "periodicity", 0.64, "Periodizitaet berechnen")
        periodicity = self._periodicity(self._periodicity_sample(raw, resolved_chunk_size, low_power=low_power))
        anomaly_coordinates = self._anomaly_coordinates(entropy_blocks)
        self._report_progress(progress_callback, "fingerprint", 0.82, "Fingerprint verdichten")
        fingerprint = self._build_fingerprint(
            raw=raw,
            entropy_blocks=entropy_blocks,
            entropy_mean=entropy_mean,
            periodicity=periodicity,
            anomaly_coordinates=anomaly_coordinates,
            source_type=source_type,
            source_label=source_label,
            file_profile=file_profile,
            distribution=distribution,
            low_power=low_power,
        )
        if fingerprint.file_profile is not None:
            fingerprint.file_profile["analysis_chunk_size"] = int(resolved_chunk_size)
            fingerprint.file_profile["low_power_mode"] = bool(low_power)
            fingerprint.file_profile["analysis_mode"] = "low_power" if low_power else "full"
        self._report_progress(progress_callback, "done", 1.0, "Analyse abgeschlossen")
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

    def analyze(
        self,
        file_path: str,
        source_type: str = "file",
        low_power: bool = False,
        chunk_size: int | None = None,
        progress_callback: Callable[[str, float, str], None] | None = None,
    ) -> AetherFingerprint:
        """
        Fuehrt die vollstaendige Analyse einer Datei durch und erzeugt einen AetherFingerprint.

        Args:
            file_path: Pfad zur Zieldatei.
        """
        try:
            file_profile = self.detect_and_parse_file(
                file_path,
                chunk_size=chunk_size,
                low_power=low_power,
                progress_callback=self._progress_scope(progress_callback, 0.0, 0.34),
            )
        except OSError as exc:
            raise RuntimeError(f"Datei konnte nicht gelesen werden: {exc}") from exc
        raw = bytes(file_profile.get("raw_bytes", b""))
        return self.analyze_bytes(
            raw,
            source_label=str(Path(file_path)),
            source_type=str(source_type or "file"),
            file_profile={
                key: value
                for key, value in file_profile.items()
                if key not in {"raw_bytes", "streams"}
            },
            low_power=low_power,
            chunk_size=int(file_profile.get("analysis_chunk_size", 0) or self._resolve_chunk_size(chunk_size=chunk_size, low_power=low_power)),
            progress_callback=self._progress_scope(progress_callback, 0.36, 0.90),
        )
