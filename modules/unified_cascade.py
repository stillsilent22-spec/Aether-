import importlib

# Dynamisches Laden der Engines wie im Dropper
def _try_import(name: str):
    for candidate in (name, f"modules.{name}"):
        try:
            return importlib.import_module(candidate)
        except Exception:
            continue
    return None

analysis_module = _try_import("analysis_engine")
reconstruction_module = _try_import("reconstruction_engine")
deep_scan_module = _try_import("deep_scan_engine")
session_module = _try_import("session_engine")
blockchain_module = _try_import("blockchain_interface")
swarm_bridge = _try_import("swarm_loop_bridge")

import shutil
import zipfile
import zlib
from typing import Callable
from datetime import datetime
from pathlib import Path
import json

# --- Hilfsfunktionen aus aether_dropper.py ---
def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _ensure_output_dir(source_path: Path) -> Path:
    output_dir = source_path.parent / "aether_out"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def create_backup(src_path: Path) -> Path:
    BACKUP_ROOT = Path("C:/AetherBackup")
    date_folder = BACKUP_ROOT / datetime.now().strftime("%Y-%m-%d")
    date_folder.mkdir(parents=True, exist_ok=True)
    destination = date_folder / src_path.name
    if destination.exists():
        timestamp = datetime.now().strftime("%H%M%S")
        destination = date_folder / f"{src_path.stem}_{timestamp}{src_path.suffix}"
    shutil.copy2(src_path, destination)
    return destination

def extract_archive(filepath: Path, output_dir: Path, log_fn: Callable[[str], None] | None = None) -> list[str]:
    extracted: list[str] = []
    suffix = filepath.suffix.lower()
    def write_member(member_name: str, data: bytes) -> None:
        target = output_dir / member_name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        extracted.append(str(target))
    if suffix == ".zip":
        with zipfile.ZipFile(filepath, "r") as archive:
            for info in archive.infolist():
                name = str(info.filename or "").replace("\\", "/")
                if not name:
                    continue
                if name.endswith("/"):
                    (output_dir / name).mkdir(parents=True, exist_ok=True)
                    continue
                write_member(name, archive.read(info))
    # Weitere Formate analog ergänzen ...
    if log_fn is not None:
        log_fn(f"[ARCHIVE] Extracted {len(extracted)} files into {output_dir}")
    return extracted

# --- Zentrale deterministische Pipeline ---
def run_full_pipeline(file_path: Path, log_fn: Callable[[str], None] | None = None) -> dict:
    """
    Führt alle Schritte der deterministischen Pipeline aus:
    1. Backup
    2. Analyse
    3. Cascade
    4. Swarm-Submission
    5. Reconstruction
    6. Deep Scan
    7. Archiv-Extraktion
    8. Audit-Log & Report
    """
    report = {}
    # 1. Backup
    if log_fn: log_fn("[STEP 1/7] Creating backup")
    backup_path = create_backup(file_path)
    report["backup"] = str(backup_path)


    # 2. Analyse (immer mit analysis_engine, Fallback bei Fehler)
    if log_fn: log_fn("[STEP 2/7] Structural analysis")
    def _safe_json(value):
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, tuple):
            return [_safe_json(item) for item in value]
        if isinstance(value, list):
            return [_safe_json(item) for item in value]
        if isinstance(value, dict):
            return {str(key): _safe_json(item) for key, item in value.items()}
        return value

    def extract_fallback_profile(file_path, log_fn=None):
        raw = file_path.read_bytes()
        size = len(raw)
        block_size = max(512, size // 64) if size else 512
        blocks = [raw[index : index + block_size] for index in range(0, size, block_size)] or [b""]
        anchors_found = {}
        entropy_values = []
        for block in blocks:
            entropy = -sum((b/len(block))*math.log2(b/len(block)) for b in [block.count(i) for i in range(256)] if b > 0) if block else 0.0
            entropy_values.append(entropy)
        average_entropy = sum(entropy_values) / float(len(entropy_values) or 1)
        coverage = 0.0
        trust_score = min(1.0, coverage * 4.0) + coverage + min(1.0, average_entropy / 8.0) + (1.0 if average_entropy < 7.9 else 0.0)
        trust_score /= 4.0
        payload = {
            "file": str(file_path),
            "size_bytes": size,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "md5": hashlib.md5(raw).hexdigest(),
            "entropy": round(average_entropy, 4),
            "block_count": len(blocks),
            "anchors": anchors_found,
            "anchor_coverage_ratio": round(coverage, 6),
            "trust_score": round(trust_score, 4),
            "verdict": "CONFIRMED" if coverage > 0.0 else "FAILED",
            "timestamp": _now_iso(),
        }
        return {
            "engine": "fallback",
            "summary": {
                "file_hash": payload["sha256"],
                "entropy_mean": payload["entropy"],
                "symmetry_score": payload["trust_score"],
                "anchor_coverage_ratio": payload["anchor_coverage_ratio"],
                "verdict": payload["verdict"],
            },
            "payload": payload,
        }

    try:
        engine = analysis_module.AnalysisEngine(session_context=session_module.SessionContext(seed=0xA37E)) if analysis_module and session_module else None
        if engine:
            payload = engine.analyze(str(file_path)).to_dict()
            report["analysis"] = {
                "engine": "analysis_engine",
                "summary": {
                    "file_hash": str(payload.get("file_hash", "")),
                    "entropy_mean": float(payload.get("entropy_mean", 0.0) or 0.0),
                    "symmetry_score": float(payload.get("symmetry_score", 0.0) or 0.0),
                    "anchor_coverage_ratio": float(payload.get("anchor_coverage_ratio", 0.0) or 0.0),
                    "verdict": str(payload.get("verdict", "")),
                },
                "payload": _safe_json(payload),
            }
        else:
            report["analysis"] = extract_fallback_profile(file_path, log_fn=log_fn)
    except Exception as exc:
        if log_fn: log_fn(f"[WARN] analysis_engine failed: {exc}. Falling back.")
        report["analysis"] = extract_fallback_profile(file_path, log_fn=log_fn)

    # 3. Cascade
    if log_fn: log_fn("[STEP 3/7] Cascade analysis")
    raw = file_path.read_bytes()
    session_key = None  # ggf. Session-Key aus Engine holen
    cascade_result = cascade(
        raw,
        source_id=str(file_path),
        source_type="file",
        session_key=session_key,
    )
    report["cascade"] = {k: v for k, v in cascade_result.to_dict().items() if k != "delta_encrypted_hex"}
    report["cascade"]["delta_hash"] = cascade_result.delta_hash

    # 4. Swarm-Submission (immer, falls Engine vorhanden)
    if log_fn: log_fn("[STEP 4/7] Swarm submission")
    swarm_result = None
    if swarm_bridge and hasattr(swarm_bridge, "submit_cascade_result"):
        try:
            swarm_result = swarm_bridge.submit_cascade_result(cascade_result, role="genesis")
            report["swarm"] = _safe_json(swarm_result)
        except Exception as exc:
            if log_fn: log_fn(f"[WARN] Swarm-Submission failed: {exc}")
            report["swarm"] = {"error": str(exc)}
    else:
        report["swarm"] = {"available": False, "reason": "swarm_bridge unavailable"}

    # 5. Reconstruction & Kompression (immer, falls Engine vorhanden)
    if log_fn: log_fn("[STEP 5/7] Reconstruction and compression")
    output_dir = _ensure_output_dir(file_path)
    result = {}
    try:
        if reconstruction_module:
            engine = reconstruction_module.LosslessReconstructionEngine()
            delta_log = engine.build_delta_log(raw)
            reconstructed = engine.replay(delta_log)
            verification = engine.verify(hashlib.sha256(raw).hexdigest(), delta_log)
            lossless = engine.verify_lossless(raw, reconstructed)
            delta_path = output_dir / f"{file_path.stem}_delta.json"
            delta_payload = {
                "file": str(file_path),
                "original_hash": hashlib.sha256(raw).hexdigest(),
                "delta_log": delta_log,
                "verification": _safe_json(verification),
                "lossless": _safe_json(lossless),
            }
            delta_path.write_text(json.dumps(delta_payload, indent=2, ensure_ascii=False), encoding="utf-8")
            result["delta_log"] = {
                "output": str(delta_path),
                "entry_count": len(delta_log),
                "verification": _safe_json(verification),
                "lossless": _safe_json(lossless),
            }
        # Immer auch zlib-Kompression
        compressed = zlib.compress(raw, level=9)
        compressed_path = output_dir / f"{file_path.name}.aether"
        compressed_path.write_bytes(compressed)
        result["compression"] = {
            "format": "zlib",
            "output": str(compressed_path),
            "original_bytes": len(raw),
            "compressed_bytes": len(compressed),
            "ratio": (len(compressed) / float(len(raw))) if raw else 1.0,
        }
    except Exception as exc:
        if log_fn: log_fn(f"[WARN] reconstruction_engine failed: {exc}")
    report["reconstruction"] = result

    # 6. Deep Scan (immer, falls Engine vorhanden)
    if log_fn: log_fn("[STEP 6/7] Deep scan")
    deep_scan_result = None
    if deep_scan_module:
        try:
            engine = deep_scan_module.DeepScanEngine()
            payload = engine.scan_file(str(file_path)).to_payload()
            deep_scan_result = {"available": True, "payload": _safe_json(payload)}
        except Exception as exc:
            if log_fn: log_fn(f"[WARN] deep_scan_engine failed: {exc}")
            deep_scan_result = {"available": False, "reason": str(exc)}
    else:
        deep_scan_result = {"available": False, "reason": "deep_scan_engine unavailable"}
    report["deep_scan"] = deep_scan_result

    # 7. Archiv-Extraktion
    if log_fn: log_fn("[STEP 7/7] Archive extraction")
    suffix = file_path.suffix.lower()
    archive_files = []
    if suffix in {".zip", ".rar", ".7z", ".tar", ".gz"}:
        archive_dir = output_dir / file_path.stem
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_files = extract_archive(file_path, archive_dir, log_fn=log_fn)
    report["archive_files"] = archive_files

    # 8. Audit-Log & Report
    report["processed_at"] = _now_iso()
    report_path = output_dir / f"{file_path.stem}_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if log_fn: log_fn(f"[DONE] Report written to {report_path}")
    return report
"""
Unified Deterministic Cascade — Aether core analysis pipeline.

INVARIANTS (never change without incrementing CASCADE_VERSION):
  - Metric order is fixed: entropy → zipf → benford → fourier →
    katz → attractor → delta_convergence → noether
  - run_id = SHA256(data + CASCADE_VERSION.encode())
  - Deltas are XOR-encrypted with session_key, never stored plaintext
  - cascade_version is included in every audit entry

CASCADE_VERSION must be incremented whenever:
  - Any metric implementation changes
  - Metric order changes
  - Weight changes
  - Any parameter changes

Swarm nodes running different CASCADE_VERSION cannot form quorum.
"""


import hashlib
import json
import math
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

CASCADE_VERSION = "1"
AUDIT_LOG_PATH = Path("logs/cascade_audit.jsonl")

# In-memory: source_id → last CascadeResult (for delta convergence)
_prev_results: dict[str, "CascadeResult"] = {}


@dataclass
class CascadeResult:
    # Identity
    run_id: str              # SHA256(data + CASCADE_VERSION) — content-addressed
    source_id: str           # caller label: file path, "render_42", "audio_chunk_7"
    source_type: str         # "file" | "render" | "audio" | "bytes"
    cascade_version: str     # must equal CASCADE_VERSION or swarm rejects

    timestamp: str           # UTC ISO
    byte_length: int

    # 8 metrics — fixed order, fixed meaning
    entropy: float           # 1. Shannon H(X) ∈ [0, 8]
    zipf_alpha: float        # 2. Zipf rank-frequency exponent
    benford_score: float    # 3. Benford first-digit conformance ∈ [0, 1]
    fourier_period: float    # 4. Dominant autocorrelation period (0.0 = none)
    katz_dimension: float    # 5. Katz fractal dimension
    attractor_stability: float  # 6. Lyapunov-like convergence ∈ [0, 1]
    delta_convergence: float # 7. Distance from previous run same source_id
    noether_consistency: float  # 8. Symmetry-preservation invariant ∈ [0, 1]

    # Derived
    trust_score: float       # weighted composite ∈ [0, 1]
    anomaly_flags: list[str]

    # Delta — encrypted, never plaintext
    delta_encrypted_hex: str  # XOR(raw_delta, session_key) as hex — empty if no session_key
    delta_hash: str           # SHA256(raw_delta) — public, for verification

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_json(self) -> str:
        """Deterministic JSON for signing and audit log."""
        return json.dumps(self.to_dict(), ensure_ascii=True,
                         sort_keys=True, separators=(",", ":"))

def cascade(
    data: bytes,
    source_id: str = "unknown",
    source_type: str = "bytes",
    session_key: Optional[bytes] = None,
) -> CascadeResult:
    """
    Run the unified deterministic cascade on any byte input.

    run_id is SHA256(data + CASCADE_VERSION.encode()) — deterministic,
    content-addressed, version-bound. Two nodes running the same
    CASCADE_VERSION on the same data will always produce the same run_id.

    XOR delta is encrypted with session_key if provided.
    Never stored or transmitted in plaintext.
    """
    run_id = hashlib.sha256(data + CASCADE_VERSION.encode()).hexdigest()

    # Entropy
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data) or 1
    entropy = -sum((c/total) * math.log2(c/total) for c in counts if c > 0)

    # Zipf-Alpha
    from modules.invariant_detector import detect_zipf_distribution
    freq = {}
    for b in data:
        freq[str(b)] = freq.get(str(b), 0) + 1
    zipf_alpha = float(detect_zipf_distribution(freq).get("alpha", 1.0))

    # Benford-Score
    from modules.invariant_detector import detect_benford_law
    chunk_sizes = [len(data[i:i+256]) for i in range(0, len(data), 256)]
    benford_score = float(detect_benford_law(chunk_sizes).get("benford_conformance", 0.5))

    # Fourier period
    from modules.invariant_detector import detect_fourier_periodicity
    diffs = [abs(int(data[i]) - int(data[i-1])) for i in range(1, min(len(data), 4096))]
    fourier_period = float(detect_fourier_periodicity(diffs) or 0.0)

    # Katz dimension
    def _katz(b: bytes) -> float:
        arr = list(b[:2048])
        if len(arr) < 2:
            return 1.0
        diffs = [abs(arr[i] - arr[i-1]) for i in range(1, len(arr))]
        L = sum(diffs)
        d = max((abs(arr[i] - arr[0]) for i in range(len(arr))), default=1)
        n = len(arr) - 1
        if d == 0 or n == 0 or L == 0:
            return 1.0
        avg = L / n
        return math.log10(n) / (math.log10(n) + math.log10(d / avg + 1e-9))
    katz_dimension = _katz(data)

    # Attractor stability
    from modules.attractor_engine import attractor_track
    history = [hashlib.md5(data[i:i+64]).hexdigest()[:8]
               for i in range(0, min(len(data), 4096), 64)]
    track = attractor_track(history)
    total_blocks = len(history) or 1
    attractor_stability = len(track.get("attractors", [])) / total_blocks

    # Delta convergence — all metrics normalized to [0,1] before distance computation
    def _norm(val: float, lo: float, hi: float) -> float:
        return max(0.0, min(1.0, (val - lo) / max(hi - lo, 1e-9)))

    prev = _prev_results.get(source_id)
    if prev is None:
        delta_convergence = 0.0
    else:
        delta_convergence = math.sqrt(sum([
            (_norm(entropy,             0.0, 8.0) - _norm(prev.entropy,             0.0, 8.0)) ** 2,
            (_norm(zipf_alpha,          0.0, 3.0) - _norm(prev.zipf_alpha,          0.0, 3.0)) ** 2,
            (_norm(benford_score,       0.0, 1.0) - _norm(prev.benford_score,       0.0, 1.0)) ** 2,
            (_norm(katz_dimension,      0.0, 2.0) - _norm(prev.katz_dimension,      0.0, 2.0)) ** 2,
            (_norm(attractor_stability, 0.0, 1.0) - _norm(prev.attractor_stability, 0.0, 1.0)) ** 2,
        ])) / math.sqrt(5)

    # Noether consistency
    half = len(data) // 2
    def _h(b: bytes) -> float:
        c = [0] * 256
        for x in b:
            c[x] += 1
        t = len(b) or 1
        return -sum((v/t)*math.log2(v/t) for v in c if v > 0)
    if half > 0:
        noether_consistency = 1.0 - abs(_h(data[:half]) - _h(data[half:])) / 8.0
    else:
        noether_consistency = 1.0

    # Delta: compute, hash, encrypt
    delta_key = hashlib.sha256(data).digest()
    raw_delta = bytes(b ^ delta_key[i % 32] for i, b in enumerate(data[:256]))
    delta_hash = hashlib.sha256(raw_delta).hexdigest()

    if session_key:
        encrypted = bytes(b ^ session_key[i % len(session_key)]
                         for i, b in enumerate(raw_delta))
        delta_encrypted_hex = encrypted.hex()
    else:
        delta_encrypted_hex = ""

    # Trust score
    trust_score = max(0.0, min(1.0,
        0.20 * (1.0 - entropy / 8.0) +
        0.15 * min(zipf_alpha / 2.0, 1.0) +
        0.15 * benford_score +
        0.10 * min(fourier_period / 128.0, 1.0) +
        0.15 * min(katz_dimension / 2.0, 1.0) +
        0.10 * attractor_stability +
        0.05 * (1.0 - min(delta_convergence, 1.0)) +
        0.10 * noether_consistency
    ))

    # Anomaly flags
    anomaly_flags = []
    if entropy > 7.5:                  anomaly_flags.append("HIGH_ENTROPY")
    if benford_score < 0.3:            anomaly_flags.append("BENFORD_VIOLATION")
    if delta_convergence > 0.5:        anomaly_flags.append("HIGH_DELTA")
    if noether_consistency < 0.4:      anomaly_flags.append("NOETHER_BROKEN")
    if attractor_stability > 0.8:      anomaly_flags.append("STRONG_ATTRACTOR")
    if katz_dimension > 1.8:           anomaly_flags.append("HIGH_FRACTAL")

    result = CascadeResult(
        run_id=run_id,
        source_id=source_id,
        source_type=source_type,
        cascade_version=CASCADE_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        byte_length=len(data),
        entropy=round(entropy, 5),
        zipf_alpha=round(zipf_alpha, 5),
        benford_score=round(benford_score, 5),
        fourier_period=round(fourier_period, 5),
        katz_dimension=round(katz_dimension, 5),
        attractor_stability=round(attractor_stability, 5),
        delta_convergence=round(delta_convergence, 5),
        noether_consistency=round(noether_consistency, 5),
        trust_score=round(trust_score, 5),
        anomaly_flags=anomaly_flags,
        delta_encrypted_hex=delta_encrypted_hex,
        delta_hash=delta_hash,
    )

    # Append-only audit log — canonical JSON, one line per run
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(result.canonical_json() + "\n")

    _prev_results[source_id] = result
    return result

def cascade_to_swarm_kpi(result: CascadeResult) -> dict[str, float]:
    """
    Extract the KPI dict that swarm_loop.rs expects for aggregation.
    Does NOT include delta_encrypted_hex — that never leaves the device.
    """
    return {
        "trust_score":          result.trust_score,
        "entropy_mean":         result.entropy,
        "zipf_alpha":           result.zipf_alpha,
        "benford_score":        result.benford_score,
        "fourier_period":       result.fourier_period,
        "katz_dimension":       result.katz_dimension,
        "attractor_stability":  result.attractor_stability,
        "delta_convergence":    result.delta_convergence,
        "noether_consistency":  result.noether_consistency,
        "compression_gain_percent": (1.0 - result.entropy / 8.0) * 100.0,
    }

if __name__ == "__main__":
    import sys
    from modules.session_guard import require_session
    require_session()
    if len(sys.argv) < 2:
        print("Usage: python -m modules.unified_cascade <file_path>")
        sys.exit(1)
    file_path = Path(sys.argv[1])
    def print_log(msg):
        print(msg)
    report = run_full_pipeline(file_path, log_fn=print_log)
    print("\n--- JSON REPORT ---\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
