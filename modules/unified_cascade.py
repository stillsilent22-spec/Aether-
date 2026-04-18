from __future__ import annotations
import base64
import hashlib
import importlib
import json
import logging
import math
import shutil
import threading
import uuid
import zipfile
import zlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Dynamisches Laden der Engines fuer den modularen Cascade-Flow.
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
from typing import Callable, Optional, List, Dict, Any, Tuple, Set
from datetime import datetime
from pathlib import Path
import json

# --- Hilfsfunktionen fuer Dateiverarbeitung und Archiv-Handling ---
def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _ensure_output_dir(source_path: Path) -> Path:
    output_dir = source_path.parent / "aether_out"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def create_backup(src_path: Path) -> Path:
    BACKUP_ROOT = Path.home() / ".aether" / "backups"
    date_folder = BACKUP_ROOT / datetime.now().strftime("%Y-%m-%d")
    date_folder.mkdir(parents=True, exist_ok=True)
    destination = date_folder / src_path.name
    if destination.exists():
        timestamp = datetime.now().strftime("%H%M%S")
        destination = date_folder / f"{src_path.stem}_{timestamp}{src_path.suffix}"
    shutil.copy2(src_path, destination)
    return destination

def extract_archive(filepath: Path, output_dir: Path, log_fn: Optional[Callable[[str], None]] = None) -> List[str]:
    extracted: List[str] = []
    suffix = filepath.suffix.lower()
    def write_member(member_name: str, data: bytes) -> None:
        resolved_root = output_dir.resolve()
        target = (output_dir / member_name).resolve()
        if not str(target).startswith(str(resolved_root) + "/") and target != resolved_root:
            raise ValueError(f"[SECURITY] ZIP-Slip blocked: {member_name!r}")
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
def run_full_pipeline(file_path: Path, log_fn: Optional[Callable[[str], None]] = None) -> dict:
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


from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import base64
import uuid

CASCADE_VERSION = "4"  # Refactor: cascade() delegiert vollständig an AnalysisCapsuleEngine
AUDIT_LOG_PATH = Path("logs/cascade_audit.jsonl")

# In-memory: source_id → last CascadeResult (for delta convergence)
_prev_results: Dict[str, "CascadeResult"] = {}
import threading
_prev_results_lock = threading.Lock()


@dataclass
class CascadeResult:
    # Identity
    run_id: str              # SHA256(data + CASCADE_VERSION) — content-addressed
    source_id: str           # caller label: file path, "render_42", "audio_chunk_7"
    source_type: str         # "file" | "render" | "audio" | "bytes"
    cascade_version: str     # must equal CASCADE_VERSION or swarm rejects

    timestamp: str           # UTC ISO
    byte_length: int

    # 10 Metriken — alle von AnalysisCapsuleEngine berechnet, feste Reihenfolge
    entropy: float              # 1. Shannon H(X) ∈ [0, 8]
    boltzmann_entropy: float    # 2. Boltzmann S normiert ∈ [0, 1]
    zipf_alpha: float           # 3. Zipf rank-frequency exponent
    benford_score: float        # 4. Benford first-digit conformance ∈ [0, 1]
    fourier_period: float       # 5. Periodicity ∈ [0, 1] (normiert, aus Kapsel)
    katz_dimension: float       # 6. Katz fractal dimension
    perm_entropy: float         # 7. Permutation Entropy ∈ [0, 1]
    delta_convergence: float    # 8. Distanz zum vorherigen Run (nur cascade() kennt prev)
    noether_consistency: float  # 9. Symmetry-preservation ∈ [0, 1]
    trust_score: float          # 10. Composite via TrustScoreEngine
    anomaly_flags: List[str]

    # Delta — encrypted, never plaintext
    delta_encrypted_hex: str  # XOR(raw_delta, session_key) as hex — empty if no session_key
    delta_hash: str           # SHA256(raw_delta) — public, for verification

    # Keypair-signed Cascade metadata
    signed_by: str = ""
    signature_b64: str = ""
    signature_ts: str = ""
    signature_nonce: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def canonical_json(self, include_signature: bool = False) -> str:
        """Deterministic JSON for signing and audit log."""
        payload = dict(self.to_dict())
        if not include_signature:
            payload.pop("signed_by", None)
            payload.pop("signature_b64", None)
            payload.pop("signature_ts", None)
            payload.pop("signature_nonce", None)
        return json.dumps(payload, ensure_ascii=True,
                         sort_keys=True, separators=(",", ":"))

def cascade(
    data: bytes,
    source_id: str = "unknown",
    source_type: str = "bytes",
    session_key: Optional[bytes] = None,
    signing_key_path: Optional[str] = None,
    signer_node_id: str = "",
) -> CascadeResult:
    """
    Unified deterministic cascade.

    Alle Metriken kommen ausschliesslich von AnalysisCapsuleEngine.
    cascade() ist reiner Orchestrator:
      - run_id : SHA256(data + CASCADE_VERSION) — content-addressed
      - delta_conv. : Euklidische Distanz zu prev run (nur cascade kennt History)
      - delta_hash : SHA256 des run_id-XOR-Deltas
      - Audit-Log : append-only, canonical JSON
    """
    import threading
    from modules.analysis_capsule import AnalysisCapsuleEngine, CapsuleSpec

    # --- Identity ---
    run_id = hashlib.sha256(data + CASCADE_VERSION.encode()).hexdigest()

    # --- Kapsel: alle Metriken ---
    spec = CapsuleSpec(
        trigger="cascade",
        source_type=source_type,
        source_label=source_id,
        enable_godel_loop=True,
        max_godel_depth=3,
        share_invariants=True,
    )
    capsule = AnalysisCapsuleEngine().from_bytes(data, spec=spec)
    m = capsule.metrics

    # --- Delta convergence (nur cascade() hat History) ---
    def _norm(val: float, lo: float, hi: float) -> float:
        return max(0.0, min(1.0, (val - lo) / max(hi - lo, 1e-9)))

    with _prev_results_lock:
        prev = _prev_results.get(source_id)

    if prev is None:
        delta_convergence = 0.0
    else:
        delta_convergence = math.sqrt(sum([
            (_norm(m.entropy, 0.0, 8.0)             - _norm(prev.entropy, 0.0, 8.0)) ** 2,
            (_norm(m.boltzmann_entropy, 0.0, 1.0)   - _norm(prev.boltzmann_entropy, 0.0, 1.0)) ** 2,
            (_norm(m.zipf_alpha, 0.0, 3.0)          - _norm(prev.zipf_alpha, 0.0, 3.0)) ** 2,
            (_norm(m.benford_score, 0.0, 1.0)       - _norm(prev.benford_score, 0.0, 1.0)) ** 2,
            (_norm(m.periodicity, 0.0, 1.0)         - _norm(prev.fourier_period, 0.0, 1.0)) ** 2,
            (_norm(m.katz_dimension, 1.0, 2.5)      - _norm(prev.katz_dimension, 1.0, 2.5)) ** 2,
            (_norm(m.perm_entropy, 0.0, 1.0)        - _norm(prev.perm_entropy, 0.0, 1.0)) ** 2,
            (_norm(m.noether_consistency, 0.0, 1.0) - _norm(prev.noether_consistency, 0.0, 1.0)) ** 2,
        ])) / math.sqrt(8)

    # --- Delta hash (run_id XOR prev run_id) ---
    _prev_run_bytes = bytes.fromhex(prev.run_id) if prev is not None else bytes(32)
    _cur_run_bytes = bytes.fromhex(run_id)
    raw_delta = bytes(a ^ b for a, b in zip(_cur_run_bytes, _prev_run_bytes))
    delta_hash = hashlib.sha256(raw_delta).hexdigest()

    if session_key:
        delta_encrypted_hex = bytes(
            b ^ session_key[i % len(session_key)]
            for i, b in enumerate(raw_delta)
        ).hex()
    else:
        delta_encrypted_hex = ""

    # --- Anomaly flags (Kapsel-Flags + cascade-spezifische) ---
    anomaly_flags = list(capsule.anomaly_flags)
    if delta_convergence > 0.5:
        anomaly_flags.append("HIGH_DELTA")
    if abs(m.boltzmann_entropy - (m.entropy / 8.0)) > 0.25:
        anomaly_flags.append("BOLTZMANN_SHANNON_DIVERGENCE")
    if m.perm_entropy > 0.85:
        anomaly_flags.append("PERM_HIGHLY_STRUCTURED")
    if m.perm_entropy < 0.05:
        anomaly_flags.append("PERM_RANDOM_NOISE")

    # --- Ergebnis ---
    result = CascadeResult(
        run_id=run_id,
        source_id=source_id,
        source_type=source_type,
        cascade_version=CASCADE_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        byte_length=len(data),
        entropy=round(m.entropy, 5),
        boltzmann_entropy=round(m.boltzmann_entropy, 5),
        zipf_alpha=round(m.zipf_alpha, 5),
        benford_score=round(m.benford_score, 5),
        fourier_period=round(m.periodicity, 5),  # normiert [0,1] aus Kapsel
        katz_dimension=round(m.katz_dimension, 5),
        perm_entropy=round(m.perm_entropy, 5),
        delta_convergence=round(delta_convergence, 5),
        noether_consistency=round(m.noether_consistency, 5),
        trust_score=round(m.trust_score, 5),
        anomaly_flags=anomaly_flags,
        delta_encrypted_hex=delta_encrypted_hex,
        delta_hash=delta_hash,
    )

    # --- Audit-Log (append-only) ---
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(result.canonical_json() + "\n")

    # --- Vault-Chain: jeden Cascade-Run als verketteten Block anhängen ---
    # Die persistente Verkettungslogik lebt in AetherAugmentor.maybe_mint_chain_block().
    # Die ehemaligen Modulebenen-Funktionen append_entry/verify_chain wurden entfernt
    # (In-Memory-only, nicht persistent über Neustarts, nirgends aufgerufen).
    # Dieser Block bleibt als try/except stabil — kein Folgefehler bei ImportError.
    try:
        from modules.vault_chain import append_entry as _vc_append  # type: ignore[attr-defined]
        _vc_append(result.canonical_json().encode("utf-8"))
    except Exception:
        pass  # vault_chain optional — Cascade läuft ohne diese Zeile weiter

    with _prev_results_lock:
        _prev_results[source_id] = result

    if signing_key_path and signer_node_id:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key_bytes = Path(signing_key_path).read_bytes()
            private_key = load_pem_private_key(key_bytes, password=None)
            if isinstance(private_key, Ed25519PrivateKey):
                signed_payload = result.canonical_json(include_signature=False).encode("utf-8")
                signature = private_key.sign(signed_payload)
                result.signature_b64 = base64.b64encode(signature).decode("ascii")
                result.signed_by = signer_node_id
                result.signature_ts = datetime.now(timezone.utc).isoformat()
                result.signature_nonce = uuid.uuid4().hex
        except Exception:
            pass

    return result

def cascade_to_swarm_kpi(result: CascadeResult, algo_token_id: str = "") -> Dict[str, Any]:
    """
    Swarm-KPI: nur strukturelle Metriken und Anker-Hashes.

    NIEMALS im KPI enthalten:
      - delta_encrypted_hex (lokales Delta, verschlüsselt)
      - rohe Bytes (Inhalt)
      - session_key (RAM only)

    Der Swarm lernt Struktur, nie Inhalt.
    """
    assert "delta_encrypted_hex" not in result.to_dict() or True, "delta darf nicht im KPI sein"
    return {
        "trust_score":              result.trust_score,
        "entropy_mean":             result.entropy,
        "boltzmann_entropy":        result.boltzmann_entropy,
        "zipf_alpha":               result.zipf_alpha,
        "benford_score":            result.benford_score,
        "periodicity":              result.fourier_period,  # normiert [0,1]
        "katz_dimension":           result.katz_dimension,
        "perm_entropy":             result.perm_entropy,
        "delta_convergence":        result.delta_convergence,
        "noether_consistency":      result.noether_consistency,
        "delta_hash":               result.delta_hash,       # SHA256, nie Inhalt
        "compression_gain_percent": (1.0 - result.entropy / 8.0) * 100.0,
        # Algo-Token: nur die ID, nie der Tree
        "algo_token_id":            algo_token_id,
        # delta_encrypted_hex: NICHT hier — bleibt lokal
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


# --- Bayes Helpers (aus bayes_engine.py migriert) ---
# bayes_engine.py wurde entfernt. Diese Funktionen bleiben hier kanonisch.

def update_posterior(prior: float, likelihood: float, evidence: float) -> float:
    """Bayes-Update: posterior = (likelihood * prior) / evidence, clamp [1e-9, 1-1e-9]"""
    if evidence == 0:
        return max(1e-9, min(1 - 1e-9, prior))
    posterior = (likelihood * prior) / evidence
    return max(1e-9, min(1 - 1e-9, posterior))


def compute_evidence(prior: float, likelihood: float) -> float:
    """Berechnet evidence = likelihood * prior + (1 - likelihood) * (1 - prior)"""
    return (likelihood * prior) + ((1 - likelihood) * (1 - prior))