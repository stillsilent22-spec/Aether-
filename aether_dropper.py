"""Standalone drag-and-drop file processor for Aether."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import shutil
import threading
import time
import zipfile
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    HAS_DND = True
except Exception:
    DND_FILES = "DND_Files"
    TkinterDnD = None
    HAS_DND = False


BACKUP_ROOT = Path("C:/AetherBackup")
PROJECT_ROOT = Path(__file__).resolve().parent
VERSION = "1.0.0"

COLORS = {
    "bg": "#0E141A",
    "surface": "#162028",
    "surface_alt": "#101920",
    "panel": "#121B22",
    "border": "#1F2A33",
    "accent": "#2FA3B5",
    "text": "#E8ECEF",
    "text_muted": "#A7B0B7",
    "success": "#74B89A",
    "warn": "#D29B55",
    "error": "#C96E6E",
    "drop_bg": "#101920",
    "drop_hover": "#16242D",
}

SUPPORTED_EXTENSIONS = {
    ".exe": "PE binary",
    ".pak": "game archive",
    ".iso": "disc image",
    ".bin": "binary blob",
    ".zip": "ZIP archive",
    ".rar": "RAR archive",
    ".7z": "7z archive",
    ".tar": "TAR archive",
    ".gz": "GZip/TAR.GZ archive",
    ".dll": "dynamic library",
    ".sys": "system driver",
    ".dat": "data file",
}

PI_ANCHOR = 3.14159265358979
PHI_ANCHOR = 1.61803398874989
SQRT2_ANCHOR = 1.41421356237310
E_ANCHOR = 2.71828182845904
ANCHORS = [PI_ANCHOR, PHI_ANCHOR, SQRT2_ANCHOR, E_ANCHOR]
ANCHOR_NAMES = ["pi", "phi", "sqrt2", "e"]


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


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for value in data:
        freq[value] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count <= 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _normalize_block(block: bytes) -> float:
    if not block:
        return 0.0
    return sum(block) / float(len(block) * 255.0)


def _detect_anchor(value: float, tolerance: float = 0.02) -> str | None:
    for anchor, name in zip(ANCHORS, ANCHOR_NAMES):
        fractional = anchor - int(anchor)
        if abs(value - fractional) < tolerance:
            return name
    return None


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_json(value: Any) -> Any:
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
    if is_dataclass(value):
        return _safe_json(asdict(value))
    return value


def _safe_child_path(root: Path, member_name: str) -> Path:
    target = (root / member_name).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"Archive member escapes target directory: {member_name}")
    return target


def _ensure_output_dir(source_path: Path) -> Path:
    output_dir = source_path.parent / "aether_out"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def create_backup(src_path: Path) -> Path:
    date_folder = BACKUP_ROOT / datetime.now().strftime("%Y-%m-%d")
    date_folder.mkdir(parents=True, exist_ok=True)
    destination = date_folder / src_path.name
    if destination.exists():
        timestamp = datetime.now().strftime("%H%M%S")
        destination = date_folder / f"{src_path.stem}_{timestamp}{src_path.suffix}"
    shutil.copy2(src_path, destination)
    return destination


def extract_fallback_profile(file_path: Path, log_fn: Callable[[str], None] | None = None) -> dict[str, Any]:
    if log_fn is not None:
        log_fn("[ANALYSIS] Running standalone fallback profile")
    raw = file_path.read_bytes()
    size = len(raw)
    block_size = max(512, size // 64) if size else 512
    blocks = [raw[index : index + block_size] for index in range(0, size, block_size)] or [b""]
    anchors_found: dict[str, int] = {}
    entropy_values: list[float] = []
    for block in blocks:
        entropy_values.append(_entropy(block))
        anchor_name = _detect_anchor(_normalize_block(block))
        if anchor_name is not None:
            anchors_found[anchor_name] = anchors_found.get(anchor_name, 0) + 1
    average_entropy = sum(entropy_values) / float(len(entropy_values) or 1)
    coverage = sum(anchors_found.values()) / float(len(blocks) or 1)
    trust_score = (
        min(1.0, coverage * 4.0)
        + coverage
        + min(1.0, average_entropy / 8.0)
        + min(1.0, len(anchors_found) / 4.0)
        + (1.0 if average_entropy < 7.9 else 0.0)
    ) / 5.0
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


class AetherBridge:
    def __init__(self) -> None:
        self._analysis_engine = None
        self._reconstruction_engine = None
        self._deep_scan_engine = None

    def analysis_available(self) -> bool:
        return analysis_module is not None and session_module is not None

    def reconstruction_available(self) -> bool:
        return reconstruction_module is not None

    def deep_scan_available(self) -> bool:
        return deep_scan_module is not None

    def _get_analysis_engine(self):
        if self._analysis_engine is not None:
            return self._analysis_engine
        if not self.analysis_available():
            return None
        try:
            session_context = session_module.SessionContext(seed=0xA37E)
            chain = None
            if blockchain_module is not None:
                chain = blockchain_module.AetherChain(
                    endpoint="local://aether-dropper",
                    ledger_path=PROJECT_ROOT / "data" / "dropper_chain.jsonl",
                )
            self._analysis_engine = analysis_module.AnalysisEngine(session_context=session_context, chain=chain)
        except Exception:
            self._analysis_engine = None
        return self._analysis_engine

    def _get_reconstruction_engine(self):
        if self._reconstruction_engine is not None:
            return self._reconstruction_engine
        if not self.reconstruction_available():
            return None
        try:
            self._reconstruction_engine = reconstruction_module.LosslessReconstructionEngine()
        except Exception:
            self._reconstruction_engine = None
        return self._reconstruction_engine

    def _get_deep_scan_engine(self):
        if self._deep_scan_engine is not None:
            return self._deep_scan_engine
        if not self.deep_scan_available():
            return None
        try:
            self._deep_scan_engine = deep_scan_module.DeepScanEngine()
        except Exception:
            self._deep_scan_engine = None
        return self._deep_scan_engine

    def analyze_file(self, file_path: Path, log_fn: Callable[[str], None] | None = None) -> dict[str, Any]:
        engine = self._get_analysis_engine()
        if engine is not None:
            try:
                if log_fn is not None:
                    log_fn("[ANALYSIS] Using modules.analysis_engine")
                payload = engine.analyze(str(file_path)).to_dict()
                return {
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
            except Exception as exc:
                if log_fn is not None:
                    log_fn(f"[WARN] analysis_engine failed: {exc}. Falling back.")
        return extract_fallback_profile(file_path, log_fn=log_fn)

    def build_reconstruction(
        self,
        file_path: Path,
        output_dir: Path,
        log_fn: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        raw = file_path.read_bytes()
        original_hash = hashlib.sha256(raw).hexdigest()
        import zlib

        compressed = zlib.compress(raw, level=9)
        compressed_path = output_dir / f"{file_path.name}.aether"
        compressed_path.write_bytes(compressed)
        result: dict[str, Any] = {
            "compression": {
                "format": "zlib",
                "output": str(compressed_path),
                "original_bytes": len(raw),
                "compressed_bytes": len(compressed),
                "ratio": (len(compressed) / float(len(raw))) if raw else 1.0,
            }
        }
        engine = self._get_reconstruction_engine()
        if engine is None:
            if log_fn is not None:
                log_fn("[RECON] reconstruction_engine unavailable; zlib artifact only.")
            return result
        try:
            if log_fn is not None:
                log_fn("[RECON] Using modules.reconstruction_engine")
            delta_log = engine.build_delta_log(raw)
            try:
                reconstructed = engine.replay(delta_log)
                verification = engine.verify(original_hash, delta_log)
                lossless = engine.verify_lossless(raw, reconstructed)
            except getattr(reconstruction_module, "VaultMissError", RuntimeError) as exc:
                reconstructed = b""
                verification = {
                    "reconstruction_verified": False,
                    "status": "FAILED",
                    "reason": str(exc),
                }
                lossless = {
                    "verified": False,
                    "status": "FAILED",
                    "reason": str(exc),
                }
            delta_path = output_dir / f"{file_path.stem}_delta.json"
            delta_payload = {
                "file": str(file_path),
                "original_hash": original_hash,
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
        except Exception as exc:
            if log_fn is not None:
                log_fn(f"[WARN] reconstruction_engine failed: {exc}")
        return result

    def run_deep_scan(self, file_path: Path, log_fn: Callable[[str], None] | None = None) -> dict[str, Any]:
        engine = self._get_deep_scan_engine()
        if engine is None:
            return {"available": False, "reason": "deep_scan_engine unavailable"}
        try:
            if log_fn is not None:
                log_fn("[SCAN] Using modules.deep_scan_engine")
            payload = engine.scan_file(str(file_path)).to_payload()
            return {"available": True, "payload": _safe_json(payload)}
        except Exception as exc:
            if log_fn is not None:
                log_fn(f"[WARN] deep_scan_engine failed: {exc}")
            return {"available": False, "reason": str(exc)}


def extract_archive(filepath: Path, output_dir: Path, log_fn: Callable[[str], None] | None = None) -> list[str]:
    extracted: list[str] = []
    suffix = filepath.suffix.lower()

    def write_member(member_name: str, data: bytes) -> None:
        target = _safe_child_path(output_dir, member_name)
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
                    _safe_child_path(output_dir, name).mkdir(parents=True, exist_ok=True)
                    continue
                write_member(name, archive.read(info))
    elif suffix in {".tar", ".gz"}:
        import tarfile

        with tarfile.open(filepath, "r:*") as archive:
            for member in archive.getmembers():
                name = str(member.name or "").replace("\\", "/")
                if not name:
                    continue
                if member.isdir():
                    _safe_child_path(output_dir, name).mkdir(parents=True, exist_ok=True)
                    continue
                fileobj = archive.extractfile(member)
                if fileobj is None:
                    continue
                write_member(name, fileobj.read())
    elif suffix == ".rar":
        try:
            import rarfile
        except Exception:
            if log_fn is not None:
                log_fn("[WARN] RAR support requires optional package 'rarfile'.")
            return extracted
        with rarfile.RarFile(filepath) as archive:
            for member in archive.infolist():
                name = str(member.filename or "").replace("\\", "/")
                if not name:
                    continue
                if member.isdir():
                    _safe_child_path(output_dir, name).mkdir(parents=True, exist_ok=True)
                    continue
                with archive.open(member) as handle:
                    write_member(name, handle.read())
    elif suffix == ".7z":
        try:
            import py7zr
        except Exception:
            if log_fn is not None:
                log_fn("[WARN] 7z support requires optional package 'py7zr'.")
            return extracted
        with py7zr.SevenZipFile(filepath, mode="r") as archive:
            for name, handle in archive.readall().items():
                normalized = str(name or "").replace("\\", "/")
                if normalized:
                    write_member(normalized, handle.read())

    if log_fn is not None:
        log_fn(f"[ARCHIVE] Extracted {len(extracted)} files into {output_dir}")
    return extracted


def process_file(
    filepath_str: str,
    options: dict[str, bool],
    log_fn: Callable[[str], None],
    progress_fn: Callable[[float], None],
    done_fn: Callable[[dict[str, Any] | None], None],
) -> None:
    file_path = Path(filepath_str.strip().strip('"').strip("'"))
    bridge = AetherBridge()

    try:
        if not file_path.exists():
            log_fn(f"[ERROR] File not found: {file_path}")
            done_fn(None)
            return
        if not file_path.is_file():
            log_fn(f"[ERROR] Not a regular file: {file_path}")
            done_fn(None)
            return

        output_dir = _ensure_output_dir(file_path)
        suffix = file_path.suffix.lower()
        size = file_path.stat().st_size
        report: dict[str, Any] = {
            "file": str(file_path),
            "file_type": SUPPORTED_EXTENSIONS.get(suffix, "generic file"),
            "size_bytes": int(size),
            "processed_at": _now_iso(),
        }

        log_fn("")
        log_fn("=" * 60)
        log_fn(f"[AETHER] Processing {file_path.name}")
        log_fn(f"[INFO] Type: {report['file_type']} | Size: {size:,} bytes")
        progress_fn(5)

        if options.get("backup", True):
            log_fn("[STEP 1/4] Creating backup")
            backup_path = create_backup(file_path)
            report["backup"] = str(backup_path)
            log_fn(f"[BACKUP] {backup_path}")
        else:
            log_fn("[STEP 1/4] Backup skipped")
        progress_fn(25)

        log_fn("[STEP 2/4] Structural analysis")
        analysis_result = bridge.analyze_file(file_path, log_fn=log_fn)
        report["analysis"] = analysis_result
        summary = analysis_result.get("summary", {})
        log_fn(
            "[ANALYSIS] entropy={:.4f} symmetry={:.4f} coverage={:.4f} verdict={}".format(
                float(summary.get("entropy_mean", 0.0) or 0.0),
                float(summary.get("symmetry_score", 0.0) or 0.0),
                float(summary.get("anchor_coverage_ratio", 0.0) or 0.0),
                str(summary.get("verdict", "")),
            )
        )
        progress_fn(55)

        log_fn("[STEP 3/4] Reconstruction and compression")
        reconstruction_result = bridge.build_reconstruction(file_path, output_dir, log_fn=log_fn)
        report["reconstruction"] = reconstruction_result
        compression = dict(reconstruction_result.get("compression", {}) or {})
        log_fn(
            "[RECON] {} -> {} bytes ({:.1%})".format(
                int(compression.get("original_bytes", size) or size),
                int(compression.get("compressed_bytes", size) or size),
                float(compression.get("ratio", 1.0) or 1.0),
            )
        )
        progress_fn(78)

        log_fn("[STEP 4/4] Optional scans")
        if options.get("deep_scan", True):
            deep_scan_result = bridge.run_deep_scan(file_path, log_fn=log_fn)
            report["deep_scan"] = deep_scan_result
            if bool(deep_scan_result.get("available")):
                payload = dict(deep_scan_result.get("payload", {}) or {})
                log_fn(
                    f"[SCAN] {payload.get('source_kind', 'unknown')} | "
                    f"anchors={payload.get('geometry_anchor_count', 0)}"
                )
            else:
                log_fn(f"[SCAN] skipped: {deep_scan_result.get('reason', 'unavailable')}")
        else:
            report["deep_scan"] = {"available": False, "reason": "disabled"}
            log_fn("[SCAN] Disabled")

        archive_files: list[str] = []
        if options.get("extract_archives", True) and suffix in {".zip", ".rar", ".7z", ".tar", ".gz"}:
            archive_dir = output_dir / file_path.stem
            archive_dir.mkdir(parents=True, exist_ok=True)
            archive_files = extract_archive(file_path, archive_dir, log_fn=log_fn)
        else:
            log_fn("[ARCHIVE] No extraction needed")
        report["archive_files"] = archive_files

        report_path = output_dir / f"{file_path.stem}_report.json"
        report_path.write_text(json.dumps(_safe_json(report), indent=2, ensure_ascii=False), encoding="utf-8")
        log_fn(f"[DONE] Report written to {report_path}")
        log_fn("=" * 60)
        progress_fn(100)
        done_fn(report)
    except Exception as exc:
        import traceback

        log_fn(f"[FATAL] {type(exc).__name__}: {exc}")
        log_fn(traceback.format_exc())
        done_fn(None)


class AetherDropper:
    def __init__(self) -> None:
        self.root = TkinterDnD.Tk() if HAS_DND and TkinterDnD is not None else tk.Tk()
        self.root.title(f"Aether Dropper {VERSION}")
        self.root.geometry("900x720")
        self.root.minsize(760, 620)
        self.root.configure(bg=COLORS["bg"])

        self._queue: list[str] = []
        self._busy = False
        self._results: list[dict[str, Any]] = []

        self.var_backup = tk.BooleanVar(value=True)
        self.var_extract = tk.BooleanVar(value=True)
        self.var_deep_scan = tk.BooleanVar(value=True)
        self.progress_var = tk.DoubleVar(value=0.0)

        self._configure_styles()
        self._build_ui()
        self._check_deps()

    def _configure_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Aether.Horizontal.TProgressbar",
            troughcolor=COLORS["surface_alt"],
            background=COLORS["accent"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["accent"],
            darkcolor=COLORS["accent"],
        )

    def _build_ui(self) -> None:
        shell = tk.Frame(self.root, bg=COLORS["bg"])
        shell.pack(fill="both", expand=True, padx=18, pady=18)

        header = tk.Frame(shell, bg=COLORS["bg"])
        header.pack(fill="x")
        brand = tk.Frame(header, bg=COLORS["bg"])
        brand.pack(side="left")
        self._draw_robot_mark(brand).pack(side="left", padx=(0, 12))

        title_group = tk.Frame(brand, bg=COLORS["bg"])
        title_group.pack(side="left")
        tk.Label(
            title_group,
            text="Aether Dropper",
            font=("Segoe UI Semibold", 18),
            fg=COLORS["text"],
            bg=COLORS["bg"],
        ).pack(anchor="w")
        tk.Label(
            title_group,
            text="Backup, structural analysis, reconstruction, and archive handling",
            font=("Segoe UI", 9),
            fg=COLORS["text_muted"],
            bg=COLORS["bg"],
        ).pack(anchor="w", pady=(2, 0))

        self.status_label = tk.Label(
            header,
            text="Ready",
            font=("Segoe UI Semibold", 10),
            fg=COLORS["success"],
            bg=COLORS["bg"],
        )
        self.status_label.pack(side="right", pady=6)

        tk.Frame(shell, bg=COLORS["border"], height=1).pack(fill="x", pady=(16, 16))

        drop_frame = tk.Frame(shell, bg=COLORS["drop_bg"], highlightbackground=COLORS["border"], highlightthickness=1)
        drop_frame.pack(fill="x")
        self.drop_label = tk.Label(
            drop_frame,
            text="Drop files here\nEXE  PAK  ISO  BIN  ZIP  RAR  7Z  and any other file type",
            font=("Segoe UI Semibold", 15),
            fg=COLORS["text"],
            bg=COLORS["drop_bg"],
            pady=30,
            cursor="hand2",
            justify="center",
        )
        self.drop_label.pack(fill="x")
        if HAS_DND:
            self.drop_label.drop_target_register(DND_FILES)
            self.drop_label.dnd_bind("<<Drop>>", self._on_drop)
            self.drop_label.dnd_bind("<<DragEnter>>", lambda _event: self._hover(True))
            self.drop_label.dnd_bind("<<DragLeave>>", lambda _event: self._hover(False))
        else:
            tk.Label(
                drop_frame,
                text="Native drag and drop unavailable. Click the panel to select files.",
                font=("Segoe UI", 9),
                fg=COLORS["text_muted"],
                bg=COLORS["drop_bg"],
            ).pack(pady=(0, 12))
        self.drop_label.bind("<Button-1>", self._open_dialog)

        options_panel = tk.Frame(shell, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        options_panel.pack(fill="x", pady=(14, 12))
        options_inner = tk.Frame(options_panel, bg=COLORS["surface"])
        options_inner.pack(fill="x", padx=16, pady=14)
        tk.Label(
            options_inner,
            text="Processing options",
            font=("Segoe UI Semibold", 10),
            fg=COLORS["text"],
            bg=COLORS["surface"],
        ).pack(anchor="w")
        checks = tk.Frame(options_inner, bg=COLORS["surface"])
        checks.pack(fill="x", pady=(10, 0))
        self._add_check(checks, "Create backup in C:\\AetherBackup", self.var_backup).pack(side="left", padx=(0, 16))
        self._add_check(checks, "Extract supported archives", self.var_extract).pack(side="left", padx=(0, 16))
        self._add_check(checks, "Run geometry deep scan", self.var_deep_scan).pack(side="left")

        progress_row = tk.Frame(shell, bg=COLORS["bg"])
        progress_row.pack(fill="x", pady=(0, 10))
        ttk.Progressbar(
            progress_row,
            variable=self.progress_var,
            style="Aether.Horizontal.TProgressbar",
            maximum=100,
        ).pack(side="left", fill="x", expand=True)
        self.progress_label = tk.Label(
            progress_row,
            text="0%",
            width=5,
            font=("Segoe UI", 9),
            fg=COLORS["text_muted"],
            bg=COLORS["bg"],
        )
        self.progress_label.pack(side="right", padx=(12, 0))

        log_header = tk.Frame(shell, bg=COLORS["bg"])
        log_header.pack(fill="x")
        tk.Label(
            log_header,
            text="Activity log",
            font=("Segoe UI Semibold", 10),
            fg=COLORS["text"],
            bg=COLORS["bg"],
        ).pack(side="left")
        tk.Button(
            log_header,
            text="Clear",
            font=("Segoe UI", 9),
            fg=COLORS["text"],
            bg=COLORS["surface"],
            activebackground=COLORS["surface_alt"],
            activeforeground=COLORS["text"],
            bd=0,
            relief="flat",
            padx=10,
            pady=4,
            command=self._clear_log,
            cursor="hand2",
        ).pack(side="right")

        self.log = scrolledtext.ScrolledText(
            shell,
            font=("Cascadia Mono", 9),
            bg=COLORS["panel"],
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=10,
            state="disabled",
        )
        self.log.pack(fill="both", expand=True, pady=(8, 0))
        self.log.tag_config("accent", foreground=COLORS["accent"])
        self.log.tag_config("success", foreground=COLORS["success"])
        self.log.tag_config("warn", foreground=COLORS["warn"])
        self.log.tag_config("error", foreground=COLORS["error"])

        footer = tk.Frame(shell, bg=COLORS["bg"])
        footer.pack(fill="x", pady=(10, 0))
        self.queue_label = tk.Label(
            footer,
            text="Queue: 0",
            font=("Segoe UI", 9),
            fg=COLORS["text_muted"],
            bg=COLORS["bg"],
        )
        self.queue_label.pack(side="left")
        tk.Label(
            footer,
            text=f"Backup root: {BACKUP_ROOT}",
            font=("Segoe UI", 9),
            fg=COLORS["text_muted"],
            bg=COLORS["bg"],
        ).pack(side="right")

    def _draw_robot_mark(self, parent: tk.Misc) -> tk.Canvas:
        canvas = tk.Canvas(parent, width=42, height=42, bg=COLORS["bg"], highlightthickness=0)
        line = COLORS["accent"]
        canvas.create_rectangle(9, 10, 33, 27, outline=line, fill=COLORS["surface"], width=2)
        canvas.create_oval(15, 16, 19, 20, outline=line, fill=line, width=1)
        canvas.create_oval(23, 16, 27, 20, outline=line, fill=line, width=1)
        canvas.create_line(21, 5, 21, 10, fill=line, width=2)
        canvas.create_oval(18, 2, 24, 8, outline=line, width=2)
        canvas.create_rectangle(13, 29, 29, 33, outline=line, width=2)
        return canvas

    def _add_check(self, parent: tk.Misc, text: str, variable: tk.BooleanVar) -> tk.Checkbutton:
        return tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            fg=COLORS["text"],
            bg=COLORS["surface"],
            activebackground=COLORS["surface"],
            activeforeground=COLORS["text"],
            selectcolor=COLORS["surface_alt"],
            highlightthickness=0,
            bd=0,
            font=("Segoe UI", 9),
        )

    def _hover(self, active: bool) -> None:
        self.drop_label.configure(bg=COLORS["drop_hover"] if active else COLORS["drop_bg"])

    def _extract_paths(self, raw_data: str) -> list[str]:
        if not raw_data:
            return []
        try:
            parts = list(self.root.tk.splitlist(raw_data))
        except Exception:
            parts = [raw_data]
        result: list[str] = []
        for item in parts:
            candidate = item.strip().strip('"')
            if candidate.startswith("{") and candidate.endswith("}"):
                candidate = candidate[1:-1]
            if candidate:
                result.append(candidate)
        return result

    def _on_drop(self, event) -> str:
        for path in self._extract_paths(str(getattr(event, "data", ""))):
            self._enqueue(path)
        self._hover(False)
        return "break"

    def _open_dialog(self, _event=None) -> None:
        for file_path in filedialog.askopenfilenames(
            title="Select files for Aether Dropper",
            filetypes=[
                ("All files", "*.*"),
                ("Executables", "*.exe *.dll *.sys"),
                ("Game and binary assets", "*.pak *.iso *.bin *.dat"),
                ("Archives", "*.zip *.rar *.7z *.tar *.gz"),
            ],
        ):
            self._enqueue(file_path)

    def _enqueue(self, path: str) -> None:
        self._queue.append(str(Path(path).expanduser()))
        self._update_queue_label()
        self._log(f"[QUEUE] +{Path(path).name}", tag="accent")
        if not self._busy:
            self._process_next()

    def _process_next(self) -> None:
        if not self._queue:
            self._busy = False
            self._set_status("Ready", COLORS["success"])
            self._set_progress(0)
            return
        self._busy = True
        current = self._queue.pop(0)
        self._update_queue_label()
        self._set_status("Processing", COLORS["warn"])
        self._set_progress(0)
        options = {
            "backup": bool(self.var_backup.get()),
            "extract_archives": bool(self.var_extract.get()),
            "deep_scan": bool(self.var_deep_scan.get()),
        }
        threading.Thread(
            target=process_file,
            args=(current, options, self._log_thread, self._progress_thread, self._done_thread),
            daemon=True,
        ).start()

    def _log_thread(self, message: str) -> None:
        self.root.after(0, lambda: self._log(message))

    def _progress_thread(self, value: float) -> None:
        self.root.after(0, lambda: self._set_progress(value))

    def _done_thread(self, report: dict[str, Any] | None) -> None:
        self.root.after(0, lambda: self._on_done(report))

    def _on_done(self, report: dict[str, Any] | None) -> None:
        if report is not None:
            self._results.append(report)
            verdict = str(dict(report.get("analysis", {}) or {}).get("summary", {}).get("verdict", "DONE"))
            self._log(f"[RESULT] {verdict}", tag="success" if verdict.upper() not in {"FAILED", "ERROR"} else "error")
        self._process_next()

    def _log(self, message: str, tag: str | None = None) -> None:
        self.log.configure(state="normal")
        line = f"[{time.strftime('%H:%M:%S')}] {message}\n"
        if tag is not None:
            self.log.insert("end", line, tag)
        else:
            self.log.insert("end", line)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _set_progress(self, value: float) -> None:
        self.progress_var.set(float(value))
        self.progress_label.configure(text=f"{int(value)}%")

    def _set_status(self, text: str, color: str) -> None:
        self.status_label.configure(text=text, fg=color)

    def _update_queue_label(self) -> None:
        self.queue_label.configure(text=f"Queue: {len(self._queue)}")

    def _check_deps(self) -> None:
        bridge = AetherBridge()
        self._log(
            "[INFO] Engines: analysis={} reconstruction={} deep_scan={}".format(
                "yes" if bridge.analysis_available() else "fallback",
                "yes" if bridge.reconstruction_available() else "fallback",
                "yes" if bridge.deep_scan_available() else "fallback",
            ),
            tag="accent",
        )
        if HAS_DND:
            self._log("[INFO] Native drag and drop available", tag="success")
        else:
            self._log("[WARN] tkinterdnd2 missing; click-to-open mode active", tag="warn")
        self._log(f"[INFO] Backup root: {BACKUP_ROOT}", tag="accent")
        self._log("[READY] Drop files or click the panel to begin", tag="accent")

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    AetherDropper().run()
