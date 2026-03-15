"""Kleiner lokaler Selbsttest fuer Chunking, Low-Power und Shanway-Ausgabe."""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import fitz
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    fitz = None

try:
    from PIL import Image
except Exception:  # pragma: no cover - optionale Laufzeitabhaengigkeit
    Image = None

from modules.analysis_engine import AnalysisEngine
from modules.efficiency_monitor import EfficiencyMonitor
from modules.session_engine import SessionContext
from modules.shanway import ShanwayEngine


def _write_pdf(path: Path) -> None:
    if fitz is not None:
        document = fitz.open()
        page = document.new_page()
        page.insert_text((72, 72), "Aether PDF Selftest")
        document.save(str(path))
        document.close()
        return
    path.write_bytes(b"%PDF-1.4\n% Aether selftest\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")


def _write_jpg(path: Path) -> None:
    if Image is not None:
        image = Image.new("RGB", (16, 16), color=(48, 112, 196))
        image.save(str(path), format="JPEG")
        return
    path.write_bytes(b"\xFF\xD8\xFF\xE0" + (b"AETHER" * 32) + b"\xFF\xD9")


def _write_samples(root: Path) -> dict[str, Path]:
    samples = {
        "txt": root / "sample.txt",
        "jpg": root / "sample.jpg",
        "pdf": root / "sample.pdf",
        "mp3": root / "sample.mp3",
    }
    samples["txt"].write_text("Aether selftest text file.\nStructural coherence sample.\n", encoding="utf-8")
    _write_jpg(samples["jpg"])
    _write_pdf(samples["pdf"])
    samples["mp3"].write_bytes(b"ID3" + (b"\x00" * 509))
    return samples


def _run_case(
    engine: AnalysisEngine,
    monitor: EfficiencyMonitor,
    shanway: ShanwayEngine,
    sample_path: Path,
    low_power: bool,
) -> dict[str, object]:
    progress_events: list[tuple[str, float, str]] = []
    start = time.perf_counter()
    fingerprint = engine.analyze(
        str(sample_path),
        low_power=bool(low_power),
        progress_callback=lambda stage, progress, detail="": progress_events.append((str(stage), float(progress), str(detail))),
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    snapshot = monitor.sample(status=f"selftest {'low' if low_power else 'full'} {sample_path.name}")
    assessment = shanway.detect_asymmetry(
        f"{sample_path.name} {getattr(fingerprint, 'integrity_text', '')}",
        coherence_score=float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
        browser_mode=False,
        active=True,
        h_lambda=float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
        observer_mutual_info=float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
        source_label=str(sample_path),
        file_profile=dict(getattr(fingerprint, "file_profile", {}) or {}),
        observer_payload=dict(getattr(fingerprint, "observer_payload", {}) or {}),
        beauty_signature=dict(getattr(fingerprint, "beauty_signature", {}) or {}),
        fingerprint_payload={
            "reconstruction_verification": dict(getattr(fingerprint, "reconstruction_verification", {}) or {}),
            "verdict_reconstruction": str(getattr(fingerprint, "verdict_reconstruction", "") or ""),
            "verdict_reconstruction_reason": str(getattr(fingerprint, "verdict_reconstruction_reason", "") or ""),
            "delta_session_seed": int(getattr(fingerprint, "delta_session_seed", 0) or 0),
        },
    )
    response = shanway.render_response(assessment)
    return {
        "path": str(sample_path),
        "mode": "low_power" if low_power else "full",
        "category": str(dict(getattr(fingerprint, "file_profile", {}) or {}).get("category", "")),
        "chunk_size": int(dict(getattr(fingerprint, "file_profile", {}) or {}).get("analysis_chunk_size", 0) or 0),
        "elapsed_ms": round(float(elapsed_ms), 3),
        "ram_percent": float(snapshot.ram_percent),
        "cpu_percent": float(snapshot.cpu_percent),
        "threads": int(snapshot.threads),
        "missing_dependencies": list(assessment.missing_dependencies),
        "missing_data": list(assessment.missing_data),
        "response": str(response),
        "progress_count": int(len(progress_events)),
        "reconstruction_verified": bool(dict(getattr(fingerprint, "reconstruction_verification", {}) or {}).get("verified", False)),
        "verdict_reconstruction": str(getattr(fingerprint, "verdict_reconstruction", "") or ""),
    }


def main() -> None:
    engine = AnalysisEngine(SessionContext(seed=7))
    monitor = EfficiencyMonitor()
    shanway = ShanwayEngine()
    expected_categories = {
        ".txt": "document",
        ".jpg": "image",
        ".pdf": "document",
        ".mp3": "audio",
    }
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="aether_selftest_") as temp_dir:
        root = Path(temp_dir)
        samples = _write_samples(root)
        for sample in samples.values():
            for low_power in (False, True):
                result = _run_case(engine, monitor, shanway, sample, low_power=low_power)
                results.append(result)
                assert result["category"] == expected_categories[sample.suffix.lower()], (
                    f"Kategorie falsch fuer {sample.name}: {result['category']}"
                )
                expected_chunk = 262144 if low_power else 524288
                assert int(result["chunk_size"]) == expected_chunk, (
                    f"Chunk-Groesse falsch fuer {sample.name}: {result['chunk_size']}"
                )
                assert int(result["progress_count"]) > 0, f"Kein Fortschritt fuer {sample.name}"
                response = str(result["response"])
                if result["missing_dependencies"]:
                    assert response.startswith("MISSING_DEPENDENCIES:"), (
                        f"Missing-Dependencies nicht zuerst in Shanway fuer {sample.name}"
                    )
                elif result["missing_data"]:
                    assert response.startswith("MISSING_DATA:") or response.startswith("MISSING_DEPENDENCIES:"), (
                        f"Missing-Data nicht zuerst in Shanway fuer {sample.name}"
                    )
                assert bool(result["reconstruction_verified"]), (
                    f"Rekonstruktion nicht bestaetigt fuer {sample.name}"
                )
                assert str(result["verdict_reconstruction"]) == "CONFIRMED", (
                    f"Rekonstruktionsverdict falsch fuer {sample.name}: {result['verdict_reconstruction']}"
                )
                assert float(result["ram_percent"]) < 90.0, (
                    f"RAM-Auslastung zu hoch im Selbsttest: {result['ram_percent']}"
                )

    print("Aether mini self-test")
    for result in results:
        print(
            f"{Path(str(result['path'])).name:10s} | {str(result['mode']):9s} | "
            f"{str(result['category']):8s} | chunk {int(result['chunk_size']) // 1024:3d} KB | "
            f"cpu {float(result['cpu_percent']):5.1f}% | ram {float(result['ram_percent']):5.1f}% | "
            f"{float(result['elapsed_ms']):8.2f} ms"
        )


if __name__ == "__main__":
    main()
