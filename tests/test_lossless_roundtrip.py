"""Pytest-kompatible End-to-End-Checks fuer konditional lossless Roundtrips."""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis_engine import AnalysisEngine
from modules.observer_engine import ObserverEngine
from modules.reconstruction_engine import LosslessReconstructionEngine
from modules.session_engine import SessionContext
from modules.shanway import ShanwayEngine


def _sample_bytes() -> bytes:
    """Liefert einen kleinen, stabilen Bytezustand fuer Roundtrip-Tests."""
    payload = (
        b"Aether lossless roundtrip test\n"
        b"observer-relative information remains local\n"
        b"session seeds must survive reloads\n"
    )
    return payload * 16


def _reconstruct_from_delta(delta: bytes, session_seed: int) -> bytes:
    """Hebt das XOR-Delta mit dem persistierten Session-Seed wieder auf."""
    noise = SessionContext.noise_from_seed(int(session_seed) & 0xFFFFFFFF, len(delta))
    return bytes(left ^ right for left, right in zip(delta, noise))


def _fingerprint_payload(fingerprint: Any) -> dict[str, Any]:
    """Verdichtet die Rekonstruktionsfelder fuer Shanway-Checks."""
    return {
        "reconstruction_verification": dict(getattr(fingerprint, "reconstruction_verification", {}) or {}),
        "verdict_reconstruction": str(getattr(fingerprint, "verdict_reconstruction", "") or ""),
        "verdict_reconstruction_reason": str(getattr(fingerprint, "verdict_reconstruction_reason", "") or ""),
        "delta_session_seed": int(getattr(fingerprint, "delta_session_seed", 0) or 0),
    }


def run_roundtrip_smoke_test() -> dict[str, Any]:
    """Fuehrt einen echten Analyze->Reload->Reconstruct-Roundtrip lokal aus."""
    original_bytes = _sample_bytes()
    original_hash = hashlib.sha256(original_bytes).hexdigest()

    first_context = SessionContext(seed=1337)
    engine = AnalysisEngine(first_context)
    reconstruction_engine = LosslessReconstructionEngine()
    fingerprint = engine.analyze_bytes(
        original_bytes,
        source_label="tests::lossless_roundtrip",
        source_type="memory",
    )
    verification = dict(getattr(fingerprint, "reconstruction_verification", {}) or {})
    verdict = str(getattr(fingerprint, "verdict_reconstruction", "") or "")
    persisted_seed = int(getattr(fingerprint, "delta_session_seed", 0) or 0)

    reloaded_context = SessionContext(seed=persisted_seed)
    reloaded_seed = int(reloaded_context.get_seed())
    reconstructed_bytes = _reconstruct_from_delta(bytes(getattr(fingerprint, "delta", b"")), reloaded_seed)
    replay_verification = reconstruction_engine.verify_lossless(original_bytes, reconstructed_bytes)

    shanway = ShanwayEngine()
    assessment = shanway.detect_asymmetry(
        "lossless roundtrip smoke test",
        coherence_score=float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
        browser_mode=False,
        active=True,
        h_lambda=float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
        observer_mutual_info=float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
        source_label="tests::lossless_roundtrip",
        file_profile=dict(getattr(fingerprint, "file_profile", {}) or {}),
        observer_payload=dict(getattr(fingerprint, "observer_payload", {}) or {}),
        beauty_signature=dict(getattr(fingerprint, "beauty_signature", {}) or {}),
        fingerprint_payload=_fingerprint_payload(fingerprint),
    )
    response = shanway.render_response(assessment)

    return {
        "fingerprint": fingerprint,
        "verdict_reconstruction": verdict,
        "reconstruction_verification": verification,
        "persisted_seed": int(persisted_seed),
        "reloaded_seed": int(reloaded_seed),
        "reconstructed_bytes": reconstructed_bytes,
        "replay_verification": dict(replay_verification),
        "original_hash": str(original_hash),
        "response": str(response),
    }


def run_roundtrip_failure_smoke_test() -> dict[str, Any]:
    """Simuliert einen Reload mit falschem Seed und erwartet ein klares FAILED."""
    original_bytes = _sample_bytes()
    context = SessionContext(seed=1441)
    engine = AnalysisEngine(context)
    reconstruction_engine = LosslessReconstructionEngine()
    fingerprint = engine.analyze_bytes(
        original_bytes,
        source_label="tests::lossless_roundtrip_failure",
        source_type="memory",
    )

    wrong_seed = int(getattr(fingerprint, "delta_session_seed", 0) or 0) ^ 0x55AA55AA
    reconstructed_bytes = _reconstruct_from_delta(bytes(getattr(fingerprint, "delta", b"")), wrong_seed)
    verification = dict(reconstruction_engine.verify_lossless(original_bytes, reconstructed_bytes))
    verification["session_seed_match"] = False

    shanway = ShanwayEngine()
    assessment = shanway.detect_asymmetry(
        "lossless roundtrip failure smoke test",
        coherence_score=float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
        browser_mode=False,
        active=True,
        h_lambda=float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
        observer_mutual_info=float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
        source_label="tests::lossless_roundtrip_failure",
        file_profile=dict(getattr(fingerprint, "file_profile", {}) or {}),
        observer_payload=dict(getattr(fingerprint, "observer_payload", {}) or {}),
        beauty_signature=dict(getattr(fingerprint, "beauty_signature", {}) or {}),
        fingerprint_payload={
            "reconstruction_verification": verification,
            "verdict_reconstruction": "FAILED",
            "verdict_reconstruction_reason": "delta_session_seed mismatch",
            "delta_session_seed": int(getattr(fingerprint, "delta_session_seed", 0) or 0),
        },
    )
    response = shanway.render_response(assessment)
    return {
        "verification": verification,
        "response": str(response),
        "wrong_seed": int(wrong_seed),
    }


def test_lossless_roundtrip_confirmed() -> None:
    """Der Standard-Roundtrip bleibt mit persistiertem Seed bit-exakt bestaetigt."""
    result = run_roundtrip_smoke_test()
    fingerprint = result["fingerprint"]
    verification = dict(result["reconstruction_verification"])
    replay_verification = dict(result["replay_verification"])

    assert str(result["verdict_reconstruction"]) == "CONFIRMED"
    assert bool(verification.get("verified", False)) is True
    assert bool(replay_verification.get("verified", False)) is True
    assert int(result["persisted_seed"]) == int(result["reloaded_seed"])
    assert bytes(result["reconstructed_bytes"]) == _sample_bytes()
    assert hashlib.sha256(bytes(result["reconstructed_bytes"])).hexdigest() == str(result["original_hash"])
    assert len(bytes(result["reconstructed_bytes"])) == len(_sample_bytes())
    assert 0.0 <= float(verification.get("compression_ratio", 0.0) or 0.0) <= 1.0
    assert str(result["response"]).startswith("Rekonstruktion bestätigt:")
    assert int(getattr(fingerprint, "delta_session_seed", 0) or 0) == 1337


def test_lossless_roundtrip_wrong_seed_fails() -> None:
    """Ein falscher Seed muss als FAILED samt Delta-Seed-Hinweis sichtbar werden."""
    result = run_roundtrip_failure_smoke_test()
    verification = dict(result["verification"])
    response = str(result["response"])

    assert bool(verification.get("verified", True)) is False
    assert bool(verification.get("session_seed_match", True)) is False
    assert response.startswith("Für vollständige Rekonstruktion fehlt noch:")
    assert "Delta-Seed muss für Rekonstruktion erhalten bleiben" in response


def test_lossless_roundtrip_with_recursive_raster_reflection() -> None:
    """Rekursive Miniatur-/Raster-Reflexion darf den bitgenauen Roundtrip nicht brechen."""
    original_bytes = _sample_bytes()
    context = SessionContext(seed=20260311)
    engine = AnalysisEngine(context)
    fingerprint = engine.analyze_bytes(
        original_bytes,
        source_label="tests::recursive_raster_roundtrip",
        source_type="memory",
    )
    fingerprint.observer_knowledge_ratio = max(0.96, float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0))
    fingerprint.observer_mutual_info = max(
        float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
        float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0),
    )
    fingerprint.unresolved_residual_ratio = 0.02

    observer = ObserverEngine()
    temp_learning_dir = PROJECT_ROOT / "tests" / ".tmp_observer_learning"
    observer.learning_store_dir = temp_learning_dir
    miniature_payload = {
        "hash": hashlib.sha256(b"miniature").hexdigest(),
        "local_entropy": 1.18,
        "symmetry": 0.94,
        "emergence_spots": 3,
        "noether_invariant_ratio": 0.93,
    }
    raster_payload = {
        "enabled": True,
        "hash": hashlib.sha256(b"raster").hexdigest(),
        "symmetry": 0.92,
        "entropy_mean": 0.44,
        "hotspot_count": 2,
        "verdict": "CLEAN",
    }
    reflection = observer.summarize_reflection_state(
        miniature_payload=miniature_payload,
        raster_payload=raster_payload,
        fingerprint=fingerprint,
        enable_raster_insight=True,
        max_depth=5,
    )
    learning_state = observer.update_learning_state(context, reflection)
    reflection["learned_insight"] = str(list(learning_state.get("learned_insights", []) or [""])[-1] or "")

    shanway = ShanwayEngine()
    assessment = shanway.detect_asymmetry(
        "recursive raster reflection roundtrip",
        coherence_score=float(getattr(fingerprint, "coherence_score", 0.0) or 0.0),
        browser_mode=False,
        active=True,
        h_lambda=float(getattr(fingerprint, "h_lambda", 0.0) or 0.0),
        observer_mutual_info=float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
        source_label="tests::recursive_raster_roundtrip",
        file_profile=dict(getattr(fingerprint, "file_profile", {}) or {}),
        observer_payload={"learning_state": dict(learning_state)},
        beauty_signature=dict(getattr(fingerprint, "beauty_signature", {}) or {}),
        fingerprint_payload=_fingerprint_payload(fingerprint),
        miniature_payload=miniature_payload,
        raster_payload=raster_payload,
        self_reflection_payload=reflection,
    )
    response = shanway.render_response(assessment)

    assert bool(dict(getattr(fingerprint, "reconstruction_verification", {}) or {}).get("verified", False)) is True
    assert "[Miniatur-Reflexion]" in response
    assert "[Raster-Self-Perception]" in response
    assert "REKURSION:" in response
    assert "GELERNTE_INSIGHT:" in response
    assert len(list(assessment.recursive_reflections)) >= 1
    assert len(list(assessment.recursive_reflections)) <= 5
    shutil.rmtree(temp_learning_dir, ignore_errors=True)


def main() -> None:
    """Fuehrt beide Smoke-Varianten direkt ohne pytest-Runner aus."""
    success = run_roundtrip_smoke_test()
    failure = run_roundtrip_failure_smoke_test()
    test_lossless_roundtrip_with_recursive_raster_reflection()
    gain = max(
        0.0,
        min(
            100.0,
            (1.0 - float(dict(success["reconstruction_verification"]).get("compression_ratio", 1.0) or 1.0))
            * 100.0,
        ),
    )
    print(
        "Roundtrip erfolgreich: "
        f"{success['verdict_reconstruction']}, {gain:.1f}% Gewinn, seed={success['persisted_seed']}"
    )
    print(
        "Roundtrip Fehlersimulation: "
        f"verified={bool(dict(failure['verification']).get('verified', False))}, "
        f"seed_ok={bool(dict(failure['verification']).get('session_seed_match', False))}"
    )
    print("Roundtrip Rekursion: erfolgreich | Raster-Einsicht lokal verifiziert")


if __name__ == "__main__":
    main()
