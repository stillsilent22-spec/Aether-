"""Pytest-kompatible End-to-End-Checks fuer konditional lossless Roundtrips."""

from __future__ import annotations

import hashlib
import http.server
import json
import shutil
import sys
import threading
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.ae_evolution_core import AEAlgorithmVault
from modules.agent_loop import AgentLoopEngine
from modules.analysis_engine import AnalysisEngine
from modules.browser_engine import BrowserEngine
from modules.observer_engine import ObserverEngine
from modules.public_ttd_transport import PublicTTDTransport
from modules.reconstruction_engine import GoedelLoopTerminator, LosslessReconstructionEngine
from modules.screen_vision_engine import is_private_context as is_private_screen_context
from modules.session_engine import SessionContext
from modules.shanway import ShanwayEngine
from modules.vault_chain import AetherAugmentor


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


def test_vault_growth_reduces_delta_size(tmp_path: Path) -> None:
    """Beweist C(t) -> 1 fuer wiederholte lokale Rekonstruktionen mit gleichem Input."""
    engine = LosslessReconstructionEngine(vault_db_path=str(tmp_path / "anchors.db"))
    sample = _sample_bytes()

    delta_1 = engine.build_delta_log(sample)
    delta_2 = engine.build_delta_log(sample)

    add_ops_1 = [entry for entry in delta_1 if entry.get("op") == "add"]
    add_ops_2 = [entry for entry in delta_2 if entry.get("op") == "add"]
    ref_ops_2 = [entry for entry in delta_2 if entry.get("op") == "ref"]

    assert len(add_ops_2) < len(add_ops_1)
    assert len(ref_ops_2) > 0
    assert engine.coherence_index(delta_2) > engine.coherence_index(delta_1)

    reconstructed = engine.reconstruct_from_vault(delta_2)
    assert reconstructed == sample
    result = engine.verify_lossless(sample, reconstructed)
    assert result["verified"] is True


def test_privacy_boundary_blocks_chat() -> None:
    """Privacy Boundary blockiert Chat-, Mail- und Passwortkontexte fail-closed."""
    assert is_private_screen_context("whatsapp_chat", "") is True
    assert is_private_screen_context("email_inbox", "") is True
    assert is_private_screen_context("", "password=abc123") is True
    assert is_private_screen_context("", "user@example.com") is True
    assert is_private_screen_context("aether_vault", "anchor_data") is False
    assert is_private_screen_context("game_renderer", "texture_load") is False


def test_goedel_loop_terminates(tmp_path: Path) -> None:
    """Der Goedel-Loop endet deterministisch vor der Maximalgrenze."""
    engine = LosslessReconstructionEngine(vault_db_path=str(tmp_path / "goedel_anchors.db"))
    terminator = GoedelLoopTerminator()
    sample = _sample_bytes()

    result = terminator.run_loop(sample, engine)
    assert result["terminated"] is True
    assert result["depth"] <= GoedelLoopTerminator.MAX_RECURSION_DEPTH
    assert 0.0 <= result["coherence"] <= 1.0
    assert result["goedel_rest"] >= 0.0


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
    assert str(reflection.get("learned_insight", "") or "").strip()
    assert str(dict(learning_state).get("current_insight", "") or "").strip()
    assert len(list(assessment.recursive_reflections)) >= 1
    assert len(list(assessment.recursive_reflections)) <= 5
    shutil.rmtree(temp_learning_dir, ignore_errors=True)


def test_ttd_auto_export_writes_dna_seed_and_jsonl() -> None:
    """Stabile TTD-Kandidaten muessen einen lokalen DNA-Export mit Seed und JSONL-Audit ausloesen."""
    temp_export_root = PROJECT_ROOT / "tests" / ".tmp_ttd_export"
    shutil.rmtree(temp_export_root, ignore_errors=True)
    temp_export_root.mkdir(parents=True, exist_ok=True)
    vault = AEAlgorithmVault(export_dir=temp_export_root / "aelab_vault")

    context = SessionContext(seed=424242)
    engine = AnalysisEngine(context)
    fingerprint = engine.analyze_bytes(
        _sample_bytes(),
        source_label="tests::ttd_auto_export",
        source_type="memory",
    )
    reflection_payload = {
        "ttd_candidates": [
            {
                "hash": hashlib.sha256(b"ttd-auto-export").hexdigest(),
                "delta_stability": 0.98,
                "symmetry": 0.94,
                "residual": 0.02,
                "public_metrics": {
                    "residual": 0.02,
                    "symmetry": 0.94,
                    "delta_i_obs_percent": 7.8,
                },
            }
        ]
    }
    source_payload = {
        "scan_hash": str(getattr(fingerprint, "scan_hash", "") or ""),
        "file_hash": str(getattr(fingerprint, "file_hash", "") or ""),
        "delta_session_seed": int(getattr(fingerprint, "delta_session_seed", 0) or 0),
        "scan_anchor_entries": [
            dict(item)
            for item in list(dict(getattr(fingerprint, "scan_payload", {}) or {}).get("scan_anchor_entries", []) or [])
            if isinstance(item, dict)
        ],
    }
    result = vault.auto_export_ttd_snapshot(
        reflection_payload,
        source_payload=source_payload,
        export_anchors=list(source_payload["scan_anchor_entries"]),
        source_label="tests::ttd_auto_export",
    )

    export_path = Path(str(result.get("export_path", "") or ""))
    assert bool(result.get("exported", False)) is True
    assert export_path.is_file()
    header = export_path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    assert f"delta_session_seed={int(getattr(fingerprint, 'delta_session_seed', 0) or 0)}" in header

    export_log_path = Path(str(result.get("export_log_path", "") or ""))
    assert export_log_path.is_file()
    export_logs = [json.loads(line) for line in export_log_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    assert any(str(item.get("ttd_hash", "") or "") == str(result.get("ttd_hash", "") or "") for item in export_logs)

    duplicate = vault.auto_export_ttd_snapshot(
        reflection_payload,
        source_payload=source_payload,
        export_anchors=list(source_payload["scan_anchor_entries"]),
        source_label="tests::ttd_auto_export",
    )
    assert bool(duplicate.get("already_exported", False)) is True
    shutil.rmtree(temp_export_root, ignore_errors=True)


def test_public_ttd_pool_requires_three_peer_validations_for_operator() -> None:
    """Normale Nutzer brauchen drei unabhaengige Validierungen, bevor ein oeffentlicher Anker lernwirksam wird."""
    temp_public_root = PROJECT_ROOT / "tests" / ".tmp_public_ttd_pool"
    shutil.rmtree(temp_public_root, ignore_errors=True)
    temp_public_root.mkdir(parents=True, exist_ok=True)

    context = SessionContext(seed=515151)
    context.user_role = "operator"
    engine = AnalysisEngine(context)
    fingerprint = engine.analyze_bytes(
        _sample_bytes(),
        source_label="tests::public_ttd_pool",
        source_type="memory",
    )
    observer = ObserverEngine()
    observer.learning_store_dir = temp_public_root / "observer_learning"

    reflection_payload = {
        "residual_after": 0.02,
        "stability_score": 0.98,
        "recursive_reflections": [
            {"level": 1, "delta": 0.04, "mt_shift": 0.30, "residual_before": 0.05, "residual_after": 0.04},
            {"level": 2, "delta": 0.03, "mt_shift": 0.24, "residual_before": 0.04, "residual_after": 0.03},
            {"level": 3, "delta": 0.02, "mt_shift": 0.18, "residual_before": 0.03, "residual_after": 0.02},
        ],
        "ttd_candidates": [
            {
                "hash": hashlib.sha256(b"public-ttd-anchor").hexdigest(),
                "delta_stability": 0.98,
                "symmetry": 0.94,
                "residual": 0.02,
                "public_metrics": {
                    "residual": 0.02,
                    "symmetry": 0.94,
                    "i_obs_ratio": 0.95,
                    "delta_i_obs_percent": 1.2,
                },
            }
        ],
    }

    bundles = []
    for seed in (515151, 616161, 717171):
        peer_context = SessionContext(seed=seed)
        peer_context.user_role = "operator"
        peer_context.username = f"peer_{seed}"
        peer_augmentor = AetherAugmentor(peer_context, registry=None)
        bundle = peer_augmentor.build_public_ttd_anchor_bundle(
            source_label="tests::public_ttd_pool",
            reflection_payload=reflection_payload,
            fingerprint=fingerprint,
            scope="metrics_only",
        )
        assert bool(bundle)
        assert bool(dict(bundle.get("validation", {}) or {}).get("valid", False)) is True
        bundles.append((peer_augmentor, bundle))

    first_augmentor, first_bundle = bundles[0]
    payload = dict(first_bundle.get("payload", {}) or {})
    assert payload.get("schema") == "aether.public_ttd_anchor.v1"
    assert bool(payload.get("raw_data_included", True)) is False
    assert bool(payload.get("deltas_included", True)) is False
    assert bool(payload.get("internal_only", True)) is False
    assert payload.get("uploader_role") == "operator"
    assert "pseudonym" in payload

    stored_first = first_augmentor.append_public_ttd_anchor_bundle(first_bundle, directory=str(temp_public_root))
    assert bool(stored_first.get("stored", False)) is True
    assert int(dict(stored_first.get("record", {}) or {}).get("validation_count", 0) or 0) == 1
    assert bool(dict(stored_first.get("record", {}) or {}).get("quorum_met", True)) is False

    loaded_first = first_augmentor.load_public_ttd_anchor_bundle(directory=str(temp_public_root))
    assert int(loaded_first.get("trusted_anchor_count", 0) or 0) == 0
    assert int(loaded_first.get("candidate_anchor_count", 0) or 0) == 1
    learning_first = observer.merge_public_anchor_bundle(context, loaded_first)
    assert int(learning_first.get("imported_anchor_count", 0) or 0) == 0
    assert int(learning_first.get("pending_quorum_count", 0) or 0) == 1

    second_augmentor, second_bundle = bundles[1]
    stored_second = second_augmentor.append_public_ttd_anchor_bundle(second_bundle, directory=str(temp_public_root))
    assert bool(stored_second.get("stored", False)) is True
    assert int(dict(stored_second.get("record", {}) or {}).get("validation_count", 0) or 0) == 2
    assert bool(dict(stored_second.get("record", {}) or {}).get("quorum_met", True)) is False

    third_augmentor, third_bundle = bundles[2]
    stored_third = third_augmentor.append_public_ttd_anchor_bundle(third_bundle, directory=str(temp_public_root))
    assert bool(stored_third.get("stored", False)) is True
    assert int(dict(stored_third.get("record", {}) or {}).get("validation_count", 0) or 0) == 3
    assert bool(dict(stored_third.get("record", {}) or {}).get("quorum_met", False)) is True

    loaded = third_augmentor.load_public_ttd_anchor_bundle(directory=str(temp_public_root))
    public_anchors = [dict(item) for item in list(loaded.get("public_anchors", []) or []) if isinstance(item, dict)]
    assert len(public_anchors) == 1
    assert int(loaded.get("trusted_anchor_count", 0) or 0) == 1
    assert int(loaded.get("candidate_anchor_count", 0) or 0) == 0
    assert int(loaded.get("quorum_validated_count", 0) or 0) == 1
    assert bool(public_anchors[0].get("quorum_met", False)) is True
    assert int(public_anchors[0].get("validation_count", 0) or 0) == 3

    learning_result = observer.merge_public_anchor_bundle(context, loaded)
    assert int(learning_result.get("imported_anchor_count", 0) or 0) == 1
    assert int(learning_result.get("trusted_anchor_count", 0) or 0) == 1
    assert int(learning_result.get("pending_quorum_count", 0) or 0) == 0
    assert float(learning_result.get("symmetry_gain_percent", 0.0) or 0.0) > 0.0
    assert "Anker von 3 Peers validiert" in str(learning_result.get("current_insight", "") or "")

    duplicate = third_augmentor.append_public_ttd_anchor_bundle(third_bundle, directory=str(temp_public_root))
    assert bool(duplicate.get("already_present", False)) is True
    shutil.rmtree(temp_public_root, ignore_errors=True)


def test_public_ttd_pool_admin_anchor_is_trusted_immediately() -> None:
    """Admin-Anker sind sofort vertrauenswuerdig und brauchen kein Quorum von drei Peers."""
    temp_public_root = PROJECT_ROOT / "tests" / ".tmp_public_ttd_pool_admin"
    shutil.rmtree(temp_public_root, ignore_errors=True)
    temp_public_root.mkdir(parents=True, exist_ok=True)

    context = SessionContext(seed=818181)
    context.user_role = "admin"
    context.username = "creator"
    engine = AnalysisEngine(context)
    fingerprint = engine.analyze_bytes(
        _sample_bytes(),
        source_label="tests::public_ttd_pool_admin",
        source_type="memory",
    )
    augmentor = AetherAugmentor(context, registry=None)
    observer = ObserverEngine()
    observer.learning_store_dir = temp_public_root / "observer_learning"

    reflection_payload = {
        "residual_after": 0.01,
        "stability_score": 0.99,
        "recursive_reflections": [
            {"level": 1, "delta": 0.04, "mt_shift": 0.30, "residual_before": 0.03, "residual_after": 0.02},
            {"level": 2, "delta": 0.03, "mt_shift": 0.24, "residual_before": 0.02, "residual_after": 0.01},
            {"level": 3, "delta": 0.02, "mt_shift": 0.18, "residual_before": 0.01, "residual_after": 0.01},
        ],
        "ttd_candidates": [
            {
                "hash": hashlib.sha256(b"admin-public-ttd-anchor").hexdigest(),
                "delta_stability": 0.99,
                "symmetry": 0.96,
                "residual": 0.01,
                "public_metrics": {
                    "residual": 0.01,
                    "symmetry": 0.96,
                    "i_obs_ratio": 0.97,
                    "delta_i_obs_percent": 1.5,
                },
            }
        ],
    }

    bundle = augmentor.build_public_ttd_anchor_bundle(
        source_label="tests::public_ttd_pool_admin",
        reflection_payload=reflection_payload,
        fingerprint=fingerprint,
        scope="signed",
    )
    stored = augmentor.append_public_ttd_anchor_bundle(bundle, directory=str(temp_public_root))
    record = dict(stored.get("record", {}) or {})
    assert bool(stored.get("stored", False)) is True
    assert int(record.get("validation_count", 0) or 0) == 1
    assert int(record.get("quorum_threshold", 0) or 0) == 1
    assert bool(record.get("quorum_met", False)) is True
    assert str(record.get("trust_reason", "") or "") == "admin_auto_trust"

    loaded = augmentor.load_public_ttd_anchor_bundle(directory=str(temp_public_root))
    assert int(loaded.get("trusted_anchor_count", 0) or 0) == 1
    assert int(loaded.get("admin_trusted_count", 0) or 0) == 1
    learning_result = observer.merge_public_anchor_bundle(context, loaded)
    assert int(learning_result.get("imported_anchor_count", 0) or 0) == 1
    assert "Admin-Anker direkt vertrauenswuerdig" in str(learning_result.get("current_insight", "") or "")
    shutil.rmtree(temp_public_root, ignore_errors=True)


def test_public_ttd_transport_http_mirror_roundtrip() -> None:
    """Der optionale Mirror-Transport muss ein Public-TTD-Bundle ueber HTTP senden und wieder einlesen koennen."""
    temp_network_root = PROJECT_ROOT / "tests" / ".tmp_public_ttd_transport"
    shutil.rmtree(temp_network_root, ignore_errors=True)
    temp_network_root.mkdir(parents=True, exist_ok=True)

    context = SessionContext(seed=919191)
    context.user_role = "admin"
    context.username = "creator"
    engine = AnalysisEngine(context)
    fingerprint = engine.analyze_bytes(
        _sample_bytes(),
        source_label="tests::public_ttd_transport",
        source_type="memory",
    )
    augmentor = AetherAugmentor(context, registry=None)
    observer = ObserverEngine()
    observer.learning_store_dir = temp_network_root / "observer_learning"
    transport = PublicTTDTransport(temp_network_root / "network_settings.json")

    reflection_payload = {
        "residual_after": 0.01,
        "stability_score": 0.99,
        "recursive_reflections": [
            {"level": 1, "delta": 0.04, "mt_shift": 0.30, "residual_before": 0.03, "residual_after": 0.02},
            {"level": 2, "delta": 0.03, "mt_shift": 0.24, "residual_before": 0.02, "residual_after": 0.01},
            {"level": 3, "delta": 0.02, "mt_shift": 0.18, "residual_before": 0.01, "residual_after": 0.01},
        ],
        "ttd_candidates": [
            {
                "hash": hashlib.sha256(b"http-mirror-ttd-anchor").hexdigest(),
                "delta_stability": 0.99,
                "symmetry": 0.95,
                "residual": 0.01,
                "public_metrics": {
                    "residual": 0.01,
                    "symmetry": 0.95,
                    "i_obs_ratio": 0.96,
                    "delta_i_obs_percent": 1.4,
                },
            }
        ],
    }
    bundle = augmentor.build_public_ttd_anchor_bundle(
        source_label="tests::public_ttd_transport",
        reflection_payload=reflection_payload,
        fingerprint=fingerprint,
        scope="signed",
    )

    class _MirrorHandler(http.server.BaseHTTPRequestHandler):
        posted_bundle: dict[str, Any] = {}

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length)
            _MirrorHandler.posted_bundle = json.loads(raw.decode("utf-8"))
            payload = json.dumps({"ok": True, "received": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            payload = json.dumps(_MirrorHandler.posted_bundle).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MirrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    transport.save_settings(
        {
            "enabled": True,
            "ipfs_api_url": "",
            "ipfs_gateway_urls": "",
            "mirror_publish_url": f"{base_url}/publish",
            "mirror_pull_urls": f"{base_url}/latest",
            "tracked_cids": "",
            "timeout_seconds": "5",
        }
    )

    published = transport.publish_bundle(bundle)
    assert bool(published.get("published", False)) is True
    assert bool(dict(published.get("mirror", {}) or {}).get("ok", False)) is True
    assert dict(_MirrorHandler.posted_bundle).get("payload")

    pulled = transport.pull_remote_bundles()
    assert bool(pulled.get("network_used", False)) is True
    assert len(list(pulled.get("remote_bundles", []) or [])) >= 1
    for remote_payload in list(pulled.get("remote_bundles", []) or []):
        stored = augmentor.append_public_ttd_anchor_bundle(remote_payload, directory=str(temp_network_root / "pool"))
        assert bool(stored.get("stored", False)) or bool(stored.get("already_present", False))
    summary = augmentor.load_public_ttd_anchor_bundle(directory=str(temp_network_root / "pool"))
    assert int(summary.get("trusted_anchor_count", 0) or 0) == 1
    learning_result = observer.merge_public_anchor_bundle(context, summary)
    assert int(learning_result.get("imported_anchor_count", 0) or 0) == 1
    assert "Admin-Anker direkt vertrauenswuerdig" in str(learning_result.get("current_insight", "") or "")

    server.shutdown()
    server.server_close()
    shutil.rmtree(temp_network_root, ignore_errors=True)


def test_agent_loop_plans_browser_followup_for_open_state() -> None:
    """Offene Shanway-Befunde muessen einen begrenzten lokalen Browser-Folgeschritt planen."""
    loop = AgentLoopEngine()
    assessment_payload = {
        "classification": "uncertain",
        "next_action": "Weitere strukturverwandte Dateien einspeisen",
        "missing_dependencies": [],
        "missing_data": [],
        "vault_gap": "",
        "boundary": "STRUCTURAL_HYPOTHESIS",
        "narrative_text": "Die Struktur bleibt offen und lernbar.",
    }
    directive = loop.plan_browser_followup(
        source_key="filehash-open-state",
        source_label="Arial.ttf",
        file_type=".ttf",
        h_lambda=5.3,
        observer_state="OFFEN",
        assessment_payload=assessment_payload,
        browser_enabled=True,
        browser_available=True,
        current_url="",
    )
    assert directive.should_execute is True
    assert directive.action == "browser_search"
    action_payload = dict(directive.action_payload or {})
    query = str(action_payload.get("query", "") or "")
    assert "ttf" in query.lower() or "font" in query.lower()
    url = BrowserEngine.build_search_url(query)
    assert url.startswith("https://")
    loop.note_browser_navigation("filehash-open-state", url)

    second = loop.plan_browser_followup(
        source_key="filehash-open-state",
        source_label="Arial.ttf",
        file_type=".ttf",
        h_lambda=5.1,
        observer_state="OFFEN",
        assessment_payload=assessment_payload,
        browser_enabled=True,
        browser_available=True,
        current_url=url,
    )
    assert int(second.loop_iteration) <= 2


def test_browser_engine_fetch_search_context_is_parsed_without_real_network() -> None:
    """Die Suchkontext-Verdichtung soll mit stubbed Download robust funktionieren."""
    original = BrowserEngine._download_text

    def _fake_download(_url: str, timeout: float = 6.0) -> str:
        return """
        <html>
          <body>
            <main>
              <h1>Artificial general intelligence</h1>
              <p>AGI beschreibt ein System, das mehrere Aufgabenbereiche flexibel bearbeiten kann.</p>
              <p>Aether bleibt lokal, observer-relativ und fail-closed.</p>
            </main>
          </body>
        </html>
        """

    BrowserEngine._download_text = staticmethod(_fake_download)
    try:
        result = BrowserEngine.fetch_search_context("Was ist AGI?", provider="duckduckgo")
    finally:
        BrowserEngine._download_text = original

    assert bool(result.get("ok", False)) is True
    assert "Artificial general intelligence" in str(result.get("summary", ""))
    assert str(result.get("search_url", "")).startswith("https://")


def test_browser_engine_inspect_url_flags_obfuscation_and_hate_patterns() -> None:
    """Die lokale URL-Probe soll HTML-Risiken ohne echten Vollbrowser erkennen."""

    class _ProbeHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = """
            <html>
              <head>
                <title>Breaking Truth Mirror</title>
                <script>eval(atob("YWxlcnQoMSk="));document.write("wallet gift card urgent");</script>
                <style>body{font-family:monospace;}</style>
              </head>
              <body>
                <main>
                  <h1>Breaking exclusive leaked news</h1>
                  <p>Wake up. The media lies. Parasites and vermin must disappear.</p>
                  <p>Use crypto wallet now. Limited offer.</p>
                </main>
              </body>
            </html>
            """.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:  # noqa: A003
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/probe"
        result = BrowserEngine.inspect_url(url, timeout=3.0, max_bytes=65536)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert bool(result.get("ok", False)) is True
    assert str(result.get("risk_label", "")) in {"SUSPICIOUS", "CRITICAL"}
    assert float(result.get("obfuscation_score", 0.0) or 0.0) > 0.0
    assert float(result.get("hate_risk_score", 0.0) or 0.0) > 0.0
    assert bool(result.get("open_recommended", True)) is False


def test_shanway_partner_reply_includes_history_and_web_context() -> None:
    """Shanway soll lokalen Verlauf und optionalen Netzkontext lesbar zusammenziehen."""
    engine = ShanwayEngine()
    assessment = engine.detect_asymmetry(
        "Was ist AGI?",
        coherence_score=91.0,
        browser_mode=False,
        active=True,
        h_lambda=1.1,
        observer_mutual_info=2.4,
        source_label="chat://private/local/shanway",
        observer_knowledge_ratio=0.93,
        history_factor=4.0,
        fingerprint_payload={
            "reconstruction_verification": {
                "verified": True,
                "byte_match": True,
                "size_match": True,
                "compression_ratio": 1.0,
                "anchor_coverage_ratio": 0.91,
                "unresolved_residual_ratio": 0.04,
            },
            "verdict_reconstruction": "CONFIRMED",
        },
    )
    reply = engine.compose_chat_partner_reply(
        "Was ist AGI?",
        assessment,
        assistant_text="AGI lese ich hier als lokalen Analyse- und Reflexionskreis.",
        history_excerpt="Du: Erklaere Aether | Shanway: Aether bleibt lokal und strukturell.",
        web_context={
            "ok": True,
            "provider": "duckduckgo",
            "summary": "AGI bezeichnet ein allgemeineres, flexibel lernendes System; Aether bleibt dabei bewusst lokal.",
        },
        channel_kind="private_shanway",
    )

    assert "Kontext gehalten:" in reply
    assert "Netzkontext (duckduckgo):" in reply
    assert "AGI lese ich hier" in reply


def main() -> None:
    """Fuehrt beide Smoke-Varianten direkt ohne pytest-Runner aus."""
    success = run_roundtrip_smoke_test()
    failure = run_roundtrip_failure_smoke_test()
    test_lossless_roundtrip_with_recursive_raster_reflection()
    test_ttd_auto_export_writes_dna_seed_and_jsonl()
    test_public_ttd_pool_requires_three_peer_validations_for_operator()
    test_public_ttd_pool_admin_anchor_is_trusted_immediately()
    test_public_ttd_transport_http_mirror_roundtrip()
    test_agent_loop_plans_browser_followup_for_open_state()
    test_browser_engine_fetch_search_context_is_parsed_without_real_network()
    test_browser_engine_inspect_url_flags_obfuscation_and_hate_patterns()
    test_shanway_partner_reply_includes_history_and_web_context()
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
    print("TTD Autoexport: DNA mit Seed und export_log.jsonl lokal verifiziert")
    print("Public TTD Pool: Peer-Quorum und Admin-Autotrust lokal verifiziert")
    print("Public TTD Transport: HTTP-Mirror lokal verifiziert")
    print("Agent-Loop: Browser-Folgeschritt fuer offene Struktur lokal verifiziert")
    print("Browser-Kontext: stubbed DuckDuckGo-Verdichtung lokal verifiziert")
    print("Browser-Probe: lokale URL-Risikoanalyse mit HTML-Stichprobe verifiziert")
    print("Chat-Partner: Verlauf und Netzkontext lokal verifiziert")


if __name__ == "__main__":
    main()
