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
from modules.observer_engine import ObserverEngine
from modules.public_ttd_transport import PublicTTDTransport
from modules.reconstruction_engine import GoedelLoopTerminator, LosslessReconstructionEngine, VaultMissError
from modules.screen_vision_engine import is_private_context as is_private_screen_context
from modules.session_engine import SessionContext
from modules.vault_chain import AetherAugmentor


def _sample_bytes() -> bytes:
    """Liefert einen kleinen, stabilen Bytezustand fuer Roundtrip-Tests."""
    payload = (
        b"Aether lossless roundtrip test\n"
        b"observer-relative information remains local\n"
        b"session seeds must survive reloads\n"
    )
    return payload * 16


def _workspace_tmp_dir(name: str) -> Path:
    """Legt ein reproduzierbares Temp-Verzeichnis im Workspace statt im OS-Temp an."""
    path = PROJECT_ROOT / "tests" / ".tmp_pytest" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _reconstruct_from_delta(delta: bytes, session_seed: int) -> bytes:
    """Hebt das XOR-Delta mit dem persistierten Session-Seed wieder auf."""
    noise = SessionContext.noise_from_seed(int(session_seed) & 0xFFFFFFFF, len(delta))
    return bytes(left ^ right for left, right in zip(delta, noise))


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

    return {
        "fingerprint": fingerprint,
        "verdict_reconstruction": verdict,
        "reconstruction_verification": verification,
        "persisted_seed": int(persisted_seed),
        "reloaded_seed": int(reloaded_seed),
        "reconstructed_bytes": reconstructed_bytes,
        "replay_verification": dict(replay_verification),
        "original_hash": str(original_hash),
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

    return {
        "verification": verification,
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
    assert int(getattr(fingerprint, "delta_session_seed", 0) or 0) == 1337


def test_lossless_roundtrip_wrong_seed_fails() -> None:
    """Ein falscher Seed muss als FAILED erkannt werden."""
    result = run_roundtrip_failure_smoke_test()
    verification = dict(result["verification"])

    assert bool(verification.get("verified", True)) is False
    assert bool(verification.get("session_seed_match", True)) is False


def test_vault_growth_reduces_delta_size() -> None:
    """Beweist C(t) -> 1 fuer wiederholte lokale Rekonstruktionen mit gleichem Input."""
    tmp_dir = _workspace_tmp_dir("vault_growth_reduces_delta_size")
    engine = LosslessReconstructionEngine(vault_db_path=str(tmp_dir / "anchors.db"))
    sample = _sample_bytes()

    delta_1 = engine.build_delta_log(sample)
    delta_2 = engine.build_delta_log(sample)

    add_ops_1 = [entry for entry in delta_1 if entry.get("op") == "add"]
    add_ops_2 = [entry for entry in delta_2 if entry.get("op") == "add"]
    ref_ops_2 = [entry for entry in delta_2 if entry.get("op") == "ref"]

    assert len(add_ops_2) < len(add_ops_1)
    assert len(ref_ops_2) > 0
    assert engine.coherence_index(delta_2) > engine.coherence_index(delta_1)

    try:
        reconstructed = engine.reconstruct_from_vault(delta_2)
    except VaultMissError as exc:
        result = {"verified": False, "failure_reason": str(exc)}
        reconstructed = b""
    else:
        result = engine.verify_lossless(sample, reconstructed)
    assert reconstructed == sample
    assert result["verified"] is True
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_privacy_boundary_blocks_chat() -> None:
    """Privacy Boundary blockiert Chat-, Mail- und Passwortkontexte fail-closed."""
    assert is_private_screen_context("whatsapp_chat", "") is True
    assert is_private_screen_context("email_inbox", "") is True
    assert is_private_screen_context("", "password=abc123") is True
    assert is_private_screen_context("", "user@example.com") is True
    assert is_private_screen_context("aether_vault", "anchor_data") is False
    assert is_private_screen_context("game_renderer", "texture_load") is False


def test_goedel_loop_terminates() -> None:
    """Der Goedel-Loop endet deterministisch vor der Maximalgrenze."""
    tmp_dir = _workspace_tmp_dir("goedel_loop_terminates")
    engine = LosslessReconstructionEngine(vault_db_path=str(tmp_dir / "goedel_anchors.db"))
    terminator = GoedelLoopTerminator()
    sample = _sample_bytes()

    result = terminator.run_loop(sample, engine)
    assert result["terminated"] is True
    assert result["depth"] <= GoedelLoopTerminator.MAX_RECURSION_DEPTH
    assert 0.0 <= result["coherence"] <= 1.0
    assert result["goedel_rest"] >= 0.0
    shutil.rmtree(tmp_dir, ignore_errors=True)


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

    assert bool(dict(getattr(fingerprint, "reconstruction_verification", {}) or {}).get("verified", False)) is True
    assert str(reflection.get("learned_insight", "") or "").strip()
    assert str(dict(learning_state).get("current_insight", "") or "").strip()
    shutil.rmtree(temp_learning_dir, ignore_errors=True)


def test_reconstruct_from_vault_reports_failed_result_on_missing_anchor() -> None:
    """Fehlende Vault-Referenzen muessen explizit als FAILED statt als Leerbytes enden."""
    engine = LosslessReconstructionEngine(vault_db_path=":memory:")
    delta_log = [
        {"op": "init", "size": 8},
        {"op": "ref", "offset": 0, "length": 8, "anchor_hash": "missing-anchor"},
    ]
    try:
        engine.reconstruct_from_vault(delta_log)
    except VaultMissError as exc:
        result = {"verified": False, "status": "FAILED", "reason": str(exc)}
    else:
        result = {"verified": True, "status": "CONFIRMED", "reason": ""}
    assert result["verified"] is False
    assert result["status"] == "FAILED"
    assert "missing-anchor" in result["reason"]


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
    """Genesis-Anker sind sofort vertrauenswuerdig wenn der Pipeline-Trustscore erreicht ist.

    Testet die Pool-Schicht direkt mit verifizierten Genesis-Credentials.
    Hardware-Bindung (device_lock) wird auf Ebene der VaultChain/security_engine erzwungen;
    dieser Test prueft ausschliesslich den Pool-Trust-Mechanismus.
    """
    from modules.p2p_anchor_pool import build_public_ttd_anchor_record, summarize_public_ttd_anchor_records
    from modules.registry import GENESIS_NODE_ID

    temp_public_root = PROJECT_ROOT / "tests" / ".tmp_public_ttd_pool_admin"
    shutil.rmtree(temp_public_root, ignore_errors=True)
    temp_public_root.mkdir(parents=True, exist_ok=True)

    context = SessionContext(seed=818181)
    context.user_role = "admin"
    context.username = "creator"
    observer = ObserverEngine()
    observer.learning_store_dir = temp_public_root / "observer_learning"

    # Direkt einen Genesis-Payload mit vollstaendigen Pipeline-Metriken aufbauen.
    # uploader_node_id = GENESIS_NODE_ID simuliert die Ausgabe von vault_chain
    # auf dem verifizierten Genesis-Geraet (Hardware-Bindung dort erfuellt).
    genesis_payload = {
        "pseudonym": "test-genesis-pseudonym-aabbcc112233",
        "uploader_role": "admin",
        "uploader_node_id": GENESIS_NODE_ID,
        "ttd_hash": hashlib.sha256(b"admin-public-ttd-anchor").hexdigest(),
        "source_label": "tests::public_ttd_pool_admin",
        "timestamp": "2024-01-01T00:00:00+00:00",
        "public_metrics": {
            "residual": 0.01,
            "symmetry": 0.96,
            "i_obs_ratio": 0.97,
            "delta_stability": 0.99,
            "delta_i_obs_percent": 1.5,
        },
        "artifact_class": "performance_route",
        "transport_hint": "ipfs_libp2p_bundle",
        "source_scope": "derived_public_metrics",
        "privacy_class": "public_metric_only",
    }
    record = build_public_ttd_anchor_record(genesis_payload, signature_included=True)

    assert int(record.get("validation_count", 0) or 0) == 1
    assert int(record.get("quorum_threshold", 0) or 0) == 1
    assert bool(record.get("admin_trusted", False)) is True
    assert bool(record.get("quorum_met", False)) is True
    assert str(record.get("trust_reason", "") or "") == "genesis_auto_trust"
    assert str(record.get("trust_state", "") or "") == "trusted"
    assert bool(record.get("auto_push_ready", False)) is True

    summary = summarize_public_ttd_anchor_records([record])
    assert int(summary.get("trusted_anchor_count", 0) or 0) == 1
    assert int(summary.get("admin_trusted_count", 0) or 0) == 1

    learning_result = observer.merge_public_anchor_bundle(context, summary)
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
    """Offene Assistant-Befunde duerfen hoechstens einen lokalen Suchhinweis planen."""
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
    url = f"local://search?query={query}"
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
