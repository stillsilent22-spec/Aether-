from pathlib import Path
from uuid import uuid4

from modules.privacy_anchor_builder import PrivacyAnchorBuilder
from modules.telemetry_classifier import TelemetryVerdict


def _verdict(name: str, classification: str) -> TelemetryVerdict:
    return TelemetryVerdict(
        entity_name=name,
        entity_type="process",
        telemetry_score=0.8,
        classification=classification,
        anchor_matches=["a"],
        behavioral_signals=["fixed_interval"],
        recommendation="test",
        log_weight=0.7,
        privacy_anchor_hash=f"hash-{name}",
    )


def _test_vault_dir() -> Path:
    root = Path("data") / "test_privacy_anchor_builder" / uuid4().hex
    root.mkdir(parents=True, exist_ok=True)
    return root


def test_verdict_to_fingerprint_source_type_is_process() -> None:
    builder = PrivacyAnchorBuilder(vault_path=str(_test_vault_dir()))
    fingerprint = builder.verdict_to_fingerprint(_verdict("proc", "CONFIRMED"), session_id="sid")
    assert fingerprint.source_type == "process"


def test_build_and_save_all_persists_only_relevant_verdicts() -> None:
    builder = PrivacyAnchorBuilder(vault_path=str(_test_vault_dir()))
    saved = builder.build_and_save_all(
        [_verdict("proc1", "CONFIRMED"), _verdict("proc2", "SUSPECTED"), _verdict("proc3", "CLEAN")],
        session_id="sid",
    )
    assert len(saved) == 2
