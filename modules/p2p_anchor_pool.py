"""Lokale, transportagnostische Quorum-Logik fuer oeffentliche TTD-Anker."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


PUBLIC_TTD_POOL_SCHEMA = "aether.public_ttd_anchor.pool.v2"
PUBLIC_TTD_QUORUM_DEFAULT = 3


def normalize_public_role(role: str | None) -> str:
    """Normalisiert Rollen fuer den oeffentlichen TTD-Pool."""
    normalized = str(role or "operator").strip().lower()
    return "admin" if normalized == "admin" else "operator"


def quorum_threshold_for_role(role: str | None) -> int:
    """Liefert die Quorum-Schwelle pro Rolle."""
    return 1 if normalize_public_role(role) == "admin" else PUBLIC_TTD_QUORUM_DEFAULT


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_metrics(metrics: dict[str, Any] | None) -> dict[str, float | int]:
    source = dict(metrics or {})
    return {
        "residual": round(float(source.get("residual", 0.0) or 0.0), 12),
        "symmetry": round(float(source.get("symmetry", 0.0) or 0.0), 12),
        "i_obs_ratio": round(float(source.get("i_obs_ratio", 0.0) or 0.0), 12),
        "delta_stability": round(float(source.get("delta_stability", 0.0) or 0.0), 12),
        "delta_i_obs_percent": round(float(source.get("delta_i_obs_percent", 0.0) or 0.0), 12),
        "recursive_count": int(source.get("recursive_count", 0) or 0),
    }


def _average_metrics(
    left: dict[str, Any] | None,
    right: dict[str, Any] | None,
    *,
    left_weight: int,
    right_weight: int = 1,
) -> dict[str, float | int]:
    base = _canonical_metrics(left)
    incoming = _canonical_metrics(right)
    total_weight = max(1, int(left_weight)) + max(1, int(right_weight))
    averaged: dict[str, float | int] = {}
    for key in ("residual", "symmetry", "i_obs_ratio", "delta_stability", "delta_i_obs_percent"):
        averaged[key] = round(
            ((float(base.get(key, 0.0) or 0.0) * max(1, int(left_weight))) + (float(incoming.get(key, 0.0) or 0.0) * max(1, int(right_weight))))
            / float(total_weight),
            12,
        )
    averaged["recursive_count"] = max(
        int(base.get("recursive_count", 0) or 0),
        int(incoming.get("recursive_count", 0) or 0),
    )
    return averaged


def _apply_trust_state(record: dict[str, Any]) -> dict[str, Any]:
    validation_count = int(record.get("validation_count", 0) or 0)
    threshold = int(record.get("quorum_threshold", PUBLIC_TTD_QUORUM_DEFAULT) or PUBLIC_TTD_QUORUM_DEFAULT)
    uploader_role = normalize_public_role(record.get("uploader_role", "operator"))
    admin_trusted = uploader_role == "admin"
    quorum_met = bool(admin_trusted or validation_count >= threshold)
    if admin_trusted:
        trust_reason = "admin_auto_trust"
    elif quorum_met:
        trust_reason = "peer_quorum_met"
    else:
        trust_reason = "peer_quorum_pending"
    updated = dict(record)
    updated["uploader_role"] = uploader_role
    updated["quorum_threshold"] = 1 if admin_trusted else max(3, threshold)
    updated["validation_count"] = int(validation_count)
    updated["admin_trusted"] = bool(admin_trusted)
    updated["quorum_met"] = bool(quorum_met)
    updated["trust_state"] = "trusted" if quorum_met else "candidate"
    updated["trust_reason"] = str(trust_reason)
    if quorum_met and not str(updated.get("trusted_at", "") or "").strip():
        updated["trusted_at"] = _utc_now()
    return updated


def build_public_ttd_anchor_record(payload: dict[str, Any], *, signature_included: bool = False) -> dict[str, Any]:
    """Erzeugt einen neuen Quorum-Datensatz fuer einen oeffentlichen TTD-Anker."""
    item = dict(payload or {})
    pseudonym = str(item.get("pseudonym", "") or "").strip()
    uploader_role = normalize_public_role(item.get("uploader_role", "operator"))
    validators = [pseudonym] if pseudonym else []
    record = {
        "schema": "aether.public_ttd_anchor.record.v1",
        "ttd_hash": str(item.get("ttd_hash", "") or ""),
        "source_label": str(item.get("source_label", "") or ""),
        "first_seen_at": str(item.get("timestamp", "") or _utc_now()),
        "last_seen_at": str(item.get("timestamp", "") or _utc_now()),
        "uploader_pseudonym": pseudonym,
        "uploader_role": uploader_role,
        "validation_pseudonyms": validators,
        "validation_count": int(len(validators)),
        "signed_validation_count": 1 if bool(signature_included) else 0,
        "public_metrics": _canonical_metrics(item.get("public_metrics", {})),
        "latest_metrics": _canonical_metrics(item.get("public_metrics", {})),
        "raw_data_included": False,
        "deltas_included": False,
        "internal_only": False,
        "transport_hint": str(item.get("transport_hint", "ipfs_libp2p_bundle") or "ipfs_libp2p_bundle"),
    }
    return _apply_trust_state(record)


def public_ttd_validator_present(record: dict[str, Any], pseudonym: str) -> bool:
    """Prueft, ob ein Pseudonym den Anker bereits validiert hat."""
    normalized = str(pseudonym or "").strip()
    validators = [str(item) for item in list(record.get("validation_pseudonyms", []) or []) if str(item).strip()]
    return bool(normalized and normalized in validators)


def merge_public_ttd_anchor_record(
    record: dict[str, Any],
    payload: dict[str, Any],
    *,
    signature_included: bool = False,
) -> dict[str, Any]:
    """Fuegt eine weitere unabhaengige Validierung in einen vorhandenen Anchor-Record ein."""
    existing = dict(record or {})
    item = dict(payload or {})
    pseudonym = str(item.get("pseudonym", "") or "").strip()
    validators = [str(value) for value in list(existing.get("validation_pseudonyms", []) or []) if str(value).strip()]
    if pseudonym and pseudonym not in validators:
        validators.append(pseudonym)
    previous_count = int(existing.get("validation_count", 0) or len(validators) or 0)
    merged = dict(existing)
    merged["last_seen_at"] = str(item.get("timestamp", "") or _utc_now())
    merged["validation_pseudonyms"] = validators[-32:]
    merged["validation_count"] = int(len(merged["validation_pseudonyms"]))
    merged["signed_validation_count"] = int(existing.get("signed_validation_count", 0) or 0) + (1 if bool(signature_included) and pseudonym and pseudonym in validators else 0)
    merged["latest_metrics"] = _canonical_metrics(item.get("public_metrics", {}))
    merged["public_metrics"] = _average_metrics(
        existing.get("public_metrics", {}),
        item.get("public_metrics", {}),
        left_weight=max(1, previous_count),
    )
    return _apply_trust_state(merged)


def public_ttd_anchor_view(record: dict[str, Any]) -> dict[str, Any]:
    """Reduziert einen internen Quorum-Record auf ein lernbares, oeffentliches Anchor-Objekt."""
    item = dict(record or {})
    return {
        "schema": "aether.public_ttd_anchor.v1",
        "ttd_hash": str(item.get("ttd_hash", "") or ""),
        "source_label": str(item.get("source_label", "") or ""),
        "public_metrics": _canonical_metrics(item.get("public_metrics", {})),
        "validation_count": int(item.get("validation_count", 0) or 0),
        "quorum_threshold": int(item.get("quorum_threshold", PUBLIC_TTD_QUORUM_DEFAULT) or PUBLIC_TTD_QUORUM_DEFAULT),
        "quorum_met": bool(item.get("quorum_met", False)),
        "trust_state": str(item.get("trust_state", "candidate") or "candidate"),
        "trust_reason": str(item.get("trust_reason", "") or ""),
        "uploader_role": normalize_public_role(item.get("uploader_role", "operator")),
        "pseudonym": str(item.get("uploader_pseudonym", "") or ""),
        "raw_data_included": False,
        "deltas_included": False,
        "internal_only": False,
    }


def summarize_public_ttd_anchor_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Leitet trusted/candidate-Sichten und Pool-Kennzahlen aus den Records ab."""
    normalized_records = [_apply_trust_state(dict(item or {})) for item in list(records or []) if isinstance(item, dict)]
    trusted_records = [record for record in normalized_records if bool(record.get("quorum_met", False))]
    candidate_records = [record for record in normalized_records if not bool(record.get("quorum_met", False))]
    trusted_views = [public_ttd_anchor_view(record) for record in trusted_records]
    candidate_views = [public_ttd_anchor_view(record) for record in candidate_records]
    quorum_validated_count = sum(1 for record in trusted_records if str(record.get("trust_reason", "") or "") == "peer_quorum_met")
    admin_trusted_count = sum(1 for record in trusted_records if bool(record.get("admin_trusted", False)))
    return {
        "schema": PUBLIC_TTD_POOL_SCHEMA,
        "updated_at": _utc_now(),
        "anchor_records": normalized_records,
        "anchor_record_count": int(len(normalized_records)),
        "public_anchors": trusted_views,
        "trusted_anchor_count": int(len(trusted_views)),
        "candidate_anchors": candidate_views,
        "candidate_anchor_count": int(len(candidate_views)),
        "quorum_validated_count": int(quorum_validated_count),
        "admin_trusted_count": int(admin_trusted_count),
    }
