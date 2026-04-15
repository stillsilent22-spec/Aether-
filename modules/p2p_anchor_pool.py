from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""Lokale, transportagnostische Quorum-Logik fuer oeffentliche TTD-Anker.

Admin/Genesis-Rolle ist kryptografisch an die Genesis-Node-ID gebunden.
Ein einfacher role='admin' String im Payload reicht NICHT —
er muss zusaetzlich von is_genesis_node() bestaetigt werden.
"""


import re
from datetime import datetime, timezone
from typing import Any

from modules.registry import is_genesis_node as _is_genesis_node, TRUSTED_ANCHOR_UPLOAD_MIN_SCORE as _GENESIS_PUSH_MIN_SCORE

_CORROBORATION_LABEL_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")


def _normalize_corroboration_labels(payload: dict[str, Any] | None) -> list[str]:
    if not isinstance(payload, dict):
        return []
    labels: list[str] = []

    def add_label(value: str | None) -> None:
        if not value:
            return
        normalized = str(value).strip().lower()
        if _CORROBORATION_LABEL_RE.match(normalized):
            labels.append(normalized)

    raw = payload.get("corroboration_labels")
    if isinstance(raw, list):
        for item in raw:
            add_label(str(item or ""))

    anomaly_flags = payload.get("anomaly_flags")
    if isinstance(anomaly_flags, list):
        for item in anomaly_flags:
            add_label(str(item or ""))

    add_label(str(payload.get("source_label", "") or ""))
    add_label(str(payload.get("artifact_class", "") or ""))

    return sorted(dict.fromkeys(labels))[:16]


def _corroboration_score(validation_count: int, label_count: int, confirmed_lossless: bool) -> float:
    score = 0.0
    score += min(1.0, float(validation_count) * 0.12)
    score += min(0.3, float(label_count) * 0.07)
    if confirmed_lossless:
        score += 0.2
    return min(1.0, score)


PUBLIC_TTD_POOL_SCHEMA = "aether.public_ttd_anchor.pool.v2"
PUBLIC_TTD_QUORUM_DEFAULT = 3


def normalize_public_role(role: str | None) -> str:
    """Normalisiert Rollen fuer den oeffentlichen TTD-Pool.

    Genesis ist der einzige privilegierte Node — 'admin' existiert nicht.
    Altes 'admin' aus Legacy-Daten wird auf 'genesis' normalisiert.
    """
    normalized = str(role or "operator").strip().lower()
    return "genesis" if normalized in ("genesis", "admin") else "operator"


def normalize_public_artifact_class(artifact_class: str | None) -> str:
    """Erlaubt nur explizit modellierte oeffentliche Artefaktklassen."""
    normalized = str(artifact_class or "performance_route").strip().lower()
    if normalized in {"performance_route", "collaborative_discovery", "public_field_observation"}:
        return normalized
    return "performance_route"


def share_channel_for_artifact(artifact_class: str | None) -> str:
    """Leitet die Weitergabe-Semantik aus der Artefaktklasse ab."""
    normalized = normalize_public_artifact_class(artifact_class)
    if normalized == "performance_route":
        return "auto_push"
    if normalized == "public_field_observation":
        return "passive_observation"
    return "consent_required"


def quorum_threshold_for_role(role: str | None, node_id: str | None = None) -> int:
    """Liefert die Quorum-Schwelle pro Rolle.

    Genesis-Schwelle (1) wird NUR gewaehrt wenn:
    1. role == 'genesis' (Legacy 'admin' wird normalisiert)
    2. node_id mit dem kryptografisch registrierten Genesis-Node uebereinstimmt.

    Jede andere Kombination ergibt PUBLIC_TTD_QUORUM_DEFAULT (3).
    Das verhindert, dass ein beliebiger Node sich als Genesis ausgibt.
    """
    if normalize_public_role(role) == "genesis" and _is_genesis_node(str(node_id or "")):
        return 1
    return PUBLIC_TTD_QUORUM_DEFAULT


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
    uploader_role = normalize_public_role(record.get("uploader_role", "operator"))
    artifact_class = normalize_public_artifact_class(record.get("artifact_class", "performance_route"))
    share_channel = str(record.get("share_channel", share_channel_for_artifact(artifact_class)) or share_channel_for_artifact(artifact_class))
    # Genesis-Node: uploader_node_id muss die verifizierte GENESIS_NODE_ID sein.
    # Nur dann greift die quorum_bypass-Logik (threshold=1 statt 3).
    # Der Pipeline-Trustscore gilt fuer jeden — auch fuer Genesis. Keine Ausnahme.
    uploader_node_id = str(record.get("uploader_node_id", "") or "").strip()
    # Genesis ist der einzige privilegierte Node — kein 'admin' existiert als separater Role.
    genesis_trusted = (
        uploader_role == "genesis"
        and _is_genesis_node(uploader_node_id)
    )
    effective_threshold = quorum_threshold_for_role(
        uploader_role, node_id=uploader_node_id
    )
    threshold = int(record.get("quorum_threshold", effective_threshold) or effective_threshold)
    threshold = min(threshold, effective_threshold)  # never lower than what role allows
    # Trustscore from pipeline metrics — mandatory gate even for genesis.
    # Derived from values already present in public_metrics (no pipeline modification).
    _pm = dict(record.get("public_metrics", {}) or {})
    pipeline_trust_score = round(
        float(_pm.get("delta_stability", 0.0) or 0.0) * 0.4
        + float(_pm.get("symmetry", 0.0) or 0.0) * 0.35
        + max(0.0, 1.0 - float(_pm.get("residual", 1.0) or 1.0)) * 0.25,
        4,
    )
    trust_score_met = pipeline_trust_score >= _GENESIS_PUSH_MIN_SCORE
    # Genesis: Peer-Count-Quorum umgangen (threshold=1) — Trustscore ist Pflicht fuer jeden.
    # Peers: Peer-Count-Quorum erforderlich (unveraendert). Trustscore gilt nicht als Gate fuer Peers.
    quorum_met = bool(
        (genesis_trusted and trust_score_met)
        or (not genesis_trusted and validation_count >= effective_threshold)
    )
    if genesis_trusted and trust_score_met:
        trust_reason = "genesis_quorum_bypass"
    elif genesis_trusted:
        trust_reason = "genesis_score_pending"
    elif quorum_met:
        trust_reason = "peer_quorum_met"
    else:
        trust_reason = "peer_quorum_pending"
    updated = dict(record)
    updated["uploader_role"] = uploader_role
    updated["quorum_threshold"] = effective_threshold
    updated["validation_count"] = int(validation_count)
    updated["genesis_trusted"] = bool(genesis_trusted)
    updated["admin_trusted"] = bool(genesis_trusted)  # alias: 'admin' und 'genesis' sind synonym fuer den Eigentuemer
    updated["quorum_met"] = bool(quorum_met)
    updated["pipeline_trust_score"] = pipeline_trust_score
    updated["trust_state"] = "trusted" if quorum_met else "candidate"
    updated["trust_reason"] = str(trust_reason)
    updated["artifact_class"] = artifact_class
    updated["share_channel"] = share_channel
    updated["source_scope"] = str(record.get("source_scope", "derived_public_metrics") or "derived_public_metrics")
    updated["privacy_class"] = str(record.get("privacy_class", "public_metric_only") or "public_metric_only")
    updated["user_confirmation_required"] = bool(share_channel == "consent_required")

    # Corroboration is an additive peer-quality signal for public anchors.
    corroboration_labels = _normalize_corroboration_labels(record)
    corroboration_count = int(record.get("corroboration_count", 0) or 0)
    confirmed_lossless = bool(record.get("confirmed_lossless", False))
    corroboration_score = _corroboration_score(corroboration_count, len(corroboration_labels), confirmed_lossless)
    corroboration_ready = bool(corroboration_score >= 0.5 and corroboration_count >= 2)
    updated["corroboration_labels"] = corroboration_labels
    updated["corroboration_count"] = corroboration_count
    updated["corroboration_score"] = corroboration_score
    updated["corroboration_ready"] = corroboration_ready

    # Genesis: auto_push vom Trustscore gegattet (Peer-Count-Quorum umgangen, Trustscore Pflicht).
    # Peers: auto_push erfordert sowohl Peer-Count-Quorum als auch ausreichende Peer-Korroboration.
    genesis_push_ready = bool(genesis_trusted and artifact_class == "performance_route" and trust_score_met)
    peer_push_ready = bool(not genesis_trusted and artifact_class == "performance_route" and quorum_met and corroboration_ready)
    updated["auto_push_ready"] = bool(genesis_push_ready or peer_push_ready)
    updated["auto_push_reason"] = (
        "genesis_override" if genesis_push_ready
        else "peer_quorum_and_corroboration" if peer_push_ready
        else "not_ready"
    )
    if quorum_met and not str(updated.get("trusted_at", "") or "").strip():
        updated["trusted_at"] = _utc_now()
    return updated


def build_public_ttd_anchor_record(payload: dict[str, Any], *, signature_included: bool = False) -> dict[str, Any]:
    """Erzeugt einen neuen Quorum-Datensatz fuer einen oeffentlichen TTD-Anker."""
    item = dict(payload or {})
    pseudonym = str(item.get("pseudonym", "") or "").strip()
    uploader_role = normalize_public_role(item.get("uploader_role", "operator"))
    artifact_class = normalize_public_artifact_class(item.get("artifact_class", "performance_route"))
    validators = [pseudonym] if pseudonym else []
    corroboration_labels = _normalize_corroboration_labels(item)
    corroboration_count = int(len(validators))
    record = {
        "schema": "aether.public_ttd_anchor.record.v1",
        "ttd_hash": str(item.get("ttd_hash", "") or ""),
        "source_label": str(item.get("source_label", "") or ""),
        "first_seen_at": str(item.get("timestamp", "") or _utc_now()),
        "last_seen_at": str(item.get("timestamp", "") or _utc_now()),
        "uploader_pseudonym": pseudonym,
        "uploader_node_id": str(item.get("uploader_node_id", "") or "").strip(),
        "uploader_role": uploader_role,
        "validation_pseudonyms": validators,
        "validation_count": corroboration_count,
        "signed_validation_count": 1 if bool(signature_included) else 0,
        "corroboration_labels": corroboration_labels,
        "corroboration_count": corroboration_count,
        "corroboration_score": _corroboration_score(corroboration_count, len(corroboration_labels), bool(item.get("confirmed_lossless", False))),
        "public_metrics": _canonical_metrics(item.get("public_metrics", {})),
        "latest_metrics": _canonical_metrics(item.get("public_metrics", {})),
        "raw_data_included": False,
        "deltas_included": False,
        "internal_only": False,
        "transport_hint": str(item.get("transport_hint", "ipfs_libp2p_bundle") or "ipfs_libp2p_bundle"),
        "artifact_class": artifact_class,
        "share_channel": str(item.get("share_channel", share_channel_for_artifact(artifact_class)) or share_channel_for_artifact(artifact_class)),
        "source_scope": str(item.get("source_scope", "derived_public_metrics") or "derived_public_metrics"),
        "privacy_class": str(item.get("privacy_class", "public_metric_only") or "public_metric_only"),
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
    merged["artifact_class"] = normalize_public_artifact_class(item.get("artifact_class", existing.get("artifact_class", "performance_route")))
    merged["share_channel"] = str(item.get("share_channel", existing.get("share_channel", share_channel_for_artifact(merged.get("artifact_class", "performance_route")))) or existing.get("share_channel", share_channel_for_artifact(merged.get("artifact_class", "performance_route"))))
    merged["source_scope"] = str(item.get("source_scope", existing.get("source_scope", "derived_public_metrics")) or existing.get("source_scope", "derived_public_metrics"))
    merged["privacy_class"] = str(item.get("privacy_class", existing.get("privacy_class", "public_metric_only")) or existing.get("privacy_class", "public_metric_only"))
    merged["corroboration_labels"] = _normalize_corroboration_labels({
        **existing,
        **item,
        "corroboration_labels": list(existing.get("corroboration_labels", [])) + list(item.get("corroboration_labels", [])),
    })
    merged["corroboration_count"] = int(merged["validation_count"])
    merged["corroboration_score"] = _corroboration_score(
        int(merged["corroboration_count"]),
        len(merged["corroboration_labels"]),
        bool(existing.get("confirmed_lossless", False) or item.get("confirmed_lossless", False)),
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
        "artifact_class": normalize_public_artifact_class(item.get("artifact_class", "performance_route")),
        "share_channel": str(item.get("share_channel", share_channel_for_artifact(item.get("artifact_class", "performance_route"))) or share_channel_for_artifact(item.get("artifact_class", "performance_route"))),
        "source_scope": str(item.get("source_scope", "derived_public_metrics") or "derived_public_metrics"),
        "privacy_class": str(item.get("privacy_class", "public_metric_only") or "public_metric_only"),
        "user_confirmation_required": bool(item.get("user_confirmation_required", False)),
        "auto_push_ready": bool(item.get("auto_push_ready", False)),
        "corroboration_labels": list(item.get("corroboration_labels", []) or []),
        "corroboration_count": int(item.get("corroboration_count", 0) or 0),
        "corroboration_score": float(item.get("corroboration_score", 0.0) or 0.0),
        "corroboration_ready": bool(item.get("corroboration_ready", False)),
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
    genesis_trusted_count = sum(1 for record in trusted_records if bool(record.get("genesis_trusted", False)))
    auto_push_ready_count = sum(1 for record in trusted_records if bool(record.get("auto_push_ready", False)))
    corroboration_ready_count = sum(1 for record in trusted_records if bool(record.get("corroboration_ready", False)))
    consent_required_count = sum(1 for record in normalized_records if bool(record.get("user_confirmation_required", False)))
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
        "genesis_trusted_count": int(genesis_trusted_count),
        "admin_trusted_count": int(genesis_trusted_count),  # alias: "admin" normalizes to "genesis"
        "auto_push_ready_count": int(auto_push_ready_count),
        "corroboration_ready_count": int(corroboration_ready_count),
        "consent_required_count": int(consent_required_count),
    }


class P2PAnchorPool:
    """Thin wrapper around public TTD anchor pool functions for object-oriented access."""

    def build_record(self, payload: dict, *, signature_included: bool = False) -> dict:
        return build_public_ttd_anchor_record(payload, signature_included=signature_included)

    def validator_present(self, record: dict, pseudonym: str) -> bool:
        return public_ttd_validator_present(record, pseudonym)

    def merge_record(self, *args, **kwargs) -> dict:
        return merge_public_ttd_anchor_record(*args, **kwargs)

    def anchor_view(self, record: dict) -> dict:
        return public_ttd_anchor_view(record)

    def summarize(self, records: list) -> dict:
        return summarize_public_ttd_anchor_records(records)

    def normalize_role(self, role: str) -> str:
        return normalize_public_role(role)
