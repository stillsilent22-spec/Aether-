"""Vault-, Chain- und Signaturlogik fuer Aether-Zusatzpanels."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from .analysis_engine import AetherFingerprint
from .chat_crypto import decrypt_text, derive_fernet_key, encrypt_text, crypto_available
from .observer_engine import AnchorPoint
from .p2p_anchor_pool import (
    build_public_ttd_anchor_record,
    merge_public_ttd_anchor_record,
    public_ttd_anchor_view,
    public_ttd_validator_present,
    summarize_public_ttd_anchor_records,
)
from .registry import GENESIS_HASH, compute_chain_block_hash, legacy_chain_block_hash_candidates
from .security_engine import (
    pseudonymous_network_identity,
    public_ttd_quorum_policy,
    public_ttd_share_policy,
    validate_public_ttd_candidate,
)
from .session_engine import SessionContext


def _canonical_json(payload: Any) -> str:
    """Serialisiert Payloads deterministisch fuer Signaturen."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _compact_file_profile(profile: dict[str, Any] | None) -> dict[str, Any]:
    """Reduziert Multi-Type-Dateiprofile auf append-only relevante Kerndaten."""
    payload = dict(profile or {})
    summary = dict(payload.get("summary", {}) or {})
    return {
        "category": str(payload.get("category", "binary") or "binary"),
        "subtype": str(payload.get("subtype", "") or ""),
        "mime_type": str(payload.get("mime_type", "") or ""),
        "parser_confidence": float(payload.get("parser_confidence", 0.0) or 0.0),
        "missing_dependencies": [str(item) for item in list(payload.get("missing_dependencies", []) or []) if str(item).strip()],
        "missing_data": [str(item) for item in list(payload.get("missing_data", []) or []) if str(item).strip()],
        "type_metrics": dict(payload.get("type_metrics", {}) or {}),
        "summary": {
            "stream_count": int(summary.get("stream_count", 0) or 0),
            "type_metric_count": int(summary.get("type_metric_count", 0) or 0),
        },
    }


def _compact_screen_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Verdichtet Screen-Vision fuer Signaturen und Vault-Snapshots."""
    screen = dict(payload or {})
    return {
        "SCREEN_VISION": str(screen.get("SCREEN_VISION", screen.get("screen_vision", "")) or ""),
        "SOURCE": str(screen.get("SOURCE", screen.get("source", "")) or ""),
        "CONVERGENCE": str(screen.get("CONVERGENCE", screen.get("convergence", "")) or ""),
        "shared_anchor_count": int(len(list(screen.get("shared_anchors", []) or []))),
        "visual_anchor_count": int(len(list(screen.get("VISUAL_ANCHORS", screen.get("visual_anchors", []) or [])))),
        "file_anchor_count": int(len(list(screen.get("FILE_ANCHORS", screen.get("file_anchors", []) or [])))),
    }


def _compact_observer_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Bewahrt visuelle und prozessuale Residuen ohne voluminose Rohdaten."""
    observer = dict(payload or {})
    visual_state = dict(observer.get("visual_state", {}) or {})
    process_state = dict(observer.get("process_state", {}) or {})
    return {
        "screen_vision_mode": str(observer.get("screen_vision_mode", "") or ""),
        "visual_state": {
            "mode": str(visual_state.get("mode", "") or ""),
            "width": int(visual_state.get("width", 0) or 0),
            "height": int(visual_state.get("height", 0) or 0),
            "visual_entropy": float(visual_state.get("visual_entropy", 0.0) or 0.0),
        },
        "process_state": {
            "name": str(process_state.get("name", "") or ""),
            "cpu_percent": float(process_state.get("cpu_percent", 0.0) or 0.0),
            "rss_mb": float(process_state.get("rss_mb", 0.0) or 0.0),
            "threads": int(process_state.get("threads", 0) or 0),
            "missing_dependencies": [
                str(item)
                for item in list(process_state.get("missing_dependencies", []) or [])
                if str(item).strip()
            ],
        },
        "visual_residual_hash": str(observer.get("visual_residual_hash", "") or ""),
        "process_residuum_hash": str(observer.get("process_residuum_hash", "") or ""),
        "O_t": dict(observer.get("O_t", {}) or {}),
        "M_t": dict(observer.get("M_t", {}) or {}),
        "R_t": dict(observer.get("R_t", {}) or {}),
    }


def _compact_emergence_layers(layers: Sequence[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Haelt Emergenz-Layer knapp und deterministisch."""
    compact: list[dict[str, Any]] = []
    for item in list(layers or [])[:4]:
        if not isinstance(item, dict):
            continue
        compact.append(
            {
                "layer": str(item.get("layer", "") or ""),
                "status": str(item.get("status", "") or ""),
                "summary": str(item.get("summary", "") or ""),
                "confidence": float(item.get("confidence", 0.0) or 0.0),
            }
        )
    return compact


def _compact_self_reflection_payload(
    payload: dict[str, Any] | None,
    *,
    include_internal: bool = False,
) -> dict[str, Any]:
    """Verdichtet Miniatur-/Raster-Selbstdeltas ohne Roharrays fuer Vault und Sharing."""
    reflection = dict(payload or {})
    miniature = dict(reflection.get("miniature_reflection", {}) or {})
    raster = dict(reflection.get("raster_self_perception", {}) or {})
    recursive = [dict(item) for item in list(reflection.get("recursive_reflections", []) or []) if isinstance(item, dict)]
    ttd_candidates = [dict(item) for item in list(reflection.get("ttd_candidates", []) or []) if isinstance(item, dict)]
    compact = {
        "internal_only": bool(reflection.get("internal_only", True)),
        "miniature_reflection": {
            "hash": str(miniature.get("hash", "") or ""),
            "local_entropy": float(miniature.get("local_entropy", 0.0) or 0.0),
            "symmetry": float(miniature.get("symmetry", 0.0) or 0.0),
            "emergence_spots": int(miniature.get("emergence_spots", 0) or 0),
            "noether_invariant_ratio": float(miniature.get("noether_invariant_ratio", 0.0) or 0.0),
        },
        "raster_self_perception": {
            "enabled": bool(raster.get("enabled", False)),
            "hash": str(raster.get("hash", "") or ""),
            "symmetry": float(raster.get("symmetry", 0.0) or 0.0),
            "entropy_mean": float(raster.get("entropy_mean", 0.0) or 0.0),
            "hotspot_count": int(raster.get("hotspot_count", 0) or 0),
            "verdict": str(raster.get("verdict", "") or ""),
        },
        "delta_i_obs_percent": float(reflection.get("delta_i_obs_percent", 0.0) or 0.0),
        "residual_before": float(reflection.get("residual_before", 0.0) or 0.0),
        "residual_after": float(reflection.get("residual_after", 0.0) or 0.0),
        "stability_score": float(reflection.get("stability_score", 0.0) or 0.0),
        "recursive_reflections": [
            {
                "level": int(item.get("level", 0) or 0),
                "delta": float(item.get("delta", 0.0) or 0.0),
                "mt_shift": float(item.get("mt_shift", 0.0) or 0.0),
                "residual_before": float(item.get("residual_before", 0.0) or 0.0),
                "residual_after": float(item.get("residual_after", 0.0) or 0.0),
                "emergence_detected": bool(item.get("emergence_detected", False)),
            }
            for item in recursive[:7]
        ],
        "ttd_candidates": [
            {
                "hash": str(item.get("hash", "") or ""),
                "delta_stability": float(item.get("delta_stability", 0.0) or 0.0),
                "symmetry": float(item.get("symmetry", 0.0) or 0.0),
                "residual": float(item.get("residual", 0.0) or 0.0),
                "public_metrics": dict(item.get("public_metrics", {}) or {}),
            }
            for item in ttd_candidates[:12]
        ],
        "learned_insight": str(reflection.get("learned_insight", "") or ""),
    }
    if include_internal:
        compact["internal_self_reflection"] = {
            "recursive_reflections": list(compact["recursive_reflections"]),
            "ttd_candidates": list(compact["ttd_candidates"]),
        }
    return compact


def _xor_bytes(*buffers: bytes) -> bytes:
    """XORt Bytepuffer gleicher Laenge."""
    if not buffers:
        return b""
    result = bytearray(buffers[0])
    for buffer in buffers[1:]:
        for index, value in enumerate(buffer):
            result[index] ^= value
    return bytes(result)


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    """Berechnet robuste Kosinus-Similaritaet."""
    lhs = np.array(left, dtype=np.float64)
    rhs = np.array(right, dtype=np.float64)
    denom = float(np.linalg.norm(lhs) * np.linalg.norm(rhs))
    if denom <= 1e-9:
        return 0.0
    return float(np.dot(lhs, rhs) / denom)


@dataclass
class VerifyRecord:
    """Darstellungseintrag fuer die Verify-Ansicht."""

    status: str
    session_id: str
    block_hash: str
    milestone: int
    timestamp: str


class AetherAugmentor:
    """Verwaltet Session-Key, Chain-Bloecke, Vault-Eintraege und JSON-Export."""

    def __init__(self, session_context: SessionContext, registry) -> None:
        self.session_context = session_context
        self.registry = registry
        self.master_secret = self._build_master_secret()
        self.key_fingerprint = self.master_secret.hex()[:32].upper()
        self._minted_milestones: set[int] = set()

    def _build_master_secret(self) -> bytes:
        """Leitet einen Master-Secret-Fingerprint aus drei Hashsimulationen ab."""
        seed_payload = (
            f"{self.session_context.session_id}|{self.session_context.seed}|{self.session_context.created_at}|"
            f"{getattr(self.session_context, 'live_session_key', '')}|"
            f"{getattr(self.session_context, 'live_session_fingerprint', '')}"
        ).encode("utf-8")
        sha = hashlib.sha256(seed_payload).digest()
        keccak_sim = hashlib.sha3_256(seed_payload).digest()
        blake3_sim = hashlib.blake2b(seed_payload, digest_size=32).digest()
        return _xor_bytes(sha, keccak_sim, blake3_sim)

    def sign_payload(self, payload: Any) -> str:
        """Signiert Payloads HMAC-artig mit dem Session-Secret."""
        canonical = _canonical_json(payload).encode("utf-8")
        return hmac.new(self.master_secret, canonical, hashlib.sha256).hexdigest()

    def feature_vector(self, fingerprint: AetherFingerprint) -> list[float]:
        """Projiziert Fingerprints auf einen festen Vault-Vektorraum."""
        return [
            float(fingerprint.entropy_mean) / 8.0,
            float(getattr(fingerprint, "symmetry_score", 0.0)) / 100.0,
            float(getattr(fingerprint, "coherence_score", 0.0)) / 100.0,
            float(getattr(fingerprint, "resonance_score", 0.0)) / 100.0,
            float(getattr(fingerprint, "ethics_score", 0.0)) / 100.0,
            float(min(14, len(fingerprint.anomaly_coordinates))) / 14.0,
            float(fingerprint.delta_ratio),
            float(min(64, getattr(fingerprint, "periodicity", 0))) / 64.0,
        ]

    def _cluster_labels(self, vectors: list[list[float]]) -> list[str]:
        """Fuehrt ein kleines deterministisches k-means mit k=3 aus."""
        if not vectors:
            return []
        data = np.array(vectors, dtype=np.float64)
        if data.shape[0] < 3:
            return ["TRANSITIONAL" for _ in range(data.shape[0])]

        seeds = [0, data.shape[0] // 2, data.shape[0] - 1]
        centroids = data[seeds, :]
        for _ in range(8):
            distances = np.linalg.norm(data[:, None, :] - centroids[None, :, :], axis=2)
            labels = np.argmin(distances, axis=1)
            for idx in range(3):
                subset = data[labels == idx]
                if subset.size > 0:
                    centroids[idx] = np.mean(subset, axis=0)

        harmonicity = centroids[:, 2] + centroids[:, 3] + centroids[:, 4]
        ordered = np.argsort(harmonicity)
        mapping = {
            int(ordered[0]): "CHAOTIC",
            int(ordered[1]): "TRANSITIONAL",
            int(ordered[2]): "HARMONIC",
        }
        return [mapping[int(item)] for item in labels.tolist()]

    def register_fingerprint(self, fingerprint: AetherFingerprint) -> dict[str, Any]:
        """Speichert einen neuen Vault-Eintrag und aktualisiert Clusterlabels."""
        vector = self.feature_vector(fingerprint)
        existing = self.registry.get_vault_entries(limit=1000, user_id=int(getattr(self.session_context, "user_id", 0) or 0))
        similarities = [
            cosine_similarity(vector, list(item.get("feature_vector", [])))
            for item in existing
            if item.get("feature_vector")
        ]
        similarity_best = max(similarities) if similarities else 0.0

        payload = {
            "session_id": self.session_context.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": str(getattr(fingerprint, "source_type", "file")),
            "source_label": str(getattr(fingerprint, "source_label", "")),
            "file_hash": fingerprint.file_hash,
            "scan_hash": str(getattr(fingerprint, "scan_hash", "")),
            "verdict": fingerprint.verdict,
            "feature_vector": vector,
            "symmetry_score": float(fingerprint.symmetry_score),
            "coherence_score": float(getattr(fingerprint, "coherence_score", 0.0)),
            "resonance_score": float(getattr(fingerprint, "resonance_score", 0.0)),
            "ethics_score": float(getattr(fingerprint, "ethics_score", 0.0)),
            "observer_mutual_info": float(getattr(fingerprint, "observer_mutual_info", 0.0)),
            "observer_knowledge_ratio": float(getattr(fingerprint, "observer_knowledge_ratio", 0.0)),
            "h_lambda": float(getattr(fingerprint, "h_lambda", 0.0)),
            "observer_state": str(getattr(fingerprint, "observer_state", "OFFEN")),
            "similarity_best": float(similarity_best),
            "screen_vision": _compact_screen_payload(dict(getattr(fingerprint, "screen_vision_payload", {}) or {})),
            "file_profile": _compact_file_profile(dict(getattr(fingerprint, "file_profile", {}) or {})),
            "observer_payload": _compact_observer_payload(dict(getattr(fingerprint, "observer_payload", {}) or {})),
            "emergence_layers": _compact_emergence_layers(list(getattr(fingerprint, "emergence_layers", []) or [])),
            "self_reflection_delta": _compact_self_reflection_payload(
                dict(getattr(fingerprint, "self_reflection_delta", {}) or {}),
                include_internal=False,
            ),
        }
        signature = self.sign_payload(payload)
        self.registry.save_vault_entry(
            session_id=self.session_context.session_id,
            source_type=payload["source_type"],
            source_label=payload["source_label"],
            file_hash=payload["file_hash"],
            feature_vector=vector,
            similarity_best=float(similarity_best),
            cluster_label="TRANSITIONAL",
            payload=payload,
            signature=signature,
        )
        self.refresh_vault_clusters()
        return payload

    def refresh_vault_clusters(self) -> list[dict[str, Any]]:
        """Berechnet Clusterlabels fuer alle Vault-Eintraege neu."""
        entries = self.registry.get_vault_entries(limit=1000, user_id=int(getattr(self.session_context, "user_id", 0) or 0))
        vectors = [list(entry.get("feature_vector", [])) for entry in entries]
        labels = self._cluster_labels(vectors)
        for entry, label in zip(entries, labels):
            self.registry.update_vault_cluster(int(entry["id"]), label)
            entry["cluster_label"] = label
        return entries

    def vault_view(self) -> list[dict[str, Any]]:
        """Liefert Vault-Eintraege samt Similarity-Matches > 0.82."""
        entries = self.refresh_vault_clusters()
        vectors = [list(entry.get("feature_vector", [])) for entry in entries]
        for idx, entry in enumerate(entries):
            matches = []
            for other_idx, other in enumerate(entries):
                if idx == other_idx:
                    continue
                similarity = cosine_similarity(vectors[idx], vectors[other_idx])
                if similarity >= 0.82:
                    matches.append(
                        {
                            "label": str(other.get("source_label", other.get("file_hash", ""))),
                            "similarity": float(similarity),
                        }
                    )
            matches.sort(key=lambda item: item["similarity"], reverse=True)
            entry["matches"] = matches[:4]
        return entries

    def maybe_mint_chain_block(self, coherence: float, metrics_payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Mintet neue Session-Bloecke bei jedem erreichten 10%-Kohaerenz-Meilenstein."""
        milestone = int(max(0, min(10, math_floor_safe(coherence * 10.0))))
        minted: list[dict[str, Any]] = []
        for current in range(1, milestone + 1):
            if current in self._minted_milestones:
                continue
            payload = {
                "session_id": self.session_context.session_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "milestone": int(current),
                "coherence": float(coherence),
                "key_fingerprint": self.key_fingerprint,
                "metrics": metrics_payload,
            }
            payload["prev_hash"] = self.registry.next_prev_hash()
            payload["prevHash"] = str(payload["prev_hash"])
            block_hash = compute_chain_block_hash(payload)
            signature = self.sign_payload({"block_hash": block_hash, "payload": payload})
            self.registry.save_chain_block(
                session_id=self.session_context.session_id,
                milestone=int(current),
                coherence=float(coherence),
                key_fingerprint=self.key_fingerprint,
                block_hash=block_hash,
                payload=payload,
                signature=signature,
            )
            self._minted_milestones.add(current)
            minted.append({"block_hash": block_hash, "milestone": current, "signature": signature})
        return minted

    def verify_chain(self) -> list[VerifyRecord]:
        """Verifiziert gespeicherte Chain-Bloecke gegen Session und Signatur."""
        records: list[VerifyRecord] = []
        genesis = self.registry.get_genesis_block()
        if genesis is None or str(genesis.get("block_hash", "")) != GENESIS_HASH:
            records.append(
                VerifyRecord(
                    status="compromised",
                    session_id="GENESIS",
                    block_hash=str((genesis or {}).get("block_hash", ""))[:16],
                    milestone=0,
                    timestamp=str((genesis or {}).get("timestamp", "")),
                )
            )
            return records

        records.append(
            VerifyRecord(
                status="shared_root",
                session_id="GENESIS",
                block_hash=GENESIS_HASH[:16],
                milestone=0,
                timestamp=str(genesis.get("timestamp", "")),
            )
        )

        blocks = sorted(
            self.registry.get_chain_blocks_raw(
                limit=500,
                user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                include_genesis=False,
            ),
            key=lambda item: int(item.get("id", 0)),
        )
        previous_hash = GENESIS_HASH
        for block in blocks:
            if int(block.get("id", -1)) == 0:
                continue
            payload = block.get("payload_json", {})
            block_hash = str(block.get("block_hash", ""))
            prev_hash = str(payload.get("prev_hash", payload.get("prevHash", "")))
            expected_signature = self.sign_payload({"block_hash": block_hash, "payload": payload})
            direct_signature = self.sign_payload(payload)
            actual_signature = str(block.get("signature", ""))
            if prev_hash != previous_hash:
                status = "tampered"
            elif block_hash not in legacy_chain_block_hash_candidates(dict(payload)):
                status = "tampered"
            elif actual_signature not in {expected_signature, direct_signature}:
                status = "foreign" if str(block.get("session_id", "")) != self.session_context.session_id else "tampered"
            elif str(block.get("session_id", "")) != self.session_context.session_id:
                status = "foreign"
            else:
                status = "current"
            records.append(
                VerifyRecord(
                    status=status,
                    session_id=str(block.get("session_id", "")),
                    block_hash=block_hash[:16],
                    milestone=int(block.get("milestone", 0)),
                    timestamp=str(block.get("timestamp", "")),
                )
            )
            previous_hash = block_hash
        return records

    def record_delta_log(
        self,
        source_label: str,
        delta_ops: Sequence[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Speichert einen signierten Delta-Log."""
        payload = {
            "session_id": self.session_context.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_label": source_label,
            "ops": list(delta_ops),
        }
        if metadata:
            payload["metadata"] = dict(metadata)
        signature = self.sign_payload(payload)
        self.registry.save_delta_log(
            session_id=self.session_context.session_id,
            source_label=source_label,
            payload=payload,
            signature=signature,
        )

    def record_self_reflection_delta(
        self,
        source_label: str,
        reflection_payload: dict[str, Any] | None,
    ) -> None:
        """Persistiert lokale Self-Reflection-Deltas strikt internal-only in der Delta-Chain."""
        compact = _compact_self_reflection_payload(dict(reflection_payload or {}), include_internal=True)
        ttd_candidates = [dict(item) for item in list(compact.get("ttd_candidates", []) or []) if isinstance(item, dict)]
        delta_ops = [
            {
                "op": "self_reflection",
                "offset": 0,
                "length": int(len(json.dumps(compact, ensure_ascii=True))),
                "hash": str(hashlib.sha256(json.dumps(compact, ensure_ascii=True, sort_keys=True).encode("utf-8")).hexdigest()),
            }
        ]
        self.record_delta_log(
            source_label=str(source_label),
            delta_ops=delta_ops,
            metadata={
                "internal_only": True,
                "self_reflection_delta": compact,
                "scope": "local_only",
                "auto_export": False,
                "auto_export_candidate": bool(ttd_candidates),
                "ttd_candidate_count": int(len(ttd_candidates)),
            },
        )

    def build_peer_delta_share_bundle(
        self,
        source_label: str,
        reflection_payload: dict[str, Any] | None,
        *,
        scope: str = "public_only",
        shared_secret: str = "",
    ) -> dict[str, Any]:
        """Erzeugt ein signiertes Peer-Bundle fuer manuelles oder LAN-nahes Delta-Sharing."""
        normalized_scope = str(scope or "public_only").strip().lower()
        include_internal = normalized_scope == "all"
        compact_public = _compact_self_reflection_payload(dict(reflection_payload or {}), include_internal=False)
        bundle_payload: dict[str, Any] = {
            "kind": "aether_peer_delta_bundle",
            "session_id": str(self.session_context.session_id),
            "source_label": str(source_label or "shared_delta"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scope": normalized_scope,
            "public_anchors": [
                dict(item)
                for item in list(compact_public.get("ttd_candidates", []) or [])
            ],
            "public_metrics": {
                "delta_i_obs_percent": float(compact_public.get("delta_i_obs_percent", 0.0) or 0.0),
                "residual_after": float(compact_public.get("residual_after", 0.0) or 0.0),
                "stability_score": float(compact_public.get("stability_score", 0.0) or 0.0),
            },
            "self_reflection_public": compact_public,
        }
        if include_internal:
            internal_payload = _compact_self_reflection_payload(dict(reflection_payload or {}), include_internal=True)
            if shared_secret and crypto_available():
                secret_key = derive_fernet_key(f"{shared_secret}|{self.session_context.session_id}|peer_delta")
                token = encrypt_text(json.dumps(internal_payload, ensure_ascii=False, sort_keys=True), secret_key)
                bundle_payload["internal_payload_encrypted"] = True
                bundle_payload["internal_payload"] = str(token)
            else:
                bundle_payload["internal_payload_encrypted"] = False
                bundle_payload["internal_payload"] = internal_payload
        signature = self.sign_payload(bundle_payload)
        payload_hash = hashlib.sha256(_canonical_json(bundle_payload).encode("utf-8")).hexdigest()
        return {
            "payload": bundle_payload,
            "signature": signature,
            "payload_hash": payload_hash,
            "key_fingerprint": self.key_fingerprint,
        }

    def decode_peer_delta_share_bundle(
        self,
        bundle: dict[str, Any] | None,
        *,
        shared_secret: str = "",
    ) -> dict[str, Any]:
        """Entschluesselt und validiert ein importiertes Peer-Bundle fail-closed."""
        envelope = dict(bundle or {})
        payload = dict(envelope.get("payload", {}) or {})
        signature = str(envelope.get("signature", "") or "")
        payload_hash = str(envelope.get("payload_hash", "") or "")
        expected_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest() if payload else ""
        if not payload or payload_hash != expected_hash:
            return {}
        result = dict(payload)
        result["sender_signature"] = signature
        if bool(payload.get("internal_payload_encrypted", False)):
            token = str(payload.get("internal_payload", "") or "")
            if not token or not shared_secret or not crypto_available():
                return {}
            try:
                secret_key = derive_fernet_key(f"{shared_secret}|{self.session_context.session_id}|peer_delta")
                result["internal_payload"] = json.loads(decrypt_text(token, secret_key))
            except Exception:
                return {}
        return result

    def build_public_ttd_anchor_bundle(
        self,
        source_label: str,
        reflection_payload: dict[str, Any] | None,
        *,
        fingerprint: AetherFingerprint | None = None,
        scope: str = "metrics_only",
    ) -> dict[str, Any]:
        """Erzeugt ein metrics-only Bundle fuer stabile TTD-Anker ohne Rohdaten oder Deltas."""
        policy = public_ttd_share_policy(scope)
        if not bool(policy.get("share_public_anchor", False)):
            return {}
        quorum_policy = public_ttd_quorum_policy(self.session_context)
        compact = _compact_self_reflection_payload(dict(reflection_payload or {}), include_internal=False)
        candidates = [dict(item) for item in list(compact.get("ttd_candidates", []) or []) if isinstance(item, dict)]
        if not candidates:
            return {}
        candidate = dict(candidates[0] or {})
        fingerprint_payload = {
            "entropy_mean": float(getattr(fingerprint, "entropy_mean", 0.0) or 0.0),
            "observer_mutual_info": float(getattr(fingerprint, "observer_mutual_info", 0.0) or 0.0),
            "observer_knowledge_ratio": float(getattr(fingerprint, "observer_knowledge_ratio", 0.0) or 0.0),
            "boundary": str(getattr(fingerprint, "boundary", "") or ""),
            "anomaly_count": int(len(list(getattr(fingerprint, "anomaly_coordinates", []) or []))),
            "reconstruction_verification": dict(getattr(fingerprint, "reconstruction_verification", {}) or {}),
            "source_label": str(getattr(fingerprint, "source_label", "") or source_label or ""),
            "scan_hash": str(getattr(fingerprint, "scan_hash", "") or ""),
            "file_hash": str(getattr(fingerprint, "file_hash", "") or ""),
        } if fingerprint is not None else {"source_label": str(source_label or "")}
        validation = validate_public_ttd_candidate(
            candidate,
            fingerprint_payload=fingerprint_payload,
            reflection_payload=compact,
        )
        if not bool(validation.get("valid", False)):
            return {
                "valid": False,
                "validation": dict(validation),
            }
        metrics = dict(validation.get("metrics", {}) or {})
        payload = {
            "schema": "aether.public_ttd_anchor.v1",
            "kind": "public_ttd_anchor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_label": str(source_label or fingerprint_payload.get("source_label", "") or "ttd_anchor"),
            "ttd_hash": str(candidate.get("hash", "") or ""),
            "public_metrics": {
                "residual": round(float(metrics.get("residual", 0.0) or 0.0), 12),
                "symmetry": round(float(metrics.get("symmetry", 0.0) or 0.0), 12),
                "i_obs_ratio": round(float(metrics.get("i_obs_ratio", 0.0) or 0.0), 12),
                "delta_stability": round(float(metrics.get("delta_stability", 0.0) or 0.0), 12),
                "delta_i_obs_percent": round(float(dict(candidate.get("public_metrics", {}) or {}).get("delta_i_obs_percent", 0.0) or 0.0), 12),
                "recursive_count": int(metrics.get("recursive_count", 0) or 0),
            },
            "pseudonym": pseudonymous_network_identity(self.session_context, purpose="public_ttd_anchor"),
            "uploader_role": str(quorum_policy.get("uploader_role", "operator")),
            "quorum_threshold": int(quorum_policy.get("quorum_threshold", 3) or 3),
            "auto_trusted": bool(quorum_policy.get("auto_trusted", False)),
            "transport_hint": "ipfs_libp2p_bundle",
            "raw_data_included": False,
            "deltas_included": False,
            "internal_only": False,
        }
        signature = self.sign_payload(payload) if bool(policy.get("share_signature", False)) else ""
        envelope = {
            "payload": payload,
            "payload_hash": hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest(),
            "signature": signature,
            "signature_included": bool(signature),
            "validation": dict(validation),
        }
        return envelope

    def _read_public_ttd_history_envelopes(self, target_dir: Path) -> list[dict[str, Any]]:
        """Laedt alle lokalen Public-TTD-History-Eintraege fail-closed."""
        history_dir = target_dir / "history"
        if not history_dir.is_dir():
            return []
        envelopes: list[dict[str, Any]] = []
        for path in sorted(history_dir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(payload, dict):
                envelopes.append(dict(payload))
        return envelopes

    def append_public_ttd_anchor_bundle(
        self,
        bundle: dict[str, Any] | None,
        *,
        directory: str | None = None,
    ) -> dict[str, Any]:
        """Speichert oeffentliche TTD-Anker append-only in einen lokalen Public-Pool."""
        envelope = dict(bundle or {})
        payload = dict(envelope.get("payload", {}) or {})
        payload_hash = str(envelope.get("payload_hash", "") or "")
        expected_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest() if payload else ""
        if not payload or payload_hash != expected_hash:
            return {"stored": False, "reason": "invalid_payload_hash", "bundle_path": "", "latest_path": ""}
        target_dir = Path(directory) if directory is not None else Path("data") / "public_ttd_anchor_pool"
        history_dir = target_dir / "history"
        target_dir.mkdir(parents=True, exist_ok=True)
        history_dir.mkdir(parents=True, exist_ok=True)
        latest_path = target_dir / "latest.json"
        history_path = history_dir / f"ttd_anchor_{str(payload.get('timestamp', '')).replace(':', '').replace('-', '')[:15]}_{payload_hash[:12]}.json"
        current_summary = self.load_public_ttd_anchor_bundle(directory=str(target_dir))
        current_records = [dict(item) for item in list(current_summary.get("anchor_records", []) or []) if isinstance(item, dict)]
        existing_record = next(
            (
                dict(item)
                for item in current_records
                if str(item.get("ttd_hash", "") or "") == str(payload.get("ttd_hash", "") or "")
            ),
            {},
        )
        if existing_record and public_ttd_validator_present(existing_record, str(payload.get("pseudonym", "") or "")):
            return {
                "stored": False,
                "already_present": True,
                "bundle_path": str(history_path),
                "latest_path": str(latest_path),
                "public_anchor_count": int(current_summary.get("trusted_anchor_count", 0) or 0),
                "candidate_anchor_count": int(current_summary.get("candidate_anchor_count", 0) or 0),
                "record": existing_record,
            }
        history_path.write_text(json.dumps(envelope, ensure_ascii=True, indent=2), encoding="utf-8")
        latest_wrapper = self.load_public_ttd_anchor_bundle(directory=str(target_dir))
        latest_path.write_text(json.dumps(latest_wrapper, ensure_ascii=True, indent=2), encoding="utf-8")
        updated_record = next(
            (
                dict(item)
                for item in list(latest_wrapper.get("anchor_records", []) or [])
                if str(item.get("ttd_hash", "") or "") == str(payload.get("ttd_hash", "") or "")
            ),
            build_public_ttd_anchor_record(payload, signature_included=bool(envelope.get("signature_included", False))),
        )
        return {
            "stored": True,
            "bundle_path": str(history_path),
            "latest_path": str(latest_path),
            "public_anchor_count": int(latest_wrapper.get("trusted_anchor_count", 0) or 0),
            "candidate_anchor_count": int(latest_wrapper.get("candidate_anchor_count", 0) or 0),
            "quorum_validated_count": int(latest_wrapper.get("quorum_validated_count", 0) or 0),
            "admin_trusted_count": int(latest_wrapper.get("admin_trusted_count", 0) or 0),
            "ttd_hash": str(payload.get("ttd_hash", "") or ""),
            "record": updated_record,
        }

    def load_public_ttd_anchor_bundle(self, directory: str | None = None) -> dict[str, Any]:
        """Laedt den lokalen Public-TTD-Pool fail-closed fuer Observer-Lernen."""
        target_dir = Path(directory) if directory is not None else Path("data") / "public_ttd_anchor_pool"
        latest_path = target_dir / "latest.json"
        history_envelopes = self._read_public_ttd_history_envelopes(target_dir)
        if history_envelopes:
            records_by_hash: dict[str, dict[str, Any]] = {}
            for envelope in history_envelopes:
                payload = dict(envelope.get("payload", {}) or {})
                payload_hash = str(envelope.get("payload_hash", "") or "")
                expected_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest() if payload else ""
                if not payload or payload_hash != expected_hash:
                    continue
                if str(payload.get("schema", "") or "") != "aether.public_ttd_anchor.v1":
                    continue
                ttd_hash = str(payload.get("ttd_hash", "") or "")
                if not ttd_hash:
                    continue
                signature_included = bool(envelope.get("signature_included", False))
                existing = records_by_hash.get(ttd_hash)
                if existing is None:
                    records_by_hash[ttd_hash] = build_public_ttd_anchor_record(
                        payload,
                        signature_included=signature_included,
                    )
                else:
                    records_by_hash[ttd_hash] = merge_public_ttd_anchor_record(
                        existing,
                        payload,
                        signature_included=signature_included,
                    )
            summary = summarize_public_ttd_anchor_records(list(records_by_hash.values()))
            try:
                latest_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
            except Exception:
                pass
            return summary
        if not latest_path.is_file():
            return {
                "schema": "aether.public_ttd_anchor.pool.v2",
                "public_anchors": [],
                "trusted_anchor_count": 0,
                "candidate_anchor_count": 0,
                "anchor_records": [],
            }
        try:
            payload = json.loads(latest_path.read_text(encoding="utf-8"))
        except Exception:
            return {
                "schema": "aether.public_ttd_anchor.pool.v2",
                "public_anchors": [],
                "trusted_anchor_count": 0,
                "candidate_anchor_count": 0,
                "anchor_records": [],
            }
        if str(payload.get("schema", "") or "") == "aether.public_ttd_anchor.pool.v2":
            return {
                "schema": "aether.public_ttd_anchor.pool.v2",
                "updated_at": str(payload.get("updated_at", "") or ""),
                "anchor_records": [dict(item) for item in list(payload.get("anchor_records", []) or []) if isinstance(item, dict)],
                "anchor_record_count": int(payload.get("anchor_record_count", 0) or 0),
                "public_anchors": [dict(item) for item in list(payload.get("public_anchors", []) or []) if isinstance(item, dict)],
                "trusted_anchor_count": int(payload.get("trusted_anchor_count", 0) or 0),
                "candidate_anchors": [dict(item) for item in list(payload.get("candidate_anchors", []) or []) if isinstance(item, dict)],
                "candidate_anchor_count": int(payload.get("candidate_anchor_count", 0) or 0),
                "quorum_validated_count": int(payload.get("quorum_validated_count", 0) or 0),
                "admin_trusted_count": int(payload.get("admin_trusted_count", 0) or 0),
            }
        legacy_anchors = [dict(item) for item in list(payload.get("public_anchors", []) or []) if isinstance(item, dict)]
        legacy_records = []
        for item in legacy_anchors:
            legacy_record = build_public_ttd_anchor_record(
                {
                    **public_ttd_anchor_view(
                        {
                            "ttd_hash": str(item.get("ttd_hash", item.get("hash", "")) or ""),
                            "source_label": str(item.get("source_label", "") or ""),
                            "public_metrics": dict(item.get("public_metrics", {}) or {}),
                            "uploader_role": str(item.get("uploader_role", "admin") or "admin"),
                            "pseudonym": str(item.get("pseudonym", "LEGACY") or "LEGACY"),
                        }
                    ),
                    "timestamp": str(payload.get("updated_at", "") or datetime.now(timezone.utc).isoformat()),
                    "uploader_role": str(item.get("uploader_role", "admin") or "admin"),
                    "pseudonym": str(item.get("pseudonym", "LEGACY") or "LEGACY"),
                    "ttd_hash": str(item.get("ttd_hash", item.get("hash", "")) or ""),
                    "source_label": str(item.get("source_label", "") or ""),
                    "public_metrics": dict(item.get("public_metrics", {}) or {}),
                },
                signature_included=bool(item.get("signature_included", False)),
            )
            legacy_record["quorum_met"] = True
            legacy_record["trust_state"] = "trusted"
            legacy_record["trust_reason"] = "legacy_trusted"
            legacy_records.append(legacy_record)
        summary = summarize_public_ttd_anchor_records(legacy_records)
        try:
            latest_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
        except Exception:
            pass
        return summary

    def export_signed_json(self, kind: str, file_path: str) -> int:
        """Exportiert Vault- oder Delta-Daten als signiertes JSON."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if kind == "vault":
            payload = {
                "key_fingerprint": self.key_fingerprint,
                "records": self.registry.get_vault_entries(
                    limit=1000,
                    user_id=int(getattr(self.session_context, "user_id", 0) or 0),
                ),
            }
        elif kind == "delta":
            payload = {
                "key_fingerprint": self.key_fingerprint,
                "records": self.registry.get_delta_logs(session_id=self.session_context.session_id, limit=5000),
            }
        else:
            raise ValueError("Unbekannter Exporttyp.")
        envelope = {
            "kind": kind,
            "session_id": self.session_context.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
            "signature": self.sign_payload(payload),
        }
        path.write_text(json.dumps(envelope, ensure_ascii=True, indent=2), encoding="utf-8")
        return len(payload["records"])

    def record_alarm(self, reason: str, severity: str, payload: dict[str, Any]) -> None:
        """Persistiert einen Alarmvorfall fuer die Header-Anzeige."""
        self.registry.save_alarm_event(
            session_id=self.session_context.session_id,
            reason=reason,
            severity=severity,
            payload=payload,
        )

    def alarm_count(self) -> int:
        """Liefert die gespeicherte Alarmanzahl der laufenden Session."""
        return self.registry.get_alarm_count(session_id=self.session_context.session_id)


def math_floor_safe(value: float) -> int:
    """Berechnet den Bodenwert fuer positive und negative Floats robust."""
    return int(np.floor(float(value)))
