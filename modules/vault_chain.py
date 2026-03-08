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
from .observer_engine import AnchorPoint
from .registry import GENESIS_HASH, compute_chain_block_hash, legacy_chain_block_hash_candidates
from .session_engine import SessionContext


def _canonical_json(payload: Any) -> str:
    """Serialisiert Payloads deterministisch fuer Signaturen."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


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
            "verdict": fingerprint.verdict,
            "feature_vector": vector,
            "symmetry_score": float(fingerprint.symmetry_score),
            "coherence_score": float(getattr(fingerprint, "coherence_score", 0.0)),
            "resonance_score": float(getattr(fingerprint, "resonance_score", 0.0)),
            "ethics_score": float(getattr(fingerprint, "ethics_score", 0.0)),
            "similarity_best": float(similarity_best),
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
