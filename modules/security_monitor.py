"""Deterministische lokale Sicherheits- und Trust-Ueberwachung fuer Aether."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .registry import (
    GENESIS_HASH,
    canonical_json,
    legacy_chain_block_hash_candidates,
)


@dataclass
class SecuritySnapshot:
    """Verdichteter Sicherheitszustand einer lokalen Node."""

    node_id: str
    baseline_node_id: str
    mode: str
    trust_state: str
    maze_state: str
    summary: str
    findings: list[dict[str, Any]]
    policy: dict[str, Any]
    self_metrics: dict[str, Any]
    checked_at: str

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert den Snapshot fuer Session-Weitergabe."""
        return {
            "node_id": str(self.node_id),
            "baseline_node_id": str(self.baseline_node_id),
            "mode": str(self.mode),
            "trust_state": str(self.trust_state),
            "maze_state": str(self.maze_state),
            "summary": str(self.summary),
            "findings": [dict(item) for item in self.findings],
            "policy": dict(self.policy),
            "self_metrics": dict(self.self_metrics),
            "checked_at": str(self.checked_at),
        }


class AetherSecurityMonitor:
    """Prueft lokale Integritaet, Trust und Maze-Modi rein defensiv."""

    NODE_FILES = {
        "entrypoint": "start.py",
        "analysis_engine": "modules/analysis_engine.py",
        "observer_engine": "modules/observer_engine.py",
        "evolved_language": "modules/evolved_language.py",
        "registry": "modules/registry.py",
        "security_engine": "modules/security_engine.py",
        "session_engine": "modules/session_engine.py",
        "security_monitor": "modules/security_monitor.py",
        "ae_evolution_core": "modules/ae_evolution_core.py",
    }
    STATIC_CONFIG = "data/security_static.json"
    HONEYPOT_RULES = (
        {"name": "sentinel_alpha", "rule": "NEVER_LOAD::SC-LIFE::ALPHA", "kind": "honeypot_rule"},
        {"name": "sentinel_beta", "rule": "NEVER_EXPORT::GP::BETA", "kind": "honeypot_rule"},
    )

    def __init__(self, project_root: str | Path, registry) -> None:
        self.project_root = Path(project_root)
        self.registry = registry
        self.language_state_path = self.project_root / "data" / "evolved_language.json"

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _sha256_file(self, path: Path) -> str:
        if not path.is_file():
            return hashlib.sha256(f"missing:{path.as_posix()}".encode("utf-8")).hexdigest()
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _static_config_hash(self) -> str:
        path = self.project_root / self.STATIC_CONFIG
        if not path.is_file():
            return hashlib.sha256(b"missing:security_static").hexdigest()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            payload = path.read_text(encoding="utf-8", errors="replace")
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def _schema_hash(self) -> str:
        rows = self.registry.connection.execute(
            """
            SELECT name, sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name IN (
                  'fingerprints', 'raw_storage_blobs', 'chain_blocks', 'chain_block_annotations',
                  'vault_entries', 'delta_logs', 'export_log', 'security_events',
                  'gp_rule_snapshots', 'node_identity', 'users', 'app_sessions'
              )
            ORDER BY name ASC
            """
        ).fetchall()
        payload = {
            str(row["name"]): str(row["sql"] or "")
            for row in rows
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def build_manifest(self) -> dict[str, Any]:
        """Erzeugt den deterministischen Node-Manifestzustand."""
        file_hashes = {
            label: self._sha256_file(self.project_root / relative)
            for label, relative in self.NODE_FILES.items()
        }
        manifest = {
            "files": file_hashes,
            "schema_hash": self._schema_hash(),
            "config_hash": self._static_config_hash(),
        }
        return manifest

    def compute_node_id(self, manifest: dict[str, Any] | None = None) -> str:
        """Leitet eine deterministische Node-ID aus Code, Schema und statischer Konfiguration ab."""
        active_manifest = dict(manifest or self.build_manifest())
        material = [
            str(active_manifest.get("files", {}).get(label, ""))
            for label in sorted(self.NODE_FILES)
        ]
        material.append(str(active_manifest.get("schema_hash", "")))
        material.append(str(active_manifest.get("config_hash", "")))
        return hashlib.sha256("|".join(material).encode("utf-8")).hexdigest()

    def sign_payload(self, payload: dict[str, Any], key_material: str) -> str:
        """Signiert lokale Sicherheits- und GP-Payloads deterministisch mit der Node-ID."""
        key = hashlib.sha256(f"{key_material}|AETHER_SECURITY".encode("utf-8")).digest()
        return hmac.new(key, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _gp_rule_hash_candidates(payload: dict[str, Any]) -> set[str]:
        """Akzeptiert kanonische und fruehere legacy-Hashes fuer bestehende GP-Snapshots."""
        legacy_json = json.dumps(payload, ensure_ascii=False)
        return {
            hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
            hashlib.sha256(legacy_json.encode("utf-8")).hexdigest(),
        }

    def _finding(
        self,
        event_type: str,
        severity: str,
        message: str,
        **details: Any,
    ) -> dict[str, Any]:
        return {
            "event_type": str(event_type),
            "severity": str(severity),
            "message": str(message),
            "details": dict(details),
        }

    def _check_chain_integrity(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        genesis = self.registry.get_genesis_block()
        if genesis is None or str(genesis.get("block_hash", "")) != GENESIS_HASH:
            findings.append(
                self._finding(
                    "CHAIN_CORRUPT",
                    "critical",
                    "Genesis-Block fehlt oder stimmt nicht mit dem gemeinsamen Root ueberein.",
                )
            )
            return findings

        previous_hash = GENESIS_HASH
        blocks = sorted(
            self.registry.get_chain_blocks_raw(limit=5000, include_genesis=False),
            key=lambda item: int(item.get("id", 0)),
        )
        corrupt_count = 0
        for block in blocks:
            if int(block.get("id", -1)) == 0:
                continue
            payload = dict(block.get("payload_json", {}))
            prev_hash = str(payload.get("prev_hash", payload.get("prevHash", "")))
            block_hash = str(block.get("block_hash", ""))
            if prev_hash != previous_hash:
                corrupt_count += 1
                findings.append(
                    self._finding(
                        "CHAIN_CORRUPT",
                        "critical",
                        "Die Chain-Verkettung ist inkonsistent.",
                        block_id=int(block.get("id", 0)),
                        expected_prev_hash=previous_hash,
                        actual_prev_hash=prev_hash,
                    )
                )
            if block_hash not in legacy_chain_block_hash_candidates(payload):
                corrupt_count += 1
                findings.append(
                    self._finding(
                        "CHAIN_CORRUPT",
                        "critical",
                        "Der Block-Hash passt nicht zum serialisierten Payload.",
                        block_id=int(block.get("id", 0)),
                        block_hash=block_hash,
                    )
                )
            merkle_root = str(payload.get("merkle_root", "")).strip()
            if merkle_root and not re.fullmatch(r"[0-9a-f]{64}", merkle_root):
                findings.append(
                    self._finding(
                        "CHAIN_CORRUPT",
                        "warning",
                        "Ein Block traegt einen unplausiblen Merkle-Root.",
                        block_id=int(block.get("id", 0)),
                        merkle_root=merkle_root,
                    )
                )
            previous_hash = block_hash or previous_hash
        if corrupt_count <= 0 and blocks:
            findings.append(
                self._finding(
                    "CHAIN_OK",
                    "info",
                    f"Chain konsistent ueber {len(blocks)} lokale Bloecke.",
                )
            )
        return findings

    def _check_vault_integrity(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        rows = self.registry.connection.execute(
            """
            SELECT id, source_type, source_label, file_hash, payload_json
            FROM fingerprints
            ORDER BY id DESC
            LIMIT 24
            """
        ).fetchall()
        if not rows:
            return findings

        mismatches = 0
        verified = 0
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            anchor_count = int(payload.get("anchor_count", 0) or 0)
            if anchor_count < 0:
                mismatches += 1
            if str(row["source_type"]) == "file":
                try:
                    reconstructed = self.registry.reconstruct_original(int(row["id"]), session_context=None, prefer_raw=False)
                except Exception:
                    reconstructed = b""
                if not reconstructed or hashlib.sha256(reconstructed).hexdigest() != str(row["file_hash"]):
                    mismatches += 1
                else:
                    verified += 1
        if mismatches >= 3:
            findings.append(
                self._finding(
                    "VAULT_INCONSISTENT",
                    "critical",
                    "Mehrere Vault-/Fingerprint-Eintraege lassen sich nicht sauber verifizieren.",
                    verified=verified,
                    mismatches=mismatches,
                )
            )
        elif mismatches > 0:
            findings.append(
                self._finding(
                    "VAULT_INCONSISTENT",
                    "warning",
                    "Es gibt einzelne Inkonsistenzen in Vault-/Fingerprint-Daten.",
                    verified=verified,
                    mismatches=mismatches,
                )
            )
        else:
            findings.append(
                self._finding(
                    "VAULT_OK",
                    "info",
                    f"Vault-/Fingerprint-Stichprobe konsistent ({verified} verifiziert).",
                )
            )
        return findings

    def _validate_language_state(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not self.language_state_path.is_file():
            return findings
        try:
            state = json.loads(self.language_state_path.read_text(encoding="utf-8"))
        except Exception:
            return [
                self._finding(
                    "GP_RULE_TAMPERED",
                    "critical",
                    "Der Sprach-GP-Zustand ist nicht mehr als JSON lesbar.",
                    path=str(self.language_state_path),
                )
            ]
        if not isinstance(state, dict):
            return [
                self._finding(
                    "GP_RULE_TAMPERED",
                    "critical",
                    "Der Sprach-GP-Zustand besitzt keine gueltige Struktur.",
                    path=str(self.language_state_path),
                )
            ]
        for key in ("population", "top", "events"):
            value = state.get(key, [])
            if not isinstance(value, list):
                findings.append(
                    self._finding(
                        "GP_RULE_TAMPERED",
                        "warning",
                        "Der Sprach-GP-Zustand enthaelt ein unplausibles Feld.",
                        field=key,
                    )
                )
        return findings

    def _ensure_gp_honeypots(self, baseline_key: str, existing_node: bool) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        snapshots = self.registry.get_gp_rule_snapshots(limit=64, scope="security", include_honeypots=True)
        existing_honeypots = [item for item in snapshots if bool(item.get("is_honeypot", False))]
        existing_payloads = {
            canonical_json(dict(item.get("payload_json", {})))
            for item in existing_honeypots
            if isinstance(item.get("payload_json", {}), dict)
        }
        expected_payloads = {canonical_json(payload) for payload in self.HONEYPOT_RULES}
        missing_payloads = expected_payloads - existing_payloads
        if missing_payloads and existing_node:
            findings.append(
                self._finding(
                    "HONEYPOT_TRIGGERED",
                    "critical",
                    "Mindestens ein GP-Honeypot fehlt oder wurde ueberschrieben.",
                    missing=len(missing_payloads),
                )
            )
        for snapshot in existing_honeypots:
            payload = dict(snapshot.get("payload_json", {}))
            if str(snapshot.get("rule_hash", "")) not in self._gp_rule_hash_candidates(payload):
                findings.append(
                    self._finding(
                        "HONEYPOT_TRIGGERED",
                        "critical",
                        "Ein GP-Honeypot traegt einen ungueltigen Hash.",
                        snapshot_id=int(snapshot.get("id", 0)),
                    )
                )
            signature = str(snapshot.get("signature", "")).strip()
            if signature and signature != self.sign_payload(payload, baseline_key):
                findings.append(
                    self._finding(
                        "HONEYPOT_TRIGGERED",
                        "critical",
                        "Ein GP-Honeypot traegt eine ungueltige Signatur.",
                        snapshot_id=int(snapshot.get("id", 0)),
                    )
                )
        for payload in self.HONEYPOT_RULES:
            payload_key = canonical_json(payload)
            if payload_key in existing_payloads:
                continue
            self.registry.save_gp_rule_snapshot(
                session_id="SYSTEM",
                scope="security",
                rule_type="honeypot",
                payload=payload,
                signature=self.sign_payload(payload, baseline_key),
                version=1,
                is_honeypot=True,
            )
        return findings

    def _check_gp_integrity(self, baseline_key: str, existing_node: bool) -> list[dict[str, Any]]:
        findings = self._ensure_gp_honeypots(baseline_key=baseline_key, existing_node=existing_node)
        findings.extend(self._validate_language_state())

        snapshots = self.registry.get_gp_rule_snapshots(limit=24, include_honeypots=False)
        for snapshot in snapshots:
            payload = dict(snapshot.get("payload_json", {}))
            if not isinstance(payload, dict):
                findings.append(
                    self._finding(
                        "GP_RULE_TAMPERED",
                        "critical",
                        "Ein GP-Snapshot besitzt keinen lesbaren Payload.",
                        snapshot_id=int(snapshot.get("id", 0)),
                    )
                )
                continue
            if str(snapshot.get("rule_hash", "")) not in self._gp_rule_hash_candidates(payload):
                findings.append(
                    self._finding(
                        "GP_RULE_TAMPERED",
                        "critical",
                        "Der gespeicherte GP-Hash passt nicht zum Payload.",
                        snapshot_id=int(snapshot.get("id", 0)),
                    )
                )
            signature = str(snapshot.get("signature", "")).strip()
            if signature and signature != self.sign_payload(payload, baseline_key):
                findings.append(
                    self._finding(
                        "GP_RULE_TAMPERED",
                        "warning",
                        "Ein GP-Snapshot traegt eine ungueltige Signatur.",
                        snapshot_id=int(snapshot.get("id", 0)),
                    )
                )
            if "rules" in payload and not isinstance(payload.get("rules"), list):
                findings.append(
                    self._finding(
                        "GP_RULE_TAMPERED",
                        "warning",
                        "Ein GP-Snapshot enthaelt keine plausible Regelliste.",
                        snapshot_id=int(snapshot.get("id", 0)),
                    )
                )
        return findings

    def _build_self_metrics(self) -> dict[str, Any]:
        fingerprint_row = self.registry.connection.execute(
            """
            SELECT COUNT(*) AS samples,
                   AVG(entropy_mean) AS avg_entropy,
                   AVG(coherence_score) AS avg_coherence,
                   AVG(CAST(json_extract(payload_json, '$.h_lambda') AS REAL)) AS avg_h_lambda
            FROM fingerprints
            """
        ).fetchone()
        chain_row = self.registry.connection.execute(
            """
            SELECT COUNT(*) AS blocks
            FROM chain_blocks
            WHERE id != 0
            """
        ).fetchone()
        alarm_row = self.registry.connection.execute(
            "SELECT COUNT(*) AS alarms FROM alarm_events"
        ).fetchone()
        confirmed_lossless = 0
        for block in self.registry.get_chain_blocks(limit=2000, include_genesis=False):
            if bool(dict(block.get("payload_json", {})).get("confirmed_lossless", False)):
                confirmed_lossless += 1
        return {
            "files": int(fingerprint_row["samples"] or 0) if fingerprint_row is not None else 0,
            "avg_entropy": float(fingerprint_row["avg_entropy"] or 0.0) if fingerprint_row is not None else 0.0,
            "avg_coherence": float(fingerprint_row["avg_coherence"] or 0.0) if fingerprint_row is not None else 0.0,
            "avg_h_lambda": float(fingerprint_row["avg_h_lambda"] or 0.0) if fingerprint_row is not None else 0.0,
            "chain_blocks": int(chain_row["blocks"] or 0) if chain_row is not None else 0,
            "alarms": int(alarm_row["alarms"] or 0) if alarm_row is not None else 0,
            "confirmed_lossless": int(confirmed_lossless),
        }

    def _derive_trust_and_maze(
        self,
        findings: list[dict[str, Any]],
        mode: str,
        previous: dict[str, Any] | None,
    ) -> tuple[str, str, str]:
        critical = [item for item in findings if str(item.get("severity")) == "critical"]
        warnings = [item for item in findings if str(item.get("severity")) == "warning"]
        only_node_tamper = (
            len(critical) == 1
            and str(critical[0].get("event_type")) == "NODE_TAMPER_DETECTED"
            and not warnings
        )
        if critical:
            trust_state = "SUSPECT" if mode == "DEV" and only_node_tamper else "UNTRUSTED"
        elif warnings:
            trust_state = "SUSPECT"
        else:
            trust_state = "TRUSTED"

        active_mode = str(mode or "PROD").upper()
        previous_untrusted = int((previous or {}).get("untrusted_count", 0) or 0)
        if trust_state == "TRUSTED":
            maze_state = "NONE"
        elif active_mode != "PROD":
            maze_state = "SOFT"
        elif trust_state == "SUSPECT":
            maze_state = "SOFT"
        elif previous_untrusted >= 2 or len(critical) >= 3:
            maze_state = "DEAD"
        else:
            maze_state = "HARD"

        if critical:
            reason = str(critical[0].get("message", "Kritische Integritaetsabweichung"))
        elif warnings:
            reason = str(warnings[0].get("message", "Lokale Unsicherheit erkannt"))
        else:
            reason = "Node und lokale Wissensbasis sind strukturell konsistent."
        return trust_state, maze_state, reason

    def _requires_fail_closed(self, findings: list[dict[str, Any]], mode: str) -> bool:
        """Erzwingt bei Kern-Tamper im PROD-Modus einen klaren Start-Lock statt Restbetrieb."""
        if str(mode or "PROD").upper() != "PROD":
            return False
        critical_types = {
            "NODE_TAMPER_DETECTED",
            "CHAIN_CORRUPT",
            "VAULT_INCONSISTENT",
            "GP_RULE_TAMPERED",
        }
        for finding in findings:
            if str(finding.get("severity", "")).lower() != "critical":
                continue
            if str(finding.get("event_type", "")).upper() in critical_types:
                return True
        return False

    def _build_policy(self, trust_state: str, maze_state: str, mode: str, fail_closed: bool = False) -> dict[str, Any]:
        active_mode = str(mode or "PROD").upper()
        delay_scale = {"NONE": 1.0, "SOFT": 1.45, "HARD": 2.1, "DEAD": 3.0}
        confidence_scale = {"NONE": 1.0, "SOFT": 0.85, "HARD": 0.55, "DEAD": 0.2}
        if active_mode != "PROD":
            return {
                "allow_analysis": True,
                "allow_chain_append": True,
                "allow_public_anchor": False,
                "allow_export_confirmed": True,
                "allow_remote_submission": False,
                "allow_gp_evolution": True,
                "allow_gp_snapshots": True,
                "allow_cluster_persist": True,
                "allow_semantic_promotion": True,
                "dummy_cluster_mode": False,
                "reduce_sc_life": False,
                "suppress_lossless_confirmation": False,
                "force_local_exports_only": True,
                "maze_delay_scale": 1.0,
                "maze_confidence_scale": 1.0,
                "fail_closed_lock": False,
            }
        if fail_closed:
            return {
                "allow_analysis": False,
                "allow_chain_append": False,
                "allow_public_anchor": False,
                "allow_export_confirmed": False,
                "allow_remote_submission": False,
                "allow_gp_evolution": False,
                "allow_gp_snapshots": False,
                "allow_cluster_persist": False,
                "allow_semantic_promotion": False,
                "dummy_cluster_mode": True,
                "reduce_sc_life": True,
                "suppress_lossless_confirmation": True,
                "force_local_exports_only": True,
                "maze_delay_scale": float(delay_scale.get("DEAD", 3.0)),
                "maze_confidence_scale": float(confidence_scale.get("DEAD", 0.2)),
                "fail_closed_lock": True,
            }
        return {
            "allow_analysis": True,
            "allow_chain_append": trust_state != "UNTRUSTED",
            "allow_public_anchor": trust_state == "TRUSTED" and active_mode == "PROD",
            "allow_export_confirmed": trust_state == "TRUSTED" and maze_state == "NONE" and active_mode == "PROD",
            "allow_remote_submission": trust_state == "TRUSTED" and active_mode == "PROD",
            "allow_gp_evolution": trust_state == "TRUSTED" and active_mode == "PROD",
            "allow_gp_snapshots": maze_state != "DEAD",
            "allow_cluster_persist": maze_state not in {"HARD", "DEAD"},
            "allow_semantic_promotion": trust_state != "UNTRUSTED",
            "dummy_cluster_mode": maze_state == "HARD",
            "reduce_sc_life": trust_state != "TRUSTED",
            "suppress_lossless_confirmation": trust_state == "UNTRUSTED",
            "force_local_exports_only": trust_state != "TRUSTED" or active_mode != "PROD",
            "maze_delay_scale": float(delay_scale.get(maze_state, 1.0)),
            "maze_confidence_scale": float(confidence_scale.get(maze_state, 1.0)),
            "fail_closed_lock": False,
        }

    def _build_summary(
        self,
        *,
        mode: str,
        trust_state: str,
        maze_state: str,
        reason: str,
        self_metrics: dict[str, Any],
    ) -> str:
        return (
            f"{mode} | {trust_state} | Maze {maze_state} | "
            f"Dateien {int(self_metrics.get('files', 0) or 0)} | "
            f"Blocks {int(self_metrics.get('chain_blocks', 0) or 0)} | "
            f"Lossless {int(self_metrics.get('confirmed_lossless', 0) or 0)} | "
            f"{reason}"
        )

    def run_integrity_check(
        self,
        *,
        session_context: Any | None = None,
        mode: str = "PROD",
    ) -> SecuritySnapshot:
        """Fuehrt alle lokalen Sicherheitspruefungen aus und aktualisiert den Node-Zustand."""
        active_mode = str(mode or "PROD").upper()
        existing = self.registry.get_node_identity()
        manifest = self.build_manifest()
        current_node_id = self.compute_node_id(manifest)
        baseline_node_id = str((existing or {}).get("baseline_node_id", "") or current_node_id)
        findings: list[dict[str, Any]] = []

        if existing is None:
            self.registry.save_security_event(
                user_id=int(getattr(session_context, "user_id", 0) or 0),
                username=str(getattr(session_context, "username", "")),
                event_type="NODE_INIT",
                severity="info",
                payload={"node_id": current_node_id, "mode": active_mode},
            )
        elif baseline_node_id != current_node_id:
            findings.append(
                self._finding(
                    "NODE_TAMPER_DETECTED",
                    "critical",
                    "Die aktuelle Node-ID weicht vom gespeicherten Basiszustand ab.",
                    baseline_node_id=baseline_node_id,
                    current_node_id=current_node_id,
                )
            )

        findings.extend(self._check_chain_integrity())
        findings.extend(self._check_vault_integrity())
        findings.extend(self._check_gp_integrity(baseline_key=baseline_node_id, existing_node=existing is not None))
        self_metrics = self._build_self_metrics()
        trust_state, maze_state, reason = self._derive_trust_and_maze(findings, active_mode, existing)
        fail_closed = self._requires_fail_closed(findings, active_mode)
        policy = self._build_policy(trust_state, maze_state, active_mode, fail_closed=fail_closed)
        summary = self._build_summary(
            mode=active_mode,
            trust_state=trust_state,
            maze_state=maze_state,
            reason=("Start-Lock aktiv. " + reason) if fail_closed else reason,
            self_metrics=self_metrics,
        )
        checked_at = self._now_iso()

        tamper_count = int((existing or {}).get("tamper_count", 0) or 0)
        if any(str(item.get("event_type")) == "NODE_TAMPER_DETECTED" for item in findings):
            tamper_count += 1
        untrusted_count = int((existing or {}).get("untrusted_count", 0) or 0)
        if trust_state == "UNTRUSTED":
            untrusted_count += 1

        self.registry.save_node_identity(
            baseline_node_id=baseline_node_id,
            current_node_id=current_node_id,
            mode=active_mode,
            trust_state=trust_state,
            maze_state=maze_state,
            manifest=manifest,
            self_metrics=self_metrics,
            last_reason=reason,
            tamper_count=tamper_count,
            untrusted_count=untrusted_count,
        )

        previous_trust = str((existing or {}).get("trust_state", "") or "")
        previous_maze = str((existing or {}).get("maze_state", "") or "")
        if existing is not None and (previous_trust != trust_state or previous_maze != maze_state):
            self.registry.save_security_event(
                user_id=int(getattr(session_context, "user_id", 0) or 0),
                username=str(getattr(session_context, "username", "")),
                event_type="TRUST_STATE_CHANGED",
                severity="warning" if trust_state != "TRUSTED" else "info",
                payload={
                    "from_trust_state": previous_trust,
                    "to_trust_state": trust_state,
                    "from_maze_state": previous_maze,
                    "to_maze_state": maze_state,
                    "mode": active_mode,
                },
            )

        for finding in findings:
            event_type = str(finding.get("event_type", "SECURITY_EVENT"))
            if event_type.endswith("_OK"):
                continue
            self.registry.save_security_event(
                user_id=int(getattr(session_context, "user_id", 0) or 0),
                username=str(getattr(session_context, "username", "")),
                event_type=event_type,
                severity=str(finding.get("severity", "info")),
                payload={
                    "message": str(finding.get("message", "")),
                    "details": dict(finding.get("details", {})),
                    "node_id": current_node_id,
                    "trust_state": trust_state,
                    "maze_state": maze_state,
                    "mode": active_mode,
                },
            )

        snapshot = SecuritySnapshot(
            node_id=current_node_id,
            baseline_node_id=baseline_node_id,
            mode=active_mode,
            trust_state=trust_state,
            maze_state=maze_state,
            summary=summary,
            findings=findings,
            policy=policy,
            self_metrics=self_metrics,
            checked_at=checked_at,
        )
        if session_context is not None:
            session_context.apply_security_state(snapshot.to_dict())
        return snapshot

    @staticmethod
    def can_adopt_current_node(snapshot: SecuritySnapshot | None, session_context: Any | None = None) -> bool:
        """Erlaubt ein kontrolliertes Re-Baselining nur fuer legitime lokale Updates."""
        if snapshot is None:
            return False
        role = str(getattr(session_context, "user_role", "") or getattr(session_context, "role", "") or "").lower()
        if role not in {"admin", "owner"}:
            return False
        findings = [dict(item) for item in list(getattr(snapshot, "findings", [])) if isinstance(item, dict)]
        critical = [item for item in findings if str(item.get("severity", "")).lower() == "critical"]
        warnings = [item for item in findings if str(item.get("severity", "")).lower() == "warning"]
        return (
            str(getattr(snapshot, "mode", "PROD")).upper() == "PROD"
            and bool(dict(getattr(snapshot, "policy", {}) or {}).get("fail_closed_lock", False))
            and len(critical) == 1
            and str(critical[0].get("event_type", "")).upper() == "NODE_TAMPER_DETECTED"
            and not warnings
        )

    def adopt_current_node_as_baseline(self, session_context: Any | None = None, mode: str = "PROD") -> SecuritySnapshot:
        """Uebernimmt die aktuelle lokale Installation explizit als neue vertrauenswuerdige Basis."""
        active_mode = str(mode or "PROD").upper()
        existing = self.registry.get_node_identity() or {}
        manifest = self.build_manifest()
        current_node_id = self.compute_node_id(manifest)
        self_metrics = self._build_self_metrics()
        self.registry.save_node_identity(
            baseline_node_id=current_node_id,
            current_node_id=current_node_id,
            mode=active_mode,
            trust_state="TRUSTED",
            maze_state="NONE",
            manifest=manifest,
            self_metrics=self_metrics,
            last_reason="Lokales Update wurde als neuer Basiszustand bestaetigt.",
            tamper_count=int(existing.get("tamper_count", 0) or 0),
            untrusted_count=int(existing.get("untrusted_count", 0) or 0),
        )
        self.registry.save_security_event(
            user_id=int(getattr(session_context, "user_id", 0) or 0),
            username=str(getattr(session_context, "username", "")),
            event_type="NODE_REBASELINED",
            severity="warning",
            payload={
                "node_id": current_node_id,
                "mode": active_mode,
                "reason": "local_update_confirmed",
            },
        )
        return self.run_integrity_check(session_context=session_context, mode=active_mode)

    def manual_recheck(self, session_context: Any) -> SecuritySnapshot:
        """Fuehrt einen erneuten Integritaetscheck mit aktuellem Session-Kontext aus."""
        return self.run_integrity_check(
            session_context=session_context,
            mode=str(getattr(session_context, "security_mode", "PROD")),
        )

    def register_honeypot_trigger(
        self,
        session_context: Any,
        coordinate: tuple[int, int],
        reason: str = "Lokaler Honeypot getroffen",
    ) -> SecuritySnapshot:
        """Eskaliert einen Honeypot-Treffer lokal auf mindestens SUSPECT."""
        self.registry.save_security_event(
            user_id=int(getattr(session_context, "user_id", 0) or 0),
            username=str(getattr(session_context, "username", "")),
            event_type="HONEYPOT_TRIGGERED",
            severity="warning",
            payload={
                "coordinate": [int(coordinate[0]), int(coordinate[1])],
                "reason": str(reason),
                "node_id": str(getattr(session_context, "node_id", "")),
            },
        )
        current = self.registry.get_node_identity() or {}
        current_mode = str(getattr(session_context, "security_mode", current.get("mode", "PROD"))).upper()
        target_trust = "UNTRUSTED" if str(getattr(session_context, "trust_state", "TRUSTED")) == "UNTRUSTED" else "SUSPECT"
        target_maze = "HARD" if target_trust == "UNTRUSTED" else "SOFT"
        summary = (
            f"{current_mode} | {target_trust} | Maze {target_maze} | "
            f"Honeypot-Treffer bei {coordinate[0]},{coordinate[1]}."
        )
        self.registry.save_node_identity(
            baseline_node_id=str(current.get("baseline_node_id", getattr(session_context, "baseline_node_id", ""))),
            current_node_id=str(current.get("current_node_id", getattr(session_context, "node_id", ""))),
            mode=current_mode,
            trust_state=target_trust,
            maze_state=target_maze,
            manifest=dict(current.get("manifest_json", {})),
            self_metrics=dict(current.get("self_metrics_json", {})),
            last_reason=str(reason),
            tamper_count=int(current.get("tamper_count", 0) or 0),
            untrusted_count=int(current.get("untrusted_count", 0) or 0) + (1 if target_trust == "UNTRUSTED" else 0),
        )
        if str(current.get("trust_state", getattr(session_context, "trust_state", "TRUSTED"))) != target_trust:
            self.registry.save_security_event(
                user_id=int(getattr(session_context, "user_id", 0) or 0),
                username=str(getattr(session_context, "username", "")),
                event_type="TRUST_STATE_CHANGED",
                severity="warning",
                payload={
                    "from_trust_state": str(current.get("trust_state", getattr(session_context, "trust_state", "TRUSTED"))),
                    "to_trust_state": target_trust,
                    "from_maze_state": str(current.get("maze_state", getattr(session_context, "maze_state", "NONE"))),
                    "to_maze_state": target_maze,
                    "reason": str(reason),
                },
            )
        snapshot = SecuritySnapshot(
            node_id=str(current.get("current_node_id", getattr(session_context, "node_id", ""))),
            baseline_node_id=str(current.get("baseline_node_id", getattr(session_context, "baseline_node_id", ""))),
            mode=current_mode,
            trust_state=target_trust,
            maze_state=target_maze,
            summary=summary,
            findings=[
                self._finding(
                    "HONEYPOT_TRIGGERED",
                    "warning",
                    str(reason),
                    coordinate=[int(coordinate[0]), int(coordinate[1])],
                )
            ],
            policy=self._build_policy(target_trust, target_maze, current_mode),
            self_metrics=dict(current.get("self_metrics_json", {})),
            checked_at=self._now_iso(),
        )
        session_context.apply_security_state(snapshot.to_dict())
        return snapshot
