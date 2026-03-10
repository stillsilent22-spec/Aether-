"""Persistente SQLite-Registry fuer Aether."""

from __future__ import annotations

import csv
import base64
import hashlib
import json
import math
import re
import secrets
import sqlite3
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.error import URLError
from urllib.request import urlopen
from uuid import uuid4

import numpy as np

from .analysis_engine import AetherFingerprint
from .chat_crypto import (
    InvalidToken,
    crypto_available,
    decrypt_bytes_aes256,
    decrypt_text,
    derive_fernet_key,
    encrypt_bytes_aes256,
    encrypt_text,
    generate_group_key,
)
from .local_secret_store import is_protected_local_secret, protect_local_secret, unprotect_local_secret
from .session_engine import SessionContext
from .voxel_grid import VoxelDelta

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    trusted_publisher_crypto_available = True
except Exception:  # pragma: no cover - defensive fallback
    InvalidSignature = Exception  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]
    trusted_publisher_crypto_available = False

if TYPE_CHECKING:
    from .spectrum_engine import SpectrumFingerprint
    from .theremin_engine import ThereminFrameState


GENESIS_SEED = "AETHER_GENESIS_2026_HANNEMANN"
GENESIS_HASH = hashlib.sha256(GENESIS_SEED.encode("utf-8")).hexdigest()
GENESIS_PREV_HASH = "0000000000000000000000000000000000"
GENESIS_TIMESTAMP = 1741219200
GENESIS_CONTENT = "Aether self-organizes. Structure is not imposed — it emerges."
DELTA_PACK_PREFIX = b"AETHZ1:"
SHANWAY_MEMBER_NAME = "shanway"
UNREADABLE_CHAT_TEXT = "[nachricht nicht lesbar]"
HIDDEN_CHAT_TEXT = "[verschluesselt]"
RAW_STORAGE_CIPHER = "AES-256-GCM"
TRUSTED_PUBLISHERS_PATH = Path("data") / "trusted_publishers.json"
TRUSTED_PUBLISHER_KEY_DIR = Path("data") / "publisher_keys"
TRUSTED_ANCHOR_UPLOAD_MIN_SCORE = 0.72
OFFICIAL_PUBLIC_ANCHOR_MIRROR = {
    "publisher_id": "stillsilent22-spec/Aether-",
    "index_url": "https://raw.githubusercontent.com/stillsilent22-spec/Aether-/main/data/public_anchor_library/index.json",
    "latest_url": "https://raw.githubusercontent.com/stillsilent22-spec/Aether-/main/data/public_anchor_library/latest.json",
}
BLOCK_HASH_IGNORED_FIELDS = {
    "anchor_status",
    "anchor_job_id",
    "anchor_receipt_id",
    "block_hash",
    "eth_tx",
    "ipfs_cid",
    "public_anchor",
    "public_anchor_error",
    "public_anchor_queue",
    "public_anchor_result",
    "signature",
}


def canonical_json(payload: Any) -> str:
    """Serialisiert Payloads deterministisch fuer Hashes und Signaturen."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def normalized_chain_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Entfernt rein abgeleitete Blockfelder vor der Hashbildung."""
    normalized = dict(payload)
    for key in BLOCK_HASH_IGNORED_FIELDS:
        normalized.pop(key, None)
    return normalized


def compute_chain_block_hash(payload: dict[str, Any]) -> str:
    """Berechnet den kanonischen Hash eines Chain-Payloads."""
    normalized = normalized_chain_payload(payload)
    return hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()


def legacy_chain_block_hash_candidates(payload: dict[str, Any]) -> set[str]:
    """Erlaubt Altdaten weiter zu verifizieren, obwohl neue Bloecke kanonisch gehasht werden."""
    normalized = normalized_chain_payload(payload)
    return {
        compute_chain_block_hash(payload),
        hashlib.sha256(str(normalized).encode("utf-8")).hexdigest(),
        hashlib.sha256(canonical_json(dict(payload)).encode("utf-8")).hexdigest(),
        hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest(),
    }


def trusted_publisher_slug(publisher_id: str) -> str:
    """Normalisiert Publisher-IDs fuer lokale Dateinamen."""
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", str(publisher_id or "").strip())
    return normalized or "publisher"


class AetherRegistry:
    """Verwaltet Fingerprints und Spektrum-/Theremin-Daten in einer SQLite-Datenbank."""

    def __init__(self, db_path: str) -> None:
        """
        Initialisiert die Registry und legt Tabellen bei Bedarf an.

        Args:
            db_path: Pfad zur SQLite-Datenbankdatei.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30.0,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout = 30000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_tables()

    def _create_tables(self) -> None:
        """Erstellt alle benoetigten Tabellen fuer Datei-, Spektrum- und Theremin-Analysen."""
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL DEFAULT 'file',
                source_label TEXT NOT NULL DEFAULT '',
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                symmetry_score REAL NOT NULL,
                entropy_mean REAL NOT NULL,
                verdict TEXT NOT NULL,
                fourier_peaks TEXT NOT NULL,
                periodicity INTEGER NOT NULL,
                anomaly_coordinates TEXT NOT NULL,
                delta BLOB NOT NULL,
                session_seed INTEGER NOT NULL,
                delta_ratio REAL NOT NULL,
                honeypot_triggered INTEGER NOT NULL DEFAULT 0,
                coherence_score REAL NOT NULL DEFAULT 0.0,
                resonance_score REAL NOT NULL DEFAULT 0.0,
                ethics_score REAL NOT NULL DEFAULT 0.0,
                integrity_state TEXT NOT NULL DEFAULT 'STRUCTURAL_TENSION',
                integrity_text TEXT NOT NULL DEFAULT 'Strukturelle Spannung erkannt',
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS node_identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                baseline_node_id TEXT NOT NULL,
                current_node_id TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'PROD',
                trust_state TEXT NOT NULL DEFAULT 'TRUSTED',
                maze_state TEXT NOT NULL DEFAULT 'NONE',
                tamper_count INTEGER NOT NULL DEFAULT 0,
                untrusted_count INTEGER NOT NULL DEFAULT 0,
                last_reason TEXT NOT NULL DEFAULT '',
                manifest_json TEXT NOT NULL DEFAULT '{}',
                self_metrics_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_storage_blobs (
                fingerprint_id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                user_id INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                source_label TEXT NOT NULL DEFAULT '',
                file_hash TEXT NOT NULL,
                cipher_mode TEXT NOT NULL DEFAULT 'AES-256-GCM',
                key_fingerprint TEXT NOT NULL DEFAULT '',
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS spectrum_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_path TEXT NOT NULL,
                image_hash TEXT NOT NULL,
                image_size INTEGER NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                entropy_red REAL NOT NULL,
                entropy_green REAL NOT NULL,
                entropy_blue REAL NOT NULL,
                entropy_total REAL NOT NULL,
                dominant_wavelength_nm REAL NOT NULL,
                dominant_color_r INTEGER NOT NULL,
                dominant_color_g INTEGER NOT NULL,
                dominant_color_b INTEGER NOT NULL,
                delta BLOB NOT NULL,
                delta_ratio REAL NOT NULL,
                noise_seed INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS theremin_frames (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                frame_index INTEGER NOT NULL,
                entropy_red REAL NOT NULL,
                entropy_green REAL NOT NULL,
                entropy_blue REAL NOT NULL,
                entropy_total REAL NOT NULL,
                dominant_wavelength_nm REAL NOT NULL,
                dominant_color_r INTEGER NOT NULL,
                dominant_color_g INTEGER NOT NULL,
                dominant_color_b INTEGER NOT NULL,
                bass_freq REAL NOT NULL,
                mid_freq REAL NOT NULL,
                high_freq REAL NOT NULL,
                volume REAL NOT NULL,
                dissonance REAL NOT NULL,
                hand_detected INTEGER NOT NULL,
                hand_proximity REAL NOT NULL,
                recursive_state INTEGER NOT NULL,
                recursion_collapsed INTEGER NOT NULL,
                anomaly_detected INTEGER NOT NULL,
                delta BLOB NOT NULL,
                delta_ratio REAL NOT NULL,
                noise_seed INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                mic_peak_freq REAL NOT NULL DEFAULT 0.0,
                mic_peak_level REAL NOT NULL DEFAULT 0.0,
                voxel_x REAL NOT NULL DEFAULT 0.0,
                voxel_y REAL NOT NULL DEFAULT 0.0,
                voxel_z REAL NOT NULL DEFAULT 0.0,
                voxel_t REAL NOT NULL DEFAULT 0.0,
                voxel_delta REAL NOT NULL DEFAULT 0.0,
                voxel_freq REAL NOT NULL DEFAULT 0.0,
                voxel_amp REAL NOT NULL DEFAULT 0.0,
                symmetry_score REAL NOT NULL DEFAULT 0.0,
                coherence_score REAL NOT NULL DEFAULT 0.0,
                resonance_score REAL NOT NULL DEFAULT 0.0,
                ethics_score REAL NOT NULL DEFAULT 0.0,
                integrity_state TEXT NOT NULL DEFAULT 'STRUCTURAL_TENSION',
                integrity_text TEXT NOT NULL DEFAULT 'Strukturelle Spannung erkannt',
                payload_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS voxel_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_label TEXT NOT NULL,
                x REAL NOT NULL,
                y REAL NOT NULL,
                z REAL NOT NULL,
                t_value REAL NOT NULL,
                delta REAL NOT NULL,
                freq REAL NOT NULL,
                amp REAL NOT NULL,
                interference REAL NOT NULL DEFAULT 0.0
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chain_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                milestone INTEGER NOT NULL,
                coherence REAL NOT NULL,
                key_fingerprint TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chain_block_annotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_id INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                annotation_type TEXT NOT NULL DEFAULT 'payload_patch',
                payload_json TEXT NOT NULL DEFAULT '{}',
                signature TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_label TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                feature_vector TEXT NOT NULL,
                similarity_best REAL NOT NULL,
                cluster_label TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ae_dna_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL DEFAULT '',
                user_id INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                source_path TEXT NOT NULL DEFAULT '',
                source_label TEXT NOT NULL DEFAULT '',
                bucket TEXT NOT NULL DEFAULT 'sub',
                format_tag TEXT NOT NULL DEFAULT 'AELAB_DNA',
                format_version INTEGER NOT NULL DEFAULT 1,
                legacy_id TEXT NOT NULL DEFAULT '',
                header_metric INTEGER NOT NULL DEFAULT 0,
                node_count INTEGER NOT NULL DEFAULT 0,
                dna_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                dna_text TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ae_candidate_archive (
                signature TEXT NOT NULL,
                user_id INTEGER NOT NULL DEFAULT 0,
                session_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                source_kind TEXT NOT NULL DEFAULT 'runtime',
                bucket TEXT NOT NULL DEFAULT 'sub',
                origin TEXT NOT NULL DEFAULT '',
                candidate_type TEXT NOT NULL DEFAULT 'experimental',
                spec_json TEXT NOT NULL DEFAULT '{}',
                params_json TEXT NOT NULL DEFAULT '{}',
                fitness REAL NOT NULL DEFAULT 0.0,
                stable INTEGER NOT NULL DEFAULT 0,
                reproducible INTEGER NOT NULL DEFAULT 0,
                anchor_points_json TEXT NOT NULL DEFAULT '[]',
                usage_count INTEGER NOT NULL DEFAULT 0,
                promotion_count INTEGER NOT NULL DEFAULT 0,
                last_fitness REAL NOT NULL DEFAULT 0.0,
                dna_record_id INTEGER NOT NULL DEFAULT 0,
                payload_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (signature, user_id)
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS delta_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_label TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS export_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                export_kind TEXT NOT NULL,
                target_path TEXT NOT NULL,
                signature TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS anchor_priors (
                x_bin INTEGER NOT NULL,
                y_bin INTEGER NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (x_bin, y_bin)
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alarm_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                reason TEXT NOT NULL,
                severity TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt_hex TEXT NOT NULL,
                sync_identity TEXT NOT NULL DEFAULT '',
                sync_secret TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT NOT NULL DEFAULT '',
                settings_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS app_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                login_at TEXT NOT NULL,
                logout_at TEXT NOT NULL DEFAULT '',
                live_key_hash TEXT NOT NULL,
                live_key_fingerprint TEXT NOT NULL,
                algo_primary TEXT NOT NULL,
                algo_secondary TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER NOT NULL DEFAULT 0,
                username TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gp_rule_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                scope TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                rule_hash TEXT NOT NULL,
                signature TEXT NOT NULL DEFAULT '',
                is_honeypot INTEGER NOT NULL DEFAULT 0,
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS collective_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_label TEXT NOT NULL DEFAULT '',
                origin_node_id TEXT NOT NULL DEFAULT '',
                snapshot_hash TEXT NOT NULL UNIQUE,
                trust_weight REAL NOT NULL DEFAULT 1.0,
                merged_count INTEGER NOT NULL DEFAULT 1,
                signature TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT 'global',
                timestamp TEXT NOT NULL,
                message_text TEXT NOT NULL,
                fingerprint_id INTEGER NOT NULL DEFAULT 0,
                is_private INTEGER NOT NULL DEFAULT 0,
                is_group INTEGER NOT NULL DEFAULT 0,
                recipient_user_id INTEGER NOT NULL DEFAULT 0,
                recipient_username TEXT NOT NULL DEFAULT '',
                group_id TEXT NOT NULL DEFAULT '',
                key_version INTEGER NOT NULL DEFAULT 0,
                encrypted_payload TEXT NOT NULL DEFAULT '',
                reply_text TEXT NOT NULL DEFAULT '',
                encrypted_reply_text TEXT NOT NULL DEFAULT '',
                visible_to_shanway INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL UNIQUE,
                group_name TEXT NOT NULL,
                created_by_user_id INTEGER NOT NULL,
                created_by_username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                shanway_enabled INTEGER NOT NULL DEFAULT 0,
                key_version INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_group_members (
                group_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                encrypted_group_key TEXT NOT NULL DEFAULT '',
                key_version INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (group_id, username)
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_group_consensus (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                consensus_hash TEXT NOT NULL,
                canonical_text TEXT NOT NULL,
                support_count INTEGER NOT NULL DEFAULT 0,
                supporter_ids_json TEXT NOT NULL DEFAULT '[]',
                reached_at TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE (group_id, consensus_hash)
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_sync_events (
                event_uid TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                source_url TEXT NOT NULL DEFAULT '',
                remote_event_id INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_sync_cursors (
                endpoint TEXT PRIMARY KEY,
                last_event_id INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._migrate_schema()
        self._ensure_genesis_block()
        self.connection.commit()

    @staticmethod
    def _pack_delta(delta: bytes) -> bytes:
        """Komprimiert Delta-Bloecke fuer die interne Dateiablage."""
        return DELTA_PACK_PREFIX + zlib.compress(bytes(delta), level=9)

    @staticmethod
    def _unpack_delta(blob: bytes) -> bytes:
        """Dekodiert neue wie alte Delta-Ablagen robust."""
        payload = bytes(blob)
        if payload.startswith(DELTA_PACK_PREFIX):
            return zlib.decompress(payload[len(DELTA_PACK_PREFIX) :])
        return payload

    def _table_columns(self, table_name: str) -> set[str]:
        """Liest vorhandene Spaltennamen einer Tabelle aus."""
        rows = self.connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row["name"]) for row in rows}

    def _ensure_column(self, table_name: str, column_name: str, column_spec: str) -> None:
        """Fuegt eine Spalte hinzu, falls sie in einer bestehenden Datenbank fehlt."""
        columns = self._table_columns(table_name)
        if column_name in columns:
            return
        self.connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_spec}")

    def _migrate_schema(self) -> None:
        """Fuehrt Schema-Migrationen fuer neue Ethikfelder aus."""
        self._ensure_column("fingerprints", "coherence_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("fingerprints", "resonance_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("fingerprints", "ethics_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("fingerprints", "source_type", "TEXT NOT NULL DEFAULT 'file'")
        self._ensure_column("fingerprints", "source_label", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column(
            "fingerprints",
            "integrity_state",
            "TEXT NOT NULL DEFAULT 'STRUCTURAL_TENSION'",
        )
        self._ensure_column(
            "fingerprints",
            "integrity_text",
            "TEXT NOT NULL DEFAULT 'Strukturelle Spannung erkannt'",
        )
        self._ensure_column("fingerprints", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("theremin_frames", "mic_peak_freq", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "mic_peak_level", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_x", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_y", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_z", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_t", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_delta", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_freq", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "voxel_amp", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "symmetry_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "coherence_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "resonance_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("theremin_frames", "ethics_score", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column("voxel_events", "interference", "REAL NOT NULL DEFAULT 0.0")
        self._ensure_column(
            "theremin_frames",
            "integrity_state",
            "TEXT NOT NULL DEFAULT 'STRUCTURAL_TENSION'",
        )
        self._ensure_column(
            "theremin_frames",
            "integrity_text",
            "TEXT NOT NULL DEFAULT 'Strukturelle Spannung erkannt'",
        )
        self._ensure_column("users", "disabled", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("users", "failed_attempts", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("users", "locked_until", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("users", "settings_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("users", "sync_identity", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("users", "sync_secret", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("app_sessions", "role", "TEXT NOT NULL DEFAULT 'operator'")
        self._ensure_column("app_sessions", "logout_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("app_sessions", "live_key_hash", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("app_sessions", "live_key_fingerprint", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("app_sessions", "algo_primary", "TEXT NOT NULL DEFAULT 'sha256'")
        self._ensure_column("app_sessions", "algo_secondary", "TEXT NOT NULL DEFAULT 'blake2b'")
        self._ensure_column("app_sessions", "status", "TEXT NOT NULL DEFAULT 'active'")
        self._ensure_column("app_sessions", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("node_identity", "mode", "TEXT NOT NULL DEFAULT 'PROD'")
        self._ensure_column("node_identity", "trust_state", "TEXT NOT NULL DEFAULT 'TRUSTED'")
        self._ensure_column("node_identity", "maze_state", "TEXT NOT NULL DEFAULT 'NONE'")
        self._ensure_column("node_identity", "tamper_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("node_identity", "untrusted_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("node_identity", "last_reason", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("node_identity", "manifest_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("node_identity", "self_metrics_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("raw_storage_blobs", "source_label", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("raw_storage_blobs", "file_hash", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("raw_storage_blobs", "cipher_mode", "TEXT NOT NULL DEFAULT 'AES-256-GCM'")
        self._ensure_column("raw_storage_blobs", "key_fingerprint", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("raw_storage_blobs", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("chat_messages", "is_private", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("chat_messages", "is_group", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("chat_messages", "recipient_user_id", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("chat_messages", "recipient_username", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("chat_messages", "group_id", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("chat_messages", "key_version", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("chat_messages", "encrypted_payload", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("chat_messages", "encrypted_reply_text", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("chat_messages", "visible_to_shanway", "INTEGER NOT NULL DEFAULT 1")

    def _genesis_payload(self) -> dict[str, Any]:
        """Erzeugt den weltweit geteilten Genesis-Payload."""
        return {
            "id": 0,
            "hash": GENESIS_HASH,
            "prevHash": GENESIS_PREV_HASH,
            "prev_hash": GENESIS_PREV_HASH,
            "C": 0.0,
            "D": 1.5,
            "milestone": 0.0,
            "timestamp": GENESIS_TIMESTAMP,
            "content": GENESIS_CONTENT,
            "label": "GENESIS · shared root · all instances",
            "genesis": True,
        }

    def _ensure_genesis_block(self) -> None:
        """Legt den identischen Genesis-Block als Kettenursprung an, falls er fehlt."""
        row = self.connection.execute(
            "SELECT id, block_hash FROM chain_blocks WHERE id = 0"
        ).fetchone()
        if row is not None:
            return
        payload = self._genesis_payload()
        self.connection.execute(
            """
            INSERT INTO chain_blocks (
                id, session_id, timestamp, milestone, coherence, key_fingerprint, block_hash, payload_json, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                0,
                "GENESIS",
                str(GENESIS_TIMESTAMP),
                0,
                0.0,
                "GENESIS_SHARED_ROOT",
                GENESIS_HASH,
                json.dumps(payload, ensure_ascii=False),
                "GENESIS_SHARED_ROOT",
            ),
        )

    def get_node_identity(self) -> dict[str, Any] | None:
        """Liefert den gespeicherten lokalen Node-Zustand."""
        row = self.connection.execute(
            """
            SELECT id, baseline_node_id, current_node_id, mode, trust_state, maze_state,
                   tamper_count, untrusted_count, last_reason, manifest_json,
                   self_metrics_json, created_at, updated_at
            FROM node_identity
            WHERE id = 1
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        manifest_raw = str(row["manifest_json"]).strip()
        self_metrics_raw = str(row["self_metrics_json"]).strip()
        try:
            manifest = json.loads(manifest_raw) if manifest_raw else {}
        except Exception:
            manifest = {}
        try:
            self_metrics = json.loads(self_metrics_raw) if self_metrics_raw else {}
        except Exception:
            self_metrics = {}
        return {
            "baseline_node_id": str(row["baseline_node_id"]),
            "current_node_id": str(row["current_node_id"]),
            "mode": str(row["mode"]),
            "trust_state": str(row["trust_state"]),
            "maze_state": str(row["maze_state"]),
            "tamper_count": int(row["tamper_count"]),
            "untrusted_count": int(row["untrusted_count"]),
            "last_reason": str(row["last_reason"]),
            "manifest_json": manifest,
            "self_metrics_json": self_metrics,
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def save_node_identity(
        self,
        *,
        baseline_node_id: str,
        current_node_id: str,
        mode: str,
        trust_state: str,
        maze_state: str,
        manifest: dict[str, Any] | None = None,
        self_metrics: dict[str, Any] | None = None,
        last_reason: str = "",
        tamper_count: int = 0,
        untrusted_count: int = 0,
    ) -> None:
        """Schreibt den aktuellen lokalen Node-Zustand zurueck."""
        now = self._now_iso()
        existing = self.get_node_identity()
        created_at = str(existing["created_at"]) if existing is not None else now
        self.connection.execute(
            """
            INSERT INTO node_identity (
                id, baseline_node_id, current_node_id, mode, trust_state, maze_state,
                tamper_count, untrusted_count, last_reason, manifest_json,
                self_metrics_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                baseline_node_id = excluded.baseline_node_id,
                current_node_id = excluded.current_node_id,
                mode = excluded.mode,
                trust_state = excluded.trust_state,
                maze_state = excluded.maze_state,
                tamper_count = excluded.tamper_count,
                untrusted_count = excluded.untrusted_count,
                last_reason = excluded.last_reason,
                manifest_json = excluded.manifest_json,
                self_metrics_json = excluded.self_metrics_json,
                updated_at = excluded.updated_at
            """,
            (
                1,
                str(baseline_node_id),
                str(current_node_id),
                str(mode),
                str(trust_state),
                str(maze_state),
                int(tamper_count),
                int(untrusted_count),
                str(last_reason),
                json.dumps(manifest or {}, ensure_ascii=False),
                json.dumps(self_metrics or {}, ensure_ascii=False),
                created_at,
                now,
            ),
        )
        self.connection.commit()

    @staticmethod
    def _now_iso() -> str:
        """Liefert den aktuellen UTC-Zeitstempel als ISO-String."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_sync_materials() -> tuple[str, str]:
        """Erzeugt von Login-Daten getrennte Sync-Identitaeten fuer Relay-/Chat-Schluessel."""
        return secrets.token_hex(12), secrets.token_hex(32)

    @staticmethod
    def _derive_sync_materials(username: str, password_hash: str, salt_hex: str) -> tuple[str, str]:
        """Leitet Migrationsmaterial fuer bestehende Nutzer ohne Sync-Felder ab."""
        identity = hashlib.sha256(
            f"sync-identity|{username}|{password_hash}|{salt_hex}|{GENESIS_HASH}".encode("utf-8")
        ).hexdigest()[:24]
        secret = hashlib.blake2b(
            f"sync-secret|{username}|{password_hash}|{salt_hex}|{GENESIS_SEED}".encode("utf-8"),
            digest_size=32,
        ).hexdigest()
        return identity, secret

    def _ensure_user_sync_material(
        self,
        user_id: int,
        username: str,
        password_hash: str,
        salt_hex: str,
        sync_identity: str = "",
        sync_secret: str = "",
    ) -> tuple[str, str]:
        """Stellt sicher, dass jeder Nutzer getrennte Relay-/Chat-Sync-Geheimnisse besitzt."""
        identity = str(sync_identity).strip()
        stored_secret = str(sync_secret).strip()
        if identity and stored_secret:
            try:
                secret_value = unprotect_local_secret(stored_secret)
            except Exception:
                secret_value = ""
            if secret_value:
                if not is_protected_local_secret(stored_secret):
                    self.connection.execute(
                        "UPDATE users SET sync_secret = ? WHERE id = ?",
                        (protect_local_secret(secret_value), int(user_id)),
                    )
                    self.connection.commit()
                return identity, secret_value
        if password_hash and salt_hex:
            identity, secret_value = self._derive_sync_materials(username, password_hash, salt_hex)
        else:
            identity, secret_value = self._new_sync_materials()
        protected_secret = protect_local_secret(secret_value)
        self.connection.execute(
            "UPDATE users SET sync_identity = ?, sync_secret = ? WHERE id = ?",
            (identity, protected_secret, int(user_id)),
        )
        self.connection.commit()
        return identity, secret_value

    def _user_secret_record(self, username: str) -> dict[str, Any]:
        """Liefert den stabilen lokalen Geheimnis-Kontext fuer einen Nutzer."""
        normalized = str(username).strip()
        if normalized == SHANWAY_MEMBER_NAME:
            return {
                "username": SHANWAY_MEMBER_NAME,
                "sync_identity": hashlib.sha256(
                    f"{GENESIS_HASH}|{SHANWAY_MEMBER_NAME}|sync".encode("utf-8")
                ).hexdigest()[:24],
                "sync_secret": hashlib.blake2b(
                    f"{GENESIS_SEED}|{SHANWAY_MEMBER_NAME}|sync".encode("utf-8"),
                    digest_size=32,
                ).hexdigest(),
            }
        record = self.get_user_by_username(normalized)
        if record is None:
            raise ValueError(f"Unbekannter Nutzer: {normalized}")
        return record

    def _member_wrap_key(self, username: str) -> str:
        """Leitet den lokalen Verpackungsschluessel fuer einen Gruppen-Teilnehmer ab."""
        record = self._user_secret_record(username)
        material = (
            f"member|{record['username']}|{record['sync_identity']}|"
            f"{record['sync_secret']}|{GENESIS_HASH}"
        )
        return derive_fernet_key(material)

    def _private_chat_key(self, left_username: str, right_username: str) -> str:
        """Leitet einen stabilen Schluessel fuer einen privaten Zweier-Chat ab."""
        names = sorted([str(left_username).strip(), str(right_username).strip()])
        left_record = self._user_secret_record(names[0])
        right_record = self._user_secret_record(names[1])
        material = (
            f"private|{left_record['username']}|{left_record['sync_identity']}|{left_record['sync_secret']}|"
            f"{right_record['username']}|{right_record['sync_identity']}|{right_record['sync_secret']}|"
            f"{GENESIS_HASH}"
        )
        return derive_fernet_key(material)

    def _encrypt_group_key_for_member(self, group_key: str, username: str) -> str:
        """Verpackt einen Gruppen-Schluessel fuer genau einen Teilnehmer."""
        return encrypt_text(group_key, self._member_wrap_key(username))

    def _decrypt_group_key_for_member(self, encrypted_group_key: str, username: str) -> str:
        """Entpackt einen Gruppen-Schluessel fuer genau einen Teilnehmer."""
        return decrypt_text(encrypted_group_key, self._member_wrap_key(username))

    def _group_row(self, group_id: str) -> sqlite3.Row | None:
        """Liefert die rohe Gruppenzeile fuer interne Verwaltung."""
        return self.connection.execute(
            """
            SELECT id, group_id, group_name, created_by_user_id, created_by_username,
                   created_at, shanway_enabled, key_version, payload_json
            FROM chat_groups
            WHERE group_id = ?
            LIMIT 1
            """,
            (str(group_id),),
        ).fetchone()

    def _group_member_row(self, group_id: str, username: str) -> sqlite3.Row | None:
        """Liefert die rohe Mitgliedszeile einer Gruppe fuer einen Nutzer."""
        return self.connection.execute(
            """
            SELECT group_id, user_id, username, role, joined_at, active,
                   encrypted_group_key, key_version, payload_json
            FROM chat_group_members
            WHERE group_id = ? AND username = ?
            LIMIT 1
            """,
            (str(group_id), str(username)),
        ).fetchone()

    def _active_group_member_rows(self, group_id: str) -> list[sqlite3.Row]:
        """Liefert alle aktiven Mitglieder einer Gruppe."""
        return list(
            self.connection.execute(
                """
                SELECT group_id, user_id, username, role, joined_at, active,
                       encrypted_group_key, key_version, payload_json
                FROM chat_group_members
                WHERE group_id = ? AND active = 1
                ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'assistant' THEN 2 ELSE 1 END, username ASC
                """,
                (str(group_id),),
            ).fetchall()
        )

    def _is_group_admin(self, group_id: str, username: str) -> bool:
        """Prueft, ob ein Nutzer eine Gruppe administrieren darf."""
        row = self._group_member_row(group_id, username)
        if row is None or not bool(int(row["active"])):
            return False
        return str(row["role"]) == "admin"

    def _resolve_group_key_for_user(self, group_id: str, username: str) -> tuple[str, int]:
        """Liefert den entschluesselten Gruppen-Key samt Version fuer einen aktiven Nutzer."""
        row = self._group_member_row(group_id, username)
        if row is None or not bool(int(row["active"])):
            raise PermissionError("Kein aktiver Gruppenzugang vorhanden.")
        encrypted_group_key = str(row["encrypted_group_key"]).strip()
        if not encrypted_group_key:
            raise ValueError("Gruppen-Schluessel fehlt.")
        group_key = self._decrypt_group_key_for_member(encrypted_group_key, str(row["username"]))
        return group_key, int(row["key_version"])

    def _delete_group_consensus(self, group_id: str) -> None:
        """Loescht gruppenlokales Konsenswissen sofort."""
        self.connection.execute(
            "DELETE FROM chat_group_consensus WHERE group_id = ?",
            (str(group_id),),
        )

    def _rotate_group_key(self, group_id: str) -> int:
        """Rotiert den Gruppen-Key und verschluesselt alte Nachrichten fuer Restmitglieder neu."""
        group_row = self._group_row(group_id)
        if group_row is None:
            raise ValueError("Gruppe nicht gefunden.")
        active_members = self._active_group_member_rows(group_id)
        human_members = [row for row in active_members if str(row["username"]) != SHANWAY_MEMBER_NAME]
        if not human_members:
            raise ValueError("Es muss mindestens ein aktives Gruppenmitglied verbleiben.")

        old_key, old_version = self._resolve_group_key_for_user(group_id, str(human_members[0]["username"]))
        new_key = generate_group_key()
        new_version = int(old_version) + 1

        self.connection.execute(
            "UPDATE chat_groups SET key_version = ? WHERE group_id = ?",
            (new_version, str(group_id)),
        )
        for row in active_members:
            self.connection.execute(
                """
                UPDATE chat_group_members
                SET encrypted_group_key = ?, key_version = ?
                WHERE group_id = ? AND username = ?
                """,
                (
                    self._encrypt_group_key_for_member(new_key, str(row["username"])),
                    new_version,
                    str(group_id),
                    str(row["username"]),
                ),
            )

        rows = self.connection.execute(
            """
            SELECT id, message_text, encrypted_payload, reply_text, encrypted_reply_text
            FROM chat_messages
            WHERE group_id = ?
            ORDER BY id ASC
            """,
            (str(group_id),),
        ).fetchall()
        for row in rows:
            message_plain = ""
            reply_plain = ""
            encrypted_payload = str(row["encrypted_payload"]).strip()
            encrypted_reply = str(row["encrypted_reply_text"]).strip()
            if encrypted_payload:
                message_plain = decrypt_text(encrypted_payload, old_key)
            elif str(row["message_text"]).strip() and str(row["message_text"]) != HIDDEN_CHAT_TEXT:
                message_plain = str(row["message_text"])
            if encrypted_reply:
                reply_plain = decrypt_text(encrypted_reply, old_key)
            elif str(row["reply_text"]).strip() and str(row["reply_text"]) != HIDDEN_CHAT_TEXT:
                reply_plain = str(row["reply_text"])
            self.connection.execute(
                """
                UPDATE chat_messages
                SET message_text = ?, encrypted_payload = ?, reply_text = ?, encrypted_reply_text = ?, key_version = ?
                WHERE id = ?
                """,
                (
                    HIDDEN_CHAT_TEXT if message_plain else "",
                    encrypt_text(message_plain, new_key) if message_plain else "",
                    HIDDEN_CHAT_TEXT if reply_plain else "",
                    encrypt_text(reply_plain, new_key) if reply_plain else "",
                    new_version,
                    int(row["id"]),
                ),
            )
        return new_version

    def get_genesis_block(self) -> dict[str, Any] | None:
        """Liefert den Genesis-Block aus der lokalen Datenbank."""
        row = self.connection.execute(
            """
            SELECT id, session_id, timestamp, milestone, coherence, key_fingerprint, block_hash, payload_json, signature
            FROM chain_blocks
            WHERE id = 0
            """
        ).fetchone()
        if row is None:
            return None
        return {
            "id": int(row["id"]),
            "session_id": str(row["session_id"]),
            "timestamp": str(row["timestamp"]),
            "milestone": int(row["milestone"]),
            "coherence": float(row["coherence"]),
            "key_fingerprint": str(row["key_fingerprint"]),
            "block_hash": str(row["block_hash"]),
            "payload_json": json.loads(str(row["payload_json"])),
            "signature": str(row["signature"]),
        }

    def _latest_chain_hash(self) -> str:
        """Liefert den Hash der aktuellen Kettenspitze oder den Genesis-Hash."""
        row = self.connection.execute(
            "SELECT block_hash FROM chain_blocks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return GENESIS_HASH
        return str(row["block_hash"])

    def next_prev_hash(self) -> str:
        """Liefert den prev_hash-Wert fuer den naechsten neu zu speichernden Block."""
        return self._latest_chain_hash()

    def save(
        self,
        fingerprint: AetherFingerprint,
        session_context: SessionContext,
        payload_update: dict[str, Any] | None = None,
    ) -> int:
        """
        Speichert einen Datei-Fingerprint inklusive Session-Metadaten.

        Args:
            fingerprint: Zu speichernder Analyse-Fingerprint.
            session_context: Aktiver Session-Kontext.

        Returns:
            Primarschluessel des neuen Datensatzes.
        """
        honeypot_triggered = any(
            session_context.is_honeypot(coordinate) for coordinate in fingerprint.anomaly_coordinates
        )
        payload = fingerprint.to_dict()
        if payload_update:
            payload.update(dict(payload_update))
        cursor = self.connection.execute(
            """
            INSERT INTO fingerprints (
                session_id, timestamp, source_type, source_label, file_hash, file_size, symmetry_score, entropy_mean, verdict,
                fourier_peaks, periodicity, anomaly_coordinates, delta, session_seed, delta_ratio, honeypot_triggered,
                coherence_score, resonance_score, ethics_score, integrity_state, integrity_text, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint.session_id,
                fingerprint.timestamp,
                str(getattr(fingerprint, "source_type", "file")),
                str(getattr(fingerprint, "source_label", "")),
                fingerprint.file_hash,
                fingerprint.file_size,
                fingerprint.symmetry_score,
                fingerprint.entropy_mean,
                fingerprint.verdict,
                json.dumps(fingerprint.fourier_peaks),
                int(fingerprint.periodicity),
                json.dumps([[int(x), int(y)] for x, y in fingerprint.anomaly_coordinates]),
                self._pack_delta(fingerprint.delta),
                int(session_context.seed),
                float(fingerprint.delta_ratio),
                int(honeypot_triggered),
                float(getattr(fingerprint, "coherence_score", 0.0)),
                float(getattr(fingerprint, "resonance_score", 0.0)),
                float(getattr(fingerprint, "ethics_score", 0.0)),
                str(getattr(fingerprint, "integrity_state", "STRUCTURAL_TENSION")),
                str(getattr(fingerprint, "integrity_text", "Strukturelle Spannung erkannt")),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def update_fingerprint_payload(self, record_id: int, payload_update: dict[str, Any]) -> None:
        """Erweitert den lokalen Fingerprint-Payload um additive Metadaten."""
        row = self.connection.execute(
            "SELECT payload_json FROM fingerprints WHERE id = ? LIMIT 1",
            (int(record_id),),
        ).fetchone()
        if row is None:
            raise ValueError("Fingerprint nicht gefunden.")
        payload_raw = str(row["payload_json"]).strip()
        try:
            payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            payload = {}
        payload.update(dict(payload_update))
        self.connection.execute(
            "UPDATE fingerprints SET payload_json = ? WHERE id = ?",
            (json.dumps(payload, ensure_ascii=False), int(record_id)),
        )
        self.connection.commit()

    def save_encrypted_raw_bytes(
        self,
        fingerprint_id: int,
        session_context: SessionContext,
        raw_bytes: bytes,
        file_hash: str,
        source_label: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Persistiert optionale Rohdaten nur lokal und AES-256-verschluesselt."""
        key = session_context.file_delta_key_bytes(
            file_hash=str(file_hash),
            record_id=int(fingerprint_id),
            session_id=str(session_context.session_id),
        )
        if len(key) != 32:
            raise RuntimeError("Kein gueltiger lokaler AES-256-Datei-Key verfuegbar.")
        key_fingerprint = session_context.file_delta_key_fingerprint(
            file_hash=str(file_hash),
            record_id=int(fingerprint_id),
            session_id=str(session_context.session_id),
        )
        aad = (
            f"{int(fingerprint_id)}|{session_context.session_id}|{str(file_hash)}|{str(source_label)}"
        ).encode("utf-8", errors="replace")
        nonce, ciphertext = encrypt_bytes_aes256(bytes(raw_bytes), key, aad=aad)
        payload_box = {
            "scope": "local_only",
            "shared": False,
            "included_in_gp": False,
            "included_in_semantics": False,
            "included_in_exports": False,
            "raw_size": int(len(raw_bytes)),
            "stored_at": self._now_iso(),
            "key_scope": "session_file_local",
            "key_fingerprint": str(key_fingerprint),
        }
        if payload:
            payload_box.update(dict(payload))
        self.connection.execute(
            """
            INSERT INTO raw_storage_blobs (
                fingerprint_id, session_id, user_id, timestamp, source_label, file_hash,
                cipher_mode, key_fingerprint, nonce, ciphertext, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint_id) DO UPDATE SET
                session_id = excluded.session_id,
                user_id = excluded.user_id,
                timestamp = excluded.timestamp,
                source_label = excluded.source_label,
                file_hash = excluded.file_hash,
                cipher_mode = excluded.cipher_mode,
                key_fingerprint = excluded.key_fingerprint,
                nonce = excluded.nonce,
                ciphertext = excluded.ciphertext,
                payload_json = excluded.payload_json
            """,
            (
                int(fingerprint_id),
                str(session_context.session_id),
                int(getattr(session_context, "user_id", 0) or 0),
                self._now_iso(),
                str(source_label),
                str(file_hash),
                RAW_STORAGE_CIPHER,
                str(key_fingerprint),
                sqlite3.Binary(nonce),
                sqlite3.Binary(ciphertext),
                json.dumps(payload_box, ensure_ascii=False),
            ),
        )
        self.connection.commit()

    def has_encrypted_raw_bytes(self, fingerprint_id: int) -> bool:
        """Prueft, ob fuer einen Fingerprint lokal verschluesselte Rohdaten vorliegen."""
        row = self.connection.execute(
            "SELECT 1 FROM raw_storage_blobs WHERE fingerprint_id = ? LIMIT 1",
            (int(fingerprint_id),),
        ).fetchone()
        return row is not None

    def get_raw_storage_status(self, fingerprint_id: int) -> dict[str, Any]:
        """Liefert den lokalen Dual-Mode-Status eines Dateifingerprints."""
        row = self.connection.execute(
            """
            SELECT cipher_mode, key_fingerprint, payload_json
            FROM raw_storage_blobs
            WHERE fingerprint_id = ?
            LIMIT 1
            """,
            (int(fingerprint_id),),
        ).fetchone()
        if row is None:
            return {
                "mode": "delta_only",
                "has_raw_bytes": False,
                "cipher_mode": "",
                "key_fingerprint": "",
                "payload_json": {},
            }
        payload_raw = str(row["payload_json"]).strip()
        try:
            payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            payload = {}
        return {
            "mode": "delta_plus_encrypted_raw",
            "has_raw_bytes": True,
            "cipher_mode": str(row["cipher_mode"]),
            "key_fingerprint": str(row["key_fingerprint"]),
            "payload_json": payload,
        }

    def save_spectrum_fingerprint(self, spectrum: SpectrumFingerprint) -> int:
        """
        Speichert ein Bild-/Spektrumergebnis inklusive Delta und Wellenlaengen-Metadaten.

        Args:
            spectrum: Spektralergebnis aus SpectrumEngine.
        """
        payload = spectrum.to_dict()
        cursor = self.connection.execute(
            """
            INSERT INTO spectrum_records (
                session_id, timestamp, source_type, source_path, image_hash, image_size, width, height,
                entropy_red, entropy_green, entropy_blue, entropy_total, dominant_wavelength_nm,
                dominant_color_r, dominant_color_g, dominant_color_b,
                delta, delta_ratio, noise_seed, verdict, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                spectrum.session_id,
                spectrum.timestamp,
                spectrum.source_type,
                spectrum.source_path,
                spectrum.image_hash,
                spectrum.file_size,
                spectrum.width,
                spectrum.height,
                spectrum.entropy_red,
                spectrum.entropy_green,
                spectrum.entropy_blue,
                spectrum.entropy_total,
                spectrum.dominant_wavelength_nm,
                int(spectrum.dominant_color_rgb[0]),
                int(spectrum.dominant_color_rgb[1]),
                int(spectrum.dominant_color_rgb[2]),
                spectrum.delta,
                spectrum.delta_ratio,
                int(spectrum.noise_seed),
                spectrum.verdict,
                json.dumps(payload),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def save_theremin_frame(self, frame_state: ThereminFrameState) -> int:
        """
        Speichert einen Echtzeit-Theremin-Frame in der Registry.

        Args:
            frame_state: Zustand eines analysierten Webcam-Frames.
        """
        payload = frame_state.to_dict()
        cursor = self.connection.execute(
            """
            INSERT INTO theremin_frames (
                session_id, timestamp, frame_index,
                entropy_red, entropy_green, entropy_blue, entropy_total,
                dominant_wavelength_nm, dominant_color_r, dominant_color_g, dominant_color_b,
                bass_freq, mid_freq, high_freq, volume, dissonance,
                hand_detected, hand_proximity, recursive_state, recursion_collapsed, anomaly_detected,
                delta, delta_ratio, noise_seed, verdict,
                mic_peak_freq, mic_peak_level, voxel_x, voxel_y, voxel_z, voxel_t, voxel_delta, voxel_freq, voxel_amp,
                symmetry_score, coherence_score, resonance_score, ethics_score, integrity_state, integrity_text,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                frame_state.session_id,
                frame_state.timestamp,
                int(frame_state.frame_index),
                float(frame_state.entropy_red),
                float(frame_state.entropy_green),
                float(frame_state.entropy_blue),
                float(frame_state.entropy_total),
                float(frame_state.dominant_wavelength_nm),
                int(frame_state.dominant_color_rgb[0]),
                int(frame_state.dominant_color_rgb[1]),
                int(frame_state.dominant_color_rgb[2]),
                float(frame_state.bass_freq),
                float(frame_state.mid_freq),
                float(frame_state.high_freq),
                float(frame_state.volume),
                float(frame_state.dissonance),
                int(frame_state.hand_detected),
                float(frame_state.hand_proximity),
                int(frame_state.recursive_state),
                int(frame_state.recursion_collapsed),
                int(frame_state.anomaly_detected),
                frame_state.delta,
                float(frame_state.delta_ratio),
                int(frame_state.noise_seed),
                frame_state.verdict,
                float(frame_state.mic_peak_freq),
                float(frame_state.mic_peak_level),
                float(frame_state.voxel_x),
                float(frame_state.voxel_y),
                float(frame_state.voxel_z),
                float(frame_state.voxel_t),
                float(frame_state.voxel_delta),
                float(frame_state.voxel_freq),
                float(frame_state.voxel_amp),
                float(frame_state.symmetry_score),
                float(frame_state.coherence_score),
                float(frame_state.resonance_score),
                float(frame_state.ethics_score),
                frame_state.integrity_state,
                frame_state.integrity_text,
                json.dumps(payload),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def save_voxel_events(
        self,
        session_id: str,
        source_type: str,
        source_label: str,
        voxels: list[VoxelDelta],
    ) -> int:
        """Persistiert eine Menge 4D-Voxel-Ereignisse fuer CSV-Import oder Theremin."""
        if not voxels:
            return 0

        timestamp = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                session_id,
                timestamp,
                source_type,
                source_label,
                float(voxel.x),
                float(voxel.y),
                float(voxel.z),
                float(voxel.t),
                float(voxel.delta),
                float(voxel.freq),
                float(voxel.amp),
                float(getattr(voxel, "interference", 0.0) or 0.0),
            )
            for voxel in voxels
        ]
        self.connection.executemany(
            """
            INSERT INTO voxel_events (
                session_id, timestamp, source_type, source_label,
                x, y, z, t_value, delta, freq, amp, interference
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.connection.commit()
        return len(rows)

    def export_voxel_events(self, file_path: str, session_id: str | None = None) -> int:
        """Exportiert persistierte Voxel-Ereignisse wieder als CSV."""
        query = """
            SELECT x, y, z, t_value, delta, freq, amp, interference
            FROM voxel_events
        """
        params: tuple[object, ...] = ()
        if session_id:
            query += " WHERE session_id = ?"
            params = (session_id,)
        query += " ORDER BY id ASC"

        rows = self.connection.execute(query, params).fetchall()
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(["x", "y", "z", "t", "delta", "freq", "amp", "interference"])
            for row in rows:
                writer.writerow(
                    [
                        float(row["x"]),
                        float(row["y"]),
                        float(row["z"]),
                        float(row["t_value"]),
                        float(row["delta"]),
                        float(row["freq"]),
                        float(row["amp"]),
                        float(row["interference"]),
                    ]
                )
        return len(rows)

    def save_chain_block(
        self,
        session_id: str,
        milestone: int,
        coherence: float,
        key_fingerprint: str,
        block_hash: str,
        payload: dict[str, Any],
        signature: str,
    ) -> int:
        """Speichert einen signierten Chain-Block."""
        cursor = self.connection.execute(
            """
            INSERT INTO chain_blocks (
                session_id, timestamp, milestone, coherence, key_fingerprint, block_hash, payload_json, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                datetime.now(timezone.utc).isoformat(),
                int(milestone),
                float(coherence),
                key_fingerprint,
                block_hash,
                json.dumps(payload, ensure_ascii=False),
                signature,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def append_chain_block_annotation(
        self,
        block_id: int,
        session_id: str,
        annotation_type: str,
        payload: dict[str, Any],
        signature: str = "",
    ) -> int:
        """Haengt eine additive Block-Annotation an, ohne den Basisblock zu veraendern."""
        cursor = self.connection.execute(
            """
            INSERT INTO chain_block_annotations (
                block_id, session_id, timestamp, annotation_type, payload_json, signature
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                int(block_id),
                str(session_id),
                self._now_iso(),
                str(annotation_type),
                json.dumps(payload, ensure_ascii=False),
                str(signature),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def _latest_chain_annotations(self, block_ids: list[int]) -> dict[int, dict[str, Any]]:
        """Liefert die juengste additive Annotation je Block."""
        normalized_ids = [int(item) for item in block_ids if int(item) > 0]
        if not normalized_ids:
            return {}
        placeholders = ",".join("?" for _ in normalized_ids)
        rows = self.connection.execute(
            f"""
            SELECT a.block_id, a.annotation_type, a.payload_json, a.signature, a.timestamp
            FROM chain_block_annotations AS a
            JOIN (
                SELECT block_id, MAX(id) AS max_id
                FROM chain_block_annotations
                WHERE block_id IN ({placeholders})
                GROUP BY block_id
            ) AS latest
              ON latest.max_id = a.id
            """,
            tuple(normalized_ids),
        ).fetchall()
        result: dict[int, dict[str, Any]] = {}
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            result[int(row["block_id"])] = {
                "annotation_type": str(row["annotation_type"]),
                "payload_json": payload,
                "signature": str(row["signature"]),
                "timestamp": str(row["timestamp"]),
            }
        return result

    def get_chain_blocks_raw(
        self,
        limit: int = 200,
        user_id: int | None = None,
        include_genesis: bool = True,
    ) -> list[dict[str, Any]]:
        """Liefert nur die unveraenderten Basisbloecke ohne spaetere Annotationen."""
        if user_id is None or int(user_id) <= 0:
            where_clause = "" if include_genesis else "WHERE id != 0"
            rows = self.connection.execute(
                f"""
                SELECT id, session_id, timestamp, milestone, coherence, key_fingerprint, block_hash, payload_json, signature
                FROM chain_blocks
                {where_clause}
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(1, limit)),),
            ).fetchall()
        else:
            genesis_clause = "cb.id = 0 OR " if include_genesis else ""
            rows = self.connection.execute(
                f"""
                SELECT cb.id, cb.session_id, cb.timestamp, cb.milestone, cb.coherence, cb.key_fingerprint, cb.block_hash, cb.payload_json, cb.signature
                FROM chain_blocks AS cb
                LEFT JOIN app_sessions AS s ON s.session_id = cb.session_id
                WHERE {genesis_clause} s.user_id = ?
                ORDER BY cb.id DESC
                LIMIT ?
                """,
                (int(user_id), int(max(1, limit))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            result.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "milestone": int(row["milestone"]),
                    "coherence": float(row["coherence"]),
                    "key_fingerprint": str(row["key_fingerprint"]),
                    "block_hash": str(row["block_hash"]),
                    "payload_json": payload,
                    "signature": str(row["signature"]),
                }
            )
        return result

    def get_chain_blocks(
        self,
        limit: int = 200,
        user_id: int | None = None,
        include_genesis: bool = True,
    ) -> list[dict[str, Any]]:
        """Liefert Blockbasis plus juengste additive Annotation fuer UI und Export."""
        blocks = self.get_chain_blocks_raw(limit=limit, user_id=user_id, include_genesis=include_genesis)
        annotations = self._latest_chain_annotations([int(item["id"]) for item in blocks if int(item["id"]) > 0])
        for block in blocks:
            annotation = annotations.get(int(block["id"]))
            if annotation is None:
                continue
            block["base_payload_json"] = dict(block.get("payload_json", {}))
            block["payload_json"] = dict(annotation.get("payload_json", {}))
            if str(annotation.get("signature", "")).strip():
                block["annotation_signature"] = str(annotation["signature"])
        return blocks

    def update_chain_block_payload(
        self,
        block_id: int,
        payload: dict[str, Any],
        signature: str | None = None,
    ) -> None:
        """Haengt einen neuen Payload-Stand an, ohne den Basisblock zu ueberschreiben."""
        row = self.connection.execute(
            "SELECT session_id FROM chain_blocks WHERE id = ? LIMIT 1",
            (int(block_id),),
        ).fetchone()
        if row is None:
            raise ValueError("Chain-Block nicht gefunden.")
        self.append_chain_block_annotation(
            block_id=int(block_id),
            session_id=str(row["session_id"]),
            annotation_type="payload_patch",
            payload=payload,
            signature=str(signature or ""),
        )

    def get_shanway_registry_knowledge(self, limit: int = 48) -> list[dict[str, Any]]:
        """Leitet bestaetigtes Shanway-Wissen aus CONFIRMED LOSSLESS-Blocks ab."""
        rows = self.connection.execute(
            """
            SELECT id, timestamp, payload_json
            FROM chain_blocks
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(max(24, limit * 6)),),
        ).fetchall()

        def tokens_for(*values: object) -> list[str]:
            tokens: set[str] = set()
            for value in values:
                for token in re.findall(r"[0-9A-Za-zÄÖÜäöüß]+", str(value).lower()):
                    if len(token) >= 2:
                        tokens.add(token)
            return sorted(tokens)

        knowledge: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except Exception:
                continue
            if not bool(payload.get("confirmed_lossless", False)):
                continue
            source_type = str(payload.get("source_type", payload.get("tag", "")) or "")
            source_label = str(payload.get("source_label", payload.get("file_hash", "")) or "")
            file_hash = str(payload.get("file_hash", ""))[:16]
            signature = (source_type, source_label, file_hash)
            if signature in seen:
                continue
            seen.add(signature)
            integrity_text = str(payload.get("integrity_text", payload.get("observer_state", "")) or "")
            graph_phase = str(payload.get("graph_phase_state", "") or "")
            graph_region = str(payload.get("graph_region", "") or "")
            pattern_found = str(payload.get("pattern_found", "") or "")
            tag = str(payload.get("tag", "") or "")
            response_parts = [
                f"AETHER hat {source_type or 'diesen Strom'} {source_label or file_hash} selbst bestätigt.",
                "Lossless verifiziert.",
            ]
            if integrity_text:
                response_parts.append(integrity_text + ".")
            if graph_phase:
                response_parts.append(f"Graphphase {graph_phase}.")
            if "h_lambda" in payload:
                response_parts.append(f"H_lambda {float(payload.get('h_lambda', 0.0) or 0.0):.2f}.")
            if "ethics_score" in payload:
                response_parts.append(f"Ethik {float(payload.get('ethics_score', 0.0) or 0.0):.1f}.")
            response = " ".join(part.strip() for part in response_parts if part).strip()
            knowledge.append(
                {
                    "id": int(row["id"]),
                    "key": f"{source_type}:{source_label or file_hash}",
                    "timestamp": str(row["timestamp"]),
                    "source_type": source_type,
                    "source_label": source_label,
                    "keywords": tokens_for(source_type, source_label, file_hash, integrity_text, graph_phase, graph_region, pattern_found, tag),
                    "response": response,
                }
            )
            if len(knowledge) >= int(limit):
                break
        return knowledge

    def save_vault_entry(
        self,
        session_id: str,
        source_type: str,
        source_label: str,
        file_hash: str,
        feature_vector: list[float],
        similarity_best: float,
        cluster_label: str,
        payload: dict[str, Any],
        signature: str,
    ) -> int:
        """Speichert einen signierten Vault-Eintrag."""
        cursor = self.connection.execute(
            """
            INSERT INTO vault_entries (
                session_id, timestamp, source_type, source_label, file_hash,
                feature_vector, similarity_best, cluster_label, payload_json, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                datetime.now(timezone.utc).isoformat(),
                source_type,
                source_label,
                file_hash,
                json.dumps([float(item) for item in feature_vector]),
                float(similarity_best),
                cluster_label,
                json.dumps(payload),
                signature,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def update_vault_cluster(self, entry_id: int, cluster_label: str) -> None:
        """Aktualisiert das Clusterlabel eines Vault-Eintrags."""
        self.connection.execute(
            "UPDATE vault_entries SET cluster_label = ? WHERE id = ?",
            (cluster_label, int(entry_id)),
        )
        self.connection.commit()

    def update_vault_payload(
        self,
        entry_id: int,
        payload: dict[str, Any],
        signature: str | None = None,
    ) -> None:
        """Aktualisiert den JSON-Payload eines Vault-Eintrags."""
        if signature is None:
            self.connection.execute(
                "UPDATE vault_entries SET payload_json = ? WHERE id = ?",
                (json.dumps(payload), int(entry_id)),
            )
        else:
            self.connection.execute(
                "UPDATE vault_entries SET payload_json = ?, signature = ? WHERE id = ?",
                (json.dumps(payload), signature, int(entry_id)),
            )
        self.connection.commit()

    def get_vault_entries(self, limit: int = 300, user_id: int | None = None) -> list[dict[str, Any]]:
        """Liefert Vault-Eintraege fuer Anzeige, Matching und Export."""
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT id, session_id, timestamp, source_type, source_label, file_hash,
                       feature_vector, similarity_best, cluster_label, payload_json, signature
                FROM vault_entries
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(1, limit)),),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT v.id, v.session_id, v.timestamp, v.source_type, v.source_label, v.file_hash,
                       v.feature_vector, v.similarity_best, v.cluster_label, v.payload_json, v.signature
                FROM vault_entries AS v
                JOIN app_sessions AS s ON s.session_id = v.session_id
                WHERE s.user_id = ?
                ORDER BY v.id DESC
                LIMIT ?
                """,
                (int(user_id), int(max(1, limit))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "source_type": str(row["source_type"]),
                    "source_label": str(row["source_label"]),
                    "file_hash": str(row["file_hash"]),
                    "feature_vector": json.loads(str(row["feature_vector"])),
                    "similarity_best": float(row["similarity_best"]),
                    "cluster_label": str(row["cluster_label"]),
                    "payload_json": json.loads(str(row["payload_json"])),
                    "signature": str(row["signature"]),
                }
            )
        return result

    def save_legacy_ae_dna_record(
        self,
        session_id: str,
        user_id: int,
        source_path: str,
        source_label: str,
        bucket: str,
        dna_payload: dict[str, Any],
        dna_text: str,
    ) -> int:
        """Persistiert eine importierte Legacy-AELAB-DNA inklusive Rohtext und Metadaten."""
        cursor = self.connection.execute(
            """
            INSERT INTO ae_dna_records (
                session_id, user_id, timestamp, source_path, source_label, bucket,
                format_tag, format_version, legacy_id, header_metric, node_count,
                dna_hash, payload_json, dna_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(session_id),
                int(user_id or 0),
                self._now_iso(),
                str(source_path),
                str(source_label),
                str(bucket),
                str(dna_payload.get("format_tag", "AELAB_DNA")),
                int(dna_payload.get("format_version", 1) or 1),
                str(dna_payload.get("legacy_id", "")),
                int(dna_payload.get("header_metric", 0) or 0),
                int(dna_payload.get("node_count", 0) or 0),
                str(dna_payload.get("dna_hash", "")),
                json.dumps(dna_payload, ensure_ascii=False),
                str(dna_text),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_legacy_ae_dna_records(
        self,
        limit: int = 200,
        user_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Liefert importierte Legacy-DNA-Datensaetze fuer Audit und Rehydrierung."""
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT *
                FROM ae_dna_records
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(1, limit)),),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT *
                FROM ae_dna_records
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(user_id), int(max(1, limit))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except Exception:
                payload = {}
            result.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "user_id": int(row["user_id"]),
                    "timestamp": str(row["timestamp"]),
                    "source_path": str(row["source_path"]),
                    "source_label": str(row["source_label"]),
                    "bucket": str(row["bucket"]),
                    "format_tag": str(row["format_tag"]),
                    "format_version": int(row["format_version"]),
                    "legacy_id": str(row["legacy_id"]),
                    "header_metric": int(row["header_metric"]),
                    "node_count": int(row["node_count"]),
                    "dna_hash": str(row["dna_hash"]),
                    "payload_json": payload,
                    "dna_text": str(row["dna_text"]),
                }
            )
        return result

    def sync_ae_vault_state(
        self,
        session_id: str,
        user_id: int,
        ae_state: dict[str, list[dict[str, Any]]],
    ) -> int:
        """Spiegelt den aktuellen AE-Main-/Sub-Vault als persistentes Archiv."""
        saved = 0
        now = self._now_iso()
        for bucket in ("main", "sub"):
            for record in list(ae_state.get(bucket, []) or []):
                params = dict(record.get("params", {}) or {})
                payload = dict(record)
                signature = str(payload.get("signature", "") or "")
                if not signature:
                    signature = hashlib.sha256(
                        canonical_json(
                            {
                                "origin": str(payload.get("origin", "")),
                                "spec": dict(payload.get("spec", {}) or {}),
                                "params": params,
                                "bucket": bucket,
                            }
                        ).encode("utf-8")
                    ).hexdigest()
                usage_count = int(params.get("usage_count", payload.get("usage_count", 0)) or 0)
                promotion_count = int(params.get("promotion_count", payload.get("promotion_count", 0)) or 0)
                last_fitness = float(params.get("last_fitness", payload.get("fitness", 0.0)) or 0.0)
                self.connection.execute(
                    """
                    INSERT INTO ae_candidate_archive (
                        signature, user_id, session_id, created_at, updated_at, source_kind, bucket,
                        origin, candidate_type, spec_json, params_json, fitness, stable, reproducible,
                        anchor_points_json, usage_count, promotion_count, last_fitness, dna_record_id, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(signature, user_id) DO UPDATE SET
                        session_id = excluded.session_id,
                        updated_at = excluded.updated_at,
                        source_kind = excluded.source_kind,
                        bucket = excluded.bucket,
                        origin = excluded.origin,
                        candidate_type = excluded.candidate_type,
                        spec_json = excluded.spec_json,
                        params_json = excluded.params_json,
                        fitness = excluded.fitness,
                        stable = excluded.stable,
                        reproducible = excluded.reproducible,
                        anchor_points_json = excluded.anchor_points_json,
                        usage_count = excluded.usage_count,
                        promotion_count = excluded.promotion_count,
                        last_fitness = excluded.last_fitness,
                        dna_record_id = excluded.dna_record_id,
                        payload_json = excluded.payload_json
                    """,
                    (
                        signature,
                        int(user_id or 0),
                        str(session_id),
                        now,
                        now,
                        str(payload.get("source_kind", params.get("source_kind", "runtime"))),
                        str(bucket),
                        str(payload.get("origin", "")),
                        str(payload.get("type", "experimental")),
                        json.dumps(dict(payload.get("spec", {}) or {}), ensure_ascii=False),
                        json.dumps(params, ensure_ascii=False),
                        float(payload.get("fitness", 0.0) or 0.0),
                        1 if bool(payload.get("stable", False)) else 0,
                        1 if bool(payload.get("reproducible", False)) else 0,
                        json.dumps(list(payload.get("anchor_points", []) or []), ensure_ascii=False),
                        usage_count,
                        promotion_count,
                        last_fitness,
                        int(params.get("dna_record_id", 0) or 0),
                        json.dumps(payload, ensure_ascii=False),
                    ),
                )
                saved += 1
        self.connection.commit()
        return int(saved)

    def load_ae_vault_state(
        self,
        user_id: int | None = None,
        limit_main: int = 64,
        limit_sub: int = 48,
    ) -> dict[str, list[dict[str, Any]]]:
        """Laedt den letzten serialisierten AE-Vault/Subvault fuer den aktuellen Nutzer."""
        scoped_user = int(user_id or 0)
        if scoped_user <= 0:
            rows = self.connection.execute(
                """
                SELECT *
                FROM ae_candidate_archive
                ORDER BY bucket ASC, stable DESC, fitness DESC, usage_count DESC, updated_at DESC
                """
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT *
                FROM ae_candidate_archive
                WHERE user_id = ?
                ORDER BY bucket ASC, stable DESC, fitness DESC, usage_count DESC, updated_at DESC
                """,
                (scoped_user,),
            ).fetchall()
        state = {"main": [], "sub": []}
        for row in rows:
            bucket = str(row["bucket"] or "sub")
            if bucket not in state:
                continue
            if bucket == "main" and len(state["main"]) >= int(max(1, limit_main)):
                continue
            if bucket == "sub" and len(state["sub"]) >= int(max(1, limit_sub)):
                continue
            try:
                payload = json.loads(str(row["payload_json"]))
            except Exception:
                payload = {}
            if not payload:
                payload = {
                    "signature": str(row["signature"]),
                    "origin": str(row["origin"]),
                    "bucket": bucket,
                    "type": str(row["candidate_type"]),
                    "source_kind": str(row["source_kind"]),
                    "spec": json.loads(str(row["spec_json"])),
                    "params": json.loads(str(row["params_json"])),
                    "fitness": float(row["fitness"]),
                    "stable": bool(int(row["stable"])),
                    "reproducible": bool(int(row["reproducible"])),
                    "anchor_points": json.loads(str(row["anchor_points_json"])),
                }
            state[bucket].append(payload)
        return state

    def save_delta_log(
        self,
        session_id: str,
        source_label: str,
        payload: dict[str, Any],
        signature: str,
    ) -> int:
        """Speichert einen signierten Delta-Log."""
        cursor = self.connection.execute(
            """
            INSERT INTO delta_logs (session_id, timestamp, source_label, payload_json, signature)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                datetime.now(timezone.utc).isoformat(),
                source_label,
                json.dumps(payload),
                signature,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_delta_logs(self, session_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Liefert gespeicherte Delta-Logs fuer Anzeige und Export."""
        query = """
            SELECT id, session_id, timestamp, source_label, payload_json, signature
            FROM delta_logs
        """
        params: tuple[Any, ...] = ()
        if session_id is not None:
            query += " WHERE session_id = ?"
            params = (session_id,)
        query += " ORDER BY id DESC LIMIT ?"
        params = params + (int(max(1, limit)),)
        rows = self.connection.execute(query, params).fetchall()
        return [
            {
                "id": int(row["id"]),
                "session_id": str(row["session_id"]),
                "timestamp": str(row["timestamp"]),
                "source_label": str(row["source_label"]),
                "payload_json": json.loads(str(row["payload_json"])),
                "signature": str(row["signature"]),
            }
            for row in rows
        ]

    def save_export_log(
        self,
        session_id: str,
        export_kind: str,
        target_path: str,
        payload: dict[str, Any] | None = None,
        signature: str = "",
    ) -> int:
        """Haengt einen lokalen Export-Audit-Eintrag append-only an."""
        cursor = self.connection.execute(
            """
            INSERT INTO export_log (session_id, timestamp, export_kind, target_path, signature, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(session_id),
                self._now_iso(),
                str(export_kind),
                str(target_path),
                str(signature),
                json.dumps(payload or {}, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_export_logs(self, session_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        """Liefert Export-Auditdaten in chronologischer Rueckschau."""
        query = """
            SELECT id, session_id, timestamp, export_kind, target_path, signature, payload_json
            FROM export_log
        """
        params: tuple[Any, ...] = ()
        if session_id is not None:
            query += " WHERE session_id = ?"
            params = (str(session_id),)
        query += " ORDER BY id DESC LIMIT ?"
        params = params + (int(max(1, limit)),)
        rows = self.connection.execute(query, params).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            result.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "export_kind": str(row["export_kind"]),
                    "target_path": str(row["target_path"]),
                    "signature": str(row["signature"]),
                    "payload_json": payload,
                }
            )
        return result

    def update_anchor_prior(self, cells: list[tuple[int, int]]) -> None:
        """Aktualisiert das persistente Prior-Raster fuer Anchor-Haeufigkeiten."""
        if not cells:
            return
        for x_bin, y_bin in cells:
            self.connection.execute(
                """
                INSERT INTO anchor_priors (x_bin, y_bin, count)
                VALUES (?, ?, 1)
                ON CONFLICT(x_bin, y_bin) DO UPDATE SET count = count + 1
                """,
                (int(x_bin), int(y_bin)),
            )
        self.connection.commit()

    def get_anchor_priors(self, limit: int = 14) -> list[dict[str, float | int]]:
        """Liefert die haeufigsten Prior-Ankerzellen als normierte Positionen."""
        rows = self.connection.execute(
            """
            SELECT x_bin, y_bin, count
            FROM anchor_priors
            ORDER BY count DESC, y_bin ASC, x_bin ASC
            LIMIT ?
            """,
            (int(max(1, limit)),),
        ).fetchall()
        return [
            {
                "x_bin": int(row["x_bin"]),
                "y_bin": int(row["y_bin"]),
                "x_norm": float(row["x_bin"]) / 19.0,
                "y_norm": float(row["y_bin"]) / 19.0,
                "count": int(row["count"]),
            }
            for row in rows
        ]

    def save_alarm_event(
        self,
        session_id: str,
        reason: str,
        severity: str,
        payload: dict[str, Any],
    ) -> int:
        """Persistiert Alarmereignisse fuer Verstoss- oder Integritaetshinweise."""
        cursor = self.connection.execute(
            """
            INSERT INTO alarm_events (session_id, timestamp, reason, severity, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                datetime.now(timezone.utc).isoformat(),
                reason,
                severity,
                json.dumps(payload),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_alarm_count(self, session_id: str | None = None) -> int:
        """Liefert die Anzahl persistierter Alarmereignisse."""
        if session_id is None:
            row = self.connection.execute("SELECT COUNT(*) FROM alarm_events").fetchone()
        else:
            row = self.connection.execute(
                "SELECT COUNT(*) FROM alarm_events WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return int(row[0] if row is not None else 0)

    def reconstruct_original(
        self,
        record_id: int,
        session_context: SessionContext | None = None,
        prefer_raw: bool = True,
    ) -> bytes:
        """
        Rekonstruiert Originalbytes verlustfrei aus Delta und Session-Seed.

        Args:
            record_id: ID des gespeicherten Datei-Datensatzes.
        """
        row = self.connection.execute(
            "SELECT delta, session_seed, file_hash, source_label FROM fingerprints WHERE id = ?",
            (int(record_id),),
        ).fetchone()
        if row is None:
            raise ValueError("Datensatz nicht gefunden.")

        delta = self._unpack_delta(bytes(row["delta"]))
        seed = int(row["session_seed"])
        noise = SessionContext.noise_from_seed(seed, len(delta))
        reconstructed = bytes(a ^ b for a, b in zip(delta, noise))

        if not prefer_raw or session_context is None:
            return reconstructed

        raw_row = self.connection.execute(
            """
            SELECT session_id, source_label, file_hash, nonce, ciphertext
            FROM raw_storage_blobs
            WHERE fingerprint_id = ?
            LIMIT 1
            """,
            (int(record_id),),
        ).fetchone()
        if raw_row is None:
            return reconstructed

        key = session_context.file_delta_key_bytes(
            file_hash=str(raw_row["file_hash"]),
            record_id=int(record_id),
            session_id=str(raw_row["session_id"]),
        )
        if len(key) != 32:
            return reconstructed

        aad = (
            f"{int(record_id)}|{str(raw_row['session_id'])}|{str(raw_row['file_hash'])}|{str(raw_row['source_label'])}"
        ).encode("utf-8", errors="replace")
        try:
            decrypted = decrypt_bytes_aes256(
                nonce=bytes(raw_row["nonce"]),
                ciphertext=bytes(raw_row["ciphertext"]),
                key=key,
                aad=aad,
            )
        except Exception:
            return reconstructed
        expected_hash = str(row["file_hash"])
        if hashlib.sha256(decrypted).hexdigest() != expected_hash:
            return reconstructed
        if decrypted != reconstructed:
            return reconstructed
        return decrypted

    def get_latest_file_record(self, user_id: int | None = None) -> dict[str, Any] | None:
        """Liefert den neuesten lokal rekonstruierbaren Datei-Datensatz."""
        if user_id is None or int(user_id) <= 0:
            row = self.connection.execute(
                """
                SELECT id, session_id, timestamp, source_type, source_label, file_hash, file_size
                FROM fingerprints
                WHERE source_type = 'file'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        else:
            row = self.connection.execute(
                """
                SELECT f.id, f.session_id, f.timestamp, f.source_type, f.source_label, f.file_hash, f.file_size
                FROM fingerprints AS f
                JOIN app_sessions AS s ON s.session_id = f.session_id
                WHERE f.source_type = 'file' AND s.user_id = ?
                ORDER BY f.id DESC
                LIMIT 1
                """,
                (int(user_id),),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": int(row["id"]),
            "session_id": str(row["session_id"]),
            "timestamp": str(row["timestamp"]),
            "source_type": str(row["source_type"]),
            "source_label": str(row["source_label"]),
            "file_hash": str(row["file_hash"]),
            "file_size": int(row["file_size"]),
        }

    def has_users(self) -> bool:
        """Liefert, ob bereits mindestens ein lokaler Nutzer existiert."""
        row = self.connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return bool(int(row["count"]) if row is not None else 0)

    def create_user(
        self,
        username: str,
        password_hash: str,
        salt_hex: str,
        role: str,
        settings: dict[str, Any] | None = None,
        sync_identity: str | None = None,
        sync_secret: str | None = None,
    ) -> int:
        """Legt einen lokalen Nutzer persistent an."""
        identity = str(sync_identity or "").strip()
        secret_value = str(sync_secret or "").strip()
        if not identity or not secret_value:
            identity, secret_value = self._new_sync_materials()
        protected_secret = protect_local_secret(secret_value)
        cursor = self.connection.execute(
            """
            INSERT INTO users (username, password_hash, salt_hex, sync_identity, sync_secret, role, created_at, settings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(username),
                str(password_hash),
                str(salt_hex),
                identity,
                protected_secret,
                str(role),
                datetime.now(timezone.utc).isoformat(),
                json.dumps(settings or {}, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Liefert einen Nutzer samt Sicherheitsstatus ueber den Namen."""
        row = self.connection.execute(
            """
            SELECT id, username, password_hash, salt_hex, sync_identity, sync_secret, role, created_at, disabled, failed_attempts, locked_until, settings_json
            FROM users
            WHERE username = ?
            LIMIT 1
            """,
            (str(username),),
        ).fetchone()
        if row is None:
            return None
        sync_identity, sync_secret = self._ensure_user_sync_material(
            user_id=int(row["id"]),
            username=str(row["username"]),
            password_hash=str(row["password_hash"]),
            salt_hex=str(row["salt_hex"]),
            sync_identity=str(row["sync_identity"]),
            sync_secret=str(row["sync_secret"]),
        )
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "password_hash": str(row["password_hash"]),
            "salt_hex": str(row["salt_hex"]),
            "sync_identity": sync_identity,
            "sync_secret": sync_secret,
            "role": str(row["role"]),
            "created_at": str(row["created_at"]),
            "disabled": bool(int(row["disabled"])),
            "failed_attempts": int(row["failed_attempts"]),
            "locked_until": str(row["locked_until"]),
            "settings_json": json.loads(str(row["settings_json"])),
        }

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        """Liefert einen Nutzer samt Sicherheitsstatus ueber die ID."""
        row = self.connection.execute(
            """
            SELECT id, username, password_hash, salt_hex, sync_identity, sync_secret, role, created_at, disabled, failed_attempts, locked_until, settings_json
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (int(user_id),),
        ).fetchone()
        if row is None:
            return None
        sync_identity, sync_secret = self._ensure_user_sync_material(
            user_id=int(row["id"]),
            username=str(row["username"]),
            password_hash=str(row["password_hash"]),
            salt_hex=str(row["salt_hex"]),
            sync_identity=str(row["sync_identity"]),
            sync_secret=str(row["sync_secret"]),
        )
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "password_hash": str(row["password_hash"]),
            "salt_hex": str(row["salt_hex"]),
            "sync_identity": sync_identity,
            "sync_secret": sync_secret,
            "role": str(row["role"]),
            "created_at": str(row["created_at"]),
            "disabled": bool(int(row["disabled"])),
            "failed_attempts": int(row["failed_attempts"]),
            "locked_until": str(row["locked_until"]),
            "settings_json": json.loads(str(row["settings_json"])),
        }

    def list_users(
        self,
        exclude_user_id: int | None = None,
        include_disabled: bool = False,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Liefert lokale Nutzerlisten fuer Direktnachrichten und Gruppen."""
        params: list[Any] = []
        query = """
            SELECT id, username, role, disabled, created_at
            FROM users
            WHERE 1 = 1
        """
        if not include_disabled:
            query += " AND disabled = 0"
        if exclude_user_id is not None and int(exclude_user_id) > 0:
            query += " AND id != ?"
            params.append(int(exclude_user_id))
        query += " ORDER BY username ASC LIMIT ?"
        params.append(int(max(1, limit)))
        rows = self.connection.execute(query, tuple(params)).fetchall()
        return [
            {
                "id": int(row["id"]),
                "username": str(row["username"]),
                "role": str(row["role"]),
                "disabled": bool(int(row["disabled"])),
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    def update_user_security_state(
        self,
        user_id: int,
        failed_attempts: int,
        locked_until: str = "",
        disabled: bool | None = None,
    ) -> None:
        """Aktualisiert Fehlversuche, Sperrzeit und optional den Aktivstatus eines Nutzers."""
        if disabled is None:
            self.connection.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (int(failed_attempts), str(locked_until), int(user_id)),
            )
        else:
            self.connection.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?, disabled = ? WHERE id = ?",
                (int(failed_attempts), str(locked_until), int(bool(disabled)), int(user_id)),
            )
        self.connection.commit()

    def update_user_settings(self, user_id: int, settings_update: dict[str, Any]) -> dict[str, Any]:
        """Schreibt additive lokale Nutzereinstellungen zurueck."""
        current = self.get_user_by_id(int(user_id))
        if current is None:
            raise ValueError("Nutzer nicht gefunden.")
        settings = dict(current.get("settings_json", {}) or {})
        settings.update(dict(settings_update))
        self.connection.execute(
            "UPDATE users SET settings_json = ? WHERE id = ?",
            (json.dumps(settings, ensure_ascii=False), int(user_id)),
        )
        self.connection.commit()
        return settings

    def save_security_event(
        self,
        user_id: int,
        username: str,
        event_type: str,
        severity: str,
        payload: dict[str, Any],
    ) -> int:
        """Persistiert Audit-Ereignisse des lokalen Sicherheitsmodells."""
        cursor = self.connection.execute(
            """
            INSERT INTO security_events (timestamp, user_id, username, event_type, severity, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                int(user_id),
                str(username),
                str(event_type),
                str(severity),
                json.dumps(payload, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_security_events(self, limit: int = 120, user_id: int | None = None) -> list[dict[str, Any]]:
        """Liefert Sicherheitsereignisse fuer Audit-Ansichten."""
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT id, timestamp, user_id, username, event_type, severity, payload_json
                FROM security_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(1, limit)),),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT id, timestamp, user_id, username, event_type, severity, payload_json
                FROM security_events
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(user_id), int(max(1, limit))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            result.append(
                {
                    "id": int(row["id"]),
                    "timestamp": str(row["timestamp"]),
                    "user_id": int(row["user_id"]),
                    "username": str(row["username"]),
                    "event_type": str(row["event_type"]),
                    "severity": str(row["severity"]),
                    "payload_json": payload,
                }
            )
        return result

    def save_gp_rule_snapshot(
        self,
        session_id: str,
        scope: str,
        rule_type: str,
        payload: dict[str, Any],
        signature: str = "",
        version: int = 1,
        is_honeypot: bool = False,
    ) -> int:
        """Haengt einen GP-Regelstand append-only an."""
        payload_json = json.dumps(payload, ensure_ascii=False)
        rule_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        cursor = self.connection.execute(
            """
            INSERT INTO gp_rule_snapshots (
                session_id, timestamp, scope, rule_type, version, rule_hash, signature, is_honeypot, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(session_id),
                self._now_iso(),
                str(scope),
                str(rule_type),
                int(version),
                rule_hash,
                str(signature),
                int(bool(is_honeypot)),
                payload_json,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_gp_rule_snapshots(
        self,
        limit: int = 120,
        scope: str = "",
        include_honeypots: bool = True,
    ) -> list[dict[str, Any]]:
        """Liefert lokale GP-Regelstaende fuer Validierung und Audit."""
        params: list[Any] = []
        query = """
            SELECT id, session_id, timestamp, scope, rule_type, version, rule_hash, signature, is_honeypot, payload_json
            FROM gp_rule_snapshots
            WHERE 1 = 1
        """
        if scope:
            query += " AND scope = ?"
            params.append(str(scope))
        if not include_honeypots:
            query += " AND is_honeypot = 0"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(int(max(1, limit)))
        rows = self.connection.execute(query, tuple(params)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            result.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "scope": str(row["scope"]),
                    "rule_type": str(row["rule_type"]),
                    "version": int(row["version"]),
                    "rule_hash": str(row["rule_hash"]),
                    "signature": str(row["signature"]),
                    "is_honeypot": bool(int(row["is_honeypot"])),
                    "payload_json": payload,
                }
            )
        return result

    def open_user_session(
        self,
        session_id: str,
        user_id: int,
        username: str,
        role: str,
        login_at: str,
        live_key_hash: str,
        live_key_fingerprint: str,
        algo_primary: str,
        algo_secondary: str,
        payload: dict[str, Any] | None = None,
    ) -> int:
        """Persistiert eine neue Login-Session fuer einen Nutzer."""
        cursor = self.connection.execute(
            """
            INSERT INTO app_sessions (
                session_id, user_id, username, role, login_at, live_key_hash, live_key_fingerprint,
                algo_primary, algo_secondary, status, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(session_id),
                int(user_id),
                str(username),
                str(role),
                str(login_at),
                str(live_key_hash),
                str(live_key_fingerprint),
                str(algo_primary),
                str(algo_secondary),
                "active",
                json.dumps(payload or {}, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def close_user_session(self, session_id: str) -> None:
        """Markiert eine Login-Session sauber als beendet."""
        self.connection.execute(
            """
            UPDATE app_sessions
            SET logout_at = ?, status = 'closed'
            WHERE session_id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), str(session_id)),
        )
        self.connection.commit()

    def record_chat_sync_event(
        self,
        event_uid: str,
        event_type: str,
        source_url: str,
        remote_event_id: int,
        payload: dict[str, Any] | None = None,
    ) -> bool:
        """Registriert ein verarbeitetes Sync-Ereignis idempotent."""
        normalized_uid = str(event_uid).strip()
        if not normalized_uid:
            return False
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO chat_sync_events (
                event_uid, event_type, source_url, remote_event_id, created_at, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_uid,
                str(event_type),
                str(source_url),
                int(remote_event_id),
                self._now_iso(),
                json.dumps(payload or {}, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return bool(int(cursor.rowcount or 0))

    def has_chat_sync_event(self, event_uid: str) -> bool:
        """Prueft, ob ein Sync-Ereignis bereits lokal angewendet wurde."""
        row = self.connection.execute(
            "SELECT 1 FROM chat_sync_events WHERE event_uid = ? LIMIT 1",
            (str(event_uid).strip(),),
        ).fetchone()
        return row is not None

    def get_chat_sync_cursor(self, endpoint: str) -> int:
        """Liefert die letzte bekannte Remote-ID fuer ein Relay-Ende."""
        row = self.connection.execute(
            "SELECT last_event_id FROM chat_sync_cursors WHERE endpoint = ? LIMIT 1",
            (str(endpoint).strip(),),
        ).fetchone()
        if row is None:
            return 0
        return int(row["last_event_id"])

    def update_chat_sync_cursor(self, endpoint: str, last_event_id: int) -> None:
        """Schreibt den Fortschritt eines Relay-Polls persistent zurueck."""
        self.connection.execute(
            """
            INSERT INTO chat_sync_cursors (endpoint, last_event_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(endpoint) DO UPDATE SET
                last_event_id = excluded.last_event_id,
                updated_at = excluded.updated_at
            """,
            (
                str(endpoint).strip(),
                int(last_event_id),
                self._now_iso(),
            ),
        )
        self.connection.commit()

    def export_user_sync_records(self, limit: int = 400) -> list[dict[str, Any]]:
        """Exportiert lokale Nutzerstammdaten fuer vertrauensbasierten Chat-Sync."""
        rows = self.connection.execute(
            """
            SELECT id, username, password_hash, salt_hex, sync_identity, sync_secret, role, created_at, disabled, settings_json
            FROM users
            ORDER BY id ASC
            LIMIT ?
            """,
            (int(max(1, limit)),),
        ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            settings_raw = str(row["settings_json"]).strip()
            try:
                settings = json.loads(settings_raw) if settings_raw else {}
            except Exception:
                settings = {}
            sync_identity, sync_secret = self._ensure_user_sync_material(
                user_id=int(row["id"]),
                username=str(row["username"]),
                password_hash=str(row["password_hash"]),
                salt_hex=str(row["salt_hex"]),
                sync_identity=str(row["sync_identity"]),
                sync_secret=str(row["sync_secret"]),
            )
            records.append(
                {
                    "username": str(row["username"]),
                    "sync_identity": sync_identity,
                    "sync_secret": sync_secret,
                    "role": str(row["role"]),
                    "created_at": str(row["created_at"]),
                    "disabled": bool(int(row["disabled"])),
                    "auth_source": "relay_identity",
                }
            )
        return records

    def apply_synced_user_record(self, payload: dict[str, Any]) -> int:
        """Spiegelt einen remote synchronisierten Nutzer lokal nach Username."""
        username = str(payload.get("username", "")).strip()
        sync_identity = str(payload.get("sync_identity", "")).strip()
        sync_secret = str(payload.get("sync_secret", "")).strip()
        if not username or not sync_identity or not sync_secret:
            raise ValueError("Unvollstaendiger Nutzer-Sync-Payload.")
        role = str(payload.get("role", "operator") or "operator")
        created_at = str(payload.get("created_at", "") or self._now_iso())
        disabled = int(bool(payload.get("disabled", False)))
        existing = self.get_user_by_username(username)
        protected_sync_secret = protect_local_secret(sync_secret)
        if existing is None:
            placeholder_password_hash = hashlib.sha256(
                f"remote-sync-disabled|{username}|{sync_identity}|{GENESIS_HASH}".encode("utf-8")
            ).hexdigest()
            placeholder_salt_hex = hashlib.blake2b(
                f"remote-sync-disabled|{username}|{sync_identity}|{GENESIS_SEED}".encode("utf-8"),
                digest_size=16,
            ).hexdigest()
            cursor = self.connection.execute(
                """
                INSERT INTO users (
                    username, password_hash, salt_hex, sync_identity, sync_secret, role, created_at,
                    disabled, failed_attempts, locked_until, settings_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)
                """,
                (
                    username,
                    placeholder_password_hash,
                    placeholder_salt_hex,
                    sync_identity,
                    protected_sync_secret,
                    role,
                    created_at,
                    disabled,
                    json.dumps({"sync_remote_identity": True, "auth_source": "relay_identity"}, ensure_ascii=False),
                ),
            )
            self.connection.commit()
            return int(cursor.lastrowid)
        settings = dict(existing.get("settings_json", {}) or {})
        if settings.get("sync_remote_identity", False):
            self.connection.execute(
                """
                UPDATE users
                SET sync_identity = ?, sync_secret = ?, role = ?, created_at = ?, disabled = ?, settings_json = ?
                WHERE username = ?
                """,
                (
                    sync_identity,
                    protected_sync_secret,
                    role,
                    created_at,
                    disabled,
                    json.dumps({"sync_remote_identity": True, "auth_source": "relay_identity"}, ensure_ascii=False),
                    username,
                ),
            )
            self.connection.commit()
            refreshed = self.get_user_by_username(username)
            return int(refreshed["id"]) if refreshed is not None else int(existing["id"])
        self.connection.execute(
            """
            UPDATE users
            SET sync_identity = ?, sync_secret = ?
            WHERE username = ?
            """,
            (
                sync_identity,
                protected_sync_secret,
                username,
            ),
        )
        self.connection.commit()
        refreshed = self.get_user_by_username(username)
        return int(refreshed["id"]) if refreshed is not None else int(existing["id"])

    def get_chat_message_raw(self, message_id: int) -> dict[str, Any] | None:
        """Liefert einen rohen Chat-Datensatz fuer Sync-Export."""
        row = self.connection.execute(
            """
            SELECT id, session_id, user_id, username, channel, timestamp, message_text,
                   fingerprint_id, is_private, is_group, recipient_user_id, recipient_username,
                   group_id, key_version, encrypted_payload, reply_text, encrypted_reply_text,
                   visible_to_shanway, payload_json
            FROM chat_messages
            WHERE id = ?
            LIMIT 1
            """,
            (int(message_id),),
        ).fetchone()
        if row is None:
            return None
        payload_raw = str(row["payload_json"]).strip()
        try:
            payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            payload = {}
        return {
            "id": int(row["id"]),
            "session_id": str(row["session_id"]),
            "user_id": int(row["user_id"]),
            "username": str(row["username"]),
            "channel": str(row["channel"]),
            "timestamp": str(row["timestamp"]),
            "message_text": str(row["message_text"]),
            "fingerprint_id": int(row["fingerprint_id"]),
            "is_private": bool(int(row["is_private"])),
            "is_group": bool(int(row["is_group"])),
            "recipient_user_id": int(row["recipient_user_id"]),
            "recipient_username": str(row["recipient_username"]),
            "group_id": str(row["group_id"]),
            "key_version": int(row["key_version"]),
            "encrypted_payload": str(row["encrypted_payload"]),
            "reply_text": str(row["reply_text"]),
            "encrypted_reply_text": str(row["encrypted_reply_text"]),
            "visible_to_shanway": bool(int(row["visible_to_shanway"])),
            "payload_json": payload,
        }

    def save_chat_message(
        self,
        session_id: str,
        user_id: int,
        username: str,
        message_text: str,
        fingerprint_id: int = 0,
        reply_text: str = "",
        channel: str = "global",
        payload: dict[str, Any] | None = None,
        is_private: bool = False,
        recipient_user_id: int = 0,
        recipient_username: str = "",
        group_id: str = "",
        key_version: int = 0,
        visible_to_shanway: bool = True,
    ) -> int:
        """Persistiert eine lokale Chatnachricht samt struktureller Antwort."""
        payload_box = dict(payload or {})
        clean_payload = {
            str(key): value
            for key, value in payload_box.items()
            if not str(key).startswith("_")
        }
        encrypted_payload = ""
        encrypted_reply_text = ""
        stored_message_text = str(message_text)
        stored_reply_text = str(reply_text)
        group_name = str(group_id).strip()
        recipient_name = str(recipient_username).strip()
        resolved_key_version = int(max(0, key_version))
        if bool(is_private) or group_name:
            if not crypto_available():
                raise RuntimeError(
                    "Private und Gruppen-Chats benoetigen das Paket 'cryptography'."
                )
            if group_name:
                active_group_key = str(payload_box.get("_group_key", "")).strip()
                if not active_group_key:
                    active_group_key, resolved_key_version = self._resolve_group_key_for_user(
                        group_name,
                        str(username),
                    )
                else:
                    resolved_key_version = int(
                        payload_box.get("_group_key_version", resolved_key_version or 1) or 1
                    )
                encrypted_payload = (
                    encrypt_text(str(message_text), active_group_key) if str(message_text) else ""
                )
                encrypted_reply_text = (
                    encrypt_text(str(reply_text), active_group_key) if str(reply_text) else ""
                )
            else:
                if not recipient_name:
                    raise ValueError("Private Chats benoetigen einen Empfaenger.")
                private_key = self._private_chat_key(str(username), recipient_name)
                encrypted_payload = (
                    encrypt_text(str(message_text), private_key) if str(message_text) else ""
                )
                encrypted_reply_text = (
                    encrypt_text(str(reply_text), private_key) if str(reply_text) else ""
                )
                resolved_key_version = max(1, resolved_key_version or 1)
            stored_message_text = HIDDEN_CHAT_TEXT if str(message_text) else ""
            stored_reply_text = HIDDEN_CHAT_TEXT if str(reply_text) else ""
        cursor = self.connection.execute(
            """
            INSERT INTO chat_messages (
                session_id, user_id, username, channel, timestamp, message_text,
                fingerprint_id, is_private, is_group, recipient_user_id, recipient_username,
                group_id, key_version, encrypted_payload, reply_text, encrypted_reply_text,
                visible_to_shanway, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(session_id),
                int(user_id),
                str(username),
                str(channel),
                self._now_iso(),
                stored_message_text,
                int(fingerprint_id),
                int(bool(is_private)),
                int(bool(group_name)),
                int(recipient_user_id),
                recipient_name,
                group_name,
                int(resolved_key_version),
                encrypted_payload,
                stored_reply_text,
                encrypted_reply_text,
                int(bool(visible_to_shanway)),
                json.dumps(clean_payload, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_chat_messages(
        self,
        limit: int = 200,
        channel: str = "global",
        current_user_id: int | None = None,
        current_username: str = "",
    ) -> list[dict[str, Any]]:
        """Liefert Chatverlaeufe kanal- und zugriffsspezifisch."""
        normalized_channel = str(channel).strip() or "global"
        rows: list[sqlite3.Row]
        if normalized_channel.startswith("private:"):
            partner = normalized_channel.split(":", 1)[1].strip()
            rows = list(
                self.connection.execute(
                    """
                    SELECT id, session_id, user_id, username, channel, timestamp, message_text,
                           fingerprint_id, is_private, is_group, recipient_user_id, recipient_username,
                           group_id, key_version, encrypted_payload, reply_text, encrypted_reply_text,
                           visible_to_shanway, payload_json
                    FROM chat_messages
                    WHERE is_private = 1
                      AND is_group = 0
                      AND (
                            (username = ? AND recipient_username = ?)
                         OR (username = ? AND recipient_username = ?)
                      )
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (
                        str(current_username),
                        partner,
                        partner,
                        str(current_username),
                        int(max(1, limit)),
                    ),
                ).fetchall()
            )
        elif normalized_channel.startswith("group:"):
            group_id = normalized_channel.split(":", 1)[1].strip()
            member_row = self._group_member_row(group_id, str(current_username))
            if member_row is None or not bool(int(member_row["active"])):
                return []
            rows = list(
                self.connection.execute(
                    """
                    SELECT id, session_id, user_id, username, channel, timestamp, message_text,
                           fingerprint_id, is_private, is_group, recipient_user_id, recipient_username,
                           group_id, key_version, encrypted_payload, reply_text, encrypted_reply_text,
                           visible_to_shanway, payload_json
                    FROM chat_messages
                    WHERE group_id = ? AND is_group = 1
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (group_id, int(max(1, limit))),
                ).fetchall()
            )
        else:
            rows = list(
                self.connection.execute(
                    """
                    SELECT id, session_id, user_id, username, channel, timestamp, message_text,
                           fingerprint_id, is_private, is_group, recipient_user_id, recipient_username,
                           group_id, key_version, encrypted_payload, reply_text, encrypted_reply_text,
                           visible_to_shanway, payload_json
                    FROM chat_messages
                    WHERE channel = ? AND is_private = 0 AND is_group = 0
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (normalized_channel, int(max(1, limit))),
                ).fetchall()
            )
        result: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            is_private_row = bool(int(row["is_private"]))
            is_group_row = bool(int(row["is_group"]))
            message_text = str(row["message_text"])
            reply_text = str(row["reply_text"])
            if is_private_row or is_group_row:
                try:
                    if is_group_row:
                        group_key, _ = self._resolve_group_key_for_user(
                            str(row["group_id"]),
                            str(current_username),
                        )
                        if str(row["encrypted_payload"]).strip():
                            message_text = decrypt_text(str(row["encrypted_payload"]), group_key)
                        if str(row["encrypted_reply_text"]).strip():
                            reply_text = decrypt_text(str(row["encrypted_reply_text"]), group_key)
                    else:
                        left_name = str(row["username"]).strip()
                        right_name = str(row["recipient_username"]).strip()
                        partner_name = right_name if left_name == str(current_username).strip() else left_name
                        private_key = self._private_chat_key(str(current_username).strip(), partner_name)
                        if str(row["encrypted_payload"]).strip():
                            message_text = decrypt_text(str(row["encrypted_payload"]), private_key)
                        if str(row["encrypted_reply_text"]).strip():
                            reply_text = decrypt_text(str(row["encrypted_reply_text"]), private_key)
                except (InvalidToken, PermissionError, RuntimeError, ValueError):
                    message_text = UNREADABLE_CHAT_TEXT
                    reply_text = UNREADABLE_CHAT_TEXT if str(row["encrypted_reply_text"]).strip() else ""
            result.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "user_id": int(row["user_id"]),
                    "username": str(row["username"]),
                    "channel": str(row["channel"]),
                    "timestamp": str(row["timestamp"]),
                    "message_text": message_text,
                    "fingerprint_id": int(row["fingerprint_id"]),
                    "reply_text": reply_text,
                    "is_private": is_private_row,
                    "is_group": is_group_row,
                    "recipient_user_id": int(row["recipient_user_id"]),
                    "recipient_username": str(row["recipient_username"]),
                    "group_id": str(row["group_id"]),
                    "key_version": int(row["key_version"]),
                    "visible_to_shanway": bool(int(row["visible_to_shanway"])),
                    "payload_json": payload,
                }
            )
        return result

    def apply_synced_chat_message(self, payload: dict[str, Any]) -> int:
        """Importiert einen remote synchronisierten Chat-Datensatz roh und idempotent ueber Event-Dedupe."""
        username = str(payload.get("username", "")).strip()
        if not username:
            raise ValueError("Chat-Sync-Payload ohne Username.")
        local_user = self.get_user_by_username(username)
        local_recipient = self.get_user_by_username(str(payload.get("recipient_username", "")).strip())
        cursor = self.connection.execute(
            """
            INSERT INTO chat_messages (
                session_id, user_id, username, channel, timestamp, message_text,
                fingerprint_id, is_private, is_group, recipient_user_id, recipient_username,
                group_id, key_version, encrypted_payload, reply_text, encrypted_reply_text,
                visible_to_shanway, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("session_id", "")).strip() or f"SYNC-{uuid4().hex}",
                int(local_user["id"]) if isinstance(local_user, dict) else int(payload.get("user_id", 0) or 0),
                username,
                str(payload.get("channel", "global") or "global"),
                str(payload.get("timestamp", "") or self._now_iso()),
                str(payload.get("message_text", "")),
                int(payload.get("fingerprint_id", 0) or 0),
                int(bool(payload.get("is_private", False))),
                int(bool(payload.get("is_group", False))),
                int(local_recipient["id"]) if isinstance(local_recipient, dict) else int(payload.get("recipient_user_id", 0) or 0),
                str(payload.get("recipient_username", "")),
                str(payload.get("group_id", "")),
                int(payload.get("key_version", 0) or 0),
                str(payload.get("encrypted_payload", "")),
                str(payload.get("reply_text", "")),
                str(payload.get("encrypted_reply_text", "")),
                int(bool(payload.get("visible_to_shanway", True))),
                json.dumps(payload.get("payload_json", {}) or {}, ensure_ascii=False),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_chat_group_sync_snapshot(self, group_id: str) -> dict[str, Any] | None:
        """Exportiert eine Gruppe samt Mitglieder- und Key-Zustand fuer Mehrrechner-Sync."""
        group_row = self._group_row(group_id)
        if group_row is None:
            return None
        members = self.connection.execute(
            """
            SELECT group_id, user_id, username, role, joined_at, active,
                   encrypted_group_key, key_version, payload_json
            FROM chat_group_members
            WHERE group_id = ?
            ORDER BY username ASC
            """,
            (str(group_id),),
        ).fetchall()
        snapshot_members: list[dict[str, Any]] = []
        for row in members:
            payload_raw = str(row["payload_json"]).strip()
            try:
                member_payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                member_payload = {}
            snapshot_members.append(
                {
                    "user_id": int(row["user_id"]),
                    "username": str(row["username"]),
                    "role": str(row["role"]),
                    "joined_at": str(row["joined_at"]),
                    "active": bool(int(row["active"])),
                    "encrypted_group_key": str(row["encrypted_group_key"]),
                    "key_version": int(row["key_version"]),
                    "payload_json": member_payload,
                }
            )
        payload_raw = str(group_row["payload_json"]).strip()
        try:
            group_payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            group_payload = {}
        return {
            "group_id": str(group_row["group_id"]),
            "group_name": str(group_row["group_name"]),
            "created_by_user_id": int(group_row["created_by_user_id"]),
            "created_by_username": str(group_row["created_by_username"]),
            "created_at": str(group_row["created_at"]),
            "shanway_enabled": bool(int(group_row["shanway_enabled"])),
            "key_version": int(group_row["key_version"]),
            "payload_json": group_payload,
            "members": snapshot_members,
        }

    def apply_synced_chat_group_snapshot(self, payload: dict[str, Any]) -> None:
        """Spiegelt einen remote synchronisierten Gruppen-Snapshot lokal nach group_id."""
        group_id = str(payload.get("group_id", "")).strip()
        group_name = str(payload.get("group_name", "")).strip()
        if not group_id or not group_name:
            raise ValueError("Unvollstaendiger Gruppen-Sync-Payload.")
        creator_name = str(payload.get("created_by_username", "")).strip()
        creator_record = self.get_user_by_username(creator_name) if creator_name else None
        self.connection.execute(
            """
            INSERT INTO chat_groups (
                group_id, group_name, created_by_user_id, created_by_username,
                created_at, shanway_enabled, key_version, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_id) DO UPDATE SET
                group_name = excluded.group_name,
                created_by_user_id = excluded.created_by_user_id,
                created_by_username = excluded.created_by_username,
                created_at = excluded.created_at,
                shanway_enabled = excluded.shanway_enabled,
                key_version = excluded.key_version,
                payload_json = excluded.payload_json
            """,
            (
                group_id,
                group_name,
                int(creator_record["id"]) if isinstance(creator_record, dict) else int(payload.get("created_by_user_id", 0) or 0),
                creator_name,
                str(payload.get("created_at", "") or self._now_iso()),
                int(bool(payload.get("shanway_enabled", False))),
                int(payload.get("key_version", 1) or 1),
                json.dumps(payload.get("payload_json", {}) or {}, ensure_ascii=False),
            ),
        )
        snapshot_usernames: list[str] = []
        for member in list(payload.get("members", [])):
            member_box = dict(member)
            member_name = str(member_box.get("username", "")).strip()
            if not member_name:
                continue
            snapshot_usernames.append(member_name)
            user_record = self.get_user_by_username(member_name)
            self.connection.execute(
                """
                INSERT INTO chat_group_members (
                    group_id, user_id, username, role, joined_at, active,
                    encrypted_group_key, key_version, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(group_id, username) DO UPDATE SET
                    user_id = excluded.user_id,
                    role = excluded.role,
                    joined_at = excluded.joined_at,
                    active = excluded.active,
                    encrypted_group_key = excluded.encrypted_group_key,
                    key_version = excluded.key_version,
                    payload_json = excluded.payload_json
                """,
                (
                    group_id,
                    int(user_record["id"]) if isinstance(user_record, dict) else int(member_box.get("user_id", 0) or 0),
                    member_name,
                    str(member_box.get("role", "member") or "member"),
                    str(member_box.get("joined_at", "") or self._now_iso()),
                    int(bool(member_box.get("active", True))),
                    str(member_box.get("encrypted_group_key", "")),
                    int(member_box.get("key_version", payload.get("key_version", 1)) or 1),
                    json.dumps(member_box.get("payload_json", {}) or {}, ensure_ascii=False),
                ),
            )
        if snapshot_usernames:
            placeholders = ",".join("?" for _ in snapshot_usernames)
            self.connection.execute(
                f"UPDATE chat_group_members SET active = 0 WHERE group_id = ? AND username NOT IN ({placeholders})",
                (group_id, *snapshot_usernames),
            )
        self.connection.commit()

    def delete_synced_chat_group(self, group_id: str) -> None:
        """Entfernt eine remote geloeschte Gruppe lokal samt Verlauf."""
        self.connection.execute("DELETE FROM chat_messages WHERE group_id = ?", (str(group_id),))
        self.connection.execute("DELETE FROM chat_group_members WHERE group_id = ?", (str(group_id),))
        self.connection.execute("DELETE FROM chat_group_consensus WHERE group_id = ?", (str(group_id),))
        self.connection.execute("DELETE FROM chat_groups WHERE group_id = ?", (str(group_id),))
        self.connection.commit()

    def create_chat_group(
        self,
        creator_user_id: int,
        creator_username: str,
        group_name: str,
        member_usernames: list[str],
        shanway_enabled: bool = False,
    ) -> dict[str, Any]:
        """Legt eine lokale verschluesselte Chat-Gruppe an."""
        if not crypto_available():
            raise RuntimeError(
                "Gruppen-Chats benoetigen das Paket 'cryptography'."
            )
        normalized_name = " ".join(str(group_name).split()).strip()
        if len(normalized_name) < 3 or len(normalized_name) > 50:
            raise ValueError("Der Gruppenname muss zwischen 3 und 50 Zeichen lang sein.")

        creator_record = self.get_user_by_id(int(creator_user_id))
        if creator_record is None:
            raise ValueError("Der erzeugende Nutzer existiert nicht.")
        normalized_creator = str(creator_username).strip()
        if str(creator_record["username"]) != normalized_creator:
            raise PermissionError("Gruppenerzeugung nur fuer den aktuellen Nutzer erlaubt.")

        members_map: dict[str, dict[str, Any]] = {normalized_creator: creator_record}
        for raw_name in member_usernames:
            normalized = str(raw_name).strip()
            if not normalized or normalized == SHANWAY_MEMBER_NAME:
                continue
            record = self.get_user_by_username(normalized)
            if record is None or bool(record.get("disabled", False)):
                raise ValueError(f"Mitglied nicht verfuegbar: {normalized}")
            members_map[normalized] = record

        group_id = uuid4().hex
        created_at = self._now_iso()
        group_key = generate_group_key()
        self.connection.execute(
            """
            INSERT INTO chat_groups (
                group_id, group_name, created_by_user_id, created_by_username,
                created_at, shanway_enabled, key_version, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                group_id,
                normalized_name,
                int(creator_user_id),
                normalized_creator,
                created_at,
                int(bool(shanway_enabled)),
                1,
                json.dumps(
                    {
                        "member_count": len(members_map),
                        "scope": "local_encrypted",
                        "analysis_mode": "shared",
                    },
                    ensure_ascii=False,
                ),
            ),
        )
        for member_name, record in members_map.items():
            role = "admin" if member_name == normalized_creator else "member"
            self.connection.execute(
                """
                INSERT INTO chat_group_members (
                    group_id, user_id, username, role, joined_at, active,
                    encrypted_group_key, key_version, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    group_id,
                    int(record["id"]),
                    member_name,
                    role,
                    created_at,
                    1,
                    self._encrypt_group_key_for_member(group_key, member_name),
                    1,
                    json.dumps({}, ensure_ascii=False),
                ),
            )
        if bool(shanway_enabled):
            self.connection.execute(
                """
                INSERT INTO chat_group_members (
                    group_id, user_id, username, role, joined_at, active,
                    encrypted_group_key, key_version, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    group_id,
                    0,
                    SHANWAY_MEMBER_NAME,
                    "assistant",
                    created_at,
                    1,
                    self._encrypt_group_key_for_member(group_key, SHANWAY_MEMBER_NAME),
                    1,
                    json.dumps({"assistant": True}, ensure_ascii=False),
                ),
            )
        self.connection.commit()
        return self.get_chat_group(group_id, current_username=normalized_creator) or {
            "group_id": group_id,
            "group_name": normalized_name,
            "shanway_enabled": bool(shanway_enabled),
        }

    def get_chat_group(self, group_id: str, current_username: str = "") -> dict[str, Any] | None:
        """Liefert Metadaten einer Gruppe inklusive aktueller Rolle."""
        row = self._group_row(group_id)
        if row is None:
            return None
        member_row = self._group_member_row(group_id, current_username) if current_username else None
        count_row = self.connection.execute(
            """
            SELECT COUNT(*) AS member_count
            FROM chat_group_members
            WHERE group_id = ? AND active = 1 AND username != ?
            """,
            (str(group_id), SHANWAY_MEMBER_NAME),
        ).fetchone()
        payload_raw = str(row["payload_json"]).strip()
        try:
            group_payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            group_payload = {}
        return {
            "group_id": str(row["group_id"]),
            "group_name": str(row["group_name"]),
            "created_by_user_id": int(row["created_by_user_id"]),
            "created_by_username": str(row["created_by_username"]),
            "created_at": str(row["created_at"]),
            "shanway_enabled": bool(int(row["shanway_enabled"])),
            "key_version": int(row["key_version"]),
            "member_count": int(count_row["member_count"]) if count_row is not None else 0,
            "current_role": str(member_row["role"]) if member_row is not None else "",
            "current_active": bool(int(member_row["active"])) if member_row is not None else False,
            "analysis_mode": str(group_payload.get("analysis_mode", "shared") or "shared"),
            "payload_json": group_payload,
        }

    def get_chat_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Liefert aktive Gruppenmitglieder fuer Verwaltung und Anzeige."""
        return [
            {
                "group_id": str(row["group_id"]),
                "user_id": int(row["user_id"]),
                "username": str(row["username"]),
                "role": str(row["role"]),
                "joined_at": str(row["joined_at"]),
                "active": bool(int(row["active"])),
                "key_version": int(row["key_version"]),
            }
            for row in self._active_group_member_rows(group_id)
        ]

    def add_group_member(self, group_id: str, actor_username: str, new_username: str) -> bool:
        """Fuegt ein Mitglied hinzu und verpackt den aktuellen Gruppen-Key fuer es."""
        if not self._is_group_admin(group_id, actor_username):
            raise PermissionError("Nur Gruppen-Admins duerfen Mitglieder hinzufuegen.")
        normalized = str(new_username).strip()
        record = self.get_user_by_username(normalized)
        if record is None or bool(record.get("disabled", False)):
            raise ValueError("Der neue Nutzer ist nicht verfuegbar.")
        existing = self._group_member_row(group_id, normalized)
        if existing is not None and bool(int(existing["active"])):
            raise ValueError("Dieser Nutzer ist bereits Mitglied.")

        group_key, key_version = self._resolve_group_key_for_user(group_id, actor_username)
        joined_at = self._now_iso()
        if existing is None:
            self.connection.execute(
                """
                INSERT INTO chat_group_members (
                    group_id, user_id, username, role, joined_at, active,
                    encrypted_group_key, key_version, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(group_id),
                    int(record["id"]),
                    normalized,
                    "member",
                    joined_at,
                    1,
                    self._encrypt_group_key_for_member(group_key, normalized),
                    int(key_version),
                    json.dumps({}, ensure_ascii=False),
                ),
            )
        else:
            self.connection.execute(
                """
                UPDATE chat_group_members
                SET user_id = ?, role = 'member', joined_at = ?, active = 1,
                    encrypted_group_key = ?, key_version = ?
                WHERE group_id = ? AND username = ?
                """,
                (
                    int(record["id"]),
                    joined_at,
                    self._encrypt_group_key_for_member(group_key, normalized),
                    int(key_version),
                    str(group_id),
                    normalized,
                ),
            )
        self.connection.commit()
        return True

    def remove_group_member(self, group_id: str, actor_username: str, target_username: str) -> bool:
        """Entfernt ein Mitglied aus der Gruppe und rotiert danach den Schluessel."""
        normalized_target = str(target_username).strip()
        if normalized_target == SHANWAY_MEMBER_NAME:
            return self.toggle_group_shanway(group_id, actor_username, enabled=False)
        if not self._is_group_admin(group_id, actor_username):
            raise PermissionError("Nur Gruppen-Admins duerfen Mitglieder entfernen.")
        target_row = self._group_member_row(group_id, normalized_target)
        if target_row is None or not bool(int(target_row["active"])):
            raise ValueError("Dieses Mitglied ist nicht aktiv.")

        active_members = self._active_group_member_rows(group_id)
        remaining_humans = [
            row
            for row in active_members
            if str(row["username"]) not in (normalized_target, SHANWAY_MEMBER_NAME)
        ]
        self.connection.execute(
            """
            UPDATE chat_group_members
            SET active = 0
            WHERE group_id = ? AND username = ?
            """,
            (str(group_id), normalized_target),
        )
        if not remaining_humans:
            self.connection.execute("DELETE FROM chat_messages WHERE group_id = ?", (str(group_id),))
            self.connection.execute("DELETE FROM chat_group_members WHERE group_id = ?", (str(group_id),))
            self._delete_group_consensus(group_id)
            self.connection.execute("DELETE FROM chat_groups WHERE group_id = ?", (str(group_id),))
            self.connection.commit()
            return True

        if str(target_row["role"]) == "admin":
            admin_names = [str(row["username"]) for row in remaining_humans if str(row["role"]) == "admin"]
            if not admin_names:
                promoted = sorted(str(row["username"]) for row in remaining_humans)[0]
                self.connection.execute(
                    """
                    UPDATE chat_group_members
                    SET role = 'admin'
                    WHERE group_id = ? AND username = ?
                    """,
                    (str(group_id), promoted),
                )
        self._rotate_group_key(group_id)
        self.connection.commit()
        return True

    def leave_group(self, group_id: str, username: str) -> bool:
        """Laesst einen Nutzer selbst aus der Gruppe austreten."""
        normalized = str(username).strip()
        current = self._group_member_row(group_id, normalized)
        if current is None or not bool(int(current["active"])):
            return False
        active_members = self._active_group_member_rows(group_id)
        remaining_humans = [
            row
            for row in active_members
            if str(row["username"]) not in (normalized, SHANWAY_MEMBER_NAME)
        ]
        self.connection.execute(
            """
            UPDATE chat_group_members
            SET active = 0
            WHERE group_id = ? AND username = ?
            """,
            (str(group_id), normalized),
        )
        if not remaining_humans:
            self.connection.execute("DELETE FROM chat_messages WHERE group_id = ?", (str(group_id),))
            self.connection.execute("DELETE FROM chat_group_members WHERE group_id = ?", (str(group_id),))
            self._delete_group_consensus(group_id)
            self.connection.execute("DELETE FROM chat_groups WHERE group_id = ?", (str(group_id),))
            self.connection.commit()
            return True

        if str(current["role"]) == "admin":
            admin_names = [str(row["username"]) for row in remaining_humans if str(row["role"]) == "admin"]
            if not admin_names:
                promoted = sorted(str(row["username"]) for row in remaining_humans)[0]
                self.connection.execute(
                    """
                    UPDATE chat_group_members
                    SET role = 'admin'
                    WHERE group_id = ? AND username = ?
                    """,
                    (str(group_id), promoted),
                )
        self._rotate_group_key(group_id)
        self.connection.commit()
        return True

    def toggle_group_shanway(self, group_id: str, actor_username: str, enabled: bool) -> bool:
        """Aktiviert oder deaktiviert Shanway fuer eine Gruppe."""
        if not self._is_group_admin(group_id, actor_username):
            raise PermissionError("Nur Gruppen-Admins duerfen Shanway umschalten.")
        group_row = self._group_row(group_id)
        if group_row is None:
            raise ValueError("Gruppe nicht gefunden.")
        currently_enabled = bool(int(group_row["shanway_enabled"]))
        if currently_enabled == bool(enabled):
            return True
        if enabled:
            group_key, key_version = self._resolve_group_key_for_user(group_id, actor_username)
            current = self._group_member_row(group_id, SHANWAY_MEMBER_NAME)
            if current is None:
                self.connection.execute(
                    """
                    INSERT INTO chat_group_members (
                        group_id, user_id, username, role, joined_at, active,
                        encrypted_group_key, key_version, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(group_id),
                        0,
                        SHANWAY_MEMBER_NAME,
                        "assistant",
                        self._now_iso(),
                        1,
                        self._encrypt_group_key_for_member(group_key, SHANWAY_MEMBER_NAME),
                        int(key_version),
                        json.dumps({"assistant": True}, ensure_ascii=False),
                    ),
                )
            else:
                self.connection.execute(
                    """
                    UPDATE chat_group_members
                    SET active = 1, role = 'assistant', encrypted_group_key = ?, key_version = ?
                    WHERE group_id = ? AND username = ?
                    """,
                    (
                        self._encrypt_group_key_for_member(group_key, SHANWAY_MEMBER_NAME),
                        int(key_version),
                        str(group_id),
                        SHANWAY_MEMBER_NAME,
                    ),
                )
            self.connection.execute(
                "UPDATE chat_groups SET shanway_enabled = 1 WHERE group_id = ?",
                (str(group_id),),
            )
        else:
            self.connection.execute(
                "UPDATE chat_group_members SET active = 0 WHERE group_id = ? AND username = ?",
                (str(group_id), SHANWAY_MEMBER_NAME),
            )
            self.connection.execute(
                "UPDATE chat_groups SET shanway_enabled = 0 WHERE group_id = ?",
                (str(group_id),),
            )
            self._delete_group_consensus(group_id)
            self._rotate_group_key(group_id)
        self.connection.commit()
        return True

    def toggle_group_analysis_mode(self, group_id: str, actor_username: str) -> str:
        """Schaltet den Gruppenmodus zwischen shared und individual um."""
        if not self._is_group_admin(group_id, actor_username):
            raise PermissionError("Nur Gruppen-Admins duerfen den Analysemodus umschalten.")
        group_row = self._group_row(group_id)
        if group_row is None:
            raise ValueError("Gruppe nicht gefunden.")
        payload_raw = str(group_row["payload_json"]).strip()
        try:
            payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            payload = {}
        current_mode = str(payload.get("analysis_mode", "shared") or "shared").lower()
        next_mode = "individual" if current_mode == "shared" else "shared"
        payload["analysis_mode"] = next_mode
        self.connection.execute(
            "UPDATE chat_groups SET payload_json = ? WHERE group_id = ?",
            (json.dumps(payload, ensure_ascii=False), str(group_id)),
        )
        self.connection.commit()
        return next_mode

    def get_user_chat_channels(self, user_id: int, username: str) -> list[dict[str, Any]]:
        """Liefert die fuer einen Nutzer sichtbaren Chat-Kanaele."""
        normalized_username = str(username).strip()
        channels: list[dict[str, Any]] = [
            {
                "kind": "public",
                "channel": "global",
                "label": "# global",
                "title": "Global",
                "encrypted": False,
                "shanway_enabled": True,
                "analysis_mode": "shared",
            },
            {
                "kind": "private_shanway",
                "channel": f"private:{SHANWAY_MEMBER_NAME}",
                "label": "[privat] Shanway",
                "title": "Shanway privat",
                "encrypted": True,
                "shanway_enabled": True,
                "analysis_mode": "individual",
            },
        ]
        private_rows = self.connection.execute(
            """
            SELECT DISTINCT
                   CASE WHEN username = ? THEN recipient_username ELSE username END AS partner
            FROM chat_messages
            WHERE is_private = 1
              AND is_group = 0
              AND (
                    (username = ? AND recipient_username != '' AND recipient_username != ?)
                 OR (recipient_username = ? AND username != ?)
              )
            ORDER BY partner ASC
            """,
            (
                normalized_username,
                normalized_username,
                SHANWAY_MEMBER_NAME,
                normalized_username,
                SHANWAY_MEMBER_NAME,
            ),
        ).fetchall()
        for row in private_rows:
            partner = str(row["partner"]).strip()
            if not partner or partner == SHANWAY_MEMBER_NAME:
                continue
            channels.append(
                {
                    "kind": "private",
                    "channel": f"private:{partner}",
                    "label": f"@ {partner}",
                    "title": f"Direkt mit {partner}",
                    "encrypted": True,
                    "shanway_enabled": False,
                    "recipient_username": partner,
                    "analysis_mode": "individual",
                }
            )

        group_rows = self.connection.execute(
            """
            SELECT g.group_id, g.group_name, g.shanway_enabled, g.key_version, g.payload_json, m.role,
                   COUNT(CASE WHEN m2.active = 1 AND m2.username != ? THEN 1 END) AS member_count
            FROM chat_groups AS g
            JOIN chat_group_members AS m
              ON m.group_id = g.group_id AND m.username = ? AND m.active = 1
            LEFT JOIN chat_group_members AS m2
              ON m2.group_id = g.group_id
            GROUP BY g.group_id, g.group_name, g.shanway_enabled, g.key_version, g.payload_json, m.role
            ORDER BY g.group_name COLLATE NOCASE ASC
            """,
            (SHANWAY_MEMBER_NAME, normalized_username),
        ).fetchall()
        for row in group_rows:
            member_count = int(row["member_count"]) if row["member_count"] is not None else 0
            try:
                group_payload = json.loads(str(row["payload_json"])) if str(row["payload_json"]).strip() else {}
            except Exception:
                group_payload = {}
            channels.append(
                {
                    "kind": "group",
                    "channel": f"group:{row['group_id']}",
                    "label": f"[gruppe] {row['group_name']} ({member_count})",
                    "title": str(row["group_name"]),
                    "encrypted": True,
                    "shanway_enabled": bool(int(row["shanway_enabled"])),
                    "group_id": str(row["group_id"]),
                    "current_role": str(row["role"]),
                    "member_count": member_count,
                    "key_version": int(row["key_version"]),
                    "analysis_mode": str(group_payload.get("analysis_mode", "shared") or "shared"),
                }
            )
        return channels

    @staticmethod
    def _normalize_consensus_text(message_text: str) -> str:
        """Verdichtet Gruppenbotschaften fuer einfachen Konsensvergleich."""
        lowered = str(message_text).lower()
        lowered = re.sub(r"@shanway\b", "", lowered)
        lowered = re.sub(r"\s+", " ", lowered).strip()
        return lowered

    def register_group_consensus_vote(
        self,
        group_id: str,
        user_id: int,
        username: str,
        message_text: str,
    ) -> dict[str, Any] | None:
        """Verdichtet Gruppenbotschaften zu lokalem Konsenswissen ab drei Stimmen."""
        group_row = self._group_row(group_id)
        if group_row is None or not bool(int(group_row["shanway_enabled"])):
            return None
        if str(username).strip() == SHANWAY_MEMBER_NAME:
            return None
        canonical_text = self._normalize_consensus_text(message_text)
        if len(canonical_text) < 12 or "?" in canonical_text:
            return None
        consensus_hash = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
        row = self.connection.execute(
            """
            SELECT id, supporter_ids_json, support_count, reached_at
            FROM chat_group_consensus
            WHERE group_id = ? AND consensus_hash = ?
            LIMIT 1
            """,
            (str(group_id), consensus_hash),
        ).fetchone()
        supporter_ids: list[int] = []
        if row is not None:
            try:
                supporter_ids = [int(item) for item in json.loads(str(row["supporter_ids_json"]))]
            except Exception:
                supporter_ids = []
        if int(user_id) not in supporter_ids:
            supporter_ids.append(int(user_id))
        supporter_ids = sorted(set(supporter_ids))
        support_count = len(supporter_ids)
        reached_at = str(row["reached_at"]) if row is not None else ""
        if support_count >= 3 and not reached_at:
            reached_at = self._now_iso()
        payload_json = {
            "source": "group_consensus",
            "canonical_text": canonical_text,
            "latest_username": str(username).strip(),
        }
        if row is None:
            self.connection.execute(
                """
                INSERT INTO chat_group_consensus (
                    group_id, consensus_hash, canonical_text, support_count,
                    supporter_ids_json, reached_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(group_id),
                    consensus_hash,
                    canonical_text,
                    support_count,
                    json.dumps(supporter_ids, ensure_ascii=False),
                    reached_at,
                    json.dumps(payload_json, ensure_ascii=False),
                ),
            )
        else:
            self.connection.execute(
                """
                UPDATE chat_group_consensus
                SET support_count = ?, supporter_ids_json = ?, reached_at = ?, payload_json = ?
                WHERE id = ?
                """,
                (
                    support_count,
                    json.dumps(supporter_ids, ensure_ascii=False),
                    reached_at,
                    json.dumps(payload_json, ensure_ascii=False),
                    int(row["id"]),
                ),
            )
        self.connection.commit()
        return {
            "group_id": str(group_id),
            "canonical_text": canonical_text,
            "support_count": support_count,
            "reached_at": reached_at,
        }

    def get_group_consensus_knowledge(
        self,
        group_id: str,
        query_text: str = "",
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Liefert nur gruppenlokales Konsenswissen, nie globales Chatwissen."""
        rows = self.connection.execute(
            """
            SELECT canonical_text, support_count, reached_at
            FROM chat_group_consensus
            WHERE group_id = ? AND support_count >= 3
            ORDER BY support_count DESC, reached_at DESC
            LIMIT ?
            """,
            (str(group_id), int(max(1, limit * 4))),
        ).fetchall()

        def tokens_for(value: str) -> set[str]:
            return {
                token
                for token in re.findall(r"[0-9A-Za-zÄÖÜäöüß]+", str(value).lower())
                if len(token) >= 2
            }

        query_tokens = tokens_for(query_text)
        scored: list[dict[str, Any]] = []
        for row in rows:
            canonical_text = str(row["canonical_text"])
            knowledge_tokens = tokens_for(canonical_text)
            score = float(len(query_tokens & knowledge_tokens)) if query_tokens else 1.0
            if score <= 0.0 and query_tokens:
                continue
            scored.append(
                {
                    "text": canonical_text,
                    "support_count": int(row["support_count"]),
                    "reached_at": str(row["reached_at"]),
                    "score": score,
                }
            )
        scored.sort(key=lambda item: (item["score"], item["support_count"]), reverse=True)
        return scored[: int(max(1, limit))]

    def delete_private_conversation(self, username: str, other_username: str) -> int:
        """Loescht einen privaten Dialog lokal aus der Registry."""
        cursor = self.connection.execute(
            """
            DELETE FROM chat_messages
            WHERE is_private = 1
              AND is_group = 0
              AND (
                    (username = ? AND recipient_username = ?)
                 OR (username = ? AND recipient_username = ?)
              )
            """,
            (
                str(username).strip(),
                str(other_username).strip(),
                str(other_username).strip(),
                str(username).strip(),
            ),
        )
        self.connection.commit()
        return int(cursor.rowcount or 0)

    def get_user_fingerprint_history(self, user_id: int, limit: int = 300) -> list[dict[str, Any]]:
        """Liefert die gespeicherte Analysehistorie eines Nutzers ueber alle Logins."""
        rows = self.connection.execute(
            """
            SELECT f.id, f.session_id, f.timestamp, f.source_type, f.source_label, f.file_hash, f.verdict,
                   f.integrity_state, s.username, s.login_at
            FROM fingerprints AS f
            JOIN app_sessions AS s ON s.session_id = f.session_id
            WHERE s.user_id = ?
            ORDER BY f.id DESC
            LIMIT ?
            """,
            (int(user_id), int(max(1, limit))),
        ).fetchall()
        return [
            {
                "id": int(row["id"]),
                "session_id": str(row["session_id"]),
                "timestamp": str(row["timestamp"]),
                "source_type": str(row["source_type"]),
                "source_label": str(row["source_label"]),
                "file_hash": str(row["file_hash"]),
                "verdict": str(row["verdict"]),
                "integrity_state": str(row["integrity_state"]),
                "username": str(row["username"]),
                "login_at": str(row["login_at"]),
            }
            for row in rows
        ]

    def load_fingerprint(self, record_id: int) -> AetherFingerprint | None:
        """Laedt einen gespeicherten Fingerprint fuer Historiennavigation und Re-Rendering."""
        row = self.connection.execute(
            """
            SELECT id, session_id, timestamp, source_type, source_label, file_hash, file_size, symmetry_score,
                   entropy_mean, verdict, fourier_peaks, periodicity, anomaly_coordinates, delta, delta_ratio,
                   coherence_score, resonance_score, ethics_score, integrity_state, integrity_text, payload_json
            FROM fingerprints
            WHERE id = ?
            LIMIT 1
            """,
            (int(record_id),),
        ).fetchone()
        if row is None:
            return None

        payload = json.loads(str(row["payload_json"])) if str(row["payload_json"]).strip() else {}
        entropy_blocks = [float(value) for value in payload.get("entropy_blocks", [])]
        if not entropy_blocks:
            entropy_blocks = [float(row["entropy_mean"]) for _ in range(256)]
        byte_distribution_raw = payload.get("byte_distribution", {})
        byte_distribution = {
            int(key): int(value)
            for key, value in dict(byte_distribution_raw).items()
        } if isinstance(byte_distribution_raw, dict) else {}
        voxel_points = payload.get("voxel_points")
        if isinstance(voxel_points, list):
            parsed_voxels = [tuple(float(part) for part in item) for item in voxel_points if isinstance(item, (list, tuple))]
        else:
            parsed_voxels = None
        fingerprint = AetherFingerprint(
            session_id=str(row["session_id"]),
            file_hash=str(row["file_hash"]),
            file_size=int(row["file_size"]),
            entropy_blocks=entropy_blocks,
            entropy_mean=float(row["entropy_mean"]),
            fourier_peaks=json.loads(str(row["fourier_peaks"])),
            byte_distribution=byte_distribution,
            periodicity=int(row["periodicity"]),
            symmetry_score=float(row["symmetry_score"]),
            delta=self._unpack_delta(bytes(row["delta"])),
            delta_ratio=float(row["delta_ratio"]),
            anomaly_coordinates=[tuple(map(int, item)) for item in json.loads(str(row["anomaly_coordinates"]))],
            verdict=str(row["verdict"]),
            timestamp=str(row["timestamp"]),
            symmetry_component=float(payload.get("symmetry_component", row["symmetry_score"])),
            coherence_score=float(row["coherence_score"]),
            resonance_score=float(row["resonance_score"]),
            ethics_score=float(row["ethics_score"]),
            integrity_state=str(row["integrity_state"]),
            integrity_text=str(row["integrity_text"]),
            source_type=str(row["source_type"]),
            source_label=str(row["source_label"]),
            observer_mutual_info=float(payload.get("observer_mutual_info", 0.0) or 0.0),
            observer_knowledge_ratio=float(payload.get("observer_knowledge_ratio", 0.0) or 0.0),
            h_lambda=float(payload.get("h_lambda", 0.0) or 0.0),
            observer_state=str(payload.get("observer_state", "OFFEN")),
            beauty_signature={
                str(key): float(value)
                for key, value in dict(payload.get("beauty_signature", {})).items()
            } if isinstance(payload.get("beauty_signature", {}), dict) else None,
            ae_lab_summary=(
                dict(payload.get("ae_lab_summary", {}))
                if isinstance(payload.get("ae_lab_summary", {}), dict)
                else (dict(payload.get("ae_lab", {})) if isinstance(payload.get("ae_lab", {}), dict) else None)
            ),
            voxel_points=parsed_voxels,
            local_chain_tx_hash=str(payload.get("local_chain_tx_hash", "")),
            local_chain_prev_hash=str(payload.get("local_chain_prev_hash", "")),
            local_chain_endpoint=str(payload.get("local_chain_endpoint", "")),
            local_chain_attested_at=str(payload.get("local_chain_attested_at", "")),
        )
        setattr(
            fingerprint,
            "dna_share_gate_summary",
            self.describe_dna_share_payload(
                payload,
                chained=bool(payload.get("confirmed_lossless", False)),
            ),
        )
        return fingerprint

    def find_file_record(
        self,
        file_hash: str = "",
        source_label: str = "",
        user_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Sucht einen rekonstruierbaren Datei-Datensatz ueber Hash und/oder Quellenlabel."""
        normalized_hash = str(file_hash).strip()
        normalized_label = str(source_label).strip()
        if normalized_hash:
            if user_id is None or int(user_id) <= 0:
                row = self.connection.execute(
                    """
                    SELECT id, session_id, timestamp, source_type, source_label, file_hash, file_size
                    FROM fingerprints
                    WHERE source_type = 'file' AND file_hash = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (normalized_hash,),
                ).fetchone()
            else:
                row = self.connection.execute(
                    """
                    SELECT f.id, f.session_id, f.timestamp, f.source_type, f.source_label, f.file_hash, f.file_size
                    FROM fingerprints AS f
                    JOIN app_sessions AS s ON s.session_id = f.session_id
                    WHERE f.source_type = 'file' AND f.file_hash = ? AND s.user_id = ?
                    ORDER BY f.id DESC
                    LIMIT 1
                    """,
                    (normalized_hash, int(user_id)),
                ).fetchone()
            if row is not None:
                return {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "source_type": str(row["source_type"]),
                    "source_label": str(row["source_label"]),
                    "file_hash": str(row["file_hash"]),
                    "file_size": int(row["file_size"]),
                }
        if normalized_label:
            if user_id is None or int(user_id) <= 0:
                row = self.connection.execute(
                    """
                    SELECT id, session_id, timestamp, source_type, source_label, file_hash, file_size
                    FROM fingerprints
                    WHERE source_type = 'file' AND source_label = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (normalized_label,),
                ).fetchone()
            else:
                row = self.connection.execute(
                    """
                    SELECT f.id, f.session_id, f.timestamp, f.source_type, f.source_label, f.file_hash, f.file_size
                    FROM fingerprints AS f
                    JOIN app_sessions AS s ON s.session_id = f.session_id
                    WHERE f.source_type = 'file' AND f.source_label = ? AND s.user_id = ?
                    ORDER BY f.id DESC
                    LIMIT 1
                    """,
                    (normalized_label, int(user_id)),
                ).fetchone()
            if row is not None:
                return {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "source_type": str(row["source_type"]),
                    "source_label": str(row["source_label"]),
                    "file_hash": str(row["file_hash"]),
                    "file_size": int(row["file_size"]),
                }
        return None

    def search_similar(self, fingerprint: AetherFingerprint) -> list[dict[str, Any]]:
        """
        Findet die fuenf aehnlichsten historischen Datei-Eintraege.

        Vergleich erfolgt per euklidischer Distanz aus Entropie-Mittelwert und Symmetrieabweichung.
        """
        rows = self.connection.execute(
            "SELECT id, file_hash, entropy_mean, symmetry_score, verdict, timestamp FROM fingerprints"
        ).fetchall()
        scored: list[dict[str, Any]] = []
        for row in rows:
            entropy_dist = float(row["entropy_mean"]) - float(fingerprint.entropy_mean)
            symmetry_dist = float(row["symmetry_score"]) - float(fingerprint.symmetry_score)
            distance = math.sqrt((entropy_dist ** 2) + (symmetry_dist ** 2))
            scored.append(
                {
                    "id": int(row["id"]),
                    "file_hash": row["file_hash"],
                    "entropy_mean": float(row["entropy_mean"]),
                    "symmetry_score": float(row["symmetry_score"]),
                    "verdict": row["verdict"],
                    "timestamp": row["timestamp"],
                    "distance": float(distance),
                }
            )
        scored.sort(key=lambda item: item["distance"])
        return scored[:5]

    def analyze_compression_potential(self) -> dict[str, Any]:
        """Ermittelt den durchschnittlichen Delta-Ratio und den besten Kompressionskandidaten."""
        rows = self.connection.execute(
            "SELECT id, file_hash, delta_ratio, timestamp FROM fingerprints"
        ).fetchall()
        if not rows:
            return {"average_delta_ratio": 0.0, "best_entry": None}

        ratios = [float(row["delta_ratio"]) for row in rows]
        best = min(rows, key=lambda row: float(row["delta_ratio"]))
        return {
            "average_delta_ratio": float(sum(ratios) / len(ratios)),
            "best_entry": {
                "id": int(best["id"]),
                "file_hash": best["file_hash"],
                "delta_ratio": float(best["delta_ratio"]),
                "timestamp": best["timestamp"],
            },
        }

    @staticmethod
    def _collective_snapshot_hash(payload: dict[str, Any]) -> str:
        """Leitet einen stabilen Hash aus dem kanonischen Snapshot-Payload ab."""
        normalized = dict(payload)
        normalized.pop("snapshot_hash", None)
        return hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()

    @staticmethod
    def _collective_snapshot_weight(record: dict[str, Any]) -> float:
        """Gewichtet Snapshot-Vertrauen leicht nach Trust und Merge-Tiefe."""
        trust_weight = max(0.05, float(record.get("trust_weight", 1.0) or 1.0))
        merged_count = max(1, int(record.get("merged_count", 1) or 1))
        merge_factor = min(4.0, 1.0 + (0.25 * float(max(0, merged_count - 1))))
        return float(trust_weight * merge_factor)

    @staticmethod
    def _normalize_distribution(labels: list[str]) -> dict[str, float]:
        """Normiert Label-Haeufigkeiten auf eine Summenverteilung."""
        options = {"ATTRACTOR_LOCK": 0.0, "EMERGENT": 0.0, "PHASE_SHIFT": 0.0}
        for label in labels:
            if label in options:
                options[label] += 1.0
        total = sum(options.values())
        if total <= 1e-9:
            return {"ATTRACTOR_LOCK": 0.0, "EMERGENT": 1.0, "PHASE_SHIFT": 0.0}
        return {key: float(value / total) for key, value in options.items()}

    @staticmethod
    def _shanway_allows_dna_share(payload: dict[str, Any]) -> bool:
        """Blockiert DNA-Share fuer sensible oder explizit toxische Shanway-Befunde."""
        assessment = payload.get("shanway_assessment", {})
        if not isinstance(assessment, dict):
            return True
        if bool(assessment.get("sensitive", False)) or bool(assessment.get("blacklisted", False)):
            return False
        classification = str(assessment.get("classification", "")).strip().lower()
        return classification not in {"toxic", "blocked"}

    @staticmethod
    def _dna_share_trust_score(payload: dict[str, Any]) -> float:
        """Leitet einen knappen Vertrauenswert fuer Anchor-Uploads aus vorhandener Evidenz ab."""
        normalized = dict(payload or {})
        score = 0.0
        score += 0.26 if bool(normalized.get("confirmed_lossless", False)) else 0.0
        score += 0.16 if bool(normalized.get("reconstruction_verified", False)) else 0.0
        score += 0.16 if bool(normalized.get("coverage_verified", False)) else 0.0
        coverage_ratio = max(0.0, min(1.0, float(normalized.get("anchor_coverage_ratio", 0.0) or 0.0)))
        unresolved_ratio = max(0.0, min(1.0, float(normalized.get("unresolved_residual_ratio", 1.0) or 1.0)))
        score += 0.14 * coverage_ratio
        score += 0.10 * (1.0 - unresolved_ratio)
        bayes_confidence = max(
            0.0,
            min(
                1.0,
                float(normalized.get("bayes_overall_confidence", 0.0) or 0.0),
            ),
        )
        noether_confidence = max(
            0.0,
            min(
                1.0,
                float(
                    dict(normalized.get("vault_noether", {}) or {}).get(
                        "invariant_score",
                        normalized.get("graph_confidence_mean", 0.0),
                    )
                    or 0.0
                ),
            ),
        )
        anchor_source = dict(normalized.get("ae_lab", {}) or {})
        anchor_list = list(normalized.get("ae_anchors", []) or anchor_source.get("anchors", []) or [])
        score += 0.06 * bayes_confidence
        score += 0.05 * noether_confidence
        score += 0.03 * min(1.0, len(anchor_list) / 4.0)
        assessment = dict(normalized.get("shanway_assessment", {}) or {})
        if assessment:
            if bool(assessment.get("sensitive", False)) or bool(assessment.get("blacklisted", False)):
                return 0.0
            classification = str(assessment.get("classification", "")).strip().lower()
            if classification in {"toxic", "blocked"}:
                return 0.0
            if classification == "harmonic":
                score += 0.04
            elif classification == "uncertain":
                score += 0.02
            score += 0.04 * max(
                0.0,
                min(1.0, float(assessment.get("noether_symmetry", 0.0) or 0.0)),
            )
        return float(max(0.0, min(1.0, score)))

    @staticmethod
    def _dna_share_block_reason(payload: dict[str, Any]) -> str:
        """Leitet einen klaren Blockgrund fuer DNA-Share ab."""
        source_type = str(payload.get("source_type", "") or "").strip().lower()
        confirmed_lossless = bool(payload.get("confirmed_lossless", False))
        reconstruction_verified = bool(payload.get("reconstruction_verified", False))
        assessment = payload.get("shanway_assessment", {})
        if not confirmed_lossless:
            if source_type and source_type != "file":
                return "source_not_lossless"
            if not reconstruction_verified:
                return "reconstruction_failed"
            if not bool(payload.get("coverage_verified", False)):
                return "coverage_failed"
            return "not_confirmed"
        if isinstance(assessment, dict):
            if bool(assessment.get("sensitive", False)) or bool(assessment.get("blacklisted", False)):
                return "shanway_sensitive"
            classification = str(assessment.get("classification", "")).strip().lower()
            if classification in {"toxic", "blocked"}:
                return "shanway_toxic"
        if AetherRegistry._dna_share_trust_score(payload) < TRUSTED_ANCHOR_UPLOAD_MIN_SCORE:
            return "trust_score_failed"
        return ""

    @staticmethod
    def _dna_share_reason_text(reason_code: str) -> str:
        """Liefert erklaerbaren Text fuer DNA-Share-Gates."""
        mapping = {
            "eligible": "freigegeben",
            "no_vault_entries": "noch keine analysierten Vault-Eintraege",
            "source_not_lossless": "nur Datei-Drops koennen derzeit CONFIRMED lossless werden",
            "reconstruction_failed": "Rekonstruktion wurde noch nicht bestaetigt",
            "coverage_failed": "Anker-Abdeckung reicht fuer CONFIRMED lossless noch nicht aus",
            "not_confirmed": "Datensatz ist noch nicht als CONFIRMED lossless markiert",
            "not_chained": "Datensatz ist lokal vorhanden, aber noch nicht ueber die Chain bestaetigt",
            "shanway_sensitive": "Shanway-/Ethikfilter blockiert sensible oder blacklisted Inhalte",
            "shanway_toxic": "Shanway-/Ethikfilter blockiert toxische Inhalte",
            "trust_score_failed": "Aether-Trust-Score fuer sicheren Anchor-Upload ist noch zu niedrig",
        }
        return mapping.get(str(reason_code), "unbekannter Filtergrund")

    @staticmethod
    def _is_aether_origin_marker(payload: dict[str, Any]) -> bool:
        """Akzeptiert nur explizit als Aether-eigen markierte DNA-Share-Payloads."""
        marker = dict(payload.get("aether_origin", {}) or {})
        return (
            str(marker.get("producer", "")).upper() == "AETHER"
            and str(marker.get("pipeline", "")).upper() == "LOCAL_CONFIRMED_LOSSLESS"
            and bool(marker.get("anchors_self_found_only", False))
        )

    @staticmethod
    def _trusted_publisher_manifest() -> dict[str, Any]:
        """Laedt die lokal gepinnte Trusted-Publisher-Liste fuer oeffentliche Anchor-Bundles."""
        if not TRUSTED_PUBLISHERS_PATH.is_file():
            return {}
        try:
            parsed = json.loads(TRUSTED_PUBLISHERS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
        return dict(parsed or {}) if isinstance(parsed, dict) else {}

    def _trusted_publisher_entry(self, publisher_id: str) -> dict[str, Any]:
        """Liefert den gepinnten Publisher-Eintrag oder ein leeres Objekt."""
        manifest = self._trusted_publisher_manifest()
        publishers = dict(manifest.get("publishers", {}) or {})
        entry = dict(publishers.get(str(publisher_id), {}) or {})
        if not bool(entry.get("enabled", False)):
            return {}
        return entry

    def _sign_trusted_dna_share_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        """Signiert DNA-Share-Bundles mit einem lokal vorhandenen Publisher-Schluessel."""
        if not trusted_publisher_crypto_available:
            return {}
        manifest = self._trusted_publisher_manifest()
        publisher_id = str(manifest.get("default_publisher_id", "") or "").strip()
        if not publisher_id:
            return {}
        entry = self._trusted_publisher_entry(publisher_id)
        if not entry:
            return {}
        key_path = TRUSTED_PUBLISHER_KEY_DIR / f"{trusted_publisher_slug(publisher_id)}_ed25519_private.pem"
        if not key_path.is_file():
            return {}
        raw = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(raw, password=None)
        signature = private_key.sign(canonical_json(payload).encode("utf-8"))
        return {
            "trusted_publisher_id": publisher_id,
            "trusted_signature_scheme": "ed25519",
            "trusted_signature": base64.b64encode(signature).decode("ascii"),
        }

    def _verify_trusted_dna_share_signature(self, payload: dict[str, Any], wrapper: dict[str, Any]) -> None:
        """Akzeptiert nur von gepinnten Publishern signierte DNA-Share-Bundles."""
        if not trusted_publisher_crypto_available:
            raise ValueError("Trusted-Publisher-Pruefung ist ohne 'cryptography' nicht verfuegbar.")
        publisher_id = str(wrapper.get("trusted_publisher_id", "") or "").strip()
        signature_b64 = str(wrapper.get("trusted_signature", "") or "").strip()
        signature_scheme = str(wrapper.get("trusted_signature_scheme", "") or "").strip().lower()
        if not publisher_id or not signature_b64 or signature_scheme != "ed25519":
            raise ValueError("DNA-Share-Bundle hat keine gueltige Trusted-Publisher-Signatur.")
        entry = self._trusted_publisher_entry(publisher_id)
        if not entry:
            raise ValueError("DNA-Share-Bundle stammt nicht von einem gepinnten Trusted Publisher.")
        public_key_b64 = str(entry.get("public_key", "") or "").strip()
        if not public_key_b64:
            raise ValueError("Trusted Publisher hat keinen gepinnten Public Key.")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
            public_key.verify(base64.b64decode(signature_b64), canonical_json(payload).encode("utf-8"))
        except (ValueError, InvalidSignature):
            raise ValueError("Trusted-Publisher-Signatur ist ungueltig oder manipuliert.") from None

    def _validate_aether_dna_share_payload(self, payload: dict[str, Any], wrapper: dict[str, Any] | None = None) -> None:
        """Blockiert DNA-Share-Importe, die nicht wie echte Aether-Exporte aussehen."""
        if str(payload.get("schema", "")).strip() != "aether.dna_share.v1":
            raise ValueError("Nur Aether-DNA-Share-Bundles werden akzeptiert.")
        if not self._is_aether_origin_marker(payload):
            raise ValueError("DNA-Share-Bundle ist nicht als Aether-eigener Anchor-Export markiert.")
        if wrapper is None:
            raise ValueError("DNA-Share-Bundle braucht eine Trusted-Publisher-Huelle.")
        self._verify_trusted_dna_share_signature(payload, wrapper)
        dna_share = dict(payload.get("dna_share", {}) or {})
        sharing_policy = dict(dna_share.get("sharing_policy", {}) or {})
        if not bool(sharing_policy.get("source_confirmed_lossless_local_only", False)):
            raise ValueError("DNA-Share-Bundle verletzt den lokalen CONFIRMED-lossless-Pfad.")
        if not bool(sharing_policy.get("shared_anchor_assistance_only", False)):
            raise ValueError("DNA-Share-Bundle enthaelt keinen reinen Anchor-Assistance-Pfad.")
        records = list(dna_share.get("records", []) or [])
        if int(dna_share.get("record_count", 0) or 0) != len(records):
            raise ValueError("DNA-Share-Bundle hat inkonsistente Record-Zaehler.")
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("DNA-Share-Bundle enthaelt ungueltige Anchor-Records.")
            if not self._is_aether_origin_marker(record):
                raise ValueError("DNA-Share-Record stammt nicht aus einem Aether-Eigenfund.")
            record_hash = str(record.get("dna_record_hash", "")).strip().lower()
            if not record_hash:
                raise ValueError("DNA-Share-Record hat keinen Aether-Record-Hash.")
            normalized = dict(record)
            normalized.pop("dna_record_hash", None)
            expected_hash = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
            if expected_hash != record_hash:
                raise ValueError("DNA-Share-Record-Hash ist ungueltig oder manipuliert.")

    def describe_dna_share_payload(
        self,
        payload: dict[str, Any] | None,
        chained: bool | None = None,
    ) -> dict[str, Any]:
        """Beschreibt fuer einen einzelnen Payload, ob und warum DNA-Share moeglich ist."""
        normalized = dict(payload or {})
        reason_code = self._dna_share_block_reason(normalized)
        if not reason_code:
            confirmed_lossless = bool(normalized.get("confirmed_lossless", False))
            if chained is False and confirmed_lossless:
                reason_code = "not_chained"
        eligible = not bool(reason_code)
        if eligible:
            reason_code = "eligible"
        anchor_source = dict(normalized.get("ae_lab", {}) or {})
        anchor_list = list(normalized.get("ae_anchors", []) or anchor_source.get("anchors", []) or [])
        trust_score = self._dna_share_trust_score(normalized)
        return {
            "eligible": bool(eligible),
            "reason_code": str(reason_code),
            "reason_text": self._dna_share_reason_text(reason_code),
            "confirmed_lossless": bool(normalized.get("confirmed_lossless", False)),
            "reconstruction_verified": bool(normalized.get("reconstruction_verified", False)),
            "source_type": str(normalized.get("source_type", "")),
            "sharable_anchor_count": int(len(anchor_list)),
            "trust_score": float(trust_score),
            "trust_required": float(TRUSTED_ANCHOR_UPLOAD_MIN_SCORE),
        }

    def _load_vault_entries_by_ids(
        self,
        entry_ids: list[int],
        user_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Laedt gezielt Vault-Eintraege fuer bestaetigte Chain-Referenzen."""
        normalized_ids = [int(item) for item in entry_ids if int(item) > 0]
        if not normalized_ids:
            return []
        placeholders = ",".join("?" for _ in normalized_ids)
        params: list[Any] = list(normalized_ids)
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                f"""
                SELECT id, session_id, timestamp, source_type, source_label, file_hash,
                       feature_vector, similarity_best, cluster_label, payload_json, signature
                FROM vault_entries
                WHERE id IN ({placeholders})
                """,
                tuple(params),
            ).fetchall()
        else:
            rows = self.connection.execute(
                f"""
                SELECT v.id, v.session_id, v.timestamp, v.source_type, v.source_label, v.file_hash,
                       v.feature_vector, v.similarity_best, v.cluster_label, v.payload_json, v.signature
                FROM vault_entries AS v
                JOIN app_sessions AS s ON s.session_id = v.session_id
                WHERE s.user_id = ? AND v.id IN ({placeholders})
                """,
                tuple([int(user_id)] + params),
            ).fetchall()
        loaded: dict[int, dict[str, Any]] = {}
        for row in rows:
            try:
                feature_vector = json.loads(str(row["feature_vector"]))
            except Exception:
                feature_vector = []
            try:
                payload_json = json.loads(str(row["payload_json"]))
            except Exception:
                payload_json = {}
            loaded[int(row["id"])] = {
                "id": int(row["id"]),
                "session_id": str(row["session_id"]),
                "timestamp": str(row["timestamp"]),
                "source_type": str(row["source_type"]),
                "source_label": str(row["source_label"]),
                "file_hash": str(row["file_hash"]),
                "feature_vector": list(feature_vector or []),
                "similarity_best": float(row["similarity_best"]),
                "cluster_label": str(row["cluster_label"]),
                "payload_json": dict(payload_json or {}),
                "signature": str(row["signature"]),
            }
        return [loaded[entry_id] for entry_id in normalized_ids if entry_id in loaded]

    def _confirmed_lossless_dna_entries(
        self,
        user_id: int | None = None,
        limit: int = 96,
    ) -> list[dict[str, Any]]:
        """Ermittelt nur CONFIRMED-lossless Vault-Eintraege fuer den DNA-Share-Layer."""
        scoped_user = int(user_id) if user_id is not None and int(user_id) > 0 else None
        params: tuple[Any, ...]
        if scoped_user is None:
            rows = self.connection.execute(
                """
                SELECT payload_json
                FROM chain_blocks
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(48, limit * 6)),),
            ).fetchall()
        else:
            params = (scoped_user, int(max(48, limit * 6)))
            rows = self.connection.execute(
                """
                SELECT c.payload_json
                FROM chain_blocks AS c
                JOIN app_sessions AS s ON s.session_id = c.session_id
                WHERE s.user_id = ?
                ORDER BY c.id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        confirmed_payloads: dict[int, dict[str, Any]] = {}
        ordered_ids: list[int] = []
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except Exception:
                continue
            if not bool(payload.get("confirmed_lossless", False)):
                continue
            entry_id = int(payload.get("vault_entry_id", 0) or 0)
            if entry_id <= 0 or entry_id in confirmed_payloads:
                continue
            confirmed_payloads[entry_id] = dict(payload)
            ordered_ids.append(entry_id)
            if len(ordered_ids) >= int(max(1, limit)):
                break
        entries = self._load_vault_entries_by_ids(ordered_ids, user_id=scoped_user)
        filtered: list[dict[str, Any]] = []
        for entry in entries:
            entry_id = int(entry["id"])
            chain_payload = dict(confirmed_payloads.get(entry_id, {}))
            payload = dict(entry.get("payload_json", {}) or {})
            payload["confirmed_lossless"] = bool(
                payload.get("confirmed_lossless", False) or chain_payload.get("confirmed_lossless", False)
            )
            payload["reconstruction_verified"] = bool(
                payload.get("reconstruction_verified", False) or chain_payload.get("reconstruction_verified", False)
            )
            payload["dna_share_trust_score"] = float(self._dna_share_trust_score(payload))
            if self._dna_share_block_reason(payload):
                continue
            entry["payload_json"] = payload
            filtered.append(entry)
        return filtered

    def get_dna_share_gate_summary(self, user_id: int | None = None, limit: int = 96) -> dict[str, Any]:
        """Erklaert, warum DNA-Share derzeit freigegeben oder blockiert ist."""
        scoped_user = int(user_id) if user_id is not None and int(user_id) > 0 else None
        entries = self.get_vault_entries(limit=max(1, limit), user_id=scoped_user)
        if not entries:
            return {
                "entry_count": 0,
                "eligible_count": 0,
                "confirmed_count": 0,
                "reconstruction_count": 0,
                "chained_count": 0,
                "latest_reason_code": "no_vault_entries",
                "latest_reason_text": self._dna_share_reason_text("no_vault_entries"),
                "reason_counts": {"no_vault_entries": 1},
            }

        if scoped_user is None:
            rows = self.connection.execute(
                """
                SELECT payload_json
                FROM chain_blocks
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(48, limit * 6)),),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT c.payload_json
                FROM chain_blocks AS c
                JOIN app_sessions AS s ON s.session_id = c.session_id
                WHERE s.user_id = ?
                ORDER BY c.id DESC
                LIMIT ?
                """,
                (scoped_user, int(max(48, limit * 6))),
            ).fetchall()

        confirmed_ids: set[int] = set()
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except Exception:
                continue
            if not bool(payload.get("confirmed_lossless", False)):
                continue
            entry_id = int(payload.get("vault_entry_id", 0) or 0)
            if entry_id > 0:
                confirmed_ids.add(entry_id)

        reason_counts: dict[str, int] = {}
        confirmed_count = 0
        reconstruction_count = 0
        chained_count = 0
        eligible_count = 0
        trust_sum = 0.0
        latest_reason_code = "no_vault_entries"
        latest_trust_score = 0.0

        for entry in entries:
            payload = dict(entry.get("payload_json", {}) or {})
            entry_id = int(entry.get("id", 0) or 0)
            trust_score = self._dna_share_trust_score(payload)
            trust_sum += float(trust_score)
            if bool(payload.get("confirmed_lossless", False)):
                confirmed_count += 1
            if bool(payload.get("reconstruction_verified", False)):
                reconstruction_count += 1
            if entry_id > 0 and entry_id in confirmed_ids:
                chained_count += 1
            reason_code = self._dna_share_block_reason(payload)
            if not reason_code and entry_id > 0 and entry_id not in confirmed_ids and bool(payload.get("confirmed_lossless", False)):
                reason_code = "not_chained"
            if not reason_code:
                reason_code = "eligible"
                eligible_count += 1
            reason_counts[reason_code] = int(reason_counts.get(reason_code, 0)) + 1
            if latest_reason_code == "no_vault_entries":
                latest_reason_code = reason_code
                latest_trust_score = float(trust_score)

        return {
            "entry_count": int(len(entries)),
            "eligible_count": int(eligible_count),
            "confirmed_count": int(confirmed_count),
            "reconstruction_count": int(reconstruction_count),
            "chained_count": int(chained_count),
            "latest_reason_code": str(latest_reason_code),
            "latest_reason_text": self._dna_share_reason_text(latest_reason_code),
            "reason_counts": reason_counts,
            "trust_mean": float(trust_sum / max(1, len(entries))),
            "latest_trust_score": float(latest_trust_score),
            "trust_required": float(TRUSTED_ANCHOR_UPLOAD_MIN_SCORE),
        }

    def get_collective_snapshots(self, limit: int = 64) -> list[dict[str, Any]]:
        """Liefert importierte oder lokal exportierte Snapshot-Pakete."""
        rows = self.connection.execute(
            """
            SELECT id, session_id, timestamp, source_label, origin_node_id, snapshot_hash,
                   trust_weight, merged_count, signature, payload_json
            FROM collective_snapshots
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(max(1, limit)),),
        ).fetchall()
        snapshots: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            snapshots.append(
                {
                    "id": int(row["id"]),
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "source_label": str(row["source_label"]),
                    "origin_node_id": str(row["origin_node_id"]),
                    "snapshot_hash": str(row["snapshot_hash"]),
                    "trust_weight": float(row["trust_weight"]),
                    "merged_count": int(row["merged_count"]),
                    "signature": str(row["signature"]),
                    "payload_json": payload,
                }
            )
        return snapshots

    def _aggregate_collective_snapshots(
        self,
        snapshots: list[dict[str, Any]],
        source_label: str = "collective_merge",
        origin_node_id: str = "",
    ) -> dict[str, Any]:
        """Verdichtet mehrere Snapshots zu einem gemeinsamen Prior-/Pattern-Paket."""
        if not snapshots:
            return {
                "schema": "aether.collective_snapshot.v1",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "source_label": source_label,
                "origin_node_id": origin_node_id,
                "fingerprint_count": 0,
                "vault_count": 0,
                "cluster_count": 0,
                "snapshot_count": 0,
                "anchor_priors": [],
                "resonance_references": [],
                "graph_feedback": {},
                "bayes_feedback": {},
                "pattern_feedback": {},
                "merged_from": [],
            }

        total_weight = 0.0
        fingerprint_count = 0
        vault_count = 0
        cluster_count = 0
        anchor_bins: dict[tuple[int, int], float] = {}
        resonance_refs: dict[tuple[float, float, int, float], tuple[float, dict[str, Any]]] = {}
        graph_acc: dict[str, float] = {
            "attractor_mean": 0.0,
            "phase_transition_mean": 0.0,
            "confidence_mean": 0.0,
            "constructive_mean": 0.0,
            "destructive_mean": 0.0,
            "interference_mean": 0.0,
        }
        graph_phase_acc = {"ATTRACTOR_LOCK": 0.0, "EMERGENT": 0.0, "PHASE_SHIFT": 0.0}
        bayes_acc: dict[str, float] = {
            "anchor_mean": 0.0,
            "pattern_mean": 0.0,
            "alarm_mean": 0.0,
            "overall_mean": 0.0,
        }
        bayes_phase_acc = {"ATTRACTOR_LOCK": 0.0, "EMERGENT": 0.0, "PHASE_SHIFT": 0.0}
        pattern_acc: dict[str, float] = {
            "similarity_mean": 0.0,
            "stability_mean": 0.0,
        }
        cluster_profiles: dict[str, dict[str, Any]] = {}

        for snapshot in snapshots:
            payload = dict(snapshot.get("payload_json", {}) or {})
            weight = self._collective_snapshot_weight(snapshot)
            total_weight += weight
            fingerprint_count += int(payload.get("fingerprint_count", 0) or 0)
            vault_count += int(payload.get("vault_count", 0) or 0)
            cluster_count = max(cluster_count, int(payload.get("cluster_count", 0) or 0))

            for prior in list(payload.get("anchor_priors", []) or []):
                x_bin = int(prior.get("x_bin", round(float(prior.get("x_norm", 0.0) or 0.0) * 19.0)))
                y_bin = int(prior.get("y_bin", round(float(prior.get("y_norm", 0.0) or 0.0) * 19.0)))
                count = max(0.0, float(prior.get("count", 0.0) or 0.0))
                anchor_bins[(x_bin, y_bin)] = anchor_bins.get((x_bin, y_bin), 0.0) + (weight * count)

            for ref in list(payload.get("resonance_references", []) or []):
                key = (
                    round(float(ref.get("entropy_mean", 0.0) or 0.0), 3),
                    round(float(ref.get("symmetry_score", 0.0) or 0.0), 3),
                    int(ref.get("periodicity", 0) or 0),
                    round(float(ref.get("delta_ratio", 0.0) or 0.0), 4),
                )
                scored = dict(ref)
                previous = resonance_refs.get(key)
                if previous is None or weight > previous[0]:
                    resonance_refs[key] = (weight, scored)

            graph_feedback = dict(payload.get("graph_feedback", {}) or {})
            for key in graph_acc:
                graph_acc[key] += weight * float(graph_feedback.get(key, 0.0) or 0.0)
            for phase, value in dict(graph_feedback.get("phase_priors", {}) or {}).items():
                if phase in graph_phase_acc:
                    graph_phase_acc[phase] += weight * float(value or 0.0)

            bayes_feedback = dict(payload.get("bayes_feedback", {}) or {})
            for key in bayes_acc:
                bayes_acc[key] += weight * float(bayes_feedback.get(key, 0.0) or 0.0)
            for phase, value in dict(bayes_feedback.get("graph_phase_priors", {}) or {}).items():
                if phase in bayes_phase_acc:
                    bayes_phase_acc[phase] += weight * float(value or 0.0)

            pattern_feedback = dict(payload.get("pattern_feedback", {}) or {})
            pattern_acc["similarity_mean"] += weight * float(pattern_feedback.get("similarity_mean", 0.0) or 0.0)
            pattern_acc["stability_mean"] += weight * float(pattern_feedback.get("stability_mean", 0.0) or 0.0)
            for profile in list(pattern_feedback.get("cluster_profiles", []) or []):
                label = str(profile.get("label", "")).strip() or "TRANSITIONAL"
                vector = [float(value) for value in list(profile.get("vector", []) or [])]
                entry = cluster_profiles.setdefault(
                    label,
                    {
                        "weight": 0.0,
                        "member_count": 0.0,
                        "similarity_sum": 0.0,
                        "vector_sum": [0.0 for _ in vector],
                    },
                )
                if len(entry["vector_sum"]) < len(vector):
                    entry["vector_sum"].extend([0.0] * (len(vector) - len(entry["vector_sum"])))
                for index, value in enumerate(vector):
                    entry["vector_sum"][index] += weight * value
                entry["weight"] += weight
                entry["member_count"] += weight * float(profile.get("member_count", 0.0) or 0.0)
                entry["similarity_sum"] += weight * float(profile.get("similarity_mean", 0.0) or 0.0)

        if total_weight <= 1e-9:
            total_weight = 1.0

        anchor_priors = [
            {
                "x_bin": int(x_bin),
                "y_bin": int(y_bin),
                "x_norm": float(x_bin) / 19.0,
                "y_norm": float(y_bin) / 19.0,
                "count": int(round(score)),
            }
            for (x_bin, y_bin), score in sorted(anchor_bins.items(), key=lambda item: item[1], reverse=True)[:24]
        ]

        resonance_references: list[dict[str, Any]] = []
        for _, ref in sorted(
            resonance_refs.values(),
            key=lambda item: float(item[1].get("ethics_score", 0.0) or 0.0) * item[0],
            reverse=True,
        )[:48]:
            resonance_references.append(
                {
                    "entropy_mean": float(ref.get("entropy_mean", 0.0) or 0.0),
                    "symmetry_score": float(ref.get("symmetry_score", 0.0) or 0.0),
                    "periodicity": int(ref.get("periodicity", 0) or 0),
                    "delta_ratio": float(ref.get("delta_ratio", 0.0) or 0.0),
                    "ethics_score": float(ref.get("ethics_score", 0.0) or 0.0),
                }
            )

        graph_phase_priors = {
            key: float(value / total_weight) for key, value in graph_phase_acc.items()
        }
        bayes_phase_priors = {
            key: float(value / total_weight) for key, value in bayes_phase_acc.items()
        }
        graph_phase_sum = sum(graph_phase_priors.values())
        if graph_phase_sum > 1e-9:
            graph_phase_priors = {
                key: float(value / graph_phase_sum) for key, value in graph_phase_priors.items()
            }
        bayes_phase_sum = sum(bayes_phase_priors.values())
        if bayes_phase_sum > 1e-9:
            bayes_phase_priors = {
                key: float(value / bayes_phase_sum) for key, value in bayes_phase_priors.items()
            }

        cluster_profile_list: list[dict[str, Any]] = []
        for label, entry in sorted(cluster_profiles.items()):
            weight = max(1e-9, float(entry["weight"]))
            cluster_profile_list.append(
                {
                    "label": label,
                    "member_count": int(round(float(entry["member_count"]) / weight)),
                    "similarity_mean": float(float(entry["similarity_sum"]) / weight),
                    "vector": [float(value / weight) for value in list(entry["vector_sum"])],
                }
            )

        return {
            "schema": "aether.collective_snapshot.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_label": source_label,
            "origin_node_id": origin_node_id,
            "fingerprint_count": int(fingerprint_count),
            "vault_count": int(vault_count),
            "cluster_count": int(max(cluster_count, len(cluster_profile_list))),
            "snapshot_count": int(len(snapshots)),
            "anchor_priors": anchor_priors,
            "resonance_references": resonance_references,
            "graph_feedback": {
                "attractor_mean": float(graph_acc["attractor_mean"] / total_weight),
                "phase_transition_mean": float(graph_acc["phase_transition_mean"] / total_weight),
                "confidence_mean": float(graph_acc["confidence_mean"] / total_weight),
                "constructive_mean": float(graph_acc["constructive_mean"] / total_weight),
                "destructive_mean": float(graph_acc["destructive_mean"] / total_weight),
                "interference_mean": float(graph_acc["interference_mean"] / total_weight),
                "phase_priors": graph_phase_priors,
            },
            "bayes_feedback": {
                "anchor_mean": float(bayes_acc["anchor_mean"] / total_weight),
                "pattern_mean": float(bayes_acc["pattern_mean"] / total_weight),
                "alarm_mean": float(bayes_acc["alarm_mean"] / total_weight),
                "overall_mean": float(bayes_acc["overall_mean"] / total_weight),
                "graph_phase_priors": bayes_phase_priors,
            },
            "pattern_feedback": {
                "similarity_mean": float(pattern_acc["similarity_mean"] / total_weight),
                "stability_mean": float(pattern_acc["stability_mean"] / total_weight),
                "cluster_profiles": cluster_profile_list[:12],
            },
            "merged_from": [str(item.get("snapshot_hash", "")) for item in snapshots if item.get("snapshot_hash")],
        }

    def build_collective_pattern_snapshot(
        self,
        source_label: str = "manual_snapshot",
        origin_node_id: str = "",
        user_id: int | None = None,
    ) -> dict[str, Any]:
        """Baut ein signierbares Shared-Prior-Paket aus dem lokalen Wissensstand."""
        scoped_user = int(user_id) if user_id is not None and int(user_id) > 0 else None
        params: tuple[Any, ...]
        if scoped_user is None:
            fingerprint_rows = self.connection.execute(
                """
                SELECT payload_json
                FROM fingerprints
                ORDER BY id DESC
                LIMIT 240
                """
            ).fetchall()
            vault_entries = self.get_vault_entries(limit=240)
            fingerprint_count = int(self.connection.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0])
        else:
            params = (scoped_user,)
            fingerprint_rows = self.connection.execute(
                """
                SELECT f.payload_json
                FROM fingerprints AS f
                JOIN app_sessions AS s ON s.session_id = f.session_id
                WHERE s.user_id = ?
                ORDER BY f.id DESC
                LIMIT 240
                """,
                params,
            ).fetchall()
            vault_entries = self.get_vault_entries(limit=240, user_id=scoped_user)
            fingerprint_count = int(
                self.connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM fingerprints AS f
                    JOIN app_sessions AS s ON s.session_id = f.session_id
                    WHERE s.user_id = ?
                    """,
                    params,
                ).fetchone()[0]
            )

        graph_records: list[dict[str, Any]] = []
        for row in fingerprint_rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            if payload:
                graph_records.append(payload)

        graph_feedback = {
            "attractor_mean": 0.0,
            "phase_transition_mean": 0.0,
            "confidence_mean": 0.0,
            "constructive_mean": 0.0,
            "destructive_mean": 0.0,
            "interference_mean": 0.0,
            "phase_priors": {"ATTRACTOR_LOCK": 0.0, "EMERGENT": 1.0, "PHASE_SHIFT": 0.0},
        }
        bayes_feedback = {
            "anchor_mean": 0.0,
            "pattern_mean": 0.0,
            "alarm_mean": 0.0,
            "overall_mean": 0.0,
            "graph_phase_priors": {"ATTRACTOR_LOCK": 0.0, "EMERGENT": 1.0, "PHASE_SHIFT": 0.0},
        }
        if graph_records:
            graph_feedback = {
                "attractor_mean": float(
                    np.mean([float(item.get("graph_attractor_score", 0.0) or 0.0) for item in graph_records])
                ),
                "phase_transition_mean": float(
                    np.mean([float(item.get("graph_phase_transition", 0.0) or 0.0) for item in graph_records])
                ),
                "confidence_mean": float(
                    np.mean([float(item.get("graph_confidence_mean", 0.0) or 0.0) for item in graph_records])
                ),
                "constructive_mean": float(
                    np.mean([float(item.get("graph_constructive_ratio", 0.0) or 0.0) for item in graph_records])
                ),
                "destructive_mean": float(
                    np.mean([float(item.get("graph_destructive_ratio", 0.0) or 0.0) for item in graph_records])
                ),
                "interference_mean": float(
                    np.mean([float(item.get("graph_interference_mean", 0.0) or 0.0) for item in graph_records])
                ),
                "phase_priors": self._normalize_distribution(
                    [str(item.get("graph_phase_state", "EMERGENT")) for item in graph_records]
                ),
            }
            bayes_feedback = {
                "anchor_mean": float(
                    np.mean([float(item.get("bayes_anchor_posterior", 0.0) or 0.0) for item in graph_records])
                ),
                "pattern_mean": float(
                    np.mean([float(item.get("bayes_pattern_posterior", 0.0) or 0.0) for item in graph_records])
                ),
                "alarm_mean": float(
                    np.mean([float(item.get("bayes_alarm_posterior", 0.0) or 0.0) for item in graph_records])
                ),
                "overall_mean": float(
                    np.mean([float(item.get("bayes_overall_confidence", 0.0) or 0.0) for item in graph_records])
                ),
                "graph_phase_priors": self._normalize_distribution(
                    [str(item.get("bayes_graph_phase", "EMERGENT")) for item in graph_records]
                ),
            }

        cluster_profiles: list[dict[str, Any]] = []
        grouped_vectors: dict[str, list[list[float]]] = {}
        grouped_similarity: dict[str, list[float]] = {}
        for entry in vault_entries:
            label = str(entry.get("cluster_label", "TRANSITIONAL") or "TRANSITIONAL")
            grouped_vectors.setdefault(label, []).append(
                [float(value) for value in list(entry.get("feature_vector", []))]
            )
            grouped_similarity.setdefault(label, []).append(float(entry.get("similarity_best", 0.0) or 0.0))
        for label, vectors in grouped_vectors.items():
            if not vectors:
                continue
            max_len = max(len(vector) for vector in vectors)
            matrix = np.array(
                [vector + ([0.0] * (max_len - len(vector))) for vector in vectors],
                dtype=np.float64,
            )
            cluster_profiles.append(
                {
                    "label": label,
                    "member_count": int(len(vectors)),
                    "similarity_mean": float(np.mean(grouped_similarity.get(label, [0.0]))),
                    "vector": [float(value) for value in list(np.mean(matrix, axis=0))],
                }
            )

        payload = {
            "schema": "aether.collective_snapshot.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_label": source_label,
            "origin_node_id": origin_node_id,
            "fingerprint_count": int(fingerprint_count),
            "vault_count": int(len(vault_entries)),
            "cluster_count": int(len(cluster_profiles)),
            "snapshot_count": 1,
            "anchor_priors": self.get_anchor_priors(limit=24),
            "resonance_references": self.get_resonance_reference_vectors(limit=48, include_collective=False),
            "graph_feedback": graph_feedback,
            "bayes_feedback": bayes_feedback,
            "pattern_feedback": {
                "similarity_mean": float(
                    np.mean([float(entry.get("similarity_best", 0.0) or 0.0) for entry in vault_entries])
                )
                if vault_entries
                else 0.0,
                "stability_mean": float(
                    np.mean(
                        [
                            min(1.0, float(profile["member_count"]) / 6.0) * float(profile["similarity_mean"])
                            for profile in cluster_profiles
                        ]
                    )
                )
                if cluster_profiles
                else 0.0,
                "cluster_profiles": cluster_profiles[:12],
            },
            "merged_from": [],
        }
        payload["snapshot_hash"] = self._collective_snapshot_hash(payload)
        return payload

    def build_dna_share_snapshot(
        self,
        source_label: str = "dna_share_bundle",
        origin_node_id: str = "",
        user_id: int | None = None,
        limit: int = 96,
    ) -> dict[str, Any]:
        """Baut einen datensparsamen DNA-Share-Bund aus bestaetigten lokalen Ergebnissen."""
        shared_entries = self._confirmed_lossless_dna_entries(user_id=user_id, limit=limit)
        if not shared_entries:
            raise ValueError("Keine CONFIRMED-lossless DNA zum Teilen gefunden.")

        shared_payloads = [dict(entry.get("payload_json", {}) or {}) for entry in shared_entries]
        graph_feedback = {
            "attractor_mean": float(
                np.mean([float(item.get("graph_attractor_score", 0.0) or 0.0) for item in shared_payloads])
            ),
            "phase_transition_mean": float(
                np.mean([float(item.get("graph_phase_transition", 0.0) or 0.0) for item in shared_payloads])
            ),
            "confidence_mean": float(
                np.mean([float(item.get("graph_confidence_mean", 0.0) or 0.0) for item in shared_payloads])
            ),
            "constructive_mean": float(
                np.mean([float(item.get("graph_constructive_ratio", 0.0) or 0.0) for item in shared_payloads])
            ),
            "destructive_mean": float(
                np.mean([float(item.get("graph_destructive_ratio", 0.0) or 0.0) for item in shared_payloads])
            ),
            "interference_mean": float(
                np.mean([float(item.get("graph_interference_mean", 0.0) or 0.0) for item in shared_payloads])
            ),
            "phase_priors": self._normalize_distribution(
                [str(item.get("graph_phase_state", "EMERGENT")) for item in shared_payloads]
            ),
        }
        bayes_feedback = {
            "anchor_mean": float(
                np.mean([float(item.get("bayes_anchor_posterior", 0.0) or 0.0) for item in shared_payloads])
            ),
            "pattern_mean": float(
                np.mean([float(item.get("bayes_pattern_posterior", 0.0) or 0.0) for item in shared_payloads])
            ),
            "alarm_mean": float(
                np.mean([float(item.get("bayes_alarm_posterior", 0.0) or 0.0) for item in shared_payloads])
            ),
            "overall_mean": float(
                np.mean([float(item.get("bayes_overall_confidence", 0.0) or 0.0) for item in shared_payloads])
            ),
            "graph_phase_priors": self._normalize_distribution(
                [str(item.get("bayes_graph_phase", "EMERGENT")) for item in shared_payloads]
            ),
        }

        cluster_profiles: list[dict[str, Any]] = []
        grouped_vectors: dict[str, list[list[float]]] = {}
        grouped_similarity: dict[str, list[float]] = {}
        for entry in shared_entries:
            label = str(entry.get("cluster_label", "TRANSITIONAL") or "TRANSITIONAL")
            vector = [float(value) for value in list(entry.get("feature_vector", []))]
            if vector:
                grouped_vectors.setdefault(label, []).append(vector)
            grouped_similarity.setdefault(label, []).append(float(entry.get("similarity_best", 0.0) or 0.0))
        for label, vectors in grouped_vectors.items():
            if not vectors:
                continue
            max_len = max(len(vector) for vector in vectors)
            matrix = np.array(
                [vector + ([0.0] * (max_len - len(vector))) for vector in vectors],
                dtype=np.float64,
            )
            cluster_profiles.append(
                {
                    "label": label,
                    "member_count": int(len(vectors)),
                    "similarity_mean": float(np.mean(grouped_similarity.get(label, [0.0]))),
                    "vector": [float(value) for value in list(np.mean(matrix, axis=0))],
                }
            )

        resonance_references: list[dict[str, float | int]] = []
        for payload in shared_payloads[:48]:
            resonance_references.append(
                {
                    "entropy_mean": float(payload.get("entropy_mean", 0.0) or 0.0),
                    "symmetry_score": float(payload.get("symmetry_score", 0.0) or 0.0),
                    "periodicity": int(payload.get("periodicity", 0) or 0),
                    "delta_ratio": float(payload.get("delta_ratio", 0.0) or 0.0),
                    "ethics_score": float(payload.get("ethics_score", 0.0) or 0.0),
                }
            )

        dna_records: list[dict[str, Any]] = []
        for entry in shared_entries:
            payload = dict(entry.get("payload_json", {}) or {})
            ae_lab = dict(payload.get("ae_lab", {}) or {})
            anchors = [
                dict(anchor)
                for anchor in list(payload.get("ae_anchors", []) or ae_lab.get("anchors", []) or [])
                if isinstance(anchor, dict)
            ][:16]
            pi_positions = [
                {
                    "index": int(anchor.get("index", index) or index),
                    "value": float(anchor.get("value", 0.0) or 0.0),
                    "deviation": float(anchor.get("deviation", 0.0) or 0.0),
                }
                for index, anchor in enumerate(anchors)
                if str(anchor.get("nearest_constant", "")).upper() == "PI"
                or str(anchor.get("type_label", "")).upper() == "PI_LIKE"
            ][:8]
            frequency_signatures = [
                {
                    "frequency": float(peak.get("frequency", 0.0) or 0.0),
                    "magnitude": float(peak.get("magnitude", 0.0) or 0.0),
                }
                for peak in list(payload.get("fourier_peaks", []) or [])[:5]
                if isinstance(peak, dict)
            ]
            record_payload = {
                "source_type": str(entry.get("source_type", "")),
                "cluster_label": str(entry.get("cluster_label", "")),
                "anchor_count": int(len(anchors)),
                "anchors": anchors,
                "anchor_pattern_hash": hashlib.sha256(
                    canonical_json(
                        [
                            {
                                "type_label": str(anchor.get("type_label", "")),
                                "nearest_constant": str(anchor.get("nearest_constant", "")),
                                "value": float(anchor.get("value", 0.0) or 0.0),
                            }
                            for anchor in anchors
                        ]
                    ).encode("utf-8")
                ).hexdigest(),
                "aether_origin": {
                    "producer": "AETHER",
                    "pipeline": "LOCAL_CONFIRMED_LOSSLESS",
                    "anchors_self_found_only": True,
                },
                "pi_positions": pi_positions,
                "frequency_signatures": frequency_signatures,
                "structure_patterns": {
                    "embedding_vector": [float(value) for value in list(entry.get("feature_vector", []))[:32]],
                    "anchor_vector": [float(value) for value in list(payload.get("anchor_vector", []) or [])[:32]],
                    "beauty_signature": dict(payload.get("beauty_signature", {}) or {}),
                    "graph_phase_state": str(payload.get("graph_phase_state", "")),
                    "graph_region": str(payload.get("graph_region", "")),
                    "coherence_score": float(payload.get("coherence_score", 0.0) or 0.0),
                    "resonance_score": float(payload.get("resonance_score", 0.0) or 0.0),
                    "ethics_score": float(payload.get("ethics_score", 0.0) or 0.0),
                },
                "vault_noether": dict(payload.get("vault_noether", {}) or {}),
                "vault_bayes": dict(payload.get("vault_bayes", {}) or {}),
                "vault_benford": dict(payload.get("vault_benford", {}) or {}),
                "trust_inputs": {
                    "confirmed_lossless": bool(payload.get("confirmed_lossless", False)),
                    "reconstruction_verified": bool(payload.get("reconstruction_verified", False)),
                    "coverage_verified": bool(payload.get("coverage_verified", False)),
                    "anchor_coverage_ratio": float(payload.get("anchor_coverage_ratio", 0.0) or 0.0),
                    "unresolved_residual_ratio": float(payload.get("unresolved_residual_ratio", 1.0) or 1.0),
                    "bayes_overall_confidence": float(payload.get("bayes_overall_confidence", 0.0) or 0.0),
                    "graph_confidence_mean": float(payload.get("graph_confidence_mean", 0.0) or 0.0),
                    "beauty_score": float(
                        dict(payload.get("beauty_signature", {}) or {}).get("beauty_score", 0.0) or 0.0
                    ),
                    "noether_score": float(
                        dict(payload.get("vault_noether", {}) or {}).get("invariant_score", 0.0) or 0.0
                    ),
                    "benford_score": float(
                        dict(payload.get("vault_benford", {}) or {}).get("score", 0.0) or 0.0
                    ),
                    "heisenberg_uncertainty": float(
                        dict(payload.get("ae_lab", {}) or {}).get("heisenberg_mean", 0.0) or 0.0
                    ),
                },
                "sharing_policy": {
                    "source_confirmed_lossless_local": True,
                    "shanway_filter": True,
                    "shared_anchor_assistance_only": True,
                    "lossless_reconstruction_shared": False,
                    "raw_files_leave_machine": False,
                    "local_paths_included": False,
                },
            }
            record_payload["dna_record_hash"] = hashlib.sha256(
                canonical_json(record_payload).encode("utf-8")
            ).hexdigest()
            dna_records.append(record_payload)

        payload = {
            "schema": "aether.dna_share.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_label": str(source_label),
            "origin_node_id": str(origin_node_id),
            "aether_origin": {
                "producer": "AETHER",
                "pipeline": "LOCAL_CONFIRMED_LOSSLESS",
                "anchors_self_found_only": True,
            },
            "fingerprint_count": int(len(shared_entries)),
            "vault_count": int(len(shared_entries)),
            "cluster_count": int(len(cluster_profiles)),
            "snapshot_count": 1,
            "anchor_priors": [],
            "resonance_references": resonance_references,
            "graph_feedback": graph_feedback,
            "bayes_feedback": bayes_feedback,
            "pattern_feedback": {
                "similarity_mean": float(
                    np.mean([float(entry.get("similarity_best", 0.0) or 0.0) for entry in shared_entries])
                ),
                "stability_mean": float(
                    np.mean(
                        [
                            min(1.0, float(profile["member_count"]) / 6.0) * float(profile["similarity_mean"])
                            for profile in cluster_profiles
                        ]
                    )
                )
                if cluster_profiles
                else 0.0,
                "cluster_profiles": cluster_profiles[:12],
            },
            "dna_share": {
                "record_count": int(len(dna_records)),
                "records": dna_records[:64],
                "sharing_policy": {
                    "source_confirmed_lossless_local_only": True,
                    "shanway_trust_filter": True,
                    "shared_anchor_assistance_only": True,
                    "lossless_reconstruction_shared": False,
                    "raw_files_leave_machine": False,
                    "local_paths_included": False,
                },
            },
            "merged_from": [],
        }
        payload["snapshot_hash"] = self._collective_snapshot_hash(payload)
        return payload

    def save_collective_snapshot(
        self,
        payload: dict[str, Any],
        source_label: str = "",
        origin_node_id: str = "",
        session_id: str = "",
        trust_weight: float = 1.0,
        merged_count: int = 1,
        signature: str = "",
    ) -> dict[str, Any]:
        """Persistiert ein Snapshot-Paket und liefert den finalen Datensatz zurueck."""
        normalized = dict(payload)
        normalized["schema"] = str(normalized.get("schema", "aether.collective_snapshot.v1"))
        normalized["created_at"] = str(normalized.get("created_at", datetime.now(timezone.utc).isoformat()))
        normalized["source_label"] = str(normalized.get("source_label", source_label))
        normalized["origin_node_id"] = str(normalized.get("origin_node_id", origin_node_id))
        normalized["snapshot_hash"] = str(
            normalized.get("snapshot_hash", "") or self._collective_snapshot_hash(normalized)
        )
        snapshot_hash = str(normalized["snapshot_hash"])
        cursor = self.connection.execute(
            """
            INSERT INTO collective_snapshots (
                session_id, timestamp, source_label, origin_node_id, snapshot_hash,
                trust_weight, merged_count, signature, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(snapshot_hash) DO UPDATE SET
                trust_weight = excluded.trust_weight,
                merged_count = CASE
                    WHEN excluded.merged_count > collective_snapshots.merged_count THEN excluded.merged_count
                    ELSE collective_snapshots.merged_count
                END,
                signature = CASE
                    WHEN excluded.signature <> '' THEN excluded.signature
                    ELSE collective_snapshots.signature
                END,
                payload_json = excluded.payload_json
            """,
            (
                session_id,
                normalized["created_at"],
                normalized["source_label"],
                normalized["origin_node_id"],
                snapshot_hash,
                float(max(0.05, trust_weight)),
                int(max(1, merged_count)),
                str(signature or ""),
                json.dumps(normalized, ensure_ascii=True),
            ),
        )
        self.connection.commit()
        row = self.connection.execute(
            """
            SELECT id, session_id, timestamp, source_label, origin_node_id, snapshot_hash,
                   trust_weight, merged_count, signature, payload_json
            FROM collective_snapshots
            WHERE snapshot_hash = ?
            LIMIT 1
            """,
            (snapshot_hash,),
        ).fetchone()
        assert row is not None
        payload_raw = str(row["payload_json"]).strip()
        stored_payload = json.loads(payload_raw) if payload_raw else {}
        return {
            "id": int(row["id"]),
            "session_id": str(row["session_id"]),
            "timestamp": str(row["timestamp"]),
            "source_label": str(row["source_label"]),
            "origin_node_id": str(row["origin_node_id"]),
            "snapshot_hash": str(row["snapshot_hash"]),
            "trust_weight": float(row["trust_weight"]),
            "merged_count": int(row["merged_count"]),
            "signature": str(row["signature"]),
            "payload_json": stored_payload,
            "lastrowid": int(cursor.lastrowid or 0),
        }

    def export_collective_snapshot(
        self,
        file_path: str,
        payload: dict[str, Any],
        signature: str = "",
        session_id: str = "",
        trust_weight: float = 1.0,
        merged_count: int = 1,
        persist_snapshot: bool = True,
    ) -> dict[str, Any]:
        """Exportiert ein Snapshot-Paket als signierte JSON-Datei."""
        stored = self.save_collective_snapshot(
            payload=payload,
            source_label=str(payload.get("source_label", "")),
            origin_node_id=str(payload.get("origin_node_id", "")),
            session_id=session_id,
            trust_weight=trust_weight,
            merged_count=merged_count,
            signature=signature,
        ) if persist_snapshot else {
            "snapshot_hash": str(payload.get("snapshot_hash", "") or self._collective_snapshot_hash(payload)),
            "trust_weight": float(trust_weight),
            "merged_count": int(max(1, merged_count)),
            "signature": str(signature or ""),
            "payload_json": dict(payload),
        }
        wrapper = {
            "schema": "aether.collective_snapshot.bundle.v1",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_hash": str(stored.get("snapshot_hash", "")),
            "trust_weight": float(stored.get("trust_weight", trust_weight)),
            "merged_count": int(stored.get("merged_count", merged_count)),
            "signature": str(stored.get("signature", signature or "")),
            "payload": dict(stored.get("payload_json", payload)),
        }
        if str(dict(wrapper.get("payload", {}) or {}).get("schema", "")).strip() == "aether.dna_share.v1":
            wrapper.update(self._sign_trusted_dna_share_payload(dict(wrapper.get("payload", {}) or {})))
        Path(file_path).write_text(json.dumps(wrapper, ensure_ascii=True, indent=2), encoding="utf-8")
        return wrapper

    def publish_public_anchor_library(
        self,
        session_id: str = "",
        origin_node_id: str = "",
        user_id: int | None = None,
        trust_weight: float = 1.0,
        signature: str = "",
        limit: int = 96,
        directory: str | None = None,
    ) -> dict[str, Any]:
        """Veroeffentlicht einen datensparsamen Anchor-Bund in einen gemeinsamen lokalen Library-Ordner."""
        payload = self.build_dna_share_snapshot(
            source_label="public_anchor_library",
            origin_node_id=str(origin_node_id),
            user_id=user_id,
            limit=limit,
        )
        target_dir = Path(directory) if directory is not None else Path("data") / "public_anchor_library"
        history_dir = target_dir / "history"
        target_dir.mkdir(parents=True, exist_ok=True)
        history_dir.mkdir(parents=True, exist_ok=True)

        snapshot_hash = str(payload.get("snapshot_hash", "") or self._collective_snapshot_hash(payload))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        history_path = history_dir / f"dna_share_{timestamp}_{snapshot_hash[:12]}.json"
        latest_path = target_dir / "latest.json"
        index_path = target_dir / "index.json"

        wrapper = self.export_collective_snapshot(
            file_path=str(history_path),
            payload=payload,
            signature=signature,
            session_id=session_id,
            trust_weight=trust_weight,
            merged_count=1,
            persist_snapshot=True,
        )
        latest_path.write_text(json.dumps(wrapper, ensure_ascii=True, indent=2), encoding="utf-8")

        recent_files = sorted(history_dir.glob("dna_share_*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        recent_entries: list[dict[str, Any]] = []
        for path in recent_files[:24]:
            recent_entries.append(
                {
                    "file": str(path.name),
                    "updated_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                    "size_bytes": int(path.stat().st_size),
                }
            )

        records = list(dict(payload.get("dna_share", {}) or {}).get("records", []) or [])
        constant_counts: dict[str, int] = {}
        for record in records:
            for anchor in list(dict(record).get("anchors", []) or []):
                if not isinstance(anchor, dict):
                    continue
                label = str(anchor.get("nearest_constant", "") or anchor.get("type_label", "") or "EMERGENT").upper()
                constant_counts[label] = int(constant_counts.get(label, 0)) + 1

        index_payload = {
            "schema": "aether.public_anchor_library.index.v1",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "latest_snapshot_hash": str(wrapper.get("snapshot_hash", snapshot_hash)),
            "latest_file": str(latest_path.name),
            "latest_history_file": str(history_path.name),
            "record_count": int(len(records)),
            "fingerprint_count": int(payload.get("fingerprint_count", 0) or 0),
            "source_confirmed_lossless_local_only": True,
            "shared_anchor_assistance_only": True,
            "lossless_reconstruction_shared": False,
            "raw_files_leave_machine": False,
            "local_paths_included": False,
            "origin_node_id": str(origin_node_id),
            "anchor_constants": constant_counts,
            "recent_files": recent_entries,
        }
        index_path.write_text(json.dumps(index_payload, ensure_ascii=True, indent=2), encoding="utf-8")
        return {
            "directory": str(target_dir),
            "history_file": str(history_path),
            "latest_file": str(latest_path),
            "index_file": str(index_path),
            "snapshot_hash": str(wrapper.get("snapshot_hash", snapshot_hash)),
            "record_count": int(len(records)),
            "fingerprint_count": int(payload.get("fingerprint_count", 0) or 0),
            "payload": dict(payload),
            "wrapper": dict(wrapper),
        }

    def pull_official_public_anchor_library(
        self,
        session_id: str = "",
        trust_weight: float = 1.0,
        timeout_seconds: float = 8.0,
        target_dir: str | None = None,
    ) -> dict[str, Any]:
        """Laedt den offiziellen Aether-Mirror read-only und importiert nur gueltige DNA-Share-Bundles."""
        target = Path(target_dir) if target_dir is not None else Path("data") / "public_anchor_library"
        target.mkdir(parents=True, exist_ok=True)
        pulled_at = datetime.now(timezone.utc).isoformat()
        try:
            with urlopen(str(OFFICIAL_PUBLIC_ANCHOR_MIRROR["index_url"]), timeout=max(1.0, float(timeout_seconds))) as response:
                index_raw = response.read().decode("utf-8")
            with urlopen(str(OFFICIAL_PUBLIC_ANCHOR_MIRROR["latest_url"]), timeout=max(1.0, float(timeout_seconds))) as response:
                latest_raw = response.read().decode("utf-8")
        except URLError as exc:
            raise ValueError(f"Offizieller Mirror ist aktuell nicht erreichbar: {exc}") from exc

        index_payload = json.loads(index_raw)
        latest_wrapper = json.loads(latest_raw)
        payload = dict(latest_wrapper.get("payload", {}) or {})
        if str(payload.get("schema", "")).strip() != "aether.dna_share.v1":
            raise ValueError("Offizieller Mirror enthaelt kein Aether-DNA-Share-Bundle.")
        if str(latest_wrapper.get("trusted_publisher_id", "") or "") != str(OFFICIAL_PUBLIC_ANCHOR_MIRROR["publisher_id"]):
            raise ValueError("Publisher-ID des offiziellen Mirrors stimmt nicht.")

        imported = self.import_collective_snapshot_payload(
            parsed=latest_wrapper,
            session_id=session_id,
            trust_weight=trust_weight,
        )

        (target / "mirror_index.json").write_text(json.dumps(index_payload, ensure_ascii=True, indent=2), encoding="utf-8")
        (target / "mirror_latest.json").write_text(json.dumps(latest_wrapper, ensure_ascii=True, indent=2), encoding="utf-8")
        return {
            "publisher_id": str(OFFICIAL_PUBLIC_ANCHOR_MIRROR["publisher_id"]),
            "pulled_at": str(pulled_at),
            "record_count": int(dict(payload.get("dna_share", {}) or {}).get("record_count", 0) or 0),
            "snapshot_hash": str(latest_wrapper.get("snapshot_hash", payload.get("snapshot_hash", ""))),
            "latest_snapshot_hash": str(index_payload.get("latest_snapshot_hash", "")),
            "imported_snapshot_hash": str(imported.get("snapshot_hash", "")),
            "target_dir": str(target),
        }

    def import_collective_snapshot_payload(
        self,
        parsed: dict[str, Any],
        session_id: str = "",
        trust_weight: float | None = None,
    ) -> dict[str, Any]:
        """Importiert ein bereits geladenes Snapshot-Paket und legt es lokal ab."""
        if isinstance(parsed, dict) and "payload" in parsed:
            payload = dict(parsed.get("payload", {}) or {})
            signature = str(parsed.get("signature", "") or "")
            merged_count = int(parsed.get("merged_count", 1) or 1)
            import_trust = float(parsed.get("trust_weight", 1.0) or 1.0)
        else:
            payload = dict(parsed or {})
            signature = ""
            merged_count = int(payload.get("snapshot_count", 1) or 1)
            import_trust = 1.0
        if str(payload.get("schema", "")).strip() == "aether.dna_share.v1":
            self._validate_aether_dna_share_payload(payload, wrapper=dict(parsed or {}))
        final_trust = float(import_trust if trust_weight is None else trust_weight)
        return self.save_collective_snapshot(
            payload=payload,
            source_label=str(payload.get("source_label", "imported_snapshot")),
            origin_node_id=str(payload.get("origin_node_id", "")),
            session_id=session_id,
            trust_weight=final_trust,
            merged_count=max(1, merged_count),
            signature=signature,
        )

    def import_collective_snapshot(
        self,
        file_path: str,
        session_id: str = "",
        trust_weight: float | None = None,
    ) -> dict[str, Any]:
        """Importiert ein Snapshot-Paket von Disk und legt es lokal ab."""
        raw = Path(file_path).read_text(encoding="utf-8")
        parsed = json.loads(raw)
        return self.import_collective_snapshot_payload(
            parsed=dict(parsed or {}),
            session_id=session_id,
            trust_weight=trust_weight,
        )

    def get_public_anchor_library_summary(self, directory: str | None = None) -> dict[str, Any]:
        """Liest den aktuellen Status der lokalen Public-Anchor-Library."""
        target_dir = Path(directory) if directory is not None else Path("data") / "public_anchor_library"
        index_path = target_dir / "index.json"
        latest_path = target_dir / "latest.json"
        if not index_path.is_file():
            return {
                "exists": False,
                "directory": str(target_dir),
                "record_count": 0,
                "fingerprint_count": 0,
                "latest_snapshot_hash": "",
                "anchor_constants": {},
                "updated_at": "",
                "latest_history_file": "",
            }
        try:
            index_payload = json.loads(index_path.read_text(encoding="utf-8"))
        except Exception:
            index_payload = {}
        latest_wrapper: dict[str, Any] = {}
        if latest_path.is_file():
            try:
                latest_wrapper = json.loads(latest_path.read_text(encoding="utf-8"))
            except Exception:
                latest_wrapper = {}
        return {
            "exists": True,
            "directory": str(target_dir),
            "record_count": int(index_payload.get("record_count", 0) or 0),
            "fingerprint_count": int(index_payload.get("fingerprint_count", 0) or 0),
            "latest_snapshot_hash": str(index_payload.get("latest_snapshot_hash", "") or latest_wrapper.get("snapshot_hash", "")),
            "anchor_constants": dict(index_payload.get("anchor_constants", {}) or {}),
            "updated_at": str(index_payload.get("updated_at", "")),
            "latest_history_file": str(index_payload.get("latest_history_file", "")),
            "latest_file": str(index_payload.get("latest_file", "latest.json")),
        }

    def get_collective_feedback(self, limit: int = 32) -> dict[str, Any]:
        """Liefert das aggregierte Prior-/Pattern-Feedback aus gespeicherten Snapshots."""
        snapshots = self.get_collective_snapshots(limit=limit)
        merged_payload = self._aggregate_collective_snapshots(
            snapshots=snapshots,
            source_label="collective_feedback",
            origin_node_id="",
        )
        trust_values = [float(item.get("trust_weight", 1.0) or 1.0) for item in snapshots]
        return {
            "snapshot_count": int(len(snapshots)),
            "trust_mean": float(np.mean(trust_values)) if trust_values else 0.0,
            "latest_hash": str(snapshots[0]["snapshot_hash"]) if snapshots else "",
            "latest_source_label": str(snapshots[0]["source_label"]) if snapshots else "",
            "fingerprint_count": int(merged_payload.get("fingerprint_count", 0) or 0),
            "vault_count": int(merged_payload.get("vault_count", 0) or 0),
            "cluster_count": int(merged_payload.get("cluster_count", 0) or 0),
            "anchor_priors": list(merged_payload.get("anchor_priors", []) or []),
            "resonance_references": list(merged_payload.get("resonance_references", []) or []),
            "graph_feedback": dict(merged_payload.get("graph_feedback", {}) or {}),
            "bayes_feedback": dict(merged_payload.get("bayes_feedback", {}) or {}),
            "pattern_feedback": dict(merged_payload.get("pattern_feedback", {}) or {}),
        }

    def get_collective_snapshot_summary(self, limit: int = 32) -> dict[str, Any]:
        """Verdichtet Snapshot-Bestand und aktuelle Merge-Lage fuer die GUI."""
        feedback = self.get_collective_feedback(limit=limit)
        return {
            "snapshot_count": int(feedback.get("snapshot_count", 0) or 0),
            "trust_mean": float(feedback.get("trust_mean", 0.0) or 0.0),
            "latest_hash": str(feedback.get("latest_hash", "")),
            "latest_source_label": str(feedback.get("latest_source_label", "")),
            "resonance_reference_count": int(len(list(feedback.get("resonance_references", []) or []))),
            "anchor_prior_count": int(len(list(feedback.get("anchor_priors", []) or []))),
            "cluster_count": int(feedback.get("cluster_count", 0) or 0),
            "fingerprint_count": int(feedback.get("fingerprint_count", 0) or 0),
        }

    def merge_collective_snapshots(
        self,
        session_id: str = "",
        source_label: str = "manual_merge",
        origin_node_id: str = "",
        trust_weight: float = 1.0,
        limit: int = 32,
        signature: str = "",
    ) -> dict[str, Any]:
        """Erzeugt aus mehreren Snapshots einen neuen lokal gespeicherten Merge-Snapshot."""
        snapshots = self.get_collective_snapshots(limit=limit)
        merged_payload = self._aggregate_collective_snapshots(
            snapshots=snapshots,
            source_label=source_label,
            origin_node_id=origin_node_id,
        )
        merged_payload["snapshot_hash"] = self._collective_snapshot_hash(merged_payload)
        return self.save_collective_snapshot(
            payload=merged_payload,
            source_label=source_label,
            origin_node_id=origin_node_id,
            session_id=session_id,
            trust_weight=trust_weight,
            merged_count=max(1, len(snapshots)),
            signature=signature,
        )

    def get_model_depth_report(self, user_id: int | None = None) -> dict[str, Any]:
        """Leitet eine einfache Modelltiefe aus Beobachtungsmenge und Quellenvielfalt ab."""
        params: tuple[Any, ...] = ()
        if user_id is None or int(user_id) <= 0:
            sample_row = self.connection.execute(
                """
                SELECT COUNT(*) AS samples,
                       COUNT(DISTINCT source_type) AS source_types,
                       COUNT(DISTINCT source_label) AS source_labels,
                       AVG(delta_ratio) AS avg_delta
                FROM fingerprints
                """
            ).fetchone()
            vault_row = self.connection.execute(
                """
                SELECT COUNT(*) AS vault_count,
                       COUNT(DISTINCT cluster_label) AS clusters
                FROM vault_entries
                """
            ).fetchone()
        else:
            params = (int(user_id),)
            sample_row = self.connection.execute(
                """
                SELECT COUNT(*) AS samples,
                       COUNT(DISTINCT f.source_type) AS source_types,
                       COUNT(DISTINCT f.source_label) AS source_labels,
                       AVG(f.delta_ratio) AS avg_delta
                FROM fingerprints AS f
                JOIN app_sessions AS s ON s.session_id = f.session_id
                WHERE s.user_id = ?
                """,
                params,
            ).fetchone()
            vault_row = self.connection.execute(
                """
                SELECT COUNT(*) AS vault_count,
                       COUNT(DISTINCT v.cluster_label) AS clusters
                FROM vault_entries AS v
                JOIN app_sessions AS s ON s.session_id = v.session_id
                WHERE s.user_id = ?
                """,
                params,
            ).fetchone()

        samples = int(sample_row["samples"]) if sample_row is not None else 0
        source_types = int(sample_row["source_types"]) if sample_row is not None else 0
        source_labels = int(sample_row["source_labels"]) if sample_row is not None else 0
        avg_delta = float(sample_row["avg_delta"]) if sample_row is not None and sample_row["avg_delta"] is not None else 0.0
        vault_count = int(vault_row["vault_count"]) if vault_row is not None else 0
        clusters = int(vault_row["clusters"]) if vault_row is not None else 0

        sample_score = 1.0 - math.exp(-float(samples) / 48.0)
        type_score = min(1.0, float(source_types) / 5.0)
        recurrence = float(samples) / max(1.0, float(source_labels))
        recurrence_score = min(1.0, recurrence / 4.0)
        cluster_score = min(1.0, float(clusters) / 3.0)
        compression_score = min(1.0, max(0.0, 1.0 - avg_delta))
        depth_score = 100.0 * (
            (0.34 * sample_score)
            + (0.18 * type_score)
            + (0.16 * recurrence_score)
            + (0.16 * cluster_score)
            + (0.16 * compression_score)
        )
        depth_score = float(max(0.0, min(100.0, depth_score)))

        if depth_score >= 70.0:
            label = "TIEF"
        elif depth_score >= 40.0:
            label = "LERNEND"
        else:
            label = "NAIV"

        return {
            "samples": samples,
            "source_types": source_types,
            "source_labels": source_labels,
            "vault_count": vault_count,
            "clusters": clusters,
            "average_delta_ratio": avg_delta,
            "depth_score": depth_score,
            "depth_label": label,
        }

    def get_delta_learning_curve(self, user_id: int | None = None, window: int = 18) -> dict[str, Any]:
        """Vergleicht fruehe und aktuelle Delta-Ratios als Lernkurve."""
        limit = int(max(6, window))
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT id, timestamp, delta_ratio, source_type, source_label
                FROM fingerprints
                ORDER BY id ASC
                """
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT f.id, f.timestamp, f.delta_ratio, f.source_type, f.source_label
                FROM fingerprints AS f
                JOIN app_sessions AS s ON s.session_id = f.session_id
                WHERE s.user_id = ?
                ORDER BY f.id ASC
                """,
                (int(user_id),),
            ).fetchall()
        if not rows:
            return {
                "samples": 0,
                "early_average": 0.0,
                "recent_average": 0.0,
                "improvement": 0.0,
                "improvement_ratio": 0.0,
                "trend_label": "NO_DATA",
            }

        ratios = [float(row["delta_ratio"]) for row in rows]
        early_slice = ratios[:limit]
        recent_slice = ratios[-limit:]
        early_avg = float(sum(early_slice) / max(1, len(early_slice)))
        recent_avg = float(sum(recent_slice) / max(1, len(recent_slice)))
        improvement = float(early_avg - recent_avg)
        improvement_ratio = float(improvement / max(1e-9, early_avg))
        if len(ratios) < 6:
            trend_label = "EARLY"
        elif improvement_ratio >= 0.12:
            trend_label = "LEARNING"
        elif improvement_ratio <= -0.08:
            trend_label = "DRIFT"
        else:
            trend_label = "STABLE"
        return {
            "samples": len(ratios),
            "early_average": early_avg,
            "recent_average": recent_avg,
            "improvement": improvement,
            "improvement_ratio": improvement_ratio,
            "trend_label": trend_label,
        }

    def get_delta_ratio_series(self, user_id: int | None = None, limit: int = 48) -> list[float]:
        """Liefert eine chronologische Serie juengerer Delta-Ratios fuer Mini-Verlaufsgrafiken."""
        sample_limit = int(max(8, limit))
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT delta_ratio
                FROM fingerprints
                ORDER BY id DESC
                LIMIT ?
                """,
                (sample_limit,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT f.delta_ratio
                FROM fingerprints AS f
                JOIN app_sessions AS s ON s.session_id = f.session_id
                WHERE s.user_id = ?
                ORDER BY f.id DESC
                LIMIT ?
                """,
                (int(user_id), sample_limit),
            ).fetchall()
        return [float(row["delta_ratio"]) for row in reversed(rows)]

    def get_anomaly_memory(self, user_id: int | None = None, limit: int = 6) -> list[dict[str, Any]]:
        """Verdichtet wiederkehrende Alarmereignisse zu einem lokalen Immungedaechtnis."""
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT reason, severity, COUNT(*) AS count, MAX(timestamp) AS last_seen
                FROM alarm_events
                GROUP BY reason, severity
                ORDER BY count DESC, last_seen DESC
                LIMIT ?
                """,
                (int(max(1, limit)),),
            ).fetchall()
            avg_map_rows = self.connection.execute(
                """
                SELECT reason, AVG(CAST(json_extract(payload_json, '$.bayes_alarm_posterior') AS REAL)) AS avg_bayes
                FROM alarm_events
                GROUP BY reason
                """
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT a.reason, a.severity, COUNT(*) AS count, MAX(a.timestamp) AS last_seen
                FROM alarm_events AS a
                JOIN app_sessions AS s ON s.session_id = a.session_id
                WHERE s.user_id = ?
                GROUP BY a.reason, a.severity
                ORDER BY count DESC, last_seen DESC
                LIMIT ?
                """,
                (int(user_id), int(max(1, limit))),
            ).fetchall()
            avg_map_rows = self.connection.execute(
                """
                SELECT a.reason, AVG(CAST(json_extract(a.payload_json, '$.bayes_alarm_posterior') AS REAL)) AS avg_bayes
                FROM alarm_events AS a
                JOIN app_sessions AS s ON s.session_id = a.session_id
                WHERE s.user_id = ?
                GROUP BY a.reason
                """,
                (int(user_id),),
            ).fetchall()

        avg_map = {
            str(row["reason"]): float(row["avg_bayes"]) if row["avg_bayes"] is not None else 0.0
            for row in avg_map_rows
        }
        memory: list[dict[str, Any]] = []
        for row in rows:
            memory.append(
                {
                    "reason": str(row["reason"]),
                    "severity": str(row["severity"]),
                    "count": int(row["count"]),
                    "last_seen": str(row["last_seen"]),
                    "avg_bayes_alarm_posterior": float(avg_map.get(str(row["reason"]), 0.0)),
                }
            )
        return memory

    def get_recent_alarm_events(self, user_id: int | None = None, limit: int = 12) -> list[dict[str, Any]]:
        """Liefert juengere Alarmereignisse inklusive Payload fuer Detailansichten."""
        if user_id is None or int(user_id) <= 0:
            rows = self.connection.execute(
                """
                SELECT session_id, timestamp, reason, severity, payload_json
                FROM alarm_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(1, limit)),),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT a.session_id, a.timestamp, a.reason, a.severity, a.payload_json
                FROM alarm_events AS a
                JOIN app_sessions AS s ON s.session_id = a.session_id
                WHERE s.user_id = ?
                ORDER BY a.id DESC
                LIMIT ?
                """,
                (int(user_id), int(max(1, limit))),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = str(row["payload_json"]).strip()
            try:
                payload = json.loads(payload_raw) if payload_raw else {}
            except Exception:
                payload = {}
            events.append(
                {
                    "session_id": str(row["session_id"]),
                    "timestamp": str(row["timestamp"]),
                    "reason": str(row["reason"]),
                    "severity": str(row["severity"]),
                    "payload_json": payload,
                }
            )
        return events

    def get_resonance_reference_vectors(
        self,
        limit: int = 300,
        include_collective: bool = True,
    ) -> list[dict[str, float | int]]:
        """
        Liefert gesunde historische Referenzvektoren fuer Ethik-Resonanzmessung.

        Args:
            limit: Maximale Anzahl geladener Referenzdatensaetze.
            include_collective: Fuegt gemergte Snapshot-Referenzen additiv hinzu.
        """
        rows = self.connection.execute(
            """
            SELECT entropy_mean, symmetry_score, periodicity, delta_ratio, ethics_score
            FROM fingerprints
            WHERE ethics_score >= 70.0 OR verdict = 'CLEAN'
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(max(20, limit)),),
        ).fetchall()
        if not rows:
            rows = self.connection.execute(
                """
                SELECT entropy_mean, symmetry_score, periodicity, delta_ratio, ethics_score
                FROM fingerprints
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(max(20, limit)),),
            ).fetchall()

        vectors: list[dict[str, float | int]] = []
        for row in rows:
            vectors.append(
                {
                    "entropy_mean": float(row["entropy_mean"]),
                    "symmetry_score": float(row["symmetry_score"]),
                    "periodicity": int(row["periodicity"]),
                    "delta_ratio": float(row["delta_ratio"]),
                    "ethics_score": float(row["ethics_score"]) if row["ethics_score"] is not None else 0.0,
                }
            )
        if include_collective:
            remaining = max(0, int(max(20, limit)) - len(vectors))
            if remaining > 0:
                feedback = self.get_collective_feedback(limit=min(32, max(8, remaining)))
                trust_mean = max(0.4, min(1.0, float(feedback.get("trust_mean", 1.0) or 1.0)))
                for ref in list(feedback.get("resonance_references", []) or [])[:remaining]:
                    vectors.append(
                        {
                            "entropy_mean": float(ref.get("entropy_mean", 0.0) or 0.0),
                            "symmetry_score": float(ref.get("symmetry_score", 0.0) or 0.0),
                            "periodicity": int(ref.get("periodicity", 0) or 0),
                            "delta_ratio": float(ref.get("delta_ratio", 0.0) or 0.0),
                            "ethics_score": float(ref.get("ethics_score", 0.0) or 0.0) * trust_mean,
                        }
                    )
        return vectors

    def get_session_entropy_profile(self, session_id: str) -> dict[str, Any]:
        """
        Liefert ein akkumuliertes Entropie-Profil fuer die aktuelle Session.

        Args:
            session_id: Session-ID der laufenden Instanz.
        """
        rows = self.connection.execute(
            """
            SELECT entropy_total, anomaly_detected
            FROM theremin_frames
            WHERE session_id = ?
            ORDER BY id ASC
            """,
            (session_id,),
        ).fetchall()
        if not rows:
            return {
                "session_id": session_id,
                "samples": 0,
                "entropy_mean": 0.0,
                "entropy_std": 0.0,
                "entropy_min": 0.0,
                "entropy_max": 0.0,
                "anomaly_rate": 0.0,
            }

        values = np.array([float(row["entropy_total"]) for row in rows], dtype=np.float64)
        anomalies = np.array([int(row["anomaly_detected"]) for row in rows], dtype=np.float64)
        return {
            "session_id": session_id,
            "samples": int(values.size),
            "entropy_mean": float(values.mean()),
            "entropy_std": float(values.std()),
            "entropy_min": float(values.min()),
            "entropy_max": float(values.max()),
            "anomaly_rate": float(anomalies.mean() if anomalies.size else 0.0),
        }

    def export_pattern_report(self) -> dict[str, Any]:
        """Exportiert einen Gesamtbericht ueber Datei- und Theremin-Analysemuster."""
        total_files = int(self.connection.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0])
        total_spectrum = int(self.connection.execute("SELECT COUNT(*) FROM spectrum_records").fetchone()[0])
        total_frames = int(self.connection.execute("SELECT COUNT(*) FROM theremin_frames").fetchone()[0])
        total_voxels = int(self.connection.execute("SELECT COUNT(*) FROM voxel_events").fetchone()[0])

        verdict_rows = self.connection.execute(
            "SELECT verdict, COUNT(*) AS count FROM fingerprints GROUP BY verdict"
        ).fetchall()
        verdict_distribution = {row["verdict"]: int(row["count"]) for row in verdict_rows}

        avg_row = self.connection.execute(
            """
            SELECT
                AVG(symmetry_score) AS avg_symmetry,
                AVG(delta_ratio) AS avg_delta,
                AVG(ethics_score) AS avg_ethics
            FROM fingerprints
            """
        ).fetchone()
        avg_symmetry = float(avg_row["avg_symmetry"]) if avg_row["avg_symmetry"] is not None else 0.0
        avg_delta = float(avg_row["avg_delta"]) if avg_row["avg_delta"] is not None else 0.0
        avg_ethics = float(avg_row["avg_ethics"]) if avg_row["avg_ethics"] is not None else 0.0

        period_rows = self.connection.execute(
            """
            SELECT periodicity, COUNT(*) AS count
            FROM fingerprints
            GROUP BY periodicity
            ORDER BY count DESC
            LIMIT 5
            """
        ).fetchall()
        periodicities = [{"periodicity": int(row["periodicity"]), "count": int(row["count"])} for row in period_rows]

        entropy_profile = self.connection.execute(
            """
            SELECT AVG(entropy_total) AS avg_entropy, MAX(entropy_total) AS max_entropy
            FROM theremin_frames
            """
        ).fetchone()
        theremin_avg_entropy = float(entropy_profile["avg_entropy"]) if entropy_profile["avg_entropy"] is not None else 0.0
        theremin_max_entropy = float(entropy_profile["max_entropy"]) if entropy_profile["max_entropy"] is not None else 0.0

        integrity_rows = self.connection.execute(
            "SELECT integrity_state, COUNT(*) AS count FROM fingerprints GROUP BY integrity_state"
        ).fetchall()
        integrity_distribution = {str(row["integrity_state"]): int(row["count"]) for row in integrity_rows}

        return {
            "total_files": total_files,
            "total_spectrum_records": total_spectrum,
            "total_theremin_frames": total_frames,
            "total_voxel_events": total_voxels,
            "verdict_distribution": verdict_distribution,
            "average_symmetry_score": avg_symmetry,
            "average_delta_ratio": avg_delta,
            "average_ethics_score": avg_ethics,
            "integrity_distribution": integrity_distribution,
            "top_periodicities": periodicities,
            "theremin_average_entropy": theremin_avg_entropy,
            "theremin_max_entropy": theremin_max_entropy,
        }

    def close(self) -> None:
        """Schliesst die Datenbankverbindung sauber."""
        try:
            self.connection.close()
        except sqlite3.Error:
            return
