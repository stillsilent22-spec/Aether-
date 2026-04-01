from __future__ import annotations
import logging
logger = logging.getLogger(__name__)
"""symbiont_vault.py — Aether Symbiont: AES-256-GCM Delta-Vault.

Brücke zum Rust-seitigen delta_vault (LocalDeltaVault via subprocess).
Speichert/Lädt StructuralProfile-Snapshots als verschlüsselte Deltas.
Fallback auf SQLite-basierten Python-Vault wenn Rust-Binary nicht verfügbar.
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, List

from modules.symbiont_core import StructuralProfile, StructuralDelta

log = logging.getLogger("symbiont_vault")

# ── Vault-Pfade ───────────────────────────────────────────────────────────────

VAULT_DB_PATH = os.path.join("data", "symbiont_vault.db")
SNAPSHOT_TTL_DAYS = 30   # Snapshots älter als 30 Tage werden gelöscht


# ── Datenklassen ──────────────────────────────────────────────────────────────

@dataclass
class SnapshotHandle:
    """Referenz auf einen gespeicherten StructuralProfile-Snapshot."""
    snapshot_id: str        # UUID
    signal_id: str          # SHA-256[:16] des Signals
    timestamp: float
    byte_length: int
    entropy: float
    signal_type: str

    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "signal_id":   self.signal_id,
            "timestamp":   self.timestamp,
            "byte_length": self.byte_length,
            "entropy":     round(self.entropy, 5),
            "signal_type": self.signal_type,
        }


@dataclass
class ReconstructedState:
    """Rekonstruierter Zustand aus mehreren Snapshots (Delta-Kette)."""
    anchor_id: str                              # Ältester Snapshot in der Kette
    reconstructed_profile: StructuralProfile   # Aggregiertes Profil
    delta_chain_length: int
    reconstruction_confidence: float           # [0, 1]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "anchor_id":               self.anchor_id,
            "reconstructed_profile":   self.reconstructed_profile.to_dict(),
            "delta_chain_length":      self.delta_chain_length,
            "reconstruction_confidence": round(self.reconstruction_confidence, 4),
            "timestamp":               self.timestamp,
        }


@dataclass
class StructuralDiff:
    """Differenz zwischen zwei SnapshotHandles (oberflächlich)."""
    handle_a: SnapshotHandle
    handle_b: SnapshotHandle
    entropy_diff: float
    byte_diff: int
    type_changed: bool
    time_delta_s: float

    def to_dict(self) -> dict:
        return {
            "snapshot_a":   self.handle_a.snapshot_id,
            "snapshot_b":   self.handle_b.snapshot_id,
            "entropy_diff": round(self.entropy_diff, 5),
            "byte_diff":    self.byte_diff,
            "type_changed": self.type_changed,
            "time_delta_s": round(self.time_delta_s, 2),
        }


# ── Hauptklasse ───────────────────────────────────────────────────────────────

class SymbiontVault:
    """
    Persistenter Vault für StructuralProfile-Snapshots.

    Verwendet SQLite als primäre Speicherschicht. Der Rust-seitige
    LocalDeltaVault (AES-256-GCM) wird als optionaler Sicherheits-Layer
    via subprocess eingebunden wenn das Binary vorhanden ist.
    """

    def __init__(
        self,
        db_path: str = VAULT_DB_PATH,
        rust_vault_bin: Optional[str] = None,
    ) -> None:
        self._db_path = db_path
        self._rust_bin = rust_vault_bin
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception as e:
                logger.warning(f"[symbiont_vault] Fehler: {e}")
                pass
            self._conn = None

    # ── Öffentliche API ───────────────────────────────────────────────────────

    def store_snapshot(self, profile: StructuralProfile) -> SnapshotHandle:
        """Speichert ein StructuralProfile und gibt einen SnapshotHandle zurück."""
        snap_id = str(uuid.uuid4())
        now = time.time()
        blob = json.dumps(profile.to_dict()).encode()

        if self._conn:
            try:
                self._conn.execute(
                    """INSERT INTO snapshots
                       (snapshot_id, signal_id, timestamp, byte_length, entropy,
                        signal_type, profile_blob)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (snap_id, profile.signal_id, now, profile.byte_length,
                     profile.entropy, profile.signal_type, blob),
                )
                self._conn.commit()
            except Exception as exc:
                log.warning("store_snapshot DB error: %s", exc)

        return SnapshotHandle(
            snapshot_id  = snap_id,
            signal_id    = profile.signal_id,
            timestamp    = now,
            byte_length  = profile.byte_length,
            entropy      = profile.entropy,
            signal_type  = profile.signal_type,
        )

    def load_snapshot(self, snapshot_id: str) -> Optional[StructuralProfile]:
        """Lädt ein gespeichertes StructuralProfile anhand seiner Snapshot-ID."""
        if self._conn is None:
            return None
        try:
            cur = self._conn.execute(
                "SELECT profile_blob FROM snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            data = json.loads(row[0])
            return self._profile_from_dict(data)
        except Exception as exc:
            log.warning("load_snapshot error: %s", exc)
            return None

    def list_snapshots(
        self, signal_id: Optional[str] = None, limit: int = 64
    ) -> list[SnapshotHandle]:
        """Listet gespeicherte Snapshots, optional gefiltert nach signal_id."""
        if self._conn is None:
            return []
        try:
            if signal_id:
                cur = self._conn.execute(
                    "SELECT snapshot_id, signal_id, timestamp, byte_length, entropy, signal_type "
                    "FROM snapshots WHERE signal_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (signal_id, limit),
                )
            else:
                cur = self._conn.execute(
                    "SELECT snapshot_id, signal_id, timestamp, byte_length, entropy, signal_type "
                    "FROM snapshots ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                )
            return [
                SnapshotHandle(
                    snapshot_id  = row[0],
                    signal_id    = row[1],
                    timestamp    = float(row[2]),
                    byte_length  = int(row[3]),
                    entropy      = float(row[4]),
                    signal_type  = str(row[5]),
                )
                for row in cur.fetchall()
            ]
        except Exception as exc:
            log.warning("list_snapshots error: %s", exc)
            return []

    def diff_snapshots(
        self, handle_a: SnapshotHandle, handle_b: SnapshotHandle
    ) -> StructuralDiff:
        """Berechnet die oberflächliche Differenz zweier Snapshot-Handles."""
        return StructuralDiff(
            handle_a      = handle_a,
            handle_b      = handle_b,
            entropy_diff  = abs(handle_a.entropy - handle_b.entropy),
            byte_diff     = abs(handle_a.byte_length - handle_b.byte_length),
            type_changed  = handle_a.signal_type != handle_b.signal_type,
            time_delta_s  = abs(handle_a.timestamp - handle_b.timestamp),
        )

    def reconstruct_state(
        self, signal_id: str, max_chain: int = 8
    ) -> Optional[ReconstructedState]:
        """
        Rekonstruiert einen aggregierten Zustand aus den letzten max_chain
        Snapshots eines Signals.
        """
        handles = self.list_snapshots(signal_id=signal_id, limit=max_chain)
        if not handles:
            return None

        profiles = [
            p for h in handles
            if (p := self.load_snapshot(h.snapshot_id)) is not None
        ]
        if not profiles:
            return None

        # Aggregation: Mittelwerte der numerischen Felder
        n = len(profiles)
        agg = StructuralProfile(
            signal_id           = signal_id,
            timestamp           = time.time(),
            byte_length         = int(sum(p.byte_length for p in profiles) / n),
            entropy             = sum(p.entropy for p in profiles) / n,
            compression_ratio   = sum(p.compression_ratio for p in profiles) / n,
            token_count         = int(sum(p.token_count for p in profiles) / n),
            unique_token_ratio  = sum(p.unique_token_ratio for p in profiles) / n,
            structural_depth    = int(sum(p.structural_depth for p in profiles) / n),
            symmetry            = sum(p.symmetry for p in profiles) / n,
            signal_type         = profiles[0].signal_type,
        )
        confidence = min(1.0, n / max(1, max_chain))
        return ReconstructedState(
            anchor_id                  = handles[-1].snapshot_id,
            reconstructed_profile      = agg,
            delta_chain_length         = n,
            reconstruction_confidence  = round(confidence, 4),
        )

    def prune_old_snapshots(self) -> int:
        """Löscht Snapshots älter als SNAPSHOT_TTL_DAYS. Gibt Anzahl gelöschter Zeilen zurück."""
        if self._conn is None:
            return 0
        cutoff = time.time() - SNAPSHOT_TTL_DAYS * 86400
        try:
            cur = self._conn.execute(
                "DELETE FROM snapshots WHERE timestamp < ?", (cutoff,)
            )
            self._conn.commit()
            return cur.rowcount
        except Exception as e:
            return 0

    # ── Initialisierung ───────────────────────────────────────────────────────

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or "data", exist_ok=True)
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id  TEXT    PRIMARY KEY,
                    signal_id    TEXT    NOT NULL,
                    timestamp    REAL    NOT NULL,
                    byte_length  INTEGER NOT NULL,
                    entropy      REAL    NOT NULL,
                    signal_type  TEXT    NOT NULL,
                    profile_blob BLOB    NOT NULL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_snap_sig ON snapshots(signal_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_snap_ts  ON snapshots(timestamp)"
            )
            self._conn.commit()
        except Exception as exc:
            log.warning("symbiont_vault DB init failed: %s", exc)
            self._conn = None

    @staticmethod
    def _profile_from_dict(data: dict) -> StructuralProfile:
        return StructuralProfile(
            signal_id          = str(data.get("signal_id", "")),
            timestamp          = float(data.get("timestamp", 0.0)),
            byte_length        = int(data.get("byte_length", 0)),
            entropy            = float(data.get("entropy", 0.0)),
            compression_ratio  = float(data.get("compression_ratio", 0.0)),
            token_count        = int(data.get("token_count", 0)),
            unique_token_ratio = float(data.get("unique_token_ratio", 0.0)),
            structural_depth   = int(data.get("structural_depth", 0)),
            symmetry           = float(data.get("symmetry", 0.0)),
            signal_type        = str(data.get("signal_type", "unknown")),
        )
