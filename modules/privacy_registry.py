import logging
logger = logging.getLogger(__name__)
"""
Aether – Privacy Registry mit widerrufbaren Freigaben.

Trennt klar zwischen Anker (struktureller Fingerprint) und Filekey
(symmetrischer Entschlüsselungsschlüssel). Freigaben sind granular,
zeitlich begrenzt und widerrufbar.

Datenschutzprinzipien:
  - Anker und Filekeys werden niemals im selben Record gespeichert
  - Freigaben sind per Default temporär (TTL)
  - Widerruf ist sofort und irreversibel
  - Kein Netz-Export ohne explizite Freigabe
  - Alle Änderungen werden append-only geloggt
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "privacy_registry.db"

_DDL = """
CREATE TABLE IF NOT EXISTS anchors (
    anchor_id       TEXT PRIMARY KEY,
    created_at      REAL NOT NULL,
    domain          TEXT NOT NULL DEFAULT '',   -- z.B. 'process', 'file', 'text'
    meta_json       TEXT NOT NULL DEFAULT '{}'  -- strukturelle Metadaten, KEIN Inhalt
);

CREATE TABLE IF NOT EXISTS filekeys (
    key_id          TEXT PRIMARY KEY,
    anchor_id       TEXT NOT NULL,              -- Anker-Referenz (kein Join auf Inhalt)
    key_hash        TEXT NOT NULL,              -- SHA-256 des Keys (nie der Key selbst)
    created_at      REAL NOT NULL,
    FOREIGN KEY (anchor_id) REFERENCES anchors(anchor_id)
);

CREATE TABLE IF NOT EXISTS grants (
    grant_id        TEXT PRIMARY KEY,
    anchor_id       TEXT NOT NULL,
    key_id          TEXT,                       -- NULL = nur Anker-Hash geteilt
    grantee_id      TEXT NOT NULL,              -- Empfänger-ID (Gerät/Nutzer-Token)
    mode            TEXT NOT NULL,              -- 'anchor_only' | 'full_key'
    created_at      REAL NOT NULL,
    expires_at      REAL,                       -- NULL = permanent
    revoked_at      REAL,                       -- NULL = aktiv
    revoke_reason   TEXT NOT NULL DEFAULT '',
    grant_hash      TEXT NOT NULL,              -- SHA-256(anchor_id+grantee_id+mode+created_at)
    FOREIGN KEY (anchor_id) REFERENCES anchors(anchor_id)
);
CREATE INDEX IF NOT EXISTS idx_grants_anchor ON grants (anchor_id);
CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants (grantee_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    event_type      TEXT NOT NULL,              -- 'grant' | 'revoke' | 'check' | 'anchor_add'
    grant_id        TEXT,
    anchor_id       TEXT,
    grantee_id      TEXT,
    detail          TEXT NOT NULL DEFAULT ''
);
"""


class GrantMode(str, Enum):
    ANCHOR_ONLY = "anchor_only"  # Nur Struktur-Hash — kein Schlüsselzugang
    FULL_KEY    = "full_key"     # Anchor + Key-Zugang


@dataclass
class AnchorRecord:
    """Struktureller Anker-Eintrag — kein Dateiinhalt."""
    anchor_id: str
    domain: str
    created_at: float
    meta: dict = field(default_factory=dict)


@dataclass
class GrantRecord:
    """Freigabe-Eintrag."""
    grant_id: str
    anchor_id: str
    grantee_id: str
    mode: GrantMode
    created_at: float
    expires_at: Optional[float] = None
    revoked_at: Optional[float] = None
    revoke_reason: str = ""
    key_id: Optional[str] = None
    grant_hash: str = ""

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True


class PrivacyRegistry:
    """
    Widerrufbare Freigaben für Anker und Filekeys.

    Trennung von Anker und Filekey:
      - Anker: nicht-invertierbarer Strukturfingerprint (öffentlich teilbar)
      - Filekey: symmetrischer Entschlüsselungsschlüssel (nie direkt gespeichert,
                 nur als SHA-256-Hash referenziert)

    Alle Operationen sind thread-sicher und werden im Audit-Log erfasst.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self._db_path), check_same_thread=False, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception as e:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_db(self) -> None:
        with self._lock, self._conn() as con:
            con.executescript(_DDL)

    def _audit(
        self,
        con: sqlite3.Connection,
        event_type: str,
        grant_id: Optional[str] = None,
        anchor_id: Optional[str] = None,
        grantee_id: Optional[str] = None,
        detail: str = "",
    ) -> None:
        con.execute(
            """INSERT INTO audit_log (ts,event_type,grant_id,anchor_id,grantee_id,detail)
               VALUES (?,?,?,?,?,?)""",
            (time.time(), event_type, grant_id, anchor_id, grantee_id, detail),
        )

    # ------------------------------------------------------------------
    # Anker-Verwaltung
    # ------------------------------------------------------------------

    def register_anchor(
        self,
        anchor_id: str,
        domain: str = "",
        meta: Optional[dict] = None,
    ) -> AnchorRecord:
        """
        Registriert einen Anker in der Registry.

        anchor_id — nicht-invertierbarer Strukturfingerprint (SHA-256)
        domain    — Herkunftsdomäne ('process', 'file', 'text', …)
        meta      — optionale strukturelle Metadaten (kein Inhalt!)
        """
        now = time.time()
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        with self._lock, self._conn() as con:
            con.execute(
                """INSERT OR IGNORE INTO anchors (anchor_id, created_at, domain, meta_json)
                   VALUES (?,?,?,?)""",
                (anchor_id, now, domain, meta_json),
            )
            self._audit(con, "anchor_add", anchor_id=anchor_id, detail=domain)
        return AnchorRecord(
            anchor_id=anchor_id, domain=domain, created_at=now,
            meta=meta or {}
        )

    def register_filekey(self, anchor_id: str, key_bytes: bytes) -> str:
        """
        Registriert eine Filekey-Referenz (nur SHA-256-Hash wird gespeichert).

        Der Klartext-Key wird NICHT gespeichert. Nur der Hash wird in der DB
        geführt, um Freigaben referenzierbar zu machen.

        Rückgabe: key_id (UUID)
        """
        key_id = str(uuid.uuid4())
        key_hash = hashlib.sha256(key_bytes).hexdigest()
        now = time.time()
        with self._lock, self._conn() as con:
            # Sicherstellen dass Anker bekannt ist
            exists = con.execute(
                "SELECT 1 FROM anchors WHERE anchor_id=?", (anchor_id,)
            ).fetchone()
            if not exists:
                raise KeyError(f"Anker '{anchor_id}' nicht in Registry bekannt.")
            con.execute(
                """INSERT INTO filekeys (key_id, anchor_id, key_hash, created_at)
                   VALUES (?,?,?,?)""",
                (key_id, anchor_id, key_hash, now),
            )
        return key_id

    # ------------------------------------------------------------------
    # Freigabe-Verwaltung
    # ------------------------------------------------------------------

    def grant_share(
        self,
        anchor_id: str,
        grantee_id: str,
        mode: GrantMode | str = GrantMode.ANCHOR_ONLY,
        ttl_seconds: Optional[float] = None,
        key_id: Optional[str] = None,
    ) -> str:
        """
        Erstellt eine neue Freigabe.

        anchor_id   — Anker der zu teilenden Ressource
        grantee_id  — Empfänger-Kennung (Geräte-ID, Nutzer-Token, o. ä.)
        mode        — 'anchor_only' (nur Hash) oder 'full_key' (Hash + Key-Zugang)
        ttl_seconds — Gültigkeitsdauer in Sekunden (None = permanent)
        key_id      — Pflicht bei mode='full_key'

        Rückgabe: grant_id (UUID)
        """
        if isinstance(mode, str):
            mode = GrantMode(mode)
        if mode == GrantMode.FULL_KEY and key_id is None:
            raise ValueError("key_id ist bei mode='full_key' erforderlich.")

        grant_id = str(uuid.uuid4())
        now = time.time()
        expires_at = now + ttl_seconds if ttl_seconds else None
        grant_hash = hashlib.sha256(
            f"{anchor_id}|{grantee_id}|{mode.value}|{now}".encode()
        ).hexdigest()

        with self._lock, self._conn() as con:
            con.execute(
                """INSERT INTO grants
                   (grant_id, anchor_id, key_id, grantee_id, mode,
                    created_at, expires_at, revoked_at, revoke_reason, grant_hash)
                   VALUES (?,?,?,?,?,?,?,NULL,'',?)""",
                (grant_id, anchor_id, key_id, grantee_id,
                 mode.value, now, expires_at, grant_hash),
            )
            self._audit(
                con, "grant",
                grant_id=grant_id,
                anchor_id=anchor_id,
                grantee_id=grantee_id,
                detail=f"mode={mode.value}, ttl={ttl_seconds}",
            )
        return grant_id

    def revoke_share(self, grant_id: str, reason: str = "") -> bool:
        """
        Widerruft eine Freigabe sofort und unwiderruflich.

        Rückgabe: True wenn erfolgreich widerrufen, False wenn nicht gefunden
                  oder bereits widerrufen.
        """
        now = time.time()
        with self._lock, self._conn() as con:
            row = con.execute(
                "SELECT anchor_id, grantee_id, revoked_at FROM grants WHERE grant_id=?",
                (grant_id,),
            ).fetchone()
            if row is None:
                return False
            if row["revoked_at"] is not None:
                return False  # Bereits widerrufen
            con.execute(
                "UPDATE grants SET revoked_at=?, revoke_reason=? WHERE grant_id=?",
                (now, reason[:500], grant_id),
            )
            self._audit(
                con, "revoke",
                grant_id=grant_id,
                anchor_id=row["anchor_id"],
                grantee_id=row["grantee_id"],
                detail=reason[:200],
            )
        return True

    def revoke_all_for_anchor(self, anchor_id: str, reason: str = "") -> int:
        """Widerruft alle aktiven Freigaben für einen bestimmten Anker."""
        active = self.list_active_grants(anchor_id=anchor_id)
        count = 0
        for g in active:
            if self.revoke_share(g["grant_id"], reason=reason):
                count += 1
        return count

    # ------------------------------------------------------------------
    # Abfragen
    # ------------------------------------------------------------------

    def check_permission(
        self, anchor_id: str, grantee_id: str
    ) -> Optional[str]:
        """
        Prüft ob grantee_id Zugriff auf anchor_id hat.

        Rückgabe: 'anchor_only' | 'full_key' | None (kein Zugriff)
        """
        now = time.time()
        with self._lock, self._conn() as con:
            cur = con.execute(
                """SELECT mode, expires_at, revoked_at FROM grants
                   WHERE anchor_id=? AND grantee_id=?
                   ORDER BY created_at DESC""",
                (anchor_id, grantee_id),
            )
            self._audit(
                con, "check",
                anchor_id=anchor_id,
                grantee_id=grantee_id,
            )
            for row in cur.fetchall():
                if row["revoked_at"] is not None:
                    continue
                if row["expires_at"] is not None and now > row["expires_at"]:
                    continue
                return row["mode"]
        return None

    def list_active_grants(
        self,
        anchor_id: Optional[str] = None,
        grantee_id: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Gibt alle aktiven (nicht widerrufenen, nicht abgelaufenen) Freigaben zurück."""
        now = time.time()
        clauses = ["revoked_at IS NULL", "(expires_at IS NULL OR expires_at > ?)"]
        params: list[Any] = [now]
        if anchor_id:
            clauses.append("anchor_id=?")
            params.append(anchor_id)
        if grantee_id:
            clauses.append("grantee_id=?")
            params.append(grantee_id)
        params.append(limit)
        sql = (
            "SELECT * FROM grants WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at DESC LIMIT ?"
        )
        with self._lock, self._conn() as con:
            cur = con.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def list_expired_grants(self, limit: int = 100) -> list[dict[str, Any]]:
        """Gibt abgelaufene (aber noch nicht widerrufene) Freigaben zurück."""
        now = time.time()
        with self._lock, self._conn() as con:
            cur = con.execute(
                """SELECT * FROM grants
                   WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?
                   ORDER BY expires_at DESC LIMIT ?""",
                (now, limit),
            )
            return [dict(row) for row in cur.fetchall()]

    def purge_expired_grants(self) -> int:
        """Bereinigt abgelaufene Freigaben (setzt revoked_at rückwirkend)."""
        expired = self.list_expired_grants(limit=10000)
        count = 0
        for g in expired:
            if self.revoke_share(g["grant_id"], reason="ttl_expired"):
                count += 1
        return count

    def get_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Gibt die letzten Einträge des Audit-Logs zurück."""
        with self._lock, self._conn() as con:
            cur = con.execute(
                "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------
    # Statusübersicht
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, int]:
        """Kurze Statusübersicht über die Registry."""
        with self._lock, self._conn() as con:
            anchors = int(con.execute("SELECT COUNT(*) FROM anchors").fetchone()[0])
            keys    = int(con.execute("SELECT COUNT(*) FROM filekeys").fetchone()[0])
            active  = len(self.list_active_grants(limit=10000))
            total   = int(con.execute("SELECT COUNT(*) FROM grants").fetchone()[0])
            revoked = total - active
        return {
            "anchors":       anchors,
            "filekeys":      keys,
            "active_grants": active,
            "total_grants":  total,
            "revoked_grants": revoked,
        }
