"""Repository-Klassen fuer die erste Aufteilung der Aether-Registry."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable


def _canonical_json(payload: Any) -> str:
    """Serialisiert Payloads stabil fuer Hashes und Signaturen."""
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _safe_json_loads(raw_value: Any, fallback: Any) -> Any:
    """Liest JSON robust und liefert bei fehlerhaften Daten einen Fallback."""
    raw = str(raw_value).strip()
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except Exception:
        return fallback


class UserRepository:
    """Kapselt lokale User-, Session- und Security-Audit-Operationen."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        now_iso: Callable[[], str],
        new_sync_materials: Callable[[], tuple[str, str]],
        ensure_user_sync_material: Callable[[int, str, str, str, str, str], tuple[str, str]],
        protect_local_secret: Callable[[str], str],
    ) -> None:
        self.connection = connection
        self._now_iso = now_iso
        self._new_sync_materials = new_sync_materials
        self._ensure_user_sync_material = ensure_user_sync_material
        self._protect_local_secret = protect_local_secret

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
        protected_secret = self._protect_local_secret(secret_value)
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

    def _row_to_user(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        """Normalisiert eine User-Zeile inklusive Sync-Material in ein Dictionary."""
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
            "settings_json": _safe_json_loads(row["settings_json"], {}),
        }

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
        return self._row_to_user(row)

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
        return self._row_to_user(row)

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
        return [
            {
                "id": int(row["id"]),
                "timestamp": str(row["timestamp"]),
                "user_id": int(row["user_id"]),
                "username": str(row["username"]),
                "event_type": str(row["event_type"]),
                "severity": str(row["severity"]),
                "payload_json": _safe_json_loads(row["payload_json"], {}),
            }
            for row in rows
        ]

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
        rule_hash = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
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
        return [
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
                "payload_json": _safe_json_loads(row["payload_json"], {}),
            }
            for row in rows
        ]

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


class VaultRepository:
    """Kapselt Append-, Update- und Leseoperationen fuer Vault-Eintraege."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

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
        return [
            {
                "id": int(row["id"]),
                "session_id": str(row["session_id"]),
                "timestamp": str(row["timestamp"]),
                "source_type": str(row["source_type"]),
                "source_label": str(row["source_label"]),
                "file_hash": str(row["file_hash"]),
                "feature_vector": _safe_json_loads(row["feature_vector"], []),
                "similarity_best": float(row["similarity_best"]),
                "cluster_label": str(row["cluster_label"]),
                "payload_json": _safe_json_loads(row["payload_json"], {}),
                "signature": str(row["signature"]),
            }
            for row in rows
        ]


class ChainRepository:
    """Kapselt Append-only- und Leseoperationen fuer Chain-Bloecke."""

    def __init__(self, connection: sqlite3.Connection, *, now_iso: Callable[[], str]) -> None:
        self.connection = connection
        self._now_iso = now_iso

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

    def latest_chain_annotations(self, block_ids: list[int]) -> dict[int, dict[str, Any]]:
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
            result[int(row["block_id"])] = {
                "annotation_type": str(row["annotation_type"]),
                "payload_json": _safe_json_loads(row["payload_json"], {}),
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
        return [
            {
                "id": int(row["id"]),
                "session_id": str(row["session_id"]),
                "timestamp": str(row["timestamp"]),
                "milestone": int(row["milestone"]),
                "coherence": float(row["coherence"]),
                "key_fingerprint": str(row["key_fingerprint"]),
                "block_hash": str(row["block_hash"]),
                "payload_json": _safe_json_loads(row["payload_json"], {}),
                "signature": str(row["signature"]),
            }
            for row in rows
        ]

    def get_chain_blocks(
        self,
        limit: int = 200,
        user_id: int | None = None,
        include_genesis: bool = True,
    ) -> list[dict[str, Any]]:
        """Liefert Blockbasis plus juengste additive Annotation fuer UI und Export."""
        blocks = self.get_chain_blocks_raw(limit=limit, user_id=user_id, include_genesis=include_genesis)
        annotations = self.latest_chain_annotations([int(item["id"]) for item in blocks if int(item["id"]) > 0])
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


class DeltaRepository:
    """Kapselt Append- und Lesezugriffe auf gespeicherte Delta-Logs."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

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
                "payload_json": _safe_json_loads(row["payload_json"], {}),
                "signature": str(row["signature"]),
            }
            for row in rows
        ]
