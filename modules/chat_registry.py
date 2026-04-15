from __future__ import annotations

import json
import sqlite3
from typing import Any


class ChatRegistry:
    """Separate Chat-Persistenz für Aether.

    Die Kern-Registry bleibt für Analyse- und Vault-Daten zuständig.
    Chat-Tabellen und Chat-Events werden in diesem Modul verwaltet.
    """

    def __init__(self, connection: sqlite3.Connection, now_iso: callable) -> None:
        self.connection = connection
        self._now_iso = now_iso

    def _create_tables(self) -> None:
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
                visible_to_assistant INTEGER NOT NULL DEFAULT 1,
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
                assistant_enabled INTEGER NOT NULL DEFAULT 0,
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
        self.connection.commit()

    def record_chat_sync_event(
        self,
        event_uid: str,
        event_type: str,
        source_url: str,
        remote_event_id: int,
        payload: dict[str, Any] | None = None,
    ) -> bool:
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
        row = self.connection.execute(
            "SELECT 1 FROM chat_sync_events WHERE event_uid = ? LIMIT 1",
            (str(event_uid).strip(),),
        ).fetchone()
        return row is not None

    def get_chat_sync_cursor(self, endpoint: str) -> int:
        row = self.connection.execute(
            "SELECT last_event_id FROM chat_sync_cursors WHERE endpoint = ? LIMIT 1",
            (str(endpoint).strip(),),
        ).fetchone()
        if row is None:
            return 0
        return int(row["last_event_id"])

    def update_chat_sync_cursor(self, endpoint: str, last_event_id: int) -> None:
        self.connection.execute(
            """
            INSERT INTO chat_sync_cursors (endpoint, last_event_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(endpoint) DO UPDATE SET
                last_event_id = excluded.last_event_id,
                updated_at = excluded.updated_at
            """,
            (str(endpoint).strip(), int(last_event_id), self._now_iso()),
        )
        self.connection.commit()
