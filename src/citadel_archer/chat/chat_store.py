# PRD: SecureChat — Message Persistence
# Reference: Plan Milestone 1
#
# SQLite-backed message store for the SecureChat system.
# All chat messages are persisted to data/securechat.db.

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .message import ChatMessage, MessageType

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path("data/securechat.db")


class ChatStore:
    """Thread-safe SQLite store for chat messages.

    Args:
        db_path: Path to the SQLite database file. Set to ``None``
                 for in-memory mode (tests).
    """

    def __init__(self, db_path: Optional[Path] = _DEFAULT_DB_PATH):
        self._lock = threading.RLock()
        self._db_path = db_path

        if self._db_path is not None:
            self._db_path = Path(self._db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_database()

    def _get_conn(self) -> sqlite3.Connection:
        if self._db_path is None:
            raise RuntimeError("ChatStore is in memory-only mode without persistent conn")
        from ..core.db import connect as db_connect

        return db_connect(self._db_path, row_factory=True)

    def _init_database(self):
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id TEXT PRIMARY KEY,
                    from_id TEXT NOT NULL,
                    to_id TEXT NOT NULL,
                    msg_type TEXT NOT NULL DEFAULT 'text',
                    payload TEXT NOT NULL DEFAULT '{}',
                    timestamp TEXT NOT NULL,
                    signature TEXT DEFAULT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_ts ON chat_messages(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_from ON chat_messages(from_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_type ON chat_messages(msg_type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_to ON chat_messages(to_id)"
            )
            # Migration: add inter-agent correlation columns (v0.3.21)
            try:
                conn.execute(
                    "ALTER TABLE chat_messages ADD COLUMN reply_to TEXT DEFAULT NULL"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists
            try:
                conn.execute(
                    "ALTER TABLE chat_messages ADD COLUMN correlation_id TEXT DEFAULT NULL"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, msg: ChatMessage) -> None:
        """Persist a message to the database."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO chat_messages
                       (id, from_id, to_id, msg_type, payload, timestamp, signature,
                        reply_to, correlation_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        msg.id,
                        msg.from_id,
                        msg.to_id,
                        msg.msg_type.value,
                        json.dumps(msg.payload),
                        msg.timestamp,
                        msg.signature,
                        msg.reply_to,
                        msg.correlation_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_messages(
        self,
        *,
        limit: int = 50,
        before: Optional[str] = None,
        after: Optional[str] = None,
        participant: Optional[str] = None,
        msg_type: Optional[MessageType] = None,
    ) -> List[ChatMessage]:
        """Query messages with optional filters.

        Returns messages ordered oldest-first (ascending timestamp).
        """
        clauses: list = []
        params: list = []

        if before:
            clauses.append("timestamp < ?")
            params.append(before)
        if after:
            clauses.append("timestamp > ?")
            params.append(after)
        if participant:
            clauses.append("(from_id = ? OR to_id = ?)")
            params.extend([participant, participant])
        if msg_type:
            clauses.append("msg_type = ?")
            params.append(msg_type.value)

        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)

        sql = f"SELECT * FROM chat_messages {where} ORDER BY timestamp ASC LIMIT ?"
        params.append(limit)

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()
        return [self._row_to_message(r) for r in rows]

    def get_recent(self, limit: int = 50) -> List[ChatMessage]:
        """Get the N most recent messages (oldest-first order)."""
        sql = """
            SELECT * FROM (
                SELECT * FROM chat_messages ORDER BY timestamp DESC LIMIT ?
            ) sub ORDER BY timestamp ASC
        """
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(sql, (limit,)).fetchall()
            finally:
                conn.close()
        return [self._row_to_message(r) for r in rows]

    def delete_matching_payload(self, text_fragment: str) -> int:
        """Delete messages whose payload contains the given text fragment.

        Used to deduplicate persistent system messages (e.g. startup banners)
        before writing a fresh copy. Returns the number of rows deleted.
        """
        fragment = f"%{text_fragment}%"
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "DELETE FROM chat_messages WHERE payload LIKE ?", (fragment,)
                )
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    def count(self) -> int:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT COUNT(*) FROM chat_messages").fetchone()
            finally:
                conn.close()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Memory compaction support
    # ------------------------------------------------------------------

    def total_content_length_since_compaction(self) -> int:
        """Sum of payload lengths for messages added after the last compaction marker.

        Used for token estimation to decide when to trigger compaction.
        Excludes compaction marker messages themselves so the count resets
        after each compaction.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                marker_row = conn.execute(
                    "SELECT MAX(timestamp) FROM chat_messages "
                    "WHERE payload LIKE ?",
                    ('%"compaction_summary": true%',),
                ).fetchone()
                cutoff = marker_row[0] if (marker_row and marker_row[0]) else "1970-01-01"
                row = conn.execute(
                    "SELECT SUM(LENGTH(payload)) FROM chat_messages "
                    "WHERE timestamp > ? AND payload NOT LIKE ?",
                    (cutoff, '%"compaction_summary": true%'),
                ).fetchone()
                return row[0] or 0
            finally:
                conn.close()

    def get_messages_for_compaction(self, limit: int = 5000) -> List[ChatMessage]:
        """Return all non-marker messages since the last compaction, oldest-first.

        If no compaction has occurred, returns the full history up to limit.
        Compaction markers are excluded so they are never included in the
        transcript sent to Haiku.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                marker_row = conn.execute(
                    "SELECT MAX(timestamp) FROM chat_messages "
                    "WHERE payload LIKE ?",
                    ('%"compaction_summary": true%',),
                ).fetchone()
                cutoff = marker_row[0] if (marker_row and marker_row[0]) else "1970-01-01"
                rows = conn.execute(
                    "SELECT * FROM chat_messages "
                    "WHERE timestamp > ? AND payload NOT LIKE ? "
                    "ORDER BY timestamp ASC LIMIT ?",
                    (cutoff, '%"compaction_summary": true%', limit),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_message(r) for r in rows]

    def get_latest_compaction_summary(self) -> Optional[str]:
        """Return the summary text from the most recent compaction marker, or None."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT payload FROM chat_messages "
                    "WHERE payload LIKE ? "
                    "ORDER BY timestamp DESC LIMIT 1",
                    ('%"compaction_summary": true%',),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        try:
            payload = json.loads(row["payload"] or "{}")
            return payload.get("text")
        except (json.JSONDecodeError, TypeError):
            return None

    def get_latest_compaction_timestamp(self) -> Optional[str]:
        """Return the timestamp of the most recent compaction marker, or None."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT timestamp FROM chat_messages "
                    "WHERE payload LIKE ? "
                    "ORDER BY timestamp DESC LIMIT 1",
                    ('%"compaction_summary": true%',),
                ).fetchone()
            finally:
                conn.close()
        return row["timestamp"] if row else None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> ChatMessage:
        payload = {}
        try:
            payload = json.loads(row["payload"] or "{}")
        except (json.JSONDecodeError, TypeError):
            pass

        try:
            msg_type = MessageType(row["msg_type"])
        except ValueError:
            msg_type = MessageType.TEXT

        # reply_to/correlation_id added in v0.3.21 migration
        keys = row.keys() if hasattr(row, "keys") else []
        return ChatMessage(
            id=row["id"],
            from_id=row["from_id"],
            to_id=row["to_id"],
            msg_type=msg_type,
            payload=payload,
            timestamp=row["timestamp"],
            signature=row["signature"],
            reply_to=row["reply_to"] if "reply_to" in keys else None,
            correlation_id=row["correlation_id"] if "correlation_id" in keys else None,
        )
