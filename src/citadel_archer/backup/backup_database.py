"""Backup history database — tracks local backup archives.

Follows remote/shield_database.py pattern: SQLite + WAL mode via core.db.connect().
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class BackupDatabase:
    """SQLite persistence for backup metadata and history.

    Args:
        db_path: Path to SQLite database file.  Defaults to data/backup_history.db.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/backup_history.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _connect(self, row_factory: bool = False):
        from ..core.db import connect as db_connect
        return db_connect(self.db_path, row_factory=row_factory)

    def _init_database(self):
        """Create the backups table if it does not exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backups (
                    backup_id       TEXT UNIQUE NOT NULL,
                    label           TEXT DEFAULT '',
                    created_at      TEXT NOT NULL,
                    size_bytes      INTEGER DEFAULT 0,
                    db_count        INTEGER DEFAULT 0,
                    log_count       INTEGER DEFAULT 0,
                    checksum_sha256 TEXT NOT NULL,
                    archive_path    TEXT NOT NULL,
                    storage_locations TEXT DEFAULT '["local"]',
                    status          TEXT DEFAULT 'complete'
                )
            """)
            conn.commit()

    # ── CRUD ────────────────────────────────────────────────────────

    def record_backup(
        self,
        backup_id: str,
        label: str,
        size_bytes: int,
        db_count: int,
        log_count: int,
        checksum_sha256: str,
        archive_path: str,
    ) -> dict:
        """Insert a new backup record and return it."""
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO backups
                   (backup_id, label, created_at, size_bytes, db_count,
                    log_count, checksum_sha256, archive_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (backup_id, label, created_at, size_bytes, db_count,
                 log_count, checksum_sha256, archive_path),
            )
            conn.commit()
        return self.get_backup(backup_id)

    def list_backups(self, limit: int = 50) -> List[dict]:
        """Return backups sorted newest-first."""
        with self._connect(row_factory=True) as conn:
            rows = conn.execute(
                "SELECT * FROM backups ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_backup(self, backup_id: str) -> Optional[dict]:
        """Return a single backup record or None."""
        with self._connect(row_factory=True) as conn:
            row = conn.execute(
                "SELECT * FROM backups WHERE backup_id = ?", (backup_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def delete_backup_record(self, backup_id: str) -> bool:
        """Delete record from DB.  Returns True if a row was removed."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM backups WHERE backup_id = ?", (backup_id,)
            )
            conn.commit()
        return cursor.rowcount > 0

    def update_status(self, backup_id: str, status: str) -> bool:
        """Update status field (complete / corrupt / deleted)."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE backups SET status = ? WHERE backup_id = ?",
                (status, backup_id),
            )
            conn.commit()
        return cursor.rowcount > 0

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        # Parse JSON storage_locations
        try:
            d["storage_locations"] = json.loads(d.get("storage_locations", "[]"))
        except (json.JSONDecodeError, TypeError):
            d["storage_locations"] = ["local"]
        return d
