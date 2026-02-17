# PRD: Intel Module - SQLite Storage
# Reference: PHASE_2_SPEC.md
#
# Persistent storage for threat intelligence items using SQLite.
# Provides insert-with-dedup, querying by type/severity, and
# statistics for the intel pipeline.

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import IntelItem, IntelSeverity, IntelType


DEFAULT_DB_PATH = "/var/citadel/intel.db"


class IntelStore:
    """SQLite-backed storage for threat intelligence data.

    Thread-safe via a reentrant lock on all write operations.
    Deduplication is enforced at insert time via a unique constraint
    on the ``dedup_key`` column.
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        from ..core.db import connect as db_connect

        self._conn = db_connect(db_path, check_same_thread=False, row_factory=True)
        self._create_tables()

    def _create_tables(self) -> None:
        """Create the schema if it doesn't already exist."""
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS intel_items (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id     TEXT    NOT NULL UNIQUE,
                    intel_type  TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    dedup_key   TEXT    NOT NULL UNIQUE,
                    source_feed TEXT    NOT NULL DEFAULT '',
                    payload     TEXT    NOT NULL,
                    raw_data    TEXT,
                    ingested_at TEXT    NOT NULL,
                    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_intel_type
                    ON intel_items(intel_type);
                CREATE INDEX IF NOT EXISTS idx_intel_severity
                    ON intel_items(severity);
                CREATE INDEX IF NOT EXISTS idx_intel_source
                    ON intel_items(source_feed);
                CREATE INDEX IF NOT EXISTS idx_intel_ingested
                    ON intel_items(ingested_at);

                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL
                );
                """
            )
            # Re-assert foreign_keys after executescript (defensive)
            self._conn.execute("PRAGMA foreign_keys=ON")
            # Ensure version row exists
            row = self._conn.execute(
                "SELECT version FROM schema_version LIMIT 1"
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (self.SCHEMA_VERSION,),
                )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def insert(self, item: IntelItem) -> bool:
        """Insert an intel item, returning True if stored (False if duplicate)."""
        payload_json = json.dumps(
            item.payload.to_dict() if hasattr(item.payload, "to_dict") else str(item.payload)
        )
        raw_json = json.dumps(item.raw_data) if item.raw_data else None

        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO intel_items
                        (item_id, intel_type, severity, dedup_key,
                         source_feed, payload, raw_data, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.item_id,
                        item.intel_type.value,
                        item.severity.value,
                        item.dedup_key,
                        item.source_feed,
                        payload_json,
                        raw_json,
                        item.ingested_at,
                    ),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Duplicate dedup_key or item_id
                return False

    def bulk_insert(self, items: List[IntelItem]) -> Dict[str, int]:
        """Insert multiple items. Returns counts of inserted vs duplicates."""
        inserted = 0
        duplicates = 0
        for item in items:
            if self.insert(item):
                inserted += 1
            else:
                duplicates += 1
        return {"inserted": inserted, "duplicates": duplicates}

    def delete_by_id(self, item_id: str) -> bool:
        """Delete a single item by its UUID. Returns True if deleted."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM intel_items WHERE item_id = ?", (item_id,)
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def purge_older_than(self, days: int) -> int:
        """Remove items older than N days. Returns count deleted."""
        with self._lock:
            cursor = self._conn.execute(
                """
                DELETE FROM intel_items
                WHERE ingested_at < datetime('now', ?)
                """,
                (f"-{days} days",),
            )
            self._conn.commit()
            return cursor.rowcount

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_by_id(self, item_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single item by UUID."""
        row = self._conn.execute(
            "SELECT * FROM intel_items WHERE item_id = ?", (item_id,)
        ).fetchone()
        return dict(row) if row else None

    def has_key(self, dedup_key: str) -> bool:
        """Check whether a dedup_key already exists."""
        row = self._conn.execute(
            "SELECT 1 FROM intel_items WHERE dedup_key = ? LIMIT 1",
            (dedup_key,),
        ).fetchone()
        return row is not None

    def query(
        self,
        intel_type: Optional[IntelType] = None,
        severity: Optional[IntelSeverity] = None,
        source_feed: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query intel items with optional filters."""
        clauses: List[str] = []
        params: List[Any] = []

        if intel_type is not None:
            clauses.append("intel_type = ?")
            params.append(intel_type.value)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity.value)
        if source_feed is not None:
            clauses.append("source_feed = ?")
            params.append(source_feed)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM intel_items{where} ORDER BY ingested_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(
        self,
        intel_type: Optional[IntelType] = None,
        severity: Optional[IntelSeverity] = None,
    ) -> int:
        """Count items with optional filters."""
        clauses: List[str] = []
        params: List[Any] = []
        if intel_type is not None:
            clauses.append("intel_type = ?")
            params.append(intel_type.value)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity.value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        row = self._conn.execute(
            f"SELECT COUNT(*) FROM intel_items{where}", params
        ).fetchone()
        return row[0]

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics for the intel store."""
        total = self.count()
        by_type = {}
        for t in IntelType:
            by_type[t.value] = self.count(intel_type=t)
        by_severity = {}
        for s in IntelSeverity:
            by_severity[s.value] = self.count(severity=s)
        return {
            "total": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "db_path": self.db_path,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
