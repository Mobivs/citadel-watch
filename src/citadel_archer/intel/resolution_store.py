# Event Resolution Store — side-car persistence for resolved events.
#
# Tracks when a security event has been resolved (by Guardian AI or
# the user), what action was taken, and when.
#
# Design: separate DB (data/resolutions.db) so existing event schemas
# (EventAggregator, shield.db, correlation) are never mutated.
# Key: (source, external_id) — works across all event sources.

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DB_PATH = Path("data/resolutions.db")

_store_instance = None
_store_lock = threading.Lock()


class ResolutionStore:
    """SQLite-backed store for event resolution records."""

    def __init__(self, db_path: Path = _DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        from ..core.db import connect as db_connect
        self._conn = db_connect(str(db_path), check_same_thread=False, row_factory=True)
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS event_resolutions (
                    source       TEXT NOT NULL,
                    external_id  TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    resolved_at  TEXT NOT NULL,
                    resolved_by  TEXT NOT NULL DEFAULT 'user',
                    notes        TEXT,
                    PRIMARY KEY (source, external_id)
                );
            """)
            # Re-assert foreign_keys after executescript (defensive)
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.commit()

    # ── Writes ────────────────────────────────────────────────────────

    def resolve(
        self,
        source: str,
        external_id: str,
        action_taken: str,
        resolved_by: str = "user",
        notes: Optional[str] = None,
    ) -> Dict:
        """Upsert a resolution record. Returns the stored record."""
        resolved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO event_resolutions
                    (source, external_id, action_taken, resolved_at, resolved_by, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, external_id) DO UPDATE SET
                    action_taken = excluded.action_taken,
                    resolved_at  = excluded.resolved_at,
                    resolved_by  = excluded.resolved_by,
                    notes        = excluded.notes
                """,
                (source, external_id, action_taken, resolved_at, resolved_by, notes),
            )
            self._conn.commit()
        return {
            "source": source,
            "external_id": external_id,
            "action_taken": action_taken,
            "resolved_at": resolved_at,
            "resolved_by": resolved_by,
            "notes": notes,
        }

    def unresolve(self, source: str, external_id: str) -> bool:
        """Delete a resolution record. Returns True if it existed."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM event_resolutions WHERE source = ? AND external_id = ?",
                (source, external_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    # ── Reads ─────────────────────────────────────────────────────────

    def get(self, source: str, external_id: str) -> Optional[Dict]:
        """Fetch a single resolution by (source, external_id)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM event_resolutions WHERE source = ? AND external_id = ?",
                (source, external_id),
            ).fetchone()
            return dict(row) if row else None

    def get_many(self, pairs: List[Tuple[str, str]]) -> Dict[str, Dict]:
        """Bulk-fetch resolutions by (source, external_id) pairs.

        Returns dict keyed by 'source:external_id'.
        Used by the frontend to enrich event lists in a single request.
        """
        if not pairs:
            return {}
        result: Dict[str, Dict] = {}
        with self._lock:
            for source, external_id in pairs:
                row = self._conn.execute(
                    "SELECT * FROM event_resolutions WHERE source = ? AND external_id = ?",
                    (source, external_id),
                ).fetchone()
                if row:
                    result[f"{source}:{external_id}"] = dict(row)
        return result


# ── Singleton accessor ────────────────────────────────────────────────

def get_resolution_store() -> ResolutionStore:
    """Return the process-wide ResolutionStore singleton."""
    global _store_instance
    with _store_lock:
        if _store_instance is None:
            _store_instance = ResolutionStore()
        return _store_instance
