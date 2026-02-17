# User Preferences Store
# SQLite-backed key/value store for dashboard preferences.
# Follows the RemoteShieldDatabase pattern (core.db connect helper).
#
# Primary use: dashboard_mode = "technical" | "simplified"

import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Well-known preference keys
PREF_DASHBOARD_MODE = "dashboard_mode"


class UserPreferences:
    """SQLite key/value store for user preferences.

    Args:
        db_path: Path to SQLite file. Defaults to data/user_preferences.db.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/user_preferences.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        from .db import connect as db_connect

        with db_connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        from .db import connect as db_connect

        return db_connect(self.db_path, row_factory=True)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a preference value by key. Returns default if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM user_preferences WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return default
        return row["value"]

    def set(self, key: str, value: str) -> None:
        """Set a preference value (upsert)."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO user_preferences (key, value, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                       value = excluded.value,
                       updated_at = excluded.updated_at""",
                (key, value, now),
            )
            conn.commit()

    def get_all(self) -> Dict[str, str]:
        """Return all preferences as a dict."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key, value FROM user_preferences ORDER BY key"
            ).fetchall()
        return {row["key"]: row["value"] for row in rows}

    def delete(self, key: str) -> bool:
        """Delete a preference. Returns True if the key existed."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM user_preferences WHERE key = ?", (key,)
            )
            conn.commit()
            return cur.rowcount > 0


# ── Singleton ────────────────────────────────────────────────────────

_instance: Optional[UserPreferences] = None


def get_user_preferences() -> UserPreferences:
    """Get or create the singleton UserPreferences instance."""
    global _instance
    if _instance is None:
        _instance = UserPreferences()
    return _instance


def set_user_preferences(instance: Optional[UserPreferences]) -> None:
    """Replace the singleton (for testing)."""
    global _instance
    _instance = instance
