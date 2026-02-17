# PRD: Core Module — Central SQLite Connection Helper
# Reference: docs/PRD.md v0.3.8 — "SQLite WAL mode"
#
# Every Citadel Archer SQLite database should use `connect()` from this
# module instead of raw `sqlite3.connect()`. This ensures:
#
#   - WAL journal mode (concurrent readers + one writer)
#   - busy_timeout to avoid SQLITE_BUSY under contention
#   - foreign_keys enforcement on every connection
#
# WAL is required for the planned citadel-service / citadel-archer split:
# the always-on service writes events while the desktop app reads them.
# Even for single-process databases, WAL improves read concurrency
# across threads and per-method fresh connections.

import sqlite3
from pathlib import Path
from typing import Union


def connect(
    db_path: Union[str, Path],
    *,
    row_factory: bool = False,
    check_same_thread: bool = True,
) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and safe PRAGMAs.

    Args:
        db_path: Path to the database file.
        row_factory: If True, set conn.row_factory = sqlite3.Row.
        check_same_thread: Passed to sqlite3.connect().

    Returns:
        sqlite3.Connection with WAL mode, busy_timeout, and foreign_keys.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=check_same_thread)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    if row_factory:
        conn.row_factory = sqlite3.Row
    return conn
