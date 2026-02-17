"""
Tests for SQLite WAL Mode — central connect utility and per-database verification.

Covers: core/db.connect() PRAGMAs, WAL on all database modules,
shield.py inline WAL, concurrent read-during-write, busy_timeout.
"""

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from citadel_archer.core.db import connect as db_connect


# ===================================================================
# TestCoreDBConnect — central utility
# ===================================================================


class TestCoreDBConnect:
    """Verify the core connect() utility sets correct PRAGMAs."""

    def test_returns_connection(self, tmp_path):
        conn = db_connect(tmp_path / "test.db")
        assert isinstance(conn, sqlite3.Connection)
        conn.close()

    def test_wal_mode_enabled(self, tmp_path):
        conn = db_connect(tmp_path / "test.db")
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_busy_timeout_set(self, tmp_path):
        conn = db_connect(tmp_path / "test.db")
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 5000
        conn.close()

    def test_foreign_keys_on(self, tmp_path):
        conn = db_connect(tmp_path / "test.db")
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
        conn.close()

    def test_row_factory_off_by_default(self, tmp_path):
        conn = db_connect(tmp_path / "test.db")
        assert conn.row_factory is None
        conn.close()

    def test_row_factory_on_when_requested(self, tmp_path):
        conn = db_connect(tmp_path / "test.db", row_factory=True)
        assert conn.row_factory is sqlite3.Row
        conn.close()

    def test_check_same_thread_false(self, tmp_path):
        # Should not raise when accessed from a different thread
        conn = db_connect(tmp_path / "test.db", check_same_thread=False)
        results = []

        def worker():
            try:
                conn.execute("SELECT 1")
                results.append("ok")
            except Exception as e:
                results.append(str(e))

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert results == ["ok"]
        conn.close()

    def test_path_object_accepted(self, tmp_path):
        conn = db_connect(Path(tmp_path) / "pathlib.db")
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_string_path_accepted(self, tmp_path):
        conn = db_connect(str(tmp_path / "strpath.db"))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()


# ===================================================================
# TestExistingDBsWALMode — integration tests per database module
# ===================================================================


class TestExistingDBsWALMode:
    """Verify WAL is enabled on every database module."""

    def _check_wal(self, db_path: Path) -> str:
        """Query journal_mode from a database file."""
        conn = sqlite3.connect(str(db_path))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        return mode

    def test_shield_database_uses_wal(self, tmp_path):
        from citadel_archer.remote.shield_database import RemoteShieldDatabase

        db = RemoteShieldDatabase(db_path=str(tmp_path / "shield.db"))
        assert self._check_wal(db.db_path) == "wal"

    def test_agent_registry_uses_wal(self, tmp_path):
        from citadel_archer.chat.agent_registry import AgentRegistry

        db = AgentRegistry(db_path=str(tmp_path / "agents.db"))
        assert self._check_wal(db.db_path) == "wal"

    def test_panic_database_uses_wal(self, tmp_path):
        from citadel_archer.panic.panic_database import PanicDatabase

        db = PanicDatabase(db_path=tmp_path / "panic.db")
        assert self._check_wal(db.db_path) == "wal"

    def test_intel_store_uses_wal(self, tmp_path):
        from citadel_archer.intel.store import IntelStore

        db = IntelStore(db_path=str(tmp_path / "intel.db"))
        mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        db.close()

    def test_asset_inventory_uses_wal(self, tmp_path):
        from citadel_archer.intel.assets import AssetInventory

        db = AssetInventory(db_path=tmp_path / "assets.db")
        assert self._check_wal(db._db_path) == "wal"

    def test_chat_store_uses_wal(self, tmp_path):
        from citadel_archer.chat.chat_store import ChatStore

        db = ChatStore(db_path=tmp_path / "chat.db")
        assert self._check_wal(db._db_path) == "wal"

    def test_vault_manager_uses_wal(self, tmp_path):
        from citadel_archer.vault.vault_manager import VaultManager

        vm = VaultManager(vault_path=tmp_path / "vault.db")
        vm.initialize_vault("TestPassword123!")
        assert self._check_wal(vm.vault_path) == "wal"


# ===================================================================
# TestShieldAgentWAL — standalone agent inline WAL
# ===================================================================


class TestShieldAgentWAL:
    """Verify the standalone shield agent sets WAL inline."""

    def test_shield_init_db_sets_wal(self, tmp_path):
        from citadel_archer.agent.shield import init_db

        db_path = tmp_path / "events.db"
        conn = init_db(db_path=str(db_path))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 5000
        conn.close()


# ===================================================================
# TestConcurrentAccess — WAL enables concurrent reads during writes
# ===================================================================


class TestConcurrentAccess:
    """Verify WAL allows concurrent read + write."""

    def test_wal_allows_concurrent_read_during_write(self, tmp_path):
        db_path = tmp_path / "concurrent.db"
        conn = db_connect(db_path)
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO t VALUES (1, 'initial')")
        conn.commit()

        # Start a write transaction (but don't commit yet)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO t VALUES (2, 'writing')")

        # A second connection should still be able to READ
        reader = db_connect(db_path, row_factory=True)
        rows = reader.execute("SELECT * FROM t").fetchall()
        # Reader sees committed data (row 1), not uncommitted row 2
        assert len(rows) == 1
        assert rows[0]["val"] == "initial"

        conn.commit()
        reader.close()
        conn.close()

    def test_busy_timeout_prevents_immediate_failure(self, tmp_path):
        db_path = tmp_path / "busy.db"
        # Use check_same_thread=False so we can release lock from another thread
        conn1 = db_connect(db_path, check_same_thread=False)
        conn1.execute("CREATE TABLE t (id INTEGER)")
        conn1.commit()

        # Lock the database with an exclusive transaction
        conn1.execute("BEGIN EXCLUSIVE")

        conn2 = db_connect(db_path, check_same_thread=False)

        # Release the lock from another thread after a short delay
        def release():
            time.sleep(0.1)
            conn1.commit()

        t = threading.Thread(target=release)
        t.start()

        # This should succeed because busy_timeout (5000ms) > delay (100ms)
        conn2.execute("INSERT INTO t VALUES (1)")
        conn2.commit()

        t.join()
        conn1.close()
        conn2.close()

    def test_multiple_readers_no_blocking(self, tmp_path):
        db_path = tmp_path / "readers.db"
        conn = db_connect(db_path)
        conn.execute("CREATE TABLE t (id INTEGER)")
        for i in range(100):
            conn.execute("INSERT INTO t VALUES (?)", (i,))
        conn.commit()
        conn.close()

        # Open 5 concurrent readers — all should succeed
        results = []
        errors = []

        def reader():
            try:
                c = db_connect(db_path)
                count = c.execute("SELECT COUNT(*) FROM t").fetchone()[0]
                results.append(count)
                c.close()
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=reader) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert all(r == 100 for r in results)


# ===================================================================
# TestWALPersistence — WAL mode is persistent across connections
# ===================================================================


class TestWALPersistence:
    """Verify WAL mode sticks after first connection closes."""

    def test_wal_persists_across_connections(self, tmp_path):
        db_path = tmp_path / "persist.db"

        # First connection sets WAL
        conn1 = db_connect(db_path)
        conn1.execute("CREATE TABLE t (id INTEGER)")
        conn1.commit()
        conn1.close()

        # Second connection (raw sqlite3, no PRAGMA) should still see WAL
        conn2 = sqlite3.connect(str(db_path))
        mode = conn2.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn2.close()

    def test_wal_creates_sidecar_files(self, tmp_path):
        db_path = tmp_path / "sidecar.db"
        conn = db_connect(db_path)
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()

        # WAL creates -wal and -shm sidecar files
        wal_path = Path(str(db_path) + "-wal")
        shm_path = Path(str(db_path) + "-shm")
        assert wal_path.exists() or shm_path.exists()
        conn.close()
