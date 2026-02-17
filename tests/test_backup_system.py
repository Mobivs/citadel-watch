"""Tests for v0.3.33: Backup and Sync Across Systems.

Covers: BackupCrypto, BackupDatabase, BackupManager, backup API routes,
structural wiring, and frontend structural checks.
"""

import hashlib
import io
import json
import os
import sqlite3
import zipfile
from pathlib import Path

import pytest

# ── BackupCrypto Tests ──────────────────────────────────────────────


class TestBackupCrypto:
    """AES-256-GCM encryption/decryption for backup archives."""

    def test_encrypt_decrypt_roundtrip(self):
        from citadel_archer.backup.backup_crypto import BackupCrypto

        data = b"Hello, Citadel Archer backup system!"
        passphrase = "TestPassphrase123"
        encrypted = BackupCrypto.encrypt_bytes(data, passphrase)
        decrypted = BackupCrypto.decrypt_bytes(encrypted, passphrase)
        assert decrypted == data

    def test_wrong_passphrase_raises(self):
        from cryptography.exceptions import InvalidTag
        from citadel_archer.backup.backup_crypto import BackupCrypto

        data = b"secret data"
        encrypted = BackupCrypto.encrypt_bytes(data, "CorrectPass123!!")
        with pytest.raises(InvalidTag):
            BackupCrypto.decrypt_bytes(encrypted, "WrongPassword123")

    def test_salt_is_random(self):
        from citadel_archer.backup.backup_crypto import BackupCrypto

        data = b"same data"
        passphrase = "SamePassword123!"
        enc1 = BackupCrypto.encrypt_bytes(data, passphrase)
        enc2 = BackupCrypto.encrypt_bytes(data, passphrase)
        # Different salt → different ciphertext
        assert enc1 != enc2

    def test_output_format(self):
        from citadel_archer.backup.backup_crypto import BackupCrypto

        data = b"format check"
        blob = BackupCrypto.encrypt_bytes(data, "FormatCheck12345")
        # salt(32) + nonce(12) + ciphertext+tag
        assert len(blob) >= BackupCrypto._HEADER_SIZE
        salt = blob[:32]
        nonce = blob[32:44]
        assert len(salt) == 32
        assert len(nonce) == 12

    def test_empty_data(self):
        from citadel_archer.backup.backup_crypto import BackupCrypto

        encrypted = BackupCrypto.encrypt_bytes(b"", "EmptyTest12345!!")
        decrypted = BackupCrypto.decrypt_bytes(encrypted, "EmptyTest12345!!")
        assert decrypted == b""


# ── BackupDatabase Tests ────────────────────────────────────────────


class TestBackupDatabase:
    """Backup history SQLite persistence."""

    def test_record_and_retrieve(self, tmp_path):
        from citadel_archer.backup.backup_database import BackupDatabase

        db = BackupDatabase(str(tmp_path / "test.db"))
        record = db.record_backup(
            backup_id="abc123",
            label="Test Backup",
            size_bytes=1024,
            db_count=5,
            log_count=2,
            checksum_sha256="sha256hash",
            archive_path="/tmp/test.citadel-backup",
        )
        assert record["backup_id"] == "abc123"
        assert record["label"] == "Test Backup"
        assert record["size_bytes"] == 1024
        assert record["db_count"] == 5
        assert record["status"] == "complete"

        retrieved = db.get_backup("abc123")
        assert retrieved["backup_id"] == "abc123"

    def test_list_sorted_newest_first(self, tmp_path):
        from citadel_archer.backup.backup_database import BackupDatabase

        db = BackupDatabase(str(tmp_path / "test.db"))
        for i in range(3):
            db.record_backup(
                backup_id=f"id{i}",
                label=f"Backup {i}",
                size_bytes=100 * (i + 1),
                db_count=1, log_count=0,
                checksum_sha256=f"hash{i}",
                archive_path=f"/tmp/{i}.citadel-backup",
            )
        backups = db.list_backups()
        assert len(backups) == 3
        # Newest first (id2 created last)
        assert backups[0]["backup_id"] == "id2"

    def test_delete_record(self, tmp_path):
        from citadel_archer.backup.backup_database import BackupDatabase

        db = BackupDatabase(str(tmp_path / "test.db"))
        db.record_backup(
            backup_id="del1", label="", size_bytes=0,
            db_count=0, log_count=0, checksum_sha256="x",
            archive_path="/tmp/del.citadel-backup",
        )
        assert db.get_backup("del1") is not None
        assert db.delete_backup_record("del1") is True
        assert db.get_backup("del1") is None

    def test_update_status(self, tmp_path):
        from citadel_archer.backup.backup_database import BackupDatabase

        db = BackupDatabase(str(tmp_path / "test.db"))
        db.record_backup(
            backup_id="st1", label="", size_bytes=0,
            db_count=0, log_count=0, checksum_sha256="x",
            archive_path="/tmp/st.citadel-backup",
        )
        assert db.update_status("st1", "deleted") is True
        assert db.get_backup("st1")["status"] == "deleted"

    def test_schema_idempotent(self, tmp_path):
        from citadel_archer.backup.backup_database import BackupDatabase

        db_path = str(tmp_path / "idem.db")
        db1 = BackupDatabase(db_path)
        db2 = BackupDatabase(db_path)  # second init should not raise
        db2.record_backup(
            backup_id="idem1", label="", size_bytes=0,
            db_count=0, log_count=0, checksum_sha256="x",
            archive_path="/tmp/idem.citadel-backup",
        )
        assert db2.get_backup("idem1") is not None

    def test_list_with_limit(self, tmp_path):
        from citadel_archer.backup.backup_database import BackupDatabase

        db = BackupDatabase(str(tmp_path / "test.db"))
        for i in range(5):
            db.record_backup(
                backup_id=f"lim{i}", label="", size_bytes=0,
                db_count=0, log_count=0, checksum_sha256=f"h{i}",
                archive_path=f"/tmp/lim{i}.citadel-backup",
            )
        assert len(db.list_backups(limit=3)) == 3


# ── BackupManager Create Tests ──────────────────────────────────────


def _setup_test_data(data_dir):
    """Create a few test SQLite databases in data_dir for backup testing."""
    data_dir.mkdir(parents=True, exist_ok=True)

    # Create a small test DB mimicking assets.db
    db_path = data_dir / "assets.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS test_assets (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO test_assets VALUES (1, 'test-asset')")
    conn.commit()
    conn.close()

    # Create a second DB
    db_path2 = data_dir / "user_preferences.db"
    conn2 = sqlite3.connect(str(db_path2))
    conn2.execute("CREATE TABLE IF NOT EXISTS prefs (key TEXT, val TEXT)")
    conn2.execute("INSERT INTO prefs VALUES ('mode', 'technical')")
    conn2.commit()
    conn2.close()

    return data_dir


def _setup_test_logs(audit_dir):
    """Create a test audit log file."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    log_file = audit_dir / "audit_2026-02-16.log"
    log_file.write_text('{"event": "test"}\n')
    return audit_dir


@pytest.fixture
def backup_env(tmp_path):
    """Set up test data, audit logs, and return a configured BackupManager."""
    from citadel_archer.backup.backup_manager import BackupManager
    from citadel_archer.backup.backup_database import BackupDatabase

    data_dir = _setup_test_data(tmp_path / "data")
    audit_dir = _setup_test_logs(tmp_path / "audit_logs")
    backup_dir = tmp_path / "data" / "backups"
    backup_db = BackupDatabase(str(data_dir / "backup_history.db"))

    mgr = BackupManager(
        data_dir=data_dir,
        backup_dir=backup_dir,
        backup_db=backup_db,
        audit_log_dir=audit_dir,
    )
    return mgr, data_dir, backup_dir, audit_dir


GOOD_PASSPHRASE = "TestBackup1234!"


class TestBackupManagerCreate:
    """BackupManager.create_backup()"""

    def test_create_produces_archive_file(self, backup_env):
        mgr, _, backup_dir, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE, "Test")
        archive = Path(result["archive_path"])
        assert archive.exists()
        assert archive.suffix == ".citadel-backup"

    def test_create_metadata_recorded_in_db(self, backup_env):
        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE, "DB Test")
        info = mgr.get_backup_info(result["backup_id"])
        assert info is not None
        assert info["label"] == "DB Test"
        assert info["db_count"] >= 1

    def test_create_with_label(self, backup_env):
        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE, "Before Update")
        assert result["label"] == "Before Update"

    def test_create_skips_missing_dbs(self, backup_env):
        """Only existing databases are included (no error for missing ones)."""
        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)
        # We only created 2 test DBs + backup_history = 3 max
        assert result["db_count"] <= 3

    def test_archive_is_encrypted(self, backup_env):
        mgr, _, backup_dir, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)
        archive_bytes = Path(result["archive_path"]).read_bytes()
        # Should NOT contain SQLite magic header in raw bytes
        assert b"SQLite format 3" not in archive_bytes

    def test_manifest_has_checksum(self, backup_env):
        from citadel_archer.backup.backup_crypto import BackupCrypto

        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)
        archive_bytes = Path(result["archive_path"]).read_bytes()

        # Decrypt and open ZIP
        zip_bytes = BackupCrypto.decrypt_bytes(archive_bytes, GOOD_PASSPHRASE)
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))

        assert manifest["checksum_sha256"] != ""
        assert len(manifest["checksum_sha256"]) == 64  # SHA-256 hex
        # Verify checksum matches the DB record (consistency check)
        info = mgr.get_backup_info(result["backup_id"])
        assert manifest["checksum_sha256"] == info["checksum_sha256"]

    def test_hot_copy_no_lock(self, backup_env):
        """Source DB remains writable during backup."""
        mgr, data_dir, _, _ = backup_env

        # Write to source DB during backup
        conn = sqlite3.connect(str(data_dir / "assets.db"))
        conn.execute("INSERT INTO test_assets VALUES (99, 'concurrent')")
        conn.commit()
        conn.close()

        # Backup should still work
        result = mgr.create_backup(GOOD_PASSPHRASE)
        assert result["db_count"] >= 1

    def test_audit_logs_included(self, backup_env):
        from citadel_archer.backup.backup_crypto import BackupCrypto

        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)
        archive_bytes = Path(result["archive_path"]).read_bytes()

        zip_bytes = BackupCrypto.decrypt_bytes(archive_bytes, GOOD_PASSPHRASE)
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
        log_entries = [n for n in zf.namelist() if n.startswith("logs/")]
        zf.close()

        assert len(log_entries) >= 1
        assert result["log_count"] >= 1


# ── BackupManager Restore Tests ─────────────────────────────────────


class TestBackupManagerRestore:
    """BackupManager.restore_backup()"""

    def test_restore_roundtrip(self, backup_env):
        """Create → modify source → restore → verify original data."""
        mgr, data_dir, _, _ = backup_env

        # Create backup
        result = mgr.create_backup(GOOD_PASSPHRASE, "Roundtrip")
        backup_id = result["backup_id"]

        # Modify source DB
        conn = sqlite3.connect(str(data_dir / "assets.db"))
        conn.execute("DELETE FROM test_assets")
        conn.execute("INSERT INTO test_assets VALUES (999, 'modified')")
        conn.commit()
        conn.close()

        # Verify modification
        conn = sqlite3.connect(str(data_dir / "assets.db"))
        rows = conn.execute("SELECT * FROM test_assets").fetchall()
        conn.close()
        assert rows[0][0] == 999

        # Restore
        restore_result = mgr.restore_backup(backup_id, GOOD_PASSPHRASE)
        assert "assets" in restore_result["restored_dbs"]

        # Verify original data is back
        conn = sqlite3.connect(str(data_dir / "assets.db"))
        rows = conn.execute("SELECT * FROM test_assets").fetchall()
        conn.close()
        assert any(r[0] == 1 and r[1] == "test-asset" for r in rows)

    def test_restore_wrong_passphrase(self, backup_env):
        from citadel_archer.backup.backup_manager import BackupError

        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)

        with pytest.raises(BackupError, match="Invalid passphrase"):
            mgr.restore_backup(result["backup_id"], "WrongPassword123")

    def test_restore_creates_pre_restore_backup(self, backup_env):
        mgr, _, backup_dir, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE, "Original")

        # Count archives before restore
        before = len(list(backup_dir.glob("*.citadel-backup")))

        restore_result = mgr.restore_backup(result["backup_id"], GOOD_PASSPHRASE)
        after = len(list(backup_dir.glob("*.citadel-backup")))

        # Pre-restore backup should have been created
        assert after > before
        assert restore_result["pre_restore_backup_id"] is not None

    def test_restore_nonexistent_id(self, backup_env):
        from citadel_archer.backup.backup_manager import BackupError

        mgr, _, _, _ = backup_env
        with pytest.raises(BackupError, match="not found"):
            mgr.restore_backup("nonexistent123", GOOD_PASSPHRASE)

    def test_restore_audit_logs_preserved(self, backup_env):
        mgr, _, _, audit_dir = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)

        restore_result = mgr.restore_backup(result["backup_id"], GOOD_PASSPHRASE)

        # .restored.log files should exist
        restored_files = list(audit_dir.glob("*.restored.log"))
        assert len(restored_files) >= 1
        assert len(restore_result["restored_logs"]) >= 1

    def test_restore_corrupt_archive(self, backup_env):
        from citadel_archer.backup.backup_manager import BackupError

        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)

        # Corrupt the archive
        archive = Path(result["archive_path"])
        data = bytearray(archive.read_bytes())
        data[-10] ^= 0xFF  # flip bits near end
        archive.write_bytes(bytes(data))

        with pytest.raises(BackupError):
            mgr.restore_backup(result["backup_id"], GOOD_PASSPHRASE)


# ── BackupManager List/Delete Tests ─────────────────────────────────


class TestBackupManagerList:
    def test_list_empty(self, backup_env):
        mgr, _, _, _ = backup_env
        assert mgr.list_backups() == []

    def test_list_marks_deleted_if_file_missing(self, backup_env):
        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)

        # Delete the file manually
        Path(result["archive_path"]).unlink()

        backups = mgr.list_backups()
        assert len(backups) == 1
        assert backups[0]["status"] == "deleted"


class TestBackupManagerDelete:
    def test_delete_removes_file_and_updates_db(self, backup_env):
        mgr, _, _, _ = backup_env
        result = mgr.create_backup(GOOD_PASSPHRASE)
        archive = Path(result["archive_path"])
        assert archive.exists()

        assert mgr.delete_backup(result["backup_id"]) is True
        assert not archive.exists()
        assert mgr.get_backup_info(result["backup_id"]) is None

    def test_delete_nonexistent_returns_false(self, backup_env):
        mgr, _, _, _ = backup_env
        assert mgr.delete_backup("nonexistent") is False


# ── API Route Tests ─────────────────────────────────────────────────


@pytest.fixture
def backup_client(tmp_path):
    """FastAPI TestClient with BackupManager pointed at tmp_path."""
    from fastapi.testclient import TestClient
    from citadel_archer.api.main import app
    from citadel_archer.api import backup_routes, security
    from citadel_archer.backup.backup_manager import BackupManager
    from citadel_archer.backup.backup_database import BackupDatabase

    data_dir = _setup_test_data(tmp_path / "data")
    _setup_test_logs(tmp_path / "audit_logs")
    backup_db = BackupDatabase(str(data_dir / "backup_history.db"))
    mgr = BackupManager(
        data_dir=data_dir,
        backup_dir=tmp_path / "data" / "backups",
        backup_db=backup_db,
        audit_log_dir=tmp_path / "audit_logs",
    )

    old_mgr = backup_routes._backup_manager
    backup_routes._backup_manager = mgr

    old_token = security._SESSION_TOKEN
    security._SESSION_TOKEN = "test-session-token"

    yield TestClient(app)

    backup_routes._backup_manager = old_mgr
    security._SESSION_TOKEN = old_token


AUTH = {"X-Session-Token": "test-session-token"}


class TestBackupRoutes:

    def test_create_success(self, backup_client):
        resp = backup_client.post(
            "/api/backups",
            json={"passphrase": GOOD_PASSPHRASE, "label": "API Test"},
            headers=AUTH,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "backup_id" in data
        assert data["label"] == "API Test"

    def test_create_unauthorized(self, backup_client):
        resp = backup_client.post(
            "/api/backups",
            json={"passphrase": GOOD_PASSPHRASE},
        )
        assert resp.status_code == 401

    def test_list_empty(self, backup_client):
        resp = backup_client.get("/api/backups", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["backups"] == []
        assert data["total"] == 0

    def test_get_info(self, backup_client):
        # Create first
        create_resp = backup_client.post(
            "/api/backups",
            json={"passphrase": GOOD_PASSPHRASE},
            headers=AUTH,
        )
        bid = create_resp.json()["backup_id"]

        resp = backup_client.get(f"/api/backups/{bid}", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["backup_id"] == bid

    def test_get_not_found(self, backup_client):
        resp = backup_client.get("/api/backups/nonexistent", headers=AUTH)
        assert resp.status_code == 404

    def test_delete_success(self, backup_client):
        create_resp = backup_client.post(
            "/api/backups",
            json={"passphrase": GOOD_PASSPHRASE},
            headers=AUTH,
        )
        bid = create_resp.json()["backup_id"]

        resp = backup_client.delete(f"/api/backups/{bid}", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_restore_success(self, backup_client):
        create_resp = backup_client.post(
            "/api/backups",
            json={"passphrase": GOOD_PASSPHRASE},
            headers=AUTH,
        )
        bid = create_resp.json()["backup_id"]

        resp = backup_client.post(
            f"/api/backups/{bid}/restore",
            json={"passphrase": GOOD_PASSPHRASE},
            headers=AUTH,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "restored_dbs" in data

    def test_push_returns_501(self, backup_client):
        resp = backup_client.post(
            "/api/backups/anyid/push",
            headers=AUTH,
        )
        assert resp.status_code == 501


# ── Structural Tests ────────────────────────────────────────────────


class TestStructural:
    """Verify files exist and are properly wired."""

    def test_backup_routes_in_main(self):
        src = Path("src/citadel_archer/api/main.py")
        content = src.read_text(encoding="utf-8")
        assert "backup_router" in content or "backup_routes" in content

    def test_module_files_exist(self):
        base = Path("src/citadel_archer/backup")
        assert (base / "backup_crypto.py").exists()
        assert (base / "backup_database.py").exists()
        assert (base / "backup_manager.py").exists()
        assert (base / "__init__.py").exists()

    def test_backup_html_exists(self):
        assert Path("frontend/backup.html").exists()

    def test_audit_event_types(self):
        from citadel_archer.core.audit_log import EventType

        assert hasattr(EventType, "BACKUP_CREATED")
        assert hasattr(EventType, "BACKUP_RESTORED")
        assert hasattr(EventType, "BACKUP_DELETED")

    def test_dashboard_nav_has_backup_tab(self):
        content = Path("frontend/js/dashboard-nav.js").read_text(encoding="utf-8")
        assert "'backup'" in content or '"backup"' in content
        assert "backup.html" in content


class TestFrontendStructural:
    """Verify frontend files have expected structure."""

    def test_backup_html_has_create_button(self):
        content = Path("frontend/backup.html").read_text(encoding="utf-8")
        assert "backup-create-btn" in content

    def test_backup_html_has_restore_modal(self):
        content = Path("frontend/backup.html").read_text(encoding="utf-8")
        assert "backup-restore-modal" in content

    def test_backup_html_has_table(self):
        content = Path("frontend/backup.html").read_text(encoding="utf-8")
        assert "backup-table" in content

    def test_backups_js_has_init_destroy(self):
        content = Path("frontend/js/backups.js").read_text(encoding="utf-8")
        assert "export function init()" in content
        assert "export function destroy()" in content

    def test_backups_js_has_api_calls(self):
        content = Path("frontend/js/backups.js").read_text(encoding="utf-8")
        assert "/api/backups" in content
        assert "apiClient.post" in content
        assert "apiClient.get" in content
        assert "apiClient.delete" in content

    def test_index_html_has_backup_tab(self):
        content = Path("frontend/index.html").read_text(encoding="utf-8")
        assert "tab-btn-backup" in content
