# Tests for v0.3.20 — Secure File Sharing
# Covers: encrypt_file, decrypt_file, verify_checksum, SecureFileManager,
#         FileShare dataclass, API routes, self-destruct, TTL, cleanup

import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from citadel_archer.chat.secure_file import (
    NONCE_SIZE,
    KEY_SIZE,
    MAX_FILE_SIZE,
    MAX_TTL_HOURS,
    DEFAULT_TTL_HOURS,
    FileShare,
    SecureFileManager,
    decrypt_file,
    encrypt_file,
    verify_checksum,
)


# ── Helpers ───────────────────────────────────────────────────────────


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def sample_file(tmp_dir):
    """Create a sample file for sharing."""
    path = os.path.join(tmp_dir, "test_doc.txt")
    with open(path, "w") as f:
        f.write("Hello, Citadel Archer! This is a test file for secure sharing.")
    return path


@pytest.fixture
def binary_file(tmp_dir):
    """Create a binary file for sharing."""
    path = os.path.join(tmp_dir, "test_binary.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(4096))
    return path


@pytest.fixture
def manager(tmp_dir):
    """Create a SecureFileManager with temp storage."""
    db_path = os.path.join(tmp_dir, "test_shares.db")
    storage_dir = os.path.join(tmp_dir, "encrypted")
    return SecureFileManager(db_path=db_path, storage_dir=storage_dir)


# ── encrypt_file / decrypt_file ──────────────────────────────────────


class TestEncryptDecrypt:
    def test_encrypt_decrypt_roundtrip(self, sample_file, tmp_dir):
        enc_path = os.path.join(tmp_dir, "encrypted.enc")
        key, checksum = encrypt_file(sample_file, enc_path)

        assert len(key) == KEY_SIZE
        assert len(checksum) == 64  # SHA-256 hex

        plaintext = decrypt_file(enc_path, key)
        assert plaintext == Path(sample_file).read_bytes()

    def test_encrypt_decrypt_binary(self, binary_file, tmp_dir):
        enc_path = os.path.join(tmp_dir, "binary.enc")
        key, checksum = encrypt_file(binary_file, enc_path)

        plaintext = decrypt_file(enc_path, key)
        assert plaintext == Path(binary_file).read_bytes()

    def test_encrypt_with_provided_key(self, sample_file, tmp_dir):
        enc_path = os.path.join(tmp_dir, "custom_key.enc")
        custom_key = os.urandom(KEY_SIZE)
        key, _ = encrypt_file(sample_file, enc_path, key=custom_key)
        assert key == custom_key

        plaintext = decrypt_file(enc_path, custom_key)
        assert plaintext == Path(sample_file).read_bytes()

    def test_encrypt_source_not_found(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            encrypt_file("/nonexistent/file.txt", os.path.join(tmp_dir, "out.enc"))

    def test_encrypt_file_too_large(self, tmp_dir):
        large_file = os.path.join(tmp_dir, "large.bin")
        # Create a file that reports as too large
        with open(large_file, "wb") as f:
            f.write(b"\x00")  # Tiny file but we'll mock stat

        with patch("citadel_archer.chat.secure_file.Path.stat") as mock_stat:
            mock_stat.return_value.st_size = MAX_FILE_SIZE + 1
            with pytest.raises(ValueError, match="File too large"):
                encrypt_file(large_file, os.path.join(tmp_dir, "out.enc"))

    def test_decrypt_file_not_found(self, tmp_dir):
        key = os.urandom(KEY_SIZE)
        with pytest.raises(FileNotFoundError):
            decrypt_file("/nonexistent/encrypted.enc", key)

    def test_decrypt_wrong_key(self, sample_file, tmp_dir):
        enc_path = os.path.join(tmp_dir, "wrong_key.enc")
        key, _ = encrypt_file(sample_file, enc_path)

        wrong_key = os.urandom(KEY_SIZE)
        with pytest.raises(Exception):  # InvalidTag from cryptography
            decrypt_file(enc_path, wrong_key)

    def test_encrypted_file_has_nonce_prefix(self, sample_file, tmp_dir):
        enc_path = os.path.join(tmp_dir, "nonce_check.enc")
        encrypt_file(sample_file, enc_path)

        enc_data = Path(enc_path).read_bytes()
        # Encrypted file should be nonce (12) + ciphertext (>= plaintext + 16 tag)
        plaintext_size = Path(sample_file).stat().st_size
        assert len(enc_data) >= NONCE_SIZE + plaintext_size + 16

    def test_encrypt_creates_parent_dirs(self, sample_file, tmp_dir):
        enc_path = os.path.join(tmp_dir, "sub", "dir", "encrypted.enc")
        key, _ = encrypt_file(sample_file, enc_path)
        assert Path(enc_path).exists()


# ── verify_checksum ──────────────────────────────────────────────────


class TestVerifyChecksum:
    def test_valid_checksum(self):
        data = b"test data"
        import hashlib
        checksum = hashlib.sha256(data).hexdigest()
        assert verify_checksum(data, checksum) is True

    def test_invalid_checksum(self):
        assert verify_checksum(b"data", "0" * 64) is False

    def test_empty_data_checksum(self):
        import hashlib
        checksum = hashlib.sha256(b"").hexdigest()
        assert verify_checksum(b"", checksum) is True


# ── FileShare dataclass ──────────────────────────────────────────────


class TestFileShare:
    def test_to_dict_omits_server_fields(self):
        share = FileShare(
            share_id="test-uuid",
            filename="doc.pdf",
            file_size=1024,
            checksum="abc123",
            encrypted_path="/secret/path/file.enc",
            encryption_key="deadbeef" * 8,
            contact_id="contact-1",
            created_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-02T00:00:00+00:00",
            self_destruct=False,
            download_count=0,
            is_expired=False,
        )
        d = share.to_dict()

        assert "share_id" in d
        assert "filename" in d
        assert "encrypted_path" not in d
        assert "encryption_key" not in d

    def test_to_dict_contains_all_public_fields(self):
        share = FileShare(
            share_id="id", filename="f.txt", file_size=100,
            checksum="c", encrypted_path="p", encryption_key="k",
            contact_id=None, created_at="t1", expires_at="t2",
            self_destruct=True, download_count=3, is_expired=False,
        )
        d = share.to_dict()
        assert d["self_destruct"] is True
        assert d["download_count"] == 3
        assert d["contact_id"] is None


# ── SecureFileManager ────────────────────────────────────────────────


class TestSecureFileManager:
    def test_share_and_download(self, manager, sample_file):
        share = manager.share_file(sample_file)
        assert share.share_id
        assert share.filename == "test_doc.txt"
        assert share.download_count == 0
        assert share.is_expired is False

        result = manager.download(share.share_id)
        assert result is not None
        plaintext, returned_share = result
        assert plaintext == Path(sample_file).read_bytes()
        assert returned_share.download_count == 1

    def test_share_binary_file(self, manager, binary_file):
        share = manager.share_file(binary_file)
        result = manager.download(share.share_id)
        assert result is not None
        plaintext, _ = result
        assert plaintext == Path(binary_file).read_bytes()

    def test_share_with_contact_id(self, manager, sample_file):
        share = manager.share_file(sample_file, contact_id="contact-123")
        assert share.contact_id == "contact-123"

    def test_share_with_custom_ttl(self, manager, sample_file):
        share = manager.share_file(sample_file, ttl_hours=48)
        created = datetime.fromisoformat(share.created_at)
        expires = datetime.fromisoformat(share.expires_at)
        delta = expires - created
        assert 47 <= delta.total_seconds() / 3600 <= 49

    def test_share_ttl_clamped(self, manager, sample_file):
        # TTL > MAX_TTL_HOURS should be clamped
        share = manager.share_file(sample_file, ttl_hours=9999)
        created = datetime.fromisoformat(share.created_at)
        expires = datetime.fromisoformat(share.expires_at)
        delta = expires - created
        assert delta.total_seconds() / 3600 <= MAX_TTL_HOURS + 1

    def test_self_destruct(self, manager, sample_file):
        share = manager.share_file(sample_file, self_destruct=True)
        assert share.self_destruct is True

        # First download should work
        result = manager.download(share.share_id)
        assert result is not None

        # Share should be deleted after download
        assert manager.get(share.share_id) is None

    def test_self_destruct_deletes_encrypted_file(self, manager, sample_file):
        share = manager.share_file(sample_file, self_destruct=True)
        enc_path = Path(share.encrypted_path)
        assert enc_path.exists()

        manager.download(share.share_id)
        assert not enc_path.exists()

    def test_download_nonexistent(self, manager):
        assert manager.download("nonexistent-id") is None

    def test_get_nonexistent(self, manager):
        assert manager.get("nonexistent-id") is None

    def test_delete_share(self, manager, sample_file):
        share = manager.share_file(sample_file)
        enc_path = Path(share.encrypted_path)
        assert enc_path.exists()

        assert manager.delete(share.share_id) is True
        assert not enc_path.exists()
        assert manager.get(share.share_id) is None

    def test_delete_nonexistent(self, manager):
        assert manager.delete("nonexistent") is False

    def test_list_shares(self, manager, sample_file):
        manager.share_file(sample_file, contact_id="alice")
        manager.share_file(sample_file, contact_id="bob")
        manager.share_file(sample_file, contact_id="alice")

        all_shares = manager.list_shares()
        assert len(all_shares) == 3

        alice_shares = manager.list_shares(contact_id="alice")
        assert len(alice_shares) == 2

    def test_list_shares_excludes_expired_by_default(self, manager, sample_file):
        share = manager.share_file(sample_file, ttl_hours=1)

        # Manually expire the share
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with manager._lock:
            with manager._connect() as conn:
                conn.execute(
                    "UPDATE file_shares SET expires_at = ? WHERE share_id = ?",
                    (past, share.share_id),
                )

        active = manager.list_shares()
        assert len(active) == 0

        all_shares = manager.list_shares(include_expired=True)
        assert len(all_shares) == 1

    def test_extend_ttl(self, manager, sample_file):
        share = manager.share_file(sample_file, ttl_hours=24)
        original_expires = datetime.fromisoformat(share.expires_at)

        extended = manager.extend_ttl(share.share_id, 12)
        assert extended is not None
        new_expires = datetime.fromisoformat(extended.expires_at)
        assert new_expires > original_expires

    def test_extend_ttl_capped_at_max(self, manager, sample_file):
        share = manager.share_file(sample_file, ttl_hours=24)
        extended = manager.extend_ttl(share.share_id, 9999)
        assert extended is not None

        now = datetime.now(timezone.utc)
        new_expires = datetime.fromisoformat(extended.expires_at)
        if new_expires.tzinfo is None:
            new_expires = new_expires.replace(tzinfo=timezone.utc)
        max_allowed = now + timedelta(hours=MAX_TTL_HOURS)
        assert new_expires <= max_allowed + timedelta(seconds=5)

    def test_extend_ttl_nonexistent(self, manager):
        assert manager.extend_ttl("nonexistent", 12) is None

    def test_cleanup_expired(self, manager, sample_file):
        share = manager.share_file(sample_file, ttl_hours=1)
        enc_path = Path(share.encrypted_path)

        # Manually expire
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with manager._lock:
            with manager._connect() as conn:
                conn.execute(
                    "UPDATE file_shares SET expires_at = ? WHERE share_id = ?",
                    (past, share.share_id),
                )

        deleted = manager.cleanup_expired()
        assert deleted == 1
        assert not enc_path.exists()
        assert manager.get(share.share_id) is None

    def test_cleanup_no_expired(self, manager, sample_file):
        manager.share_file(sample_file, ttl_hours=24)
        assert manager.cleanup_expired() == 0

    def test_stats(self, manager, sample_file):
        manager.share_file(sample_file)
        manager.share_file(sample_file)

        stats = manager.stats()
        assert stats["total_shares"] == 2
        assert stats["active_shares"] == 2
        assert stats["expired_shares"] == 0
        assert stats["total_size_bytes"] > 0
        assert stats["total_downloads"] == 0

    def test_stats_after_download(self, manager, sample_file):
        share = manager.share_file(sample_file)
        manager.download(share.share_id)
        stats = manager.stats()
        assert stats["total_downloads"] == 1

    def test_download_expired_share_auto_deletes(self, manager, sample_file):
        share = manager.share_file(sample_file, ttl_hours=1)

        # Manually expire
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with manager._lock:
            with manager._connect() as conn:
                conn.execute(
                    "UPDATE file_shares SET expires_at = ? WHERE share_id = ?",
                    (past, share.share_id),
                )

        # Download should return None and auto-delete
        result = manager.download(share.share_id)
        assert result is None
        assert manager.get(share.share_id) is None

    def test_share_file_not_found(self, manager):
        with pytest.raises(FileNotFoundError):
            manager.share_file("/nonexistent/file.txt")

    def test_multiple_downloads_increment_count(self, manager, sample_file):
        share = manager.share_file(sample_file)

        for i in range(3):
            result = manager.download(share.share_id)
            assert result is not None
            _, s = result
            assert s.download_count == i + 1


# ── API Routes ───────────────────────────────────────────────────────


class TestFileRoutesAPI:
    @pytest.fixture(autouse=True)
    def setup_api(self, tmp_dir):
        """Set up FastAPI test client with a temp file manager."""
        from fastapi.testclient import TestClient
        from citadel_archer.api.file_routes import router
        from citadel_archer.api.security import initialize_session_token

        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)

        self.token = initialize_session_token()
        self.headers = {"X-Session-Token": self.token}
        self.client = TestClient(app)
        self.tmp_dir = tmp_dir

        # Patch get_file_manager to use our temp manager
        db_path = os.path.join(tmp_dir, "api_test.db")
        storage_dir = os.path.join(tmp_dir, "api_encrypted")
        self._mgr = SecureFileManager(db_path=db_path, storage_dir=storage_dir)
        self._patcher = patch(
            "citadel_archer.api.file_routes.get_file_manager",
            return_value=self._mgr,
        )
        self._patcher.start()

    def teardown_method(self):
        self._patcher.stop()

    def _sample_file_content(self):
        return b"Hello, secure file sharing test!"

    def test_share_file(self):
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("test.txt", self._sample_file_content(), "text/plain")},
            headers=self.headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "share_id" in data
        assert data["filename"] == "test.txt"
        assert "encryption_key" not in data
        assert "encrypted_path" not in data

    def test_share_file_no_auth(self):
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("test.txt", b"data", "text/plain")},
        )
        assert resp.status_code in (401, 403)

    def test_share_and_download(self):
        # Share
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("doc.txt", self._sample_file_content(), "text/plain")},
            headers=self.headers,
        )
        share_id = resp.json()["share_id"]

        # Download
        resp = self.client.get(
            f"/api/files/{share_id}/download",
            headers=self.headers,
        )
        assert resp.status_code == 200
        assert resp.content == self._sample_file_content()
        assert "X-Checksum-SHA256" in resp.headers

    def test_get_share_metadata(self):
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("info.txt", b"metadata test", "text/plain")},
            headers=self.headers,
        )
        share_id = resp.json()["share_id"]

        resp = self.client.get(f"/api/files/{share_id}", headers=self.headers)
        assert resp.status_code == 200
        assert resp.json()["share_id"] == share_id

    def test_get_share_not_found(self):
        resp = self.client.get("/api/files/nonexistent", headers=self.headers)
        assert resp.status_code == 404

    def test_download_not_found(self):
        resp = self.client.get(
            "/api/files/nonexistent/download",
            headers=self.headers,
        )
        assert resp.status_code == 404

    def test_list_shares(self):
        for i in range(3):
            self.client.post(
                "/api/files/share",
                files={"file": (f"file{i}.txt", f"content {i}".encode(), "text/plain")},
                headers=self.headers,
            )

        resp = self.client.get("/api/files", headers=self.headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 3

    def test_list_shares_filter_by_contact(self):
        self.client.post(
            "/api/files/share?contact_id=alice",
            files={"file": ("a.txt", b"alice", "text/plain")},
            headers=self.headers,
        )
        self.client.post(
            "/api/files/share?contact_id=bob",
            files={"file": ("b.txt", b"bob", "text/plain")},
            headers=self.headers,
        )

        resp = self.client.get(
            "/api/files?contact_id=alice",
            headers=self.headers,
        )
        assert resp.json()["total"] == 1

    def test_delete_share(self):
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("del.txt", b"delete me", "text/plain")},
            headers=self.headers,
        )
        share_id = resp.json()["share_id"]

        resp = self.client.delete(f"/api/files/{share_id}", headers=self.headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

        resp = self.client.get(f"/api/files/{share_id}", headers=self.headers)
        assert resp.status_code == 404

    def test_delete_not_found(self):
        resp = self.client.delete("/api/files/nonexistent", headers=self.headers)
        assert resp.status_code == 404

    def test_extend_ttl(self):
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("ttl.txt", b"ttl test", "text/plain")},
            headers=self.headers,
        )
        share_id = resp.json()["share_id"]
        original_expires = resp.json()["expires_at"]

        resp = self.client.post(
            f"/api/files/{share_id}/extend",
            json={"additional_hours": 12},
            headers=self.headers,
        )
        assert resp.status_code == 200
        assert resp.json()["expires_at"] > original_expires

    def test_extend_ttl_not_found(self):
        resp = self.client.post(
            "/api/files/nonexistent/extend",
            json={"additional_hours": 12},
            headers=self.headers,
        )
        assert resp.status_code == 404

    def test_cleanup(self):
        resp = self.client.post("/api/files/cleanup", headers=self.headers)
        assert resp.status_code == 200
        assert "cleaned_up" in resp.json()

    def test_stats(self):
        resp = self.client.get("/api/files/stats/summary", headers=self.headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_shares" in data
        assert "active_shares" in data

    def test_self_destruct_via_api(self):
        resp = self.client.post(
            "/api/files/share?self_destruct=true",
            files={"file": ("sd.txt", b"self destruct", "text/plain")},
            headers=self.headers,
        )
        share_id = resp.json()["share_id"]
        assert resp.json()["self_destruct"] is True

        # First download works
        resp = self.client.get(
            f"/api/files/{share_id}/download",
            headers=self.headers,
        )
        assert resp.status_code == 200

        # Second download should 404
        resp = self.client.get(
            f"/api/files/{share_id}/download",
            headers=self.headers,
        )
        assert resp.status_code == 404

    def test_share_empty_file_rejected(self):
        resp = self.client.post(
            "/api/files/share",
            files={"file": ("empty.txt", b"", "text/plain")},
            headers=self.headers,
        )
        assert resp.status_code == 400
