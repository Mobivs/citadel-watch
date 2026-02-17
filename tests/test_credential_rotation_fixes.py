"""Tests for credential_rotation.py code review fixes.

Covers:
  - Issue #12: local authorized_keys write is atomic (tmp + os.replace)
  - Issue #13: _generate_ssh_keypair uses async subprocess instead of blocking
  - Recovery key preservation during rotation
"""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.panic.panic_database import PanicDatabase


# ── Helpers ──────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """PanicDatabase backed by a temp SQLite file."""
    db_path = tmp_path / "test_panic.db"
    return PanicDatabase(db_path)


@pytest.fixture
def tmp_ssh_dir(tmp_path):
    """Temporary ~/.ssh directory with authorized_keys."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    ak_path = ssh_dir / "authorized_keys"
    return ak_path


def _write_authorized_keys(ak_path, lines):
    """Write lines to an authorized_keys file."""
    ak_path.write_text("\n".join(lines) + "\n")
    os.chmod(str(ak_path), 0o600)


def _make_credential_rotation(db):
    """Build a CredentialRotation instance with mocked config."""
    from citadel_archer.panic.actions.credential_rotation import CredentialRotation
    config = {"api_services": []}
    return CredentialRotation(db, config)


def _seed_recovery_key(db_path, key_id, public_key, comment):
    """Insert a recovery key into the test database."""
    import sqlite3
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO recovery_keys (key_id, public_key, fingerprint, comment, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            (key_id, public_key, "SHA256:fake", comment),
        )
        conn.commit()


# ── Issue #12: Atomic local write ────────────────────────────────────

class TestAtomicLocalWrite:
    """_rotate_ssh_keys_local should use tmp + os.replace for atomicity."""

    @pytest.mark.asyncio
    async def test_rotation_uses_atomic_write(self, tmp_db, tmp_ssh_dir, monkeypatch):
        """After rotation, no .tmp file should remain (os.replace consumed it)."""
        ak_path = tmp_ssh_dir

        # Setup: recovery key + old operational key
        recovery_line = "ssh-ed25519 AAAA_RECOVERY citadel-recovery-rk_test123"
        old_key = "ssh-ed25519 AAAA_OLD old-operational-key"
        _write_authorized_keys(ak_path, [recovery_line, old_key])

        _seed_recovery_key(tmp_db.db_path, "rk_test123", recovery_line, "citadel-recovery-rk_test123")

        rot = _make_credential_rotation(tmp_db)

        # Mock _generate_ssh_keypair to return predictable keys
        new_priv = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----"
        new_pub = "ssh-ed25519 AAAA_NEW panic-key-2025-01-01"

        # Redirect expanduser to our temp path
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(ak_path) if "authorized_keys" in p else p)

        with patch.object(rot, "_generate_ssh_keypair", new=AsyncMock(return_value=(new_priv, new_pub))):
            result = await rot._rotate_ssh_keys_local("sess_001")

        assert result["status"] == "success"

        # Verify no temp file left behind
        tmp_file = Path(str(ak_path) + ".tmp")
        assert not tmp_file.exists(), ".tmp file should be consumed by os.replace"

        # Verify final content: recovery key preserved, old key removed, new key added
        final = ak_path.read_text()
        assert "citadel-recovery-rk_test123" in final
        assert "AAAA_NEW" in final
        assert "AAAA_OLD" not in final

    @pytest.mark.asyncio
    async def test_rotation_preserves_recovery_key(self, tmp_db, tmp_ssh_dir, monkeypatch):
        """The recovery key must survive rotation."""
        ak_path = tmp_ssh_dir

        recovery_line = "ssh-ed25519 AAAA_REC citadel-recovery-rk_abc"
        _write_authorized_keys(ak_path, [recovery_line, "ssh-rsa OLD_KEY user@host"])

        _seed_recovery_key(tmp_db.db_path, "rk_abc", recovery_line, "citadel-recovery-rk_abc")

        rot = _make_credential_rotation(tmp_db)

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(ak_path) if "authorized_keys" in p else p)

        with patch.object(rot, "_generate_ssh_keypair",
                          new=AsyncMock(return_value=("priv", "ssh-ed25519 AAAA_NEWOP new-key"))):
            result = await rot._rotate_ssh_keys_local("sess_002")

        assert result["status"] == "success"
        assert result["result"]["recovery_keys_preserved"] >= 1

        content = ak_path.read_text()
        assert "citadel-recovery-rk_abc" in content

    @pytest.mark.asyncio
    async def test_rotation_aborts_without_recovery_key(self, tmp_db, tmp_ssh_dir, monkeypatch):
        """Rotation must fail if no recovery key is configured."""
        ak_path = tmp_ssh_dir
        _write_authorized_keys(ak_path, ["ssh-rsa SOME_KEY user@host"])

        rot = _make_credential_rotation(tmp_db)

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(ak_path) if "authorized_keys" in p else p)

        result = await rot._rotate_ssh_keys_local("sess_003")

        assert result["status"] == "failed"
        assert "recovery key" in result["error"].lower()


# ── Issue #13: Async subprocess ──────────────────────────────────────

class TestAsyncKeygen:
    """_generate_ssh_keypair should use asyncio.create_subprocess_exec."""

    @pytest.mark.asyncio
    async def test_keygen_is_async(self, tmp_db):
        """Verify that the method calls asyncio.create_subprocess_exec."""
        rot = _make_credential_rotation(tmp_db)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_proc)) as mock_exec:
            with patch("builtins.open", side_effect=[
                MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value="PRIVATE_KEY"))),
                          __exit__=MagicMock(return_value=False)),
                MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value="PUBLIC_KEY"))),
                          __exit__=MagicMock(return_value=False)),
            ]):
                with patch("os.remove"):
                    private, public = await rot._generate_ssh_keypair()

            # asyncio.create_subprocess_exec was called (not subprocess.run)
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args
            assert call_args[0][0] == "ssh-keygen"

    @pytest.mark.asyncio
    async def test_keygen_falls_back_to_python(self, tmp_db):
        """If ssh-keygen fails, should fall back to Python cryptography lib."""
        rot = _make_credential_rotation(tmp_db)

        # Make create_subprocess_exec raise an error
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("no ssh-keygen")):
            private, public = await rot._generate_ssh_keypair()

        # Should still return valid-looking keys (from cryptography fallback)
        assert "BEGIN" in private or "PRIVATE" in private
        assert "ssh-ed25519" in public


# ── Restore also uses atomic write ───────────────────────────────────

class TestRestoreAtomicWrite:
    """_restore_ssh_keys should also use tmp + os.replace."""

    @pytest.mark.asyncio
    async def test_restore_uses_atomic_write(self, tmp_db, tmp_ssh_dir, monkeypatch):
        ak_path = tmp_ssh_dir

        recovery_line = "ssh-ed25519 AAAA_REC citadel-recovery-rk_restore"
        _write_authorized_keys(ak_path, [recovery_line])

        _seed_recovery_key(tmp_db.db_path, "rk_restore", recovery_line, "citadel-recovery-rk_restore")

        rot = _make_credential_rotation(tmp_db)

        old_keys = [
            "ssh-rsa AAAA_OLDOP old-operational\n",
            "ssh-ed25519 AAAA_OLDOP2 old-key-2\n",
        ]

        monkeypatch.setattr(os.path, "expanduser", lambda p: str(ak_path) if "authorized_keys" in p else p)

        await rot._restore_ssh_keys(old_keys)

        content = ak_path.read_text()

        # Recovery key preserved
        assert "citadel-recovery-rk_restore" in content
        # Old operational keys restored
        assert "AAAA_OLDOP" in content
        # No temp file left
        assert not Path(str(ak_path) + ".tmp").exists()


# ── Source code verification ─────────────────────────────────────────

class TestSourceCodePatterns:
    """Verify the actual code uses atomic write patterns."""

    def test_rotate_local_uses_os_replace(self):
        """_rotate_ssh_keys_local source should contain os.replace."""
        import inspect
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        source = inspect.getsource(CredentialRotation._rotate_ssh_keys_local)
        assert "os.replace(" in source, "Atomic write requires os.replace()"
        assert ".tmp" in source, "Atomic write requires writing to .tmp first"

    def test_restore_uses_os_replace(self):
        """_restore_ssh_keys source should contain os.replace."""
        import inspect
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        source = inspect.getsource(CredentialRotation._restore_ssh_keys)
        assert "os.replace(" in source

    def test_generate_keypair_uses_async(self):
        """_generate_ssh_keypair should use asyncio.create_subprocess_exec."""
        import inspect
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        source = inspect.getsource(CredentialRotation._generate_ssh_keypair)
        assert "create_subprocess_exec" in source
        assert "subprocess.run" not in source, "Blocking subprocess.run should be replaced"
