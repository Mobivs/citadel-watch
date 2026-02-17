"""Tests for remote credential rotation (3C).

Covers:
  - _rotate_ssh_keys dispatch: local vs remote
  - _rotate_ssh_keys_remote: recovery key checks, atomic write, rollback-on-failure
  - SSH Manager injection (self._ssh_manager, not import)
  - Pre-flight check: no recovery key → abort
  - Base64 atomic write strategy
"""

import asyncio
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from citadel_archer.panic.actions.credential_rotation import CredentialRotation
from citadel_archer.panic.actions.base import CommandOutput


# ── Helpers ──────────────────────────────────────────────────────────

RECOVERY_LINE = "ssh-ed25519 AAAA... citadel-recovery-rk_test123"
OPERATIONAL_LINE = "ssh-ed25519 BBBB... old-operational-key"

FAKE_PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
FAKE_PUBLIC_KEY = "ssh-ed25519 CCCC... panic-key-2026-01-01"


@dataclass
class FakeSSHResult:
    """Mimics ssh_manager.CommandResult."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 10


def _make_rotation(config=None):
    """Create a CredentialRotation with a mock db that has acquire()."""
    db = MagicMock()
    # Make acquire() work as async context manager
    conn_mock = MagicMock()
    conn_mock.execute = AsyncMock()
    conn_mock.fetch = AsyncMock(return_value=[])
    conn_mock.fetchrow = AsyncMock(return_value=None)
    conn_mock.fetchval = AsyncMock(return_value=0)

    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=conn_mock)
    ctx.__aexit__ = AsyncMock(return_value=False)
    db.acquire = MagicMock(return_value=ctx)

    return CredentialRotation(db, config or {})


# ── Test: _rotate_ssh_keys dispatches local vs remote ────────────────

class TestRotateSSHKeysDispatch:
    """_rotate_ssh_keys routes to local or remote based on asset_id."""

    @pytest.mark.asyncio
    async def test_local_dispatch(self):
        rot = _make_rotation()
        with patch.object(rot, '_rotate_ssh_keys_local', new_callable=AsyncMock) as mock_local:
            mock_local.return_value = {'status': 'success'}
            result = await rot._rotate_ssh_keys("session_1", asset_id="local")
            mock_local.assert_awaited_once_with("session_1")
            assert result['status'] == 'success'

    @pytest.mark.asyncio
    async def test_none_dispatch(self):
        rot = _make_rotation()
        with patch.object(rot, '_rotate_ssh_keys_local', new_callable=AsyncMock) as mock_local:
            mock_local.return_value = {'status': 'success'}
            result = await rot._rotate_ssh_keys("session_1", asset_id=None)
            mock_local.assert_awaited_once_with("session_1")

    @pytest.mark.asyncio
    async def test_remote_dispatch(self):
        rot = _make_rotation()
        with patch.object(rot, '_rotate_ssh_keys_remote', new_callable=AsyncMock) as mock_remote:
            mock_remote.return_value = {'status': 'success', 'asset': 'vps_1'}
            result = await rot._rotate_ssh_keys("session_1", asset_id="vps_1")
            mock_remote.assert_awaited_once_with("session_1", "vps_1")
            assert result['asset'] == 'vps_1'


# ── Test: Remote rotation happy path ─────────────────────────────────

class TestRotateSSHKeysRemoteHappyPath:
    """Full remote rotation flow when everything works."""

    @pytest.mark.asyncio
    async def test_successful_rotation(self):
        rot = _make_rotation()

        # Set up SSH manager mock
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        # Step 1: read authorized_keys — has recovery + operational key
        ssh_mock.execute = AsyncMock(side_effect=[
            # 1. cat authorized_keys
            FakeSSHResult(stdout=f"{RECOVERY_LINE}\n{OPERATIONAL_LINE}\n"),
            # 2. backup (cp)
            FakeSSHResult(exit_code=0),
            # 3. write (echo | base64 -d > tmp && mv)
            FakeSSHResult(exit_code=0),
            # 4. verify (cat)
            FakeSSHResult(stdout=f"{RECOVERY_LINE}\n{FAKE_PUBLIC_KEY}\n"),
        ])

        # Mock invalidate_cache
        ssh_mock.invalidate_cache = AsyncMock()

        with patch.object(rot, '_generate_ssh_keypair', new_callable=AsyncMock) as mock_keygen:
            mock_keygen.return_value = (FAKE_PRIVATE_KEY, FAKE_PUBLIC_KEY)

            result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")

        assert result['status'] == 'success'
        assert result['asset'] == 'vps_1'
        assert result['result']['new_private_key'] == FAKE_PRIVATE_KEY
        assert result['result']['recovery_keys_preserved'] == 1

        # Verify 4 SSH commands were called
        assert ssh_mock.execute.await_count == 4

        # Verify cache was invalidated
        ssh_mock.invalidate_cache.assert_awaited_once_with("vps_1")


# ── Test: Remote rotation — no recovery key ──────────────────────────

class TestRotateSSHKeysRemoteNoRecovery:
    """Remote rotation fails when no recovery key exists on target."""

    @pytest.mark.asyncio
    async def test_aborts_without_recovery_key(self):
        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        # authorized_keys has only operational keys, no recovery key
        ssh_mock.execute = AsyncMock(return_value=FakeSSHResult(
            stdout=f"{OPERATIONAL_LINE}\n"
        ))

        result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")

        assert result['status'] == 'failed'
        assert 'No recovery key found' in result['error']
        assert result['asset'] == 'vps_1'

        # Only 1 SSH call (the initial read), nothing else
        assert ssh_mock.execute.await_count == 1


# ── Test: Remote rotation — write failure triggers NO extra writes ────

class TestRotateSSHKeysRemoteWriteFailure:
    """When the atomic write fails, return error immediately."""

    @pytest.mark.asyncio
    async def test_write_failure(self):
        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        ssh_mock.execute = AsyncMock(side_effect=[
            # 1. cat authorized_keys
            FakeSSHResult(stdout=f"{RECOVERY_LINE}\n"),
            # 2. backup
            FakeSSHResult(exit_code=0),
            # 3. write — FAILS
            FakeSSHResult(exit_code=1, stderr="Permission denied"),
        ])

        with patch.object(rot, '_generate_ssh_keypair', new_callable=AsyncMock) as mock_keygen:
            mock_keygen.return_value = (FAKE_PRIVATE_KEY, FAKE_PUBLIC_KEY)
            result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")

        assert result['status'] == 'failed'
        assert 'Permission denied' in result['error']


# ── Test: Remote rotation — verification failure restores backup ──────

class TestRotateSSHKeysRemoteVerifyFailure:
    """If recovery key is missing after write, restore backup."""

    @pytest.mark.asyncio
    async def test_verify_failure_restores_backup(self):
        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        ssh_mock.execute = AsyncMock(side_effect=[
            # 1. cat authorized_keys
            FakeSSHResult(stdout=f"{RECOVERY_LINE}\n"),
            # 2. backup
            FakeSSHResult(exit_code=0),
            # 3. write — succeeds
            FakeSSHResult(exit_code=0),
            # 4. verify — recovery key MISSING (corruption scenario)
            FakeSSHResult(stdout="some-random-key-only\n"),
            # 5. restore backup (triggered by safety check)
            FakeSSHResult(exit_code=0),
        ])

        with patch.object(rot, '_generate_ssh_keypair', new_callable=AsyncMock) as mock_keygen:
            mock_keygen.return_value = (FAKE_PRIVATE_KEY, FAKE_PUBLIC_KEY)
            result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")

        assert result['status'] == 'failed'
        assert 'Safety check failed' in result['error']
        assert 'Backup restored' in result['error']

        # 5 SSH calls: read, backup, write, verify, restore
        assert ssh_mock.execute.await_count == 5


# ── Test: Remote rotation — no SSH manager ───────────────────────────

class TestRotateSSHKeysRemoteNoSSHManager:
    """Remote rotation fails gracefully when SSH manager is None."""

    @pytest.mark.asyncio
    async def test_no_ssh_manager(self):
        rot = _make_rotation()
        rot._ssh_manager = None  # Not injected

        result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")

        assert result['status'] == 'failed'
        assert 'SSH Manager not injected' in result['error']


# ── Test: Remote rotation — bad session ID ───────────────────────────

class TestRotateSSHKeysRemoteSanitize:
    """Session ID with path traversal or injection is rejected."""

    @pytest.mark.asyncio
    async def test_bad_session_id_rejected(self):
        rot = _make_rotation()
        rot._ssh_manager = AsyncMock()

        result = await rot._rotate_ssh_keys_remote("../../etc/passwd", "vps_1")
        assert result['status'] == 'failed'
        assert 'Invalid session_id' in result['error']

    @pytest.mark.asyncio
    async def test_session_id_with_spaces_rejected(self):
        rot = _make_rotation()
        rot._ssh_manager = AsyncMock()

        result = await rot._rotate_ssh_keys_remote("session id with spaces", "vps_1")
        assert result['status'] == 'failed'

    @pytest.mark.asyncio
    async def test_valid_session_id_passes(self):
        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        # Will fail at the "no recovery key" step, but that proves
        # session_id sanitization passed
        ssh_mock.execute = AsyncMock(return_value=FakeSSHResult(
            stdout=f"{OPERATIONAL_LINE}\n"
        ))

        result = await rot._rotate_ssh_keys_remote("session_abc-123", "vps_1")
        # Should reach SSH execution, not fail at sanitize
        assert 'Invalid session_id' not in result.get('error', '')


# ── Test: SSH Manager exception handling ─────────────────────────────

class TestRotateSSHKeysRemoteSSHException:
    """SSHManagerError is caught and returned cleanly."""

    @pytest.mark.asyncio
    async def test_ssh_manager_error(self):
        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        # Import the real exception class
        from citadel_archer.remote.ssh_manager import SSHManagerError

        ssh_mock.execute = AsyncMock(side_effect=SSHManagerError("Connection refused"))

        result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")
        assert result['status'] == 'failed'
        assert 'Connection refused' in result['error']

    @pytest.mark.asyncio
    async def test_generic_exception(self):
        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        ssh_mock.execute = AsyncMock(side_effect=RuntimeError("Unexpected failure"))

        result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")
        assert result['status'] == 'failed'
        assert 'Unexpected failure' in result['error']


# ── Test: execute() integrates asset_id ──────────────────────────────

class TestExecuteDispatchesAssetId:
    """execute() reads target_asset from params and routes correctly."""

    @pytest.mark.asyncio
    async def test_execute_passes_asset_id_to_rotate_ssh(self):
        rot = _make_rotation()

        action = MagicMock()
        action.name = 'rotate_ssh_keys'
        action.params = {'target_asset': 'remote_vps_42'}

        session = MagicMock()
        session.id = 'sess_1'

        with patch.object(rot, '_rotate_ssh_keys', new_callable=AsyncMock) as mock_rotate:
            mock_rotate.return_value = {'status': 'success'}

            # Patch recovery key pre-flight to pass
            with patch('citadel_archer.panic.actions.credential_rotation.RecoveryKeyManager') as MockRKM:
                instance = MockRKM.return_value
                instance.ensure_recovery_key_present = MagicMock()

                result = await rot.execute(action, session)

            mock_rotate.assert_awaited_once_with('sess_1', asset_id='remote_vps_42')

    @pytest.mark.asyncio
    async def test_execute_defaults_to_local(self):
        rot = _make_rotation()

        action = MagicMock()
        action.name = 'rotate_ssh_keys'
        action.params = {}  # No target_asset

        session = MagicMock()
        session.id = 'sess_1'

        with patch.object(rot, '_rotate_ssh_keys', new_callable=AsyncMock) as mock_rotate:
            mock_rotate.return_value = {'status': 'success'}

            with patch('citadel_archer.panic.actions.credential_rotation.RecoveryKeyManager') as MockRKM:
                instance = MockRKM.return_value
                instance.ensure_recovery_key_present = MagicMock()

                result = await rot.execute(action, session)

            mock_rotate.assert_awaited_once_with('sess_1', asset_id='local')


# ── Test: Base64 encoding strategy ───────────────────────────────────

class TestBase64WriteStrategy:
    """Verify the base64 encode/decode write avoids SSH escaping issues."""

    @pytest.mark.asyncio
    async def test_base64_encoded_content(self):
        """The write command uses base64-encoded content to avoid
        shell escaping issues with SSH key content."""
        import base64

        rot = _make_rotation()
        ssh_mock = AsyncMock()
        rot._ssh_manager = ssh_mock

        executed_commands = []

        async def capture_execute(asset_id, cmd, *args, **kwargs):
            executed_commands.append(cmd)
            if 'cat' in cmd and 'authorized_keys' in cmd and '2>/dev/null' in cmd:
                return FakeSSHResult(stdout=f"{RECOVERY_LINE}\n")
            elif 'cp' in cmd:
                return FakeSSHResult(exit_code=0)
            elif 'base64' in cmd:
                return FakeSSHResult(exit_code=0)
            elif 'cat' in cmd:
                return FakeSSHResult(stdout=f"{RECOVERY_LINE}\n{FAKE_PUBLIC_KEY}\n")
            return FakeSSHResult(exit_code=0)

        ssh_mock.execute = AsyncMock(side_effect=capture_execute)
        ssh_mock.invalidate_cache = AsyncMock()

        with patch.object(rot, '_generate_ssh_keypair', new_callable=AsyncMock) as mock_keygen:
            mock_keygen.return_value = (FAKE_PRIVATE_KEY, FAKE_PUBLIC_KEY)
            result = await rot._rotate_ssh_keys_remote("test_session", "vps_1")

        assert result['status'] == 'success'

        # Find the write command
        write_cmd = [c for c in executed_commands if 'base64 -d' in c]
        assert len(write_cmd) == 1

        # Extract and verify the base64 payload
        # Command format: echo "<b64>" | base64 -d > ...
        import re
        match = re.search(r'echo "([^"]+)"', write_cmd[0])
        assert match, f"Base64 payload not found in: {write_cmd[0]}"

        decoded = base64.b64decode(match.group(1)).decode()
        assert RECOVERY_LINE.strip() in decoded
        assert FAKE_PUBLIC_KEY.strip() in decoded
