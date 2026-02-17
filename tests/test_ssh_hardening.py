"""
Tests for SSHHardeningOrchestrator — desktop-side SSH hardening orchestration.

All SSH commands are mocked (no real VPS connections).
"""

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.remote.ssh_hardening import (
    HardeningConfig,
    HardeningResult,
    HardeningStatus,
    RollbackResult,
    SSHHardeningOrchestrator,
)


@dataclass
class FakeCommandResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: int = 10


@pytest.fixture
def mock_ssh():
    ssh = AsyncMock()
    ssh.execute = AsyncMock(return_value=FakeCommandResult(stdout="", exit_code=0))
    ssh._connections = {}
    return ssh


@pytest.fixture
def mock_db(tmp_path):
    from citadel_archer.remote.shield_database import RemoteShieldDatabase
    return RemoteShieldDatabase(db_path=str(tmp_path / "shield.db"))


@pytest.fixture
def orchestrator(mock_ssh, mock_db):
    return SSHHardeningOrchestrator(mock_ssh, mock_db)


class TestHardeningConfig:
    """HardeningConfig dataclass."""

    def test_defaults(self):
        cfg = HardeningConfig()
        assert cfg.disable_password_auth is True
        assert cfg.permit_root_login == "prohibit-password"
        assert cfg.max_auth_tries == 3
        assert cfg.fail2ban_threshold == 5
        assert cfg.knock_sequence == [7000, 8000, 9000]

    def test_custom_values(self):
        cfg = HardeningConfig(
            custom_ssh_port=2222,
            enable_port_knocking=True,
            knock_sequence=[1111, 2222, 3333],
        )
        assert cfg.custom_ssh_port == 2222
        assert cfg.enable_port_knocking is True

    def test_serialization_roundtrip(self):
        cfg = HardeningConfig(
            max_auth_tries=5,
            ip_whitelist=["10.0.0.1"],
            ban_durations=[60, 120],
        )
        d = cfg.to_dict()
        cfg2 = HardeningConfig.from_dict(d)
        assert cfg2.max_auth_tries == 5
        assert cfg2.ip_whitelist == ["10.0.0.1"]
        assert cfg2.ban_durations == [60, 120]


class TestSSHHardeningOrchestrator:
    """Orchestrator logic with mocked SSH manager."""

    @pytest.mark.asyncio
    async def test_harden_full_flow(self, orchestrator, mock_ssh):
        """Full hardening: backup → apply → validate → reload → verify."""
        # Mock: backup ok, key exists, sshd -t ok, reload ok, verify ok
        mock_ssh.execute = AsyncMock(side_effect=[
            FakeCommandResult(exit_code=0),  # backup
            FakeCommandResult(stdout="yes", exit_code=0),  # key check
            # 8 sed directives
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),
            FakeCommandResult(exit_code=0),  # sshd -t
            FakeCommandResult(exit_code=0),  # reload
            FakeCommandResult(stdout="citadel-ok", exit_code=0),  # verify
            FakeCommandResult(exit_code=0),  # push config
        ])

        result = await orchestrator.harden_asset("vps_1", HardeningConfig())
        assert result.success is True
        assert "sshd_config backed up" in result.changes_applied
        assert "access verified" in result.changes_applied

    @pytest.mark.asyncio
    async def test_rollback_on_verify_failure(self, orchestrator, mock_ssh):
        """If access verification fails, auto-rollback fires."""
        call_count = [0]

        async def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # backup
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 2:  # key check
                return FakeCommandResult(stdout="yes", exit_code=0)
            # sed directives (3-10)
            if 3 <= call_count[0] <= 10:
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 11:  # sshd -t
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 12:  # reload
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 13:  # verify — FAIL
                return FakeCommandResult(stdout="timeout", exit_code=1)
            # rollback calls
            return FakeCommandResult(exit_code=0)

        mock_ssh.execute = AsyncMock(side_effect=side_effect)

        result = await orchestrator.harden_asset("vps_2", HardeningConfig())
        assert result.success is False
        assert "rolled back" in result.error

    @pytest.mark.asyncio
    async def test_backup_failure_aborts(self, orchestrator, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=FakeCommandResult(exit_code=1, stderr="permission denied")
        )
        result = await orchestrator.harden_asset("vps_3", HardeningConfig())
        assert result.success is False
        assert "backup" in result.error.lower()

    @pytest.mark.asyncio
    async def test_validate_failure_rolls_back(self, orchestrator, mock_ssh):
        """sshd -t failure triggers rollback."""
        call_count = [0]

        async def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # backup
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 2:  # key check
                return FakeCommandResult(stdout="yes", exit_code=0)
            if 3 <= call_count[0] <= 10:  # sed
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 11:  # sshd -t — FAIL
                return FakeCommandResult(exit_code=1, stderr="bad config")
            # rollback
            return FakeCommandResult(exit_code=0)

        mock_ssh.execute = AsyncMock(side_effect=side_effect)

        result = await orchestrator.harden_asset("vps_4", HardeningConfig())
        assert result.success is False
        assert "validation failed" in result.error

    @pytest.mark.asyncio
    async def test_reload_not_restart(self, orchestrator, mock_ssh):
        """Verify that reload (not restart) is used."""
        commands = []
        original_execute = mock_ssh.execute

        async def capture(*args, **kwargs):
            if args:
                commands.append(args[1] if len(args) > 1 else "")
            return FakeCommandResult(stdout="citadel-ok", exit_code=0)

        mock_ssh.execute = AsyncMock(side_effect=capture)

        await orchestrator.harden_asset("vps_5", HardeningConfig())
        reload_cmds = [c for c in commands if "reload" in str(c)]
        restart_cmds = [c for c in commands if "restart" in str(c)]
        assert len(reload_cmds) > 0
        assert len(restart_cmds) == 0

    @pytest.mark.asyncio
    async def test_config_saved_to_db(self, orchestrator, mock_ssh, mock_db):
        """After successful hardening, config is saved to DB."""
        mock_ssh.execute = AsyncMock(
            return_value=FakeCommandResult(stdout="citadel-ok", exit_code=0)
        )
        await orchestrator.harden_asset("vps_6", HardeningConfig())
        saved = mock_db.get_hardening_config("vps_6")
        assert saved is not None
        assert saved["status"] == "applied"

    @pytest.mark.asyncio
    async def test_password_disable_skipped_if_no_key(self, orchestrator, mock_ssh):
        """If key check fails, password auth disable is skipped."""
        call_count = [0]

        async def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # backup
                return FakeCommandResult(exit_code=0)
            if call_count[0] == 2:  # key check — no key
                return FakeCommandResult(stdout="no", exit_code=0)
            return FakeCommandResult(stdout="citadel-ok", exit_code=0)

        mock_ssh.execute = AsyncMock(side_effect=side_effect)

        config = HardeningConfig(disable_password_auth=True)
        result = await orchestrator.harden_asset("vps_7", config)
        assert any("key auth" in w.lower() for w in result.warnings)


class TestRollback:
    """Rollback safety."""

    @pytest.mark.asyncio
    async def test_rollback_restores_backup(self, orchestrator, mock_ssh, mock_db):
        mock_ssh.execute = AsyncMock(
            return_value=FakeCommandResult(exit_code=0)
        )
        mock_db.save_hardening_config("vps_rb", {}, status="applied")
        result = await orchestrator.rollback_hardening("vps_rb")
        assert result.success is True
        assert "restored" in result.details

    @pytest.mark.asyncio
    async def test_rollback_failure(self, orchestrator, mock_ssh):
        mock_ssh.execute = AsyncMock(
            return_value=FakeCommandResult(exit_code=1, stderr="no backup")
        )
        result = await orchestrator.rollback_hardening("vps_no_bak")
        assert result.success is False


class TestGetHardeningStatus:
    """Status probing."""

    @pytest.mark.asyncio
    async def test_parses_sshd_config(self, orchestrator, mock_ssh):
        sshd_text = (
            "PasswordAuthentication no\n"
            "PermitRootLogin prohibit-password\n"
            "MaxAuthTries 3\n"
            "Port 2222\n"
            "PubkeyAuthentication yes\n"
        )
        mock_ssh.execute = AsyncMock(side_effect=[
            FakeCommandResult(stdout=sshd_text, exit_code=0),  # cat sshd_config
            FakeCommandResult(stdout="yes", exit_code=0),  # backup check
            FakeCommandResult(stdout="2", exit_code=0),  # key count
            FakeCommandResult(stdout='{"port_knocking_enabled": true, "fail_threshold": 5}', exit_code=0),
        ])

        status = await orchestrator.get_hardening_status("vps_st")
        assert status.password_auth_enabled is False
        assert status.root_login == "prohibit-password"
        assert status.max_auth_tries == 3
        assert status.ssh_port == 2222
        assert status.key_installed is True
        assert status.port_knocking_active is True

    @pytest.mark.asyncio
    async def test_defaults_on_error(self, orchestrator, mock_ssh):
        mock_ssh.execute = AsyncMock(side_effect=Exception("connection failed"))
        status = await orchestrator.get_hardening_status("vps_err")
        # Should return defaults without crashing
        assert status.password_auth_enabled is True
        assert status.ssh_port == 22

    @pytest.mark.asyncio
    async def test_backup_detection(self, orchestrator, mock_ssh):
        mock_ssh.execute = AsyncMock(side_effect=[
            FakeCommandResult(stdout="Port 22\n", exit_code=0),
            FakeCommandResult(stdout="yes", exit_code=0),  # backup exists
            FakeCommandResult(stdout="0", exit_code=0),  # no keys
            FakeCommandResult(stdout="{}", exit_code=0),  # shield status
        ])
        status = await orchestrator.get_hardening_status("vps_bak")
        assert status.sshd_config_backup_exists is True
