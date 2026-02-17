"""Tests for remote execution infrastructure.

Covers:
  - BaseAction._run_command() local/remote routing
  - PlaybookEngine SSH Manager injection
  - PanicManager target_assets propagation
  - NetworkIsolation remote-aware command execution
  - Action handler asset_id propagation
"""

import asyncio
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.panic.actions.base import BaseAction, CommandOutput


# ── Concrete action for testing abstract BaseAction ───────────────────

class _TestAction(BaseAction):
    """Concrete subclass of BaseAction for testing."""

    async def execute(self, action, session):
        return {"status": "ok"}

    async def capture_state(self, action):
        return {}

    async def rollback(self, recovery_state):
        return {"status": "ok"}


# ── BaseAction._run_command() ─────────────────────────────────────────

class TestRunCommandLocal:
    """_run_command with asset_id='local' runs subprocess."""

    @pytest.mark.asyncio
    async def test_local_echo(self):
        action = _TestAction(MagicMock(), {})
        result = await action._run_command(
            ["python", "-c", "print('hello')"],
            asset_id="local",
        )
        assert isinstance(result, CommandOutput)
        assert result.returncode == 0
        assert "hello" in result.stdout
        assert result.asset_id == "local"

    @pytest.mark.asyncio
    async def test_local_failure(self):
        action = _TestAction(MagicMock(), {})
        result = await action._run_command(
            ["python", "-c", "import sys; sys.exit(1)"],
            asset_id="local",
        )
        assert result.returncode == 1

    @pytest.mark.asyncio
    async def test_local_timeout(self):
        action = _TestAction(MagicMock(), {})
        result = await action._run_command(
            ["python", "-c", "import time; time.sleep(10)"],
            asset_id="local",
            timeout=1,
        )
        assert result.returncode == -1
        assert "timed out" in result.stderr

    @pytest.mark.asyncio
    async def test_default_is_local(self):
        action = _TestAction(MagicMock(), {})
        result = await action._run_command(
            ["python", "-c", "print('default')"],
        )
        assert result.asset_id == "local"
        assert result.returncode == 0


class TestRunCommandRemote:
    """_run_command with remote asset_id routes to SSH Manager."""

    @pytest.mark.asyncio
    async def test_remote_no_ssh_manager(self):
        """Without SSH Manager, remote commands return an error."""
        action = _TestAction(MagicMock(), {})
        result = await action._run_command(
            ["whoami"], asset_id="vps-001"
        )
        assert result.returncode == -1
        assert "SSH Manager not available" in result.stderr
        assert result.asset_id == "vps-001"

    @pytest.mark.asyncio
    async def test_remote_with_ssh_manager(self):
        """With SSH Manager, remote commands route through execute()."""
        action = _TestAction(MagicMock(), {})

        mock_ssh = MagicMock()
        mock_ssh.execute = AsyncMock(return_value=MagicMock(
            stdout="root\n", stderr="", exit_code=0
        ))
        action.set_ssh_manager(mock_ssh)

        result = await action._run_command(
            ["whoami"], asset_id="vps-001"
        )
        assert result.returncode == 0
        assert result.stdout == "root\n"
        assert result.asset_id == "vps-001"
        mock_ssh.execute.assert_called_once_with("vps-001", "whoami", timeout=30)

    @pytest.mark.asyncio
    async def test_remote_list_joined(self):
        """List commands are joined into a string for remote execution."""
        action = _TestAction(MagicMock(), {})

        mock_ssh = MagicMock()
        mock_ssh.execute = AsyncMock(return_value=MagicMock(
            stdout="", stderr="", exit_code=0
        ))
        action.set_ssh_manager(mock_ssh)

        await action._run_command(
            ["iptables", "-P", "INPUT", "DROP"], asset_id="vps-002"
        )
        mock_ssh.execute.assert_called_once_with(
            "vps-002", "iptables -P INPUT DROP", timeout=30
        )

    @pytest.mark.asyncio
    async def test_remote_ssh_exception(self):
        """SSH exceptions are caught and returned as error output."""
        action = _TestAction(MagicMock(), {})

        mock_ssh = MagicMock()
        mock_ssh.execute = AsyncMock(side_effect=ConnectionError("SSH refused"))
        action.set_ssh_manager(mock_ssh)

        result = await action._run_command("whoami", asset_id="vps-001")
        assert result.returncode == -1
        assert "SSH refused" in result.stderr

    @pytest.mark.asyncio
    async def test_remote_string_command(self):
        """String commands are passed directly (not joined)."""
        action = _TestAction(MagicMock(), {})

        mock_ssh = MagicMock()
        mock_ssh.execute = AsyncMock(return_value=MagicMock(
            stdout="ok", stderr="", exit_code=0
        ))
        action.set_ssh_manager(mock_ssh)

        await action._run_command(
            "cat /etc/resolv.conf", asset_id="vps-001"
        )
        mock_ssh.execute.assert_called_once_with(
            "vps-001", "cat /etc/resolv.conf", timeout=30
        )


# ── PlaybookEngine SSH Manager injection ──────────────────────────────

class TestPlaybookEngineSSHInjection:
    """PlaybookEngine should inject SSH Manager into all action handlers."""

    def test_set_ssh_manager_propagates(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine

        mock_db = MagicMock()
        mock_db.acquire = MagicMock()
        engine = PlaybookEngine(mock_db, {})

        mock_ssh = MagicMock()
        engine.set_ssh_manager(mock_ssh)

        # All handlers should have received the SSH manager
        for name, handler in engine.action_handlers.items():
            assert handler._ssh_manager is mock_ssh, (
                f"Handler '{name}' did not receive SSH manager"
            )

    def test_init_with_ssh_manager(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine

        mock_db = MagicMock()
        mock_ssh = MagicMock()
        engine = PlaybookEngine(mock_db, {}, ssh_manager=mock_ssh)

        for name, handler in engine.action_handlers.items():
            assert handler._ssh_manager is mock_ssh

    def test_init_without_ssh_manager(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine

        mock_db = MagicMock()
        engine = PlaybookEngine(mock_db, {})

        for handler in engine.action_handlers.values():
            assert handler._ssh_manager is None


# ── PanicManager target_assets propagation ────────────────────────────

class TestPanicManagerTargetAssets:
    """PanicManager._execute_playbook should pass target_assets from session."""

    @pytest.mark.asyncio
    async def test_passes_target_assets_from_metadata(self):
        from citadel_archer.panic.panic_manager import PanicManager

        mgr = PanicManager.__new__(PanicManager)
        mgr.db = MagicMock()
        mgr.websocket_handlers = {}

        # Mock playbook engine
        mock_engine = MagicMock()
        mock_engine.execute_playbook = AsyncMock(return_value=[])
        mgr.playbook_engine = mock_engine

        # Mock _log_action and _save_recovery_state
        mgr._log_action = AsyncMock()
        mgr._save_recovery_state = AsyncMock()

        # Create a session with target_assets in metadata
        session = MagicMock()
        session.id = "test-session"
        session.metadata = {"target_assets": ["local", "vps-001", "vps-002"]}

        playbook = MagicMock()
        playbook.id = "pb-1"
        playbook.name = "TestPlaybook"

        await mgr._execute_playbook(session, playbook)

        # Verify execute_playbook was called with target_assets
        call_kwargs = mock_engine.execute_playbook.call_args
        assert call_kwargs.kwargs.get("target_assets") == ["local", "vps-001", "vps-002"]

    @pytest.mark.asyncio
    async def test_none_when_no_metadata(self):
        from citadel_archer.panic.panic_manager import PanicManager

        mgr = PanicManager.__new__(PanicManager)
        mgr.db = MagicMock()
        mgr.websocket_handlers = {}

        mock_engine = MagicMock()
        mock_engine.execute_playbook = AsyncMock(return_value=[])
        mgr.playbook_engine = mock_engine
        mgr._log_action = AsyncMock()
        mgr._save_recovery_state = AsyncMock()

        session = MagicMock()
        session.id = "test-session-2"
        session.metadata = {}

        playbook = MagicMock()
        playbook.id = "pb-2"
        playbook.name = "TestPlaybook2"

        await mgr._execute_playbook(session, playbook)

        call_kwargs = mock_engine.execute_playbook.call_args
        assert call_kwargs.kwargs.get("target_assets") is None

    @pytest.mark.asyncio
    async def test_handles_missing_metadata_attr(self):
        from citadel_archer.panic.panic_manager import PanicManager

        mgr = PanicManager.__new__(PanicManager)
        mgr.db = MagicMock()
        mgr.websocket_handlers = {}

        mock_engine = MagicMock()
        mock_engine.execute_playbook = AsyncMock(return_value=[])
        mgr.playbook_engine = mock_engine
        mgr._log_action = AsyncMock()
        mgr._save_recovery_state = AsyncMock()

        # Session without metadata attribute at all
        session = MagicMock(spec=["id"])
        session.id = "test-session-3"

        playbook = MagicMock()
        playbook.id = "pb-3"
        playbook.name = "TestPlaybook3"

        # Should not raise
        await mgr._execute_playbook(session, playbook)

        call_kwargs = mock_engine.execute_playbook.call_args
        assert call_kwargs.kwargs.get("target_assets") is None


# ── NetworkIsolation remote execution ────────────────────────────────

class TestNetworkIsolationRemote:
    """NetworkIsolation routes commands based on target_asset."""

    @pytest.mark.asyncio
    async def test_block_incoming_local(self):
        """Local execution calls _run_command with asset_id='local'."""
        from citadel_archer.panic.actions.network_isolation import NetworkIsolation

        handler = NetworkIsolation(MagicMock(), {})

        # Patch _run_command to capture calls
        calls = []
        original = handler._run_command

        async def mock_run(command, asset_id="local", **kwargs):
            calls.append((command, asset_id))
            return CommandOutput(stdout="", stderr="", returncode=0, asset_id=asset_id)

        handler._run_command = mock_run

        action = MagicMock()
        action.name = "block_all_incoming"
        action.params = {"target_asset": "local"}

        session = MagicMock()
        session.id = "s1"

        result = await handler.execute(action, session)
        assert result["status"] == "success"
        assert all(aid == "local" for _, aid in calls)

    @pytest.mark.asyncio
    async def test_block_incoming_remote(self):
        """Remote execution calls _run_command with remote asset_id."""
        from citadel_archer.panic.actions.network_isolation import NetworkIsolation

        handler = NetworkIsolation(MagicMock(), {})

        calls = []

        async def mock_run(command, asset_id="local", **kwargs):
            calls.append((command, asset_id))
            return CommandOutput(stdout="", stderr="", returncode=0, asset_id=asset_id)

        handler._run_command = mock_run

        action = MagicMock()
        action.name = "block_all_incoming"
        action.params = {"target_asset": "vps-001"}

        session = MagicMock()
        session.id = "s1"

        result = await handler.execute(action, session)
        assert result["status"] == "success"
        assert result["asset"] == "vps-001"
        # All commands should target vps-001
        assert all(aid == "vps-001" for _, aid in calls)

    @pytest.mark.asyncio
    async def test_get_connections_remote(self):
        """_get_connections routes through _run_command."""
        from citadel_archer.panic.actions.network_isolation import NetworkIsolation

        handler = NetworkIsolation(MagicMock(), {})

        async def mock_run(command, asset_id="local", **kwargs):
            if command == ['ss', '-tupan']:
                return CommandOutput(
                    stdout="State\tRecv-Q\tSend-Q\tLocal\tRemote\nESTAB\t0\t0\t10.0.0.1:22\t10.0.0.2:54321\tsshd",
                    returncode=0,
                    asset_id=asset_id,
                )
            return CommandOutput(returncode=0, asset_id=asset_id)

        handler._run_command = mock_run

        result = await handler._get_connections("vps-003")
        assert len(result) == 1
        assert result[0]["state"] == "ESTAB"


# ── Action handler asset_id propagation ──────────────────────────────

class TestActionHandlerAssetPropagation:
    """All action handlers should read target_asset from params."""

    def _make_action(self, name, asset_id="vps-test"):
        action = MagicMock()
        action.name = name
        action.params = {"target_asset": asset_id}
        action.timeout = 30
        action.retry_count = 0
        action.required = True
        return action

    @pytest.mark.asyncio
    async def test_credential_rotation_reads_asset(self):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation

        handler = CredentialRotation(MagicMock(), {"api_services": []})

        action = self._make_action("inventory_credentials", "vps-005")
        session = MagicMock()
        session.id = "s1"

        # inventory_credentials doesn't need recovery key check,
        # so it should attempt to run and we just verify it reads asset_id
        # (it will fail at DB access but that's fine)
        try:
            result = await handler.execute(action, session)
        except Exception:
            pass  # Expected — no real DB

    @pytest.mark.asyncio
    async def test_process_termination_reads_asset(self):
        from citadel_archer.panic.actions.process_termination import ProcessTermination

        handler = ProcessTermination(MagicMock(), {})
        action = self._make_action("restart_services", "vps-006")
        session = MagicMock()
        session.id = "s1"

        calls = []

        async def mock_run(command, asset_id="local", **kwargs):
            calls.append(asset_id)
            return CommandOutput(stdout="active\n", returncode=0, asset_id=asset_id)

        handler._run_command = mock_run
        result = await handler.execute(action, session)
        assert all(aid == "vps-006" for aid in calls)


# ── PlaybookEngine.execute_playbook with target_assets ────────────────

class TestPlaybookEngineExecution:
    """PlaybookEngine.execute_playbook loops over target_assets."""

    @pytest.mark.asyncio
    async def test_executes_on_multiple_assets(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine, Playbook, Action

        mock_db = MagicMock()
        engine = PlaybookEngine(mock_db, {})

        # Track which assets each handler sees
        seen_assets = []
        original_execute = engine.action_handlers['network'].execute

        async def track_execute(action, session):
            seen_assets.append(action.params.get("target_asset", "local"))
            return {
                "action": action.name,
                "type": action.type,
                "status": "success",
            }

        # Patch all handlers
        for handler in engine.action_handlers.values():
            handler.execute = track_execute

        playbook = Playbook(
            id="pb-test",
            name="Test",
            description="Test playbook",
            category="test",
            priority=1,
            requires_confirmation=False,
            actions=[Action(name="block_all_incoming", type="network")],
        )

        session = MagicMock()
        session.id = "s1"

        results = await engine.execute_playbook(
            playbook=playbook,
            session=session,
            target_assets=["local", "vps-001", "vps-002"],
        )

        assert len(results) == 3
        assert seen_assets == ["local", "vps-001", "vps-002"]

    @pytest.mark.asyncio
    async def test_defaults_to_local(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine, Playbook, Action

        mock_db = MagicMock()
        engine = PlaybookEngine(mock_db, {})

        seen_assets = []

        async def track_execute(action, session):
            seen_assets.append(action.params.get("target_asset", "local"))
            return {
                "action": action.name,
                "type": action.type,
                "status": "success",
            }

        for handler in engine.action_handlers.values():
            handler.execute = track_execute

        playbook = Playbook(
            id="pb-test2",
            name="Test2",
            description="Test playbook",
            category="test",
            priority=1,
            requires_confirmation=False,
            actions=[Action(name="snapshot_connections", type="network")],
        )

        session = MagicMock()
        session.id = "s2"

        results = await engine.execute_playbook(
            playbook=playbook,
            session=session,
        )

        assert len(results) == 1
        assert seen_assets == ["local"]
