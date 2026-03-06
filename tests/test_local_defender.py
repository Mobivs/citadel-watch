"""Tests for LocalHostDefender — subprocess command executor for localhost.

Covers:
- LocalCommandResult shape
- execute_command() with mocked subprocess
- ensure_localhost_asset() idempotency + correct fields
- Safe-command whitelist (read-only vs. write)
- AI bridge routing: local platform assets bypass SSH credential check
"""

import platform
import subprocess
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ── LocalHostDefender unit tests ─────────────────────────────────────


class TestLocalCommandResult:
    def test_success_property_true_when_exit_zero(self):
        from citadel_archer.local.local_defender import LocalCommandResult
        r = LocalCommandResult(stdout="ok", stderr="", exit_code=0, duration_ms=10)
        assert r.success is True

    def test_success_property_false_when_nonzero(self):
        from citadel_archer.local.local_defender import LocalCommandResult
        r = LocalCommandResult(stdout="", stderr="error", exit_code=1, duration_ms=5)
        assert r.success is False


class TestLocalHostDefender:
    def _make_completed(self, stdout="output", stderr="", returncode=0):
        cp = MagicMock()
        cp.stdout = stdout
        cp.stderr = stderr
        cp.returncode = returncode
        return cp

    def test_execute_command_returns_result_shape(self):
        from citadel_archer.local.local_defender import LocalHostDefender
        defender = LocalHostDefender()
        with patch("subprocess.run", return_value=self._make_completed("hello")) as mock_run:
            result = defender.execute_command("Get-Process", timeout=10)
        assert result.stdout == "hello"
        assert result.exit_code == 0
        assert result.duration_ms >= 0
        mock_run.assert_called_once()

    def test_execute_command_captures_stderr(self):
        from citadel_archer.local.local_defender import LocalHostDefender
        defender = LocalHostDefender()
        with patch("subprocess.run", return_value=self._make_completed("", "err msg", 1)):
            result = defender.execute_command("bad-cmd", timeout=10)
        assert result.stderr == "err msg"
        assert result.exit_code == 1
        assert result.success is False

    def test_execute_command_caps_stdout(self):
        from citadel_archer.local.local_defender import LocalHostDefender, LocalHostDefender as LHD
        big = "x" * 20_000
        defender = LHD()
        with patch("subprocess.run", return_value=self._make_completed(big)):
            result = defender.execute_command("Get-ChildItem", timeout=10)
        assert len(result.stdout) == LHD.MAX_OUTPUT

    def test_execute_command_timeout_raises(self):
        from citadel_archer.local.local_defender import LocalHostDefender
        defender = LocalHostDefender()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("powershell", 5)):
            with pytest.raises(TimeoutError):
                defender.execute_command("some cmd", timeout=5)

    def test_execute_command_missing_shell_raises(self):
        from citadel_archer.local.local_defender import LocalHostDefender
        defender = LocalHostDefender()
        with patch("subprocess.run", side_effect=FileNotFoundError("powershell not found")):
            with pytest.raises(RuntimeError, match="Cannot launch"):
                defender.execute_command("anything", timeout=5)

    def test_windows_uses_powershell(self):
        """On Windows, argv should include 'powershell'."""
        from citadel_archer.local import local_defender as mod

        original_os = mod._OS
        try:
            mod._OS = "Windows"
            argv = mod._build_argv("Get-Process")
        finally:
            mod._OS = original_os

        assert argv[0] == "powershell"
        assert "Get-Process" in argv

    def test_linux_uses_bash(self):
        """On Linux, argv should use bash."""
        from citadel_archer.local import local_defender as mod

        original_os = mod._OS
        try:
            mod._OS = "Linux"
            argv = mod._build_argv("ps aux")
        finally:
            mod._OS = original_os

        assert argv[0] == "bash"
        assert "ps aux" in argv


# ── ensure_localhost_asset tests ─────────────────────────────────────


class TestEnsureLocalhostAsset:
    """Use real AssetInventory (memory-only mode) to catch API mismatches."""

    def _make_real_inventory(self):
        from citadel_archer.intel.assets import AssetInventory
        return AssetInventory(db_path=None)  # memory-only, no file I/O

    def test_registers_when_not_present(self):
        from citadel_archer.local.local_defender import ensure_localhost_asset
        inv = self._make_real_inventory()
        result = ensure_localhost_asset(inv)
        assert result is True
        assert inv.get("localhost") is not None

    def test_idempotent_when_already_present(self):
        from citadel_archer.local.local_defender import ensure_localhost_asset
        inv = self._make_real_inventory()
        first = ensure_localhost_asset(inv)
        second = ensure_localhost_asset(inv)
        assert first is True
        assert second is False
        # Still exactly one asset
        assert len([a for a in inv.all() if a.asset_id == "localhost"]) == 1

    def test_registered_asset_has_correct_fields(self):
        from citadel_archer.local.local_defender import ensure_localhost_asset
        from citadel_archer.intel.assets import AssetPlatform, AssetType, AssetStatus

        inv = self._make_real_inventory()
        ensure_localhost_asset(inv)

        asset = inv.get("localhost")
        assert asset is not None
        assert asset.asset_id == "localhost"
        assert asset.platform == AssetPlatform.LOCAL
        assert asset.asset_type == AssetType.WORKSTATION
        assert asset.status == AssetStatus.PROTECTED
        assert asset.guardian_active is True
        assert asset.hostname == "localhost"
        assert asset.metadata.get("auto_registered") is True

    def test_name_is_machine_hostname(self):
        from citadel_archer.local.local_defender import ensure_localhost_asset

        inv = self._make_real_inventory()
        ensure_localhost_asset(inv)
        assert inv.get("localhost").name == platform.node()

    def test_register_failure_does_not_raise(self):
        """ensure_localhost_asset returns False (not crash) if register() fails."""
        from citadel_archer.local.local_defender import ensure_localhost_asset
        from citadel_archer.intel.assets import AssetInventory

        inv = self._make_real_inventory()
        # Monkey-patch register to simulate DB failure
        original_register = inv.register
        def boom(asset):
            raise Exception("DB error")
        inv.register = boom

        result = ensure_localhost_asset(inv)
        assert result is False


# ── Safe-command whitelist tests (Windows commands) ──────────────────


class TestWindowsSafeCommands:
    def test_get_process_is_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Get-Process") is True
        assert _is_safe_read_only("get-process") is True
        assert _is_safe_read_only("Get-Process -Name svchost") is True

    def test_get_filehash_is_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Get-FileHash C:\\file.exe") is True

    def test_get_authenticodesignature_is_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Get-AuthenticodeSignature 'C:\\file.exe'") is True

    def test_tasklist_is_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("tasklist") is True
        assert _is_safe_read_only("tasklist /fo csv") is True

    def test_ipconfig_is_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("ipconfig") is True
        assert _is_safe_read_only("ipconfig /all") is True

    def test_windows_cmd_dir_with_path_is_safe(self):
        """dir and type with Windows paths (backslash) must be whitelisted."""
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("dir C:\\Windows\\System32") is True
        assert _is_safe_read_only("type C:\\Windows\\System32\\drivers\\etc\\hosts") is True

    def test_windows_cmd_tools_no_path_are_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("tasklist /fo csv") is True
        assert _is_safe_read_only("sc query Dnscache") is True
        assert _is_safe_read_only("systeminfo") is True

    def test_stop_process_is_not_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Stop-Process -Id 1234") is False

    def test_remove_item_is_not_safe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Remove-Item C:\\evil.exe") is False

    def test_shell_metachar_always_unsafe(self):
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        # Even a safe command with metacharacter is blocked
        assert _is_safe_read_only("Get-Process; Remove-Item") is False
        assert _is_safe_read_only("Get-Process | Out-File c:\\out.txt") is False


# ── AI bridge local routing integration test ─────────────────────────


class TestAIBridgeLocalRouting:
    """Verify that the AI bridge routes local-platform assets to subprocess."""

    def _make_local_asset(self, asset_id="localhost", name="DESKTOP-JOHN"):
        from citadel_archer.intel.assets import Asset, AssetPlatform, AssetType, AssetStatus
        return Asset(
            asset_id=asset_id,
            name=name,
            platform=AssetPlatform.LOCAL,
            asset_type=AssetType.WORKSTATION,
            status=AssetStatus.PROTECTED,
            hostname="localhost",
            ip_address="127.0.0.1",
            guardian_active=True,
        )

    @pytest.mark.asyncio
    async def test_local_asset_does_not_check_ssh_credential(self):
        """Local asset with no ssh_credential_id should NOT return credential error."""
        from citadel_archer.local.local_defender import LocalCommandResult

        asset = self._make_local_asset()
        assert asset.ssh_credential_id == ""  # No credential

        # Mock inventory that returns our local asset
        inv_mock = MagicMock()
        inv_mock.get.return_value = asset
        inv_mock.all.return_value = [asset]

        fake_result = LocalCommandResult(stdout="PID  Name\n1234 svchost", stderr="", exit_code=0, duration_ms=50)

        with patch("citadel_archer.api.asset_routes.get_inventory", return_value=inv_mock):
            with patch("citadel_archer.local.local_defender.LocalHostDefender.execute_command", return_value=fake_result):
                # Import here so patches are in effect
                from citadel_archer.chat.ai_bridge import AIBridge

                bridge = MagicMock(spec=AIBridge)
                bridge._chat = MagicMock()
                bridge._tool_execute_local_command = AIBridge._tool_execute_local_command.__get__(bridge)

                result = await bridge._tool_execute_local_command(
                    "localhost", "DESKTOP-JOHN", "Get-Process", "forensic query", 30
                )

        assert "error" not in result or "credential" not in result.get("error", "")
        assert result.get("stdout") is not None or result.get("status") == "pending_approval"
