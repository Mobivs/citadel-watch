"""Tests for ssh_manager.py code review fixes.

Covers:
  - Issue #6: test_connection false success when all probes fail
  - Issue #7: disconnect_all cancels idle reaper task
  - Issue #8: unused import removed (verified by import)
  - Issue #9: reaper CancelledError propagation
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.remote.ssh_manager import (
    SSHConnectionManager,
    SSHManagerError,
    AssetNotFoundError,
    NoCredentialError,
    VaultLockedError,
    ConnectionFailedError,
    CommandTimeoutError,
    ConnectionTestResult,
    CommandResult,
    _CachedConnection,
    IDLE_TIMEOUT_SECONDS,
)
from citadel_archer.intel.assets import AssetInventory, Asset, AssetStatus


# ── Helpers ──────────────────────────────────────────────────────────

class _FakeConn:
    """Minimal asyncssh connection stub."""
    def __init__(self, *, closed=False, run_results=None):
        self._closed = closed
        self._run_results = run_results or {}

    def is_closed(self):
        return self._closed

    async def run(self, cmd, check=False):
        result = self._run_results.get(cmd)
        if result is None:
            raise Exception("probe failed")
        return result

    def close(self):
        self._closed = True

    async def wait_closed(self):
        pass


@dataclass
class _RunResult:
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0


def _make_manager(asset=None, vault_unlocked=True, cred=None):
    """Build an SSHConnectionManager with mocked vault + inventory."""
    vault = MagicMock()
    vault.is_unlocked = vault_unlocked
    vault.get_ssh_credential.return_value = cred

    inventory = MagicMock()
    inventory.get.return_value = asset
    inventory.set_status = MagicMock()

    # Patch asyncssh import check
    with patch("citadel_archer.remote.ssh_manager.asyncssh", MagicMock()):
        mgr = SSHConnectionManager(vault, inventory)

    return mgr


# ── Issue #6: test_connection false success ──────────────────────────

class TestConnectionProbeCounter:
    """test_connection should fail if all probes fail despite connection OK."""

    @pytest.mark.asyncio
    async def test_all_probes_fail_returns_failure(self):
        """If SSH connects but every probe command errors, success=False."""
        asset = MagicMock()
        asset.ssh_credential_id = "cred1"
        asset.ip_address = "1.2.3.4"
        asset.hostname = "host"
        asset.ssh_port = 22
        asset.ssh_username = "root"

        mgr = _make_manager(asset=asset, cred={"auth_type": "password", "password": "x"})

        # Inject a cached connection whose probes all fail
        fake_conn = _FakeConn(run_results={})  # empty → every run() raises
        mgr._connections["a1"] = _CachedConnection(conn=fake_conn, asset_id="a1")
        mgr.assets.get.return_value = asset

        result = await mgr.test_connection("a1")

        assert result.success is False
        assert "all probe commands failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_some_probes_succeed(self):
        """If at least one probe succeeds, success=True."""
        asset = MagicMock()
        asset.ssh_credential_id = "cred1"

        mgr = _make_manager(asset=asset)

        # One probe succeeds (hostname), others fail
        fake_conn = _FakeConn(run_results={
            "hostname": _RunResult(stdout="myhost"),
        })
        mgr._connections["a1"] = _CachedConnection(conn=fake_conn, asset_id="a1")

        result = await mgr.test_connection("a1")

        assert result.success is True
        assert result.hostname == "myhost"


# ── Issue #7: disconnect_all cancels idle reaper ─────────────────────

class TestDisconnectAllReaper:
    """disconnect_all should cancel the idle reaper task."""

    @pytest.mark.asyncio
    async def test_reaper_cancelled_on_disconnect_all(self):
        mgr = _make_manager()

        # Simulate a running reaper task
        async def fake_reaper():
            await asyncio.sleep(3600)

        mgr._idle_task = asyncio.get_event_loop().create_task(fake_reaper())

        await mgr.disconnect_all()

        assert mgr._idle_task is None

    @pytest.mark.asyncio
    async def test_disconnect_all_without_reaper(self):
        """Should work fine even when no reaper is running."""
        mgr = _make_manager()
        mgr._idle_task = None

        await mgr.disconnect_all()  # should not raise


# ── Issue #8: import verification ────────────────────────────────────

def test_no_unused_io_import():
    """Verify 'import io' was removed from ssh_manager."""
    import inspect
    import citadel_archer.remote.ssh_manager as mod
    source = inspect.getsource(mod)
    # Should NOT have a bare 'import io' line
    lines = source.split('\n')
    io_imports = [l.strip() for l in lines if l.strip() == 'import io']
    assert io_imports == [], "Unused 'import io' should have been removed"


# ── Issue #9: reaper exception handling ──────────────────────────────

class TestReaperExceptionHandling:

    @pytest.mark.asyncio
    async def test_reaper_propagates_cancelled_error(self):
        """CancelledError should propagate out of the reaper."""
        mgr = _make_manager()

        # Add a stale connection that triggers disconnect
        fake_conn = _FakeConn(closed=True)
        mgr._connections["old"] = _CachedConnection(
            conn=fake_conn,
            asset_id="old",
            last_used=time.monotonic() - IDLE_TIMEOUT_SECONDS - 100,
        )

        task = asyncio.get_event_loop().create_task(mgr._reap_idle_connections())

        # Give it a moment to start then cancel
        await asyncio.sleep(0.05)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task


# ── Exception hierarchy ──────────────────────────────────────────────

class TestExceptionHierarchy:
    """All specific errors should be subclasses of SSHManagerError."""

    def test_subclasses(self):
        assert issubclass(AssetNotFoundError, SSHManagerError)
        assert issubclass(NoCredentialError, SSHManagerError)
        assert issubclass(VaultLockedError, SSHManagerError)
        assert issubclass(ConnectionFailedError, SSHManagerError)
        assert issubclass(CommandTimeoutError, SSHManagerError)
