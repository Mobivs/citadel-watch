"""
Tests for OnboardingOrchestrator — node enrollment workflow.

Mocks SSH, deployer, hardening, and firewall components.
Uses a real RemoteShieldDatabase for persistence testing.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.remote.onboarding import (
    OnboardingOrchestrator,
    OnboardingConfig,
    OnboardingResult,
    StepResult,
    ONBOARDING_STEPS,
)
from citadel_archer.remote.shield_database import RemoteShieldDatabase


@pytest.fixture
def db(tmp_path):
    return RemoteShieldDatabase(db_path=str(tmp_path / "onboard_test.db"))


@pytest.fixture
def ssh():
    mock = AsyncMock()
    mock.connect = AsyncMock()
    mock.execute = AsyncMock()
    return mock


@pytest.fixture
def inventory():
    """Mock AssetInventory with one VPS asset."""
    mock = MagicMock()
    asset = MagicMock()
    asset.ip_address = "192.168.1.100"
    asset.hostname = "test-vps"
    mock.get.return_value = asset
    return mock


@pytest.fixture
def deployer():
    mock = AsyncMock()
    mock.deploy = AsyncMock(return_value={
        "success": True,
        "agent_status": {"version": "0.1.0", "running": True},
    })
    return mock


@pytest.fixture
def hardening_orch():
    mock = AsyncMock()
    from citadel_archer.remote.ssh_hardening import HardeningResult
    mock.harden_asset = AsyncMock(return_value=HardeningResult(
        success=True, asset_id="vps1", changes_applied=["backed up", "hardened"],
    ))
    return mock


@pytest.fixture
def firewall_mgr():
    mock = MagicMock()
    mock.add_rule = MagicMock(return_value=1)
    mock.push_rules = AsyncMock(return_value={"success": True, "pushed_count": 2, "error": ""})
    return mock


@pytest.fixture
def orch(ssh, db, inventory, deployer, hardening_orch, firewall_mgr):
    # Mock agent status for verify step
    ssh.execute.return_value = MagicMock(
        success=True,
        stdout='{"running": true, "version": "0.1.0", "unsynced_events": 0}',
        error="",
    )
    return OnboardingOrchestrator(
        ssh_manager=ssh,
        shield_db=db,
        inventory=inventory,
        agent_deployer=deployer,
        hardening_orch=hardening_orch,
        firewall_mgr=firewall_mgr,
    )


class TestOnboardingOrchestrator:
    """Node onboarding orchestrator tests."""

    @pytest.mark.asyncio
    async def test_full_onboarding_success(self, orch, db):
        config = OnboardingConfig(asset_id="vps1")
        result = await orch.start_onboarding(config)

        assert result.success is True
        assert result.status == "completed"
        assert len(result.steps) == 6
        for step in ONBOARDING_STEPS:
            assert result.steps[step]["status"] in ("completed", "skipped")

        # Verify DB session was created
        session = db.get_onboarding_session(result.session_id)
        assert session is not None
        assert session["status"] == "completed"

    @pytest.mark.asyncio
    async def test_skip_hardening(self, orch):
        config = OnboardingConfig(asset_id="vps1", skip_hardening=True)
        result = await orch.start_onboarding(config)
        assert result.steps["harden"]["status"] == "skipped"
        assert result.success is True

    @pytest.mark.asyncio
    async def test_skip_firewall(self, orch):
        config = OnboardingConfig(asset_id="vps1", skip_firewall=True)
        result = await orch.start_onboarding(config)
        assert result.steps["firewall"]["status"] == "skipped"
        assert result.success is True

    @pytest.mark.asyncio
    async def test_skip_both_optional_steps(self, orch):
        config = OnboardingConfig(
            asset_id="vps1", skip_hardening=True, skip_firewall=True,
        )
        result = await orch.start_onboarding(config)
        assert result.success is True
        assert result.steps["harden"]["status"] == "skipped"
        assert result.steps["firewall"]["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_validate_fails_no_asset(self, orch, inventory):
        inventory.get.return_value = None
        config = OnboardingConfig(asset_id="nonexistent")
        result = await orch.start_onboarding(config)
        assert result.success is False
        assert result.status == "failed"
        assert result.steps["validate"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_validate_fails_no_ip(self, orch, inventory):
        asset = MagicMock()
        asset.ip_address = None
        inventory.get.return_value = asset
        config = OnboardingConfig(asset_id="vps_no_ip")
        result = await orch.start_onboarding(config)
        assert result.success is False
        assert result.steps["validate"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_connect_failure(self, orch, ssh):
        ssh.connect.side_effect = Exception("Connection refused")
        config = OnboardingConfig(asset_id="vps1")
        result = await orch.start_onboarding(config)
        assert result.success is False
        assert result.steps["connect"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_deploy_failure_partial(self, orch, deployer):
        deployer.deploy.return_value = {"success": False, "error": "SCP timeout"}
        config = OnboardingConfig(asset_id="vps1")
        result = await orch.start_onboarding(config)
        # Deploy fails but subsequent steps still run → partial
        assert result.status == "partial"
        assert result.steps["deploy"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_verify_agent_not_running(self, orch, ssh):
        # Override the execute mock for verify step
        async def side_effect(asset_id, cmd, **kwargs):
            if "status" in cmd:
                return MagicMock(
                    success=True,
                    stdout='{"running": false}',
                    error="",
                )
            return MagicMock(success=True, stdout="Linux 5.15", error="")

        ssh.execute = AsyncMock(side_effect=side_effect)
        config = OnboardingConfig(asset_id="vps1")
        result = await orch.start_onboarding(config)
        assert result.steps["verify"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_retry_step(self, orch, db, ssh, deployer):
        # First: run onboarding with deploy failure
        deployer.deploy.return_value = {"success": False, "error": "timeout"}
        config = OnboardingConfig(asset_id="vps1")
        result = await orch.start_onboarding(config)
        assert result.steps["deploy"]["status"] == "failed"

        # Fix the deployer and retry
        deployer.deploy.return_value = {
            "success": True,
            "agent_status": {"version": "0.1.0", "running": True},
        }
        retry_result = await orch.retry_step(result.session_id, "deploy")
        assert retry_result.status == "completed"

    @pytest.mark.asyncio
    async def test_retry_invalid_session(self, orch):
        result = await orch.retry_step("nonexistent", "deploy")
        assert result.status == "failed"
        assert "not found" in result.message.lower()

    @pytest.mark.asyncio
    async def test_ws_broadcast(self, ssh, db, inventory, deployer, hardening_orch, firewall_mgr):
        broadcast = AsyncMock()
        ssh.execute.return_value = MagicMock(
            success=True,
            stdout='{"running": true, "version": "0.1.0", "unsynced_events": 0}',
            error="",
        )
        orch = OnboardingOrchestrator(
            ssh_manager=ssh, shield_db=db, inventory=inventory,
            agent_deployer=deployer, hardening_orch=hardening_orch,
            firewall_mgr=firewall_mgr, ws_broadcast=broadcast,
        )
        config = OnboardingConfig(asset_id="vps1")
        await orch.start_onboarding(config)
        # Should have broadcast multiple times (at least 2 per step: running + result)
        assert broadcast.call_count >= 6
