"""
Tests for DesktopFirewallManager (desktop-side rule management + push).
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.remote.firewall_manager import DesktopFirewallManager
from citadel_archer.remote.shield_database import RemoteShieldDatabase


@pytest.fixture
def db(tmp_path):
    return RemoteShieldDatabase(db_path=str(tmp_path / "fw_test.db"))


@pytest.fixture
def ssh():
    mock = AsyncMock()
    mock.execute = AsyncMock()
    mock.upload_file = AsyncMock()
    return mock


@pytest.fixture
def mgr(ssh, db):
    return DesktopFirewallManager(ssh, db)


class TestDesktopFirewallManager:
    """Desktop-side firewall manager."""

    def test_add_and_get_rules(self, mgr):
        rule_id = mgr.add_rule("vps1", {
            "action": "deny", "source": "1.2.3.0/24", "protocol": "tcp", "port": "22"
        })
        assert rule_id > 0
        rules = mgr.get_rules("vps1")
        assert len(rules) == 1
        assert rules[0]["source"] == "1.2.3.0/24"

    def test_remove_rule(self, mgr):
        rule_id = mgr.add_rule("vps1", {"source": "10.0.0.0/8"})
        assert mgr.remove_rule(rule_id) is True
        assert len(mgr.get_rules("vps1")) == 0

    def test_update_rule(self, mgr):
        rule_id = mgr.add_rule("vps1", {"source": "1.1.1.1"})
        assert mgr.update_rule(rule_id, {"source": "9.9.9.9"}) is True
        rules = mgr.get_rules("vps1")
        assert rules[0]["source"] == "9.9.9.9"

    def test_compile_config(self, mgr):
        mgr.add_rule("vps1", {"action": "deny", "source": "1.1.1.0/24", "port": "22"})
        mgr.add_rule("vps1", {"action": "allow", "source": "10.0.0.0/8"})
        compiled = mgr.compile_config("vps1")
        assert len(compiled) == 2
        assert all(r.get("enabled") for r in compiled)

    def test_add_auto_rule(self, mgr):
        rule_id = mgr.add_auto_rule("vps1", "1.2.3.4", "SSH brute force", 600)
        rules = mgr.get_rules("vps1")
        assert len(rules) == 1
        assert rules[0]["auto_generated"] is True
        assert rules[0]["expires_at"] is not None
        assert rules[0]["priority"] == 50

    @pytest.mark.asyncio
    async def test_push_rules(self, mgr, ssh):
        mgr.add_rule("vps1", {"source": "1.1.1.0/24", "port": "22"})

        # Mock remote config read
        ssh.execute = AsyncMock(return_value=MagicMock(
            success=True, stdout='{"fail_threshold": 5}', error=""
        ))

        result = await mgr.push_rules("vps1")
        assert result["success"] is True
        assert result["pushed_count"] == 1
        # Verify the SSH execute was called with base64 encoded config
        calls = ssh.execute.call_args_list
        assert any("base64" in str(c) for c in calls)

    @pytest.mark.asyncio
    async def test_push_geo_data(self, mgr, ssh, tmp_path):
        geo_file = tmp_path / "geo_cidrs.dat"
        geo_file.write_text("CN 1.0.0.0/8\n")
        result = await mgr.push_geo_data("vps1", str(geo_file))
        assert result["success"] is True
        ssh.upload_file.assert_awaited_once()
