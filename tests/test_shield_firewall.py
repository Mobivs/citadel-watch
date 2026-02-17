"""
Tests for FirewallRuleManager in shield.py (VPS agent side).

Tests rule parsing, geo-CIDR resolution, and status reporting.
iptables calls are mocked since tests don't run as root.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from citadel_archer.agent.shield import FirewallRuleManager, _load_config


@pytest.fixture
def geo_file(tmp_path):
    """Create a test geo_cidrs.dat file."""
    geo = tmp_path / "geo_cidrs.dat"
    geo.write_text("CN 1.0.0.0/8\nCN 2.0.0.0/8\nRU 5.0.0.0/8\n")
    return geo


class TestFirewallRuleManager:
    """FirewallRuleManager in shield.py."""

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_apply_rules_creates_chain(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        mgr = FirewallRuleManager(config={
            "firewall_rules": [
                {"action": "deny", "source": "1.2.3.0/24", "protocol": "tcp", "port": "22"},
            ]
        })
        result = mgr.apply_rules()
        assert result is True
        assert mgr.is_active is True
        # Should have created chain, added rule, and inserted jump
        chain_calls = [c for c in mock_run.call_args_list if "CITADEL-FW" in str(c)]
        assert len(chain_calls) >= 3  # flush, create, jump

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_apply_empty_rules_returns_false(self, mock_run):
        mgr = FirewallRuleManager(config={"firewall_rules": []})
        assert mgr.apply_rules() is False
        assert mgr.is_active is False

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_remove_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        mgr = FirewallRuleManager(config={
            "firewall_rules": [{"action": "deny", "source": "1.1.1.1"}]
        })
        mgr.apply_rules()
        mgr.remove_rules()
        assert mgr.is_active is False

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_rate_limit_rule(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        mgr = FirewallRuleManager(config={
            "firewall_rules": [
                {"action": "rate_limit", "source": "any", "port": "80", "rate": "50/minute"},
            ]
        })
        mgr.apply_rules()
        # Find the hashlimit call
        hashlimit_calls = [
            c for c in mock_run.call_args_list
            if "hashlimit" in str(c)
        ]
        assert len(hashlimit_calls) == 1

    def test_resolve_geo_cidrs(self, geo_file):
        mgr = FirewallRuleManager(config={"firewall_rules": []})
        mgr.GEO_CIDRS_PATH = geo_file
        cidrs = mgr._resolve_geo_cidrs("CN")
        assert cidrs == ["1.0.0.0/8", "2.0.0.0/8"]
        assert mgr._resolve_geo_cidrs("US") == []

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_geo_block_rule(self, mock_run, geo_file):
        mock_run.return_value = MagicMock(returncode=0)
        mgr = FirewallRuleManager(config={
            "firewall_rules": [{"action": "deny", "source": "geo:CN"}]
        })
        mgr.GEO_CIDRS_PATH = geo_file
        mgr.apply_rules()
        # Should generate 2 iptables calls (one per CIDR)
        drop_calls = [
            c for c in mock_run.call_args_list
            if "DROP" in str(c) and ("1.0.0.0" in str(c) or "2.0.0.0" in str(c))
        ]
        assert len(drop_calls) == 2

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_disabled_rule_skipped(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        mgr = FirewallRuleManager(config={
            "firewall_rules": [
                {"action": "deny", "source": "1.1.1.1", "enabled": False},
                {"action": "deny", "source": "2.2.2.2", "enabled": True},
            ]
        })
        mgr.apply_rules()
        # Only 2.2.2.2 should be in a DROP call
        drop_calls = [c for c in mock_run.call_args_list if "DROP" in str(c)]
        assert any("2.2.2.2" in str(c) for c in drop_calls)
        assert not any("1.1.1.1" in str(c) for c in drop_calls)

    def test_get_status(self):
        mgr = FirewallRuleManager(config={
            "firewall_rules": [{"action": "deny", "source": "x"}]
        })
        status = mgr.get_status()
        assert status["active"] is False
        assert status["rule_count"] == 1
