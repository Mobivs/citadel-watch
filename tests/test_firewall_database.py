"""
Tests for firewall_rules table CRUD in RemoteShieldDatabase.
"""

import json
import tempfile
from pathlib import Path

import pytest

from citadel_archer.remote.shield_database import RemoteShieldDatabase


@pytest.fixture
def db(tmp_path):
    """Fresh shield database in a temp directory."""
    return RemoteShieldDatabase(db_path=str(tmp_path / "test_shield.db"))


class TestFirewallDatabase:
    """Firewall rules DB CRUD."""

    def test_save_and_get_rule(self, db):
        rule_id = db.save_firewall_rule("vps1", {
            "action": "deny",
            "source": "1.2.3.0/24",
            "protocol": "tcp",
            "port": "22",
        })
        assert rule_id > 0
        rules = db.get_firewall_rules("vps1")
        assert len(rules) == 1
        assert rules[0]["source"] == "1.2.3.0/24"
        assert rules[0]["action"] == "deny"
        assert rules[0]["enabled"] is True

    def test_get_rules_enabled_only(self, db):
        db.save_firewall_rule("vps1", {"source": "1.1.1.0/24", "enabled": True})
        db.save_firewall_rule("vps1", {"source": "2.2.2.0/24", "enabled": False})
        assert len(db.get_firewall_rules("vps1", enabled_only=True)) == 1
        assert len(db.get_firewall_rules("vps1", enabled_only=False)) == 2

    def test_update_rule(self, db):
        rule_id = db.save_firewall_rule("vps1", {"source": "1.1.1.1"})
        success = db.update_firewall_rule(rule_id, {"source": "9.9.9.9", "priority": 50})
        assert success is True
        rules = db.get_firewall_rules("vps1")
        assert rules[0]["source"] == "9.9.9.9"
        assert rules[0]["priority"] == 50

    def test_delete_rule(self, db):
        rule_id = db.save_firewall_rule("vps1", {"source": "1.1.1.1"})
        assert db.delete_firewall_rule(rule_id) is True
        assert len(db.get_firewall_rules("vps1")) == 0

    def test_delete_nonexistent_rule(self, db):
        assert db.delete_firewall_rule(999) is False

    def test_priority_ordering(self, db):
        db.save_firewall_rule("vps1", {"source": "low.pri", "priority": 200})
        db.save_firewall_rule("vps1", {"source": "high.pri", "priority": 10})
        db.save_firewall_rule("vps1", {"source": "mid.pri", "priority": 100})
        rules = db.get_firewall_rules("vps1")
        assert [r["source"] for r in rules] == ["high.pri", "mid.pri", "low.pri"]

    def test_delete_expired_rules(self, db):
        # Rule with past expiry
        db.save_firewall_rule("vps1", {
            "source": "expired.ip",
            "expires_at": "2020-01-01T00:00:00",
        })
        # Rule without expiry (permanent)
        db.save_firewall_rule("vps1", {"source": "permanent.ip"})
        count = db.delete_expired_firewall_rules()
        assert count == 1
        rules = db.get_firewall_rules("vps1", enabled_only=False)
        assert len(rules) == 1
        assert rules[0]["source"] == "permanent.ip"
