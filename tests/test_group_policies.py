"""Tests for Group Policies: Apply Security Rules to Multiple Systems (v0.3.30).

Covers:
  - Database layer: CRUD for policy groups, membership, application log, compliance
  - Policy engine: Fan-out, effective rules merge, conflict resolution, compliance summary
  - API routes: Create, list, add members, apply, effective policy, structural checks
  - Agent command: apply_policy in ALLOWED_COMMAND_TYPES and windows_shield handler
  - Frontend: HTML structure, JS exports
"""

import json
import sys
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
REMOTE_SHIELD_ROUTES = ROOT / "src" / "citadel_archer" / "api" / "remote_shield_routes.py"
MAIN_PY = ROOT / "src" / "citadel_archer" / "api" / "main.py"
GROUP_POLICY_PY = ROOT / "src" / "citadel_archer" / "remote" / "group_policy.py"
GROUP_POLICY_ROUTES = ROOT / "src" / "citadel_archer" / "api" / "group_policy_routes.py"
WINDOWS_SHIELD = ROOT / "src" / "citadel_archer" / "agent" / "windows_shield.py"
RS_HTML = ROOT / "frontend" / "remote-shield.html"
RS_JS = ROOT / "frontend" / "js" / "remote-shield.js"


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def shield_db():
    """Fresh in-memory RemoteShieldDatabase for testing."""
    from citadel_archer.remote.shield_database import RemoteShieldDatabase
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = RemoteShieldDatabase(db_path=f.name)
    return db


@pytest.fixture
def populated_db(shield_db):
    """DB with 2 agents and 1 policy group."""
    shield_db.create_agent("agent-1", "pc-1", "10.0.0.1", "token-1")
    shield_db.create_agent("agent-2", "pc-2", "10.0.0.2", "token-2")
    shield_db.create_policy_group(
        "grp-family", "Family PCs", "All family computers",
        rules={"alert_threshold": 5, "update_schedule": "daily"}, priority=50,
    )
    shield_db.add_group_member("grp-family", "agent-1")
    shield_db.add_group_member("grp-family", "agent-2")
    return shield_db


# ── Database Layer Tests ─────────────────────────────────────────────


class TestPolicyGroupCRUD:
    """Database CRUD for policy_groups table."""

    def test_create_and_get(self, shield_db):
        result = shield_db.create_policy_group(
            "grp-1", "Test Group", "desc", rules={"alert_threshold": 3}, priority=10,
        )
        assert result["group_id"] == "grp-1"
        assert result["name"] == "Test Group"
        assert result["rules"]["alert_threshold"] == 3

        fetched = shield_db.get_policy_group("grp-1")
        assert fetched is not None
        assert fetched["priority"] == 10

    def test_list_ordered_by_priority(self, shield_db):
        shield_db.create_policy_group("grp-low", "Low Priority", priority=200)
        shield_db.create_policy_group("grp-high", "High Priority", priority=10)
        groups = shield_db.list_policy_groups()
        assert len(groups) == 2
        assert groups[0]["group_id"] == "grp-high"

    def test_update_rules(self, shield_db):
        shield_db.create_policy_group("grp-1", "G1")
        ok = shield_db.update_policy_group("grp-1", rules={"alert_threshold": 8})
        assert ok is True
        g = shield_db.get_policy_group("grp-1")
        assert g["rules"]["alert_threshold"] == 8

    def test_delete_cascades_members(self, populated_db):
        assert len(populated_db.get_group_members("grp-family")) == 2
        ok = populated_db.delete_policy_group("grp-family")
        assert ok is True
        assert populated_db.get_policy_group("grp-family") is None
        assert populated_db.get_group_members("grp-family") == []

    def test_get_nonexistent_returns_none(self, shield_db):
        assert shield_db.get_policy_group("nope") is None


class TestGroupMembership:
    """Membership CRUD tests."""

    def test_add_and_get_members(self, shield_db):
        shield_db.create_policy_group("grp-1", "G1")
        shield_db.create_agent("a1", "h1", "1.1.1.1", "t1")
        assert shield_db.add_group_member("grp-1", "a1") is True
        members = shield_db.get_group_members("grp-1")
        assert members == ["a1"]

    def test_duplicate_membership_returns_false(self, populated_db):
        assert populated_db.add_group_member("grp-family", "agent-1") is False

    def test_remove_member(self, populated_db):
        assert populated_db.remove_group_member("grp-family", "agent-1") is True
        members = populated_db.get_group_members("grp-family")
        assert "agent-1" not in members

    def test_get_agent_groups(self, populated_db):
        populated_db.create_policy_group("grp-2", "Security", priority=10)
        populated_db.add_group_member("grp-2", "agent-1")
        groups = populated_db.get_agent_groups("agent-1")
        assert len(groups) == 2
        # Should be sorted by priority ASC
        assert groups[0]["group_id"] == "grp-2"  # priority 10
        assert groups[1]["group_id"] == "grp-family"  # priority 50


class TestApplicationLog:
    """Policy application log and compliance."""

    def test_log_and_update(self, shield_db):
        entry = shield_db.log_policy_application("app-1", "grp-1", "a1", "cmd-1")
        assert entry["status"] == "pending"
        ok = shield_db.update_application_status("cmd-1", "applied")
        assert ok is True

    def test_compliance_shows_status(self, populated_db):
        populated_db.log_policy_application("app-1", "grp-family", "agent-1", "cmd-1")
        populated_db.update_application_status("cmd-1", "applied")
        compliance = populated_db.get_policy_compliance("grp-family")
        assert len(compliance) == 2
        statuses = {c["agent_id"]: c["status"] for c in compliance}
        assert statuses["agent-1"] == "applied"
        assert statuses["agent-2"] == "never_applied"


# ── Policy Engine Tests ──────────────────────────────────────────────


class TestGroupPolicyEngine:
    """GroupPolicyEngine unit tests."""

    def test_apply_queues_commands(self, populated_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        engine = GroupPolicyEngine(populated_db)
        result = engine.apply_policy("grp-family")
        assert result["queued"] == 2
        assert result["skipped"] == 0
        # Verify commands actually queued
        cmds = populated_db.list_commands(status="pending")
        assert len(cmds) == 2
        assert all(c["command_type"] == "apply_policy" for c in cmds)

    def test_apply_empty_group(self, shield_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        shield_db.create_policy_group("grp-empty", "Empty")
        engine = GroupPolicyEngine(shield_db)
        result = engine.apply_policy("grp-empty")
        assert result["queued"] == 0

    def test_apply_nonexistent_group(self, shield_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        engine = GroupPolicyEngine(shield_db)
        result = engine.apply_policy("nope")
        assert result["errors"]

    def test_resolve_effective_single_group(self, populated_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        engine = GroupPolicyEngine(populated_db)
        rules = engine.resolve_effective_rules("agent-1")
        assert rules["alert_threshold"] == 5
        assert rules["update_schedule"] == "daily"

    def test_resolve_effective_merge_priority(self, populated_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        # Add a higher-priority group with different threshold
        populated_db.create_policy_group(
            "grp-secure", "Secure", rules={"alert_threshold": 8}, priority=10,
        )
        populated_db.add_group_member("grp-secure", "agent-1")
        engine = GroupPolicyEngine(populated_db)
        rules = engine.resolve_effective_rules("agent-1")
        # grp-secure (priority 10) wins over grp-family (priority 50)
        assert rules["alert_threshold"] == 8

    def test_resolve_firewall_union(self, populated_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        populated_db.update_policy_group(
            "grp-family", rules={"firewall_rules": [{"source": "1.2.3.4", "port": "22"}]},
        )
        populated_db.create_policy_group(
            "grp-extra", "Extra", rules={"firewall_rules": [{"source": "5.6.7.8", "port": "80"}]},
            priority=200,
        )
        populated_db.add_group_member("grp-extra", "agent-1")
        engine = GroupPolicyEngine(populated_db)
        rules = engine.resolve_effective_rules("agent-1")
        assert len(rules["firewall_rules"]) == 2

    def test_compliance_summary(self, populated_db):
        from citadel_archer.remote.group_policy import GroupPolicyEngine
        engine = GroupPolicyEngine(populated_db)
        # Apply first
        engine.apply_policy("grp-family")
        summary = engine.get_compliance_summary("grp-family")
        assert summary["total"] == 2
        assert summary["pending"] == 2  # not yet acknowledged
        assert summary["applied"] == 0


# ── Structural / Wiring Tests ────────────────────────────────────────


class TestStructuralWiring:
    """Source-level wiring checks."""

    def test_apply_policy_in_allowed_types(self):
        from citadel_archer.api.remote_shield_routes import ALLOWED_COMMAND_TYPES
        assert "apply_policy" in ALLOWED_COMMAND_TYPES

    def test_main_includes_group_policy_router(self):
        source = MAIN_PY.read_text(encoding="utf-8")
        assert "group_policy_router" in source
        assert "include_router(group_policy_router)" in source

    def test_group_policy_routes_module_exists(self):
        assert GROUP_POLICY_ROUTES.exists()
        source = GROUP_POLICY_ROUTES.read_text(encoding="utf-8")
        assert "class PolicyGroupCreate" in source
        assert "def create_policy_group" in source
        assert "def apply_policy" in source

    def test_group_policy_engine_module_exists(self):
        assert GROUP_POLICY_PY.exists()
        source = GROUP_POLICY_PY.read_text(encoding="utf-8")
        assert "class GroupPolicyEngine" in source
        assert "def apply_policy" in source
        assert "def resolve_effective_rules" in source

    def test_windows_shield_handles_apply_policy(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert '"apply_policy"' in source
        assert "policy_applied" in source
        assert "save_config" in source


# ── Frontend Structure Tests ─────────────────────────────────────────


class TestFrontendStructure:
    """HTML and JS structural checks."""

    def test_html_has_policy_section(self):
        source = RS_HTML.read_text(encoding="utf-8")
        assert "policy-groups-container" in source
        assert "add-policy-btn" in source
        assert "Group Policies" in source

    def test_html_has_policy_css(self):
        source = RS_HTML.read_text(encoding="utf-8")
        assert ".policy-section" in source
        assert ".policy-card" in source
        assert ".compliance-badge" in source

    def test_js_exports_policy_functions(self):
        source = RS_JS.read_text(encoding="utf-8")
        assert "fetchPolicyGroups" in source
        assert "renderPolicyGroups" in source
        assert "createPolicyGroup" in source
        assert "applyPolicy" in source

    def test_js_wires_init_destroy(self):
        source = RS_JS.read_text(encoding="utf-8")
        assert "fetchPolicyGroups()" in source
        assert "_policyGroups = []" in source
        assert "_rsApplyPolicy" in source

    def test_js_uses_session_token(self):
        source = RS_JS.read_text(encoding="utf-8")
        assert "X-Session-Token" in source
        assert "_authHeaders" in source
        assert "apiClient" in source

    def test_js_escapes_group_id_in_onclick(self):
        source = RS_JS.read_text(encoding="utf-8")
        # group_id should be sanitized before injecting into onclick
        assert "replace(/[^a-zA-Z0-9_-]/g" in source
