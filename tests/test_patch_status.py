"""Tests for patch status and command queue (shield_database + route structure).

Covers:
  - agent_commands table creation and CRUD
  - Command lifecycle: pending → delivered → acknowledged
  - Patch status JSON storage/retrieval
  - _row_to_agent includes parsed patch_status
  - Command allowlist enforcement
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from citadel_archer.remote.shield_database import RemoteShieldDatabase


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def db(tmp_path):
    return RemoteShieldDatabase(db_path=tmp_path / "shield.db")


@pytest.fixture
def db_with_agent(db):
    """DB with one Windows agent pre-registered."""
    db.create_agent(
        agent_id="agent-win-1",
        hostname="family-pc",
        ip_address="192.168.1.10",
        api_token="test-token-abc",
        platform="windows",
    )
    return db


# ── agent_commands table ──────────────────────────────────────────────


class TestAgentCommandsTable:
    """Verify the agent_commands table exists with correct schema."""

    def test_agent_commands_table_exists(self, db):
        with db._connect() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='agent_commands'"
            ).fetchone()
        assert row is not None
        assert row["name"] == "agent_commands"

    def test_patch_status_json_column_exists(self, db_with_agent):
        ps = db_with_agent.get_patch_status("agent-win-1")
        assert ps == {}  # default empty JSON


# ── Command Queue CRUD ────────────────────────────────────────────────


class TestCommandQueue:
    """Command queue lifecycle tests."""

    def test_queue_command_creates_pending_record(self, db_with_agent):
        cmd = db_with_agent.queue_command(
            command_id="cmd-001",
            agent_id="agent-win-1",
            command_type="check_updates",
        )
        assert cmd["command_id"] == "cmd-001"
        assert cmd["agent_id"] == "agent-win-1"
        assert cmd["command_type"] == "check_updates"
        assert cmd["status"] == "pending"
        assert cmd["payload"] == {}

    def test_get_pending_commands_returns_oldest_first(self, db_with_agent):
        db_with_agent.queue_command("cmd-a", "agent-win-1", "check_updates")
        db_with_agent.queue_command("cmd-b", "agent-win-1", "check_updates")
        db_with_agent.queue_command("cmd-c", "agent-win-1", "check_updates")

        cmds = db_with_agent.get_pending_commands("agent-win-1", limit=5)
        assert len(cmds) == 3
        assert cmds[0]["command_id"] == "cmd-a"
        assert cmds[1]["command_id"] == "cmd-b"
        assert cmds[2]["command_id"] == "cmd-c"

    def test_get_pending_commands_marks_delivered(self, db_with_agent):
        db_with_agent.queue_command("cmd-d", "agent-win-1", "check_updates")

        cmds = db_with_agent.get_pending_commands("agent-win-1")
        assert len(cmds) == 1
        assert cmds[0]["status"] == "delivered"  # reflects actual DB state
        assert cmds[0]["delivered_at"] is not None

        # Second call should return nothing (already delivered)
        cmds2 = db_with_agent.get_pending_commands("agent-win-1")
        assert len(cmds2) == 0

    def test_get_pending_commands_respects_limit(self, db_with_agent):
        for i in range(10):
            db_with_agent.queue_command(f"cmd-{i}", "agent-win-1", "check_updates")

        cmds = db_with_agent.get_pending_commands("agent-win-1", limit=3)
        assert len(cmds) == 3

    def test_acknowledge_command_updates_status(self, db_with_agent):
        db_with_agent.queue_command("cmd-ack-1", "agent-win-1", "check_updates")

        # Deliver first
        db_with_agent.get_pending_commands("agent-win-1")

        # Now acknowledge
        ok = db_with_agent.acknowledge_command("cmd-ack-1", result="success")
        assert ok is True

        # Verify via list_commands
        cmds = db_with_agent.list_commands(agent_id="agent-win-1")
        assert cmds[0]["status"] == "acknowledged"
        assert cmds[0]["result"] == "success"
        assert cmds[0]["acknowledged_at"] is not None

    def test_acknowledge_nonexistent_command_returns_false(self, db_with_agent):
        ok = db_with_agent.acknowledge_command("no-such-cmd", result="oops")
        assert ok is False

    def test_list_commands_filters_by_status(self, db_with_agent):
        db_with_agent.queue_command("cmd-f1", "agent-win-1", "check_updates")
        db_with_agent.queue_command("cmd-f2", "agent-win-1", "check_updates")

        # Deliver first one
        db_with_agent.get_pending_commands("agent-win-1", limit=1)

        pending = db_with_agent.list_commands(agent_id="agent-win-1", status="pending")
        delivered = db_with_agent.list_commands(agent_id="agent-win-1", status="delivered")
        assert len(pending) == 1
        assert len(delivered) == 1

    def test_queue_command_with_payload(self, db_with_agent):
        cmd = db_with_agent.queue_command(
            "cmd-p", "agent-win-1", "check_updates",
            payload={"force": True, "timeout": 120},
        )
        assert cmd["payload"] == {"force": True, "timeout": 120}

        # Verify payload persists via list
        cmds = db_with_agent.list_commands(agent_id="agent-win-1")
        assert cmds[0]["payload"] == {"force": True, "timeout": 120}


# ── Patch Status ──────────────────────────────────────────────────────


class TestPatchStatus:
    """Patch status JSON storage."""

    def test_update_patch_status_stores_json(self, db_with_agent):
        data = {
            "pending_count": 3,
            "installed_count": 42,
            "last_check_date": "2026-02-15T10:00:00",
            "reboot_required": False,
            "oldest_pending_days": 2,
            "check_status": "ok",
            "pending_titles": ["KB5001234", "KB5005678", "KB5009012"],
        }
        ok = db_with_agent.update_patch_status("agent-win-1", data)
        assert ok is True

    def test_get_patch_status_returns_parsed_dict(self, db_with_agent):
        data = {"pending_count": 5, "check_status": "ok"}
        db_with_agent.update_patch_status("agent-win-1", data)

        ps = db_with_agent.get_patch_status("agent-win-1")
        assert ps == {"pending_count": 5, "check_status": "ok"}

    def test_get_patch_status_unknown_agent_returns_none(self, db_with_agent):
        ps = db_with_agent.get_patch_status("no-such-agent")
        assert ps is None

    def test_row_to_agent_includes_patch_status(self, db_with_agent):
        data = {"pending_count": 1, "reboot_required": True}
        db_with_agent.update_patch_status("agent-win-1", data)

        agent = db_with_agent.get_agent("agent-win-1")
        assert agent is not None
        assert agent["patch_status"] == {"pending_count": 1, "reboot_required": True}

    def test_patch_status_default_empty(self, db_with_agent):
        agent = db_with_agent.get_agent("agent-win-1")
        assert agent["patch_status"] == {}

    def test_update_patch_status_nonexistent_agent(self, db):
        ok = db.update_patch_status("ghost-agent", {"pending_count": 0})
        assert ok is False
