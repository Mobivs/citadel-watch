"""Tests for actions_database and defensive_playbook."""

import json
import pytest
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Point the actions database at a temp file for each test."""
    import src.citadel_archer.agent.actions_database as adb
    monkeypatch.setattr(adb, "_DB_PATH", tmp_path / "daemon_actions.db")
    adb.init_db()
    return adb


# ─────────────────────────────────────────────────────────────────────────────
# actions_database tests
# ─────────────────────────────────────────────────────────────────────────────

def test_init_db_creates_table(tmp_db):
    from src.citadel_archer.core.db import connect as db_connect
    import src.citadel_archer.agent.actions_database as adb
    with db_connect(adb._DB_PATH) as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='daemon_actions'"
        ).fetchall()
    assert len(tables) == 1


def test_queue_action_returns_uuid(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="agent1",
        action_id="block_ip",
        parameters={"source_ip": "1.2.3.4"},
        require_approval=False,
        risk_level="low",
        description="block attacker",
    )
    assert len(uuid) == 32  # hex UUID, no dashes


def test_queue_action_status_queued(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="kill_process",
        parameters={"pid": 1234}, require_approval=False,
        risk_level="low", description="test",
    )
    row = tmp_db.get_action(uuid)
    assert row["status"] == "queued"


def test_queue_pending_approval_not_delivered(tmp_db):
    tmp_db.queue_action(
        agent_id="a1", action_id="rotate_ssh_keys",
        parameters={}, require_approval=True,
        risk_level="medium", description="rotate keys",
    )
    result = tmp_db.get_queued_for_agent("a1")
    assert result == []  # pending_approval items must NOT be delivered


def test_get_queued_returns_and_marks_sent(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="collect_forensics",
        parameters={}, require_approval=False,
        risk_level="low", description="forensics",
    )
    rows = tmp_db.get_queued_for_agent("a1")
    assert len(rows) == 1
    assert rows[0]["action_uuid"] == uuid

    # status should now be 'sent'
    row = tmp_db.get_action(uuid)
    assert row["status"] == "sent"


def test_get_queued_marks_sent_atomically(tmp_db):
    """Second call returns empty — items already marked sent."""
    tmp_db.queue_action(
        agent_id="a1", action_id="block_ip",
        parameters={"source_ip": "5.6.7.8"}, require_approval=False,
        risk_level="low", description="block",
    )
    first = tmp_db.get_queued_for_agent("a1")
    second = tmp_db.get_queued_for_agent("a1")
    assert len(first) == 1
    assert second == []


def test_approve_moves_to_queued(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="restart_service",
        parameters={"service_name": "nginx"}, require_approval=True,
        risk_level="medium", description="restart nginx",
    )
    result = tmp_db.approve_action(uuid)
    assert result is True
    row = tmp_db.get_action(uuid)
    assert row["status"] == "queued"
    assert row["approved_at"] is not None

    # Should now be deliverable
    queued = tmp_db.get_queued_for_agent("a1")
    assert len(queued) == 1


def test_approve_returns_false_for_nonexistent(tmp_db):
    result = tmp_db.approve_action("deadbeef" * 4)
    assert result is False


def test_deny_marks_denied(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="apply_patches",
        parameters={}, require_approval=True,
        risk_level="medium", description="patches",
    )
    result = tmp_db.deny_action(uuid)
    assert result is True
    row = tmp_db.get_action(uuid)
    assert row["status"] == "denied"


def test_deny_returns_false_for_nonexistent(tmp_db):
    result = tmp_db.deny_action("00000000" * 4)
    assert result is False


def test_record_result_success(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="kill_process",
        parameters={"pid": 9999}, require_approval=False,
        risk_level="low", description="kill",
    )
    # Must be 'sent' before record_result can update it
    tmp_db.get_queued_for_agent("a1")  # marks as sent
    ok = tmp_db.record_result(uuid, "success", {"output": "killed"})
    assert ok is True
    row = tmp_db.get_action(uuid)
    assert row["status"] == "success"
    assert row["result"]["output"] == "killed"
    assert row["executed_at"] is not None


def test_record_result_failed(tmp_db):
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="block_ip",
        parameters={"source_ip": "9.9.9.9"}, require_approval=False,
        risk_level="low", description="block",
    )
    tmp_db.get_queued_for_agent("a1")  # marks as sent
    tmp_db.record_result(uuid, "failed", {"error": "iptables not found"})
    row = tmp_db.get_action(uuid)
    assert row["status"] == "failed"


def test_record_result_requires_sent_status(tmp_db):
    """record_result on a non-sent action must return False (no state change)."""
    uuid = tmp_db.queue_action(
        agent_id="a1", action_id="block_ip",
        parameters={"source_ip": "9.9.9.9"}, require_approval=False,
        risk_level="low", description="block",
    )
    # Still 'queued' — should not be updatable
    ok = tmp_db.record_result(uuid, "success", {"output": "blocked"})
    assert ok is False
    row = tmp_db.get_action(uuid)
    assert row["status"] == "queued"  # unchanged


def test_list_actions_filter_by_agent(tmp_db):
    tmp_db.queue_action("agentA", "block_ip", {"source_ip": "1.1.1.1"},
                        False, "low", "block")
    tmp_db.queue_action("agentB", "kill_process", {"pid": 1},
                        False, "low", "kill")
    rows = tmp_db.list_actions(agent_id="agentA")
    assert all(r["agent_id"] == "agentA" for r in rows)
    assert len(rows) == 1


def test_list_actions_filter_by_status(tmp_db):
    tmp_db.queue_action("a1", "collect_forensics", {}, False, "low", "c1")
    tmp_db.queue_action("a1", "block_ip", {"source_ip": "2.2.2.2"},
                        False, "low", "c2")
    rows = tmp_db.list_actions(status="queued")
    assert len(rows) == 2
    tmp_db.get_queued_for_agent("a1")  # marks sent
    rows = tmp_db.list_actions(status="queued")
    assert len(rows) == 0


def test_list_actions_limit(tmp_db):
    for i in range(5):
        tmp_db.queue_action("a1", "block_ip", {"source_ip": f"10.0.0.{i}"},
                            False, "low", f"block {i}")
    rows = tmp_db.list_actions(limit=3)
    assert len(rows) == 3


# ─────────────────────────────────────────────────────────────────────────────
# defensive_playbook tests
# ─────────────────────────────────────────────────────────────────────────────

from src.citadel_archer.agent.defensive_playbook import is_allowed, requires_approval


def test_playbook_known_actions_allowed():
    for action in ("kill_process", "block_ip", "disable_cron_job",
                   "collect_forensics", "rotate_ssh_keys",
                   "restart_service", "apply_patches"):
        assert is_allowed(action), f"{action} should be in playbook"


def test_playbook_unknown_action_not_allowed():
    assert not is_allowed("rm_rf_slash")
    assert not is_allowed("exfiltrate_data")
    assert not is_allowed("")


def test_low_risk_default_no_approval():
    assert requires_approval("kill_process") is False
    assert requires_approval("block_ip") is False
    assert requires_approval("collect_forensics") is False


def test_medium_risk_default_requires_approval():
    assert requires_approval("rotate_ssh_keys") is True
    assert requires_approval("restart_service") is True
    assert requires_approval("apply_patches") is True


def test_low_risk_override_accepted():
    # Override to require approval on a low-risk action — allowed
    assert requires_approval("kill_process", override=True) is True
    # Override to skip approval on low-risk — allowed
    assert requires_approval("kill_process", override=False) is False


def test_medium_risk_override_cannot_remove_approval():
    # Trying to set override=False on medium-risk must be ignored
    assert requires_approval("rotate_ssh_keys", override=False) is True
    assert requires_approval("restart_service", override=False) is True
