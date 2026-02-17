"""
Tests for AgentRegistry — External AI agent SQLite persistence.

Covers:
- Database creation and schema
- Agent registration (CRUD)
- Token security (SHA-256 hashing, verify valid/invalid/revoked)
- Token rotation
- Persistence across reinstantiation
- record_message stats
"""

import os
import tempfile
from pathlib import Path

import pytest

from citadel_archer.chat.agent_registry import (
    AgentRegistry,
    VALID_AGENT_TYPES,
    DEFAULT_RATE_LIMITS,
    _hash_token,
)


@pytest.fixture
def db_path(tmp_path):
    """Temporary database path."""
    return str(tmp_path / "test_registry.db")


@pytest.fixture
def registry(db_path):
    """Fresh AgentRegistry instance."""
    return AgentRegistry(db_path=db_path)


# ── Database Initialization ───────────────────────────────────────────


class TestDatabaseInit:
    def test_creates_database_file(self, db_path):
        AgentRegistry(db_path=db_path)
        assert Path(db_path).exists()

    def test_creates_parent_directories(self, tmp_path):
        deep = str(tmp_path / "a" / "b" / "registry.db")
        AgentRegistry(db_path=deep)
        assert Path(deep).exists()

    def test_idempotent_init(self, db_path):
        """Creating multiple instances on same DB doesn't crash."""
        AgentRegistry(db_path=db_path)
        AgentRegistry(db_path=db_path)


# ── Agent Registration ────────────────────────────────────────────────


class TestRegistration:
    def test_register_returns_agent_id_and_token(self, registry):
        agent_id, token = registry.register_agent("Forge-1", "forge")
        assert isinstance(agent_id, str)
        assert len(agent_id) == 32
        assert isinstance(token, str)
        assert len(token) > 20  # token_urlsafe(32) is ~43 chars

    def test_register_all_valid_types(self, registry):
        for agent_type in VALID_AGENT_TYPES:
            agent_id, token = registry.register_agent(f"Test-{agent_type}", agent_type)
            assert agent_id

    def test_register_invalid_type_raises(self, registry):
        with pytest.raises(ValueError, match="Invalid agent_type"):
            registry.register_agent("Bad", "unknown_type")

    def test_register_custom_rate_limit(self, registry):
        agent_id, _ = registry.register_agent("Custom", "custom", rate_limit_per_min=100)
        agent = registry.get_agent(agent_id)
        assert agent["rate_limit_per_min"] == 100

    def test_register_default_rate_limits(self, registry):
        for agent_type, expected_limit in DEFAULT_RATE_LIMITS.items():
            agent_id, _ = registry.register_agent(f"Agent-{agent_type}", agent_type)
            agent = registry.get_agent(agent_id)
            assert agent["rate_limit_per_min"] == expected_limit

    def test_register_unique_ids(self, registry):
        id1, _ = registry.register_agent("A", "forge")
        id2, _ = registry.register_agent("B", "forge")
        assert id1 != id2

    def test_register_unique_tokens(self, registry):
        _, t1 = registry.register_agent("A", "forge")
        _, t2 = registry.register_agent("B", "forge")
        assert t1 != t2


# ── Token Security ────────────────────────────────────────────────────


class TestTokenSecurity:
    def test_raw_token_not_stored(self, registry):
        """Raw token must not appear in the database."""
        _, raw_token = registry.register_agent("Forge", "forge")
        import sqlite3

        conn = sqlite3.connect(registry.db_path)
        rows = conn.execute("SELECT api_token_hash FROM external_agents").fetchall()
        conn.close()
        for row in rows:
            assert row[0] != raw_token

    def test_token_stored_as_sha256(self, registry):
        _, raw_token = registry.register_agent("Forge", "forge")
        expected_hash = _hash_token(raw_token)
        import sqlite3

        conn = sqlite3.connect(registry.db_path)
        row = conn.execute("SELECT api_token_hash FROM external_agents").fetchone()
        conn.close()
        assert row[0] == expected_hash

    def test_verify_valid_token(self, registry):
        agent_id, token = registry.register_agent("Forge", "forge")
        result = registry.verify_token(token)
        assert result is not None
        assert result["agent_id"] == agent_id
        assert result["name"] == "Forge"
        assert result["agent_type"] == "forge"

    def test_verify_invalid_token(self, registry):
        registry.register_agent("Forge", "forge")
        result = registry.verify_token("totally-bogus-token")
        assert result is None

    def test_verify_revoked_token(self, registry):
        agent_id, token = registry.register_agent("Forge", "forge")
        registry.revoke_agent(agent_id)
        result = registry.verify_token(token)
        assert result is None


# ── CRUD Operations ───────────────────────────────────────────────────


class TestCRUD:
    def test_get_agent(self, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        agent = registry.get_agent(agent_id)
        assert agent["agent_id"] == agent_id
        assert agent["name"] == "Forge"
        assert agent["agent_type"] == "forge"
        assert agent["status"] == "active"
        assert agent["message_count"] == 0

    def test_get_nonexistent_agent(self, registry):
        assert registry.get_agent("nonexistent") is None

    def test_list_agents_empty(self, registry):
        assert registry.list_agents() == []

    def test_list_agents(self, registry):
        registry.register_agent("A", "forge")
        registry.register_agent("B", "openclaw")
        agents = registry.list_agents()
        assert len(agents) == 2
        names = {a["name"] for a in agents}
        assert names == {"A", "B"}

    def test_revoke_agent(self, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        assert registry.revoke_agent(agent_id) is True
        agent = registry.get_agent(agent_id)
        assert agent["status"] == "revoked"

    def test_revoke_nonexistent(self, registry):
        assert registry.revoke_agent("nonexistent") is False


# ── Token Rotation ────────────────────────────────────────────────────


class TestTokenRotation:
    def test_rotate_returns_new_token(self, registry):
        agent_id, old_token = registry.register_agent("Forge", "forge")
        new_token = registry.rotate_token(agent_id)
        assert new_token is not None
        assert new_token != old_token

    def test_old_token_invalid_after_rotation(self, registry):
        agent_id, old_token = registry.register_agent("Forge", "forge")
        registry.rotate_token(agent_id)
        assert registry.verify_token(old_token) is None

    def test_new_token_valid_after_rotation(self, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        new_token = registry.rotate_token(agent_id)
        result = registry.verify_token(new_token)
        assert result is not None
        assert result["agent_id"] == agent_id

    def test_rotate_nonexistent(self, registry):
        assert registry.rotate_token("nonexistent") is None


# ── Persistence ───────────────────────────────────────────────────────


class TestPersistence:
    def test_survives_reinstantiation(self, db_path):
        reg1 = AgentRegistry(db_path=db_path)
        agent_id, token = reg1.register_agent("Forge", "forge")

        # Create new instance on same DB
        reg2 = AgentRegistry(db_path=db_path)
        agent = reg2.get_agent(agent_id)
        assert agent is not None
        assert agent["name"] == "Forge"

    def test_token_verifies_after_reinstantiation(self, db_path):
        reg1 = AgentRegistry(db_path=db_path)
        agent_id, token = reg1.register_agent("Forge", "forge")

        reg2 = AgentRegistry(db_path=db_path)
        result = reg2.verify_token(token)
        assert result is not None
        assert result["agent_id"] == agent_id


# ── Message Stats ─────────────────────────────────────────────────────


class TestMessageStats:
    def test_record_message_increments_count(self, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        registry.record_message(agent_id)
        registry.record_message(agent_id)
        agent = registry.get_agent(agent_id)
        assert agent["message_count"] == 2

    def test_record_message_updates_last_message_at(self, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        agent = registry.get_agent(agent_id)
        assert agent["last_message_at"] is None

        registry.record_message(agent_id)
        agent = registry.get_agent(agent_id)
        assert agent["last_message_at"] is not None
