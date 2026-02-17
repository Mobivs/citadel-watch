"""Tests for Remote Panic Capabilities: Isolate Any System from Dashboard (v0.3.31).

Covers:
  - RemotePanicDispatcher: dispatch, dispatch_rollback, resolve_agent_id, get_remote_status
  - PlaybookEngine: agent-backed asset dispatch vs local execution
  - Agent handler: panic_isolate, panic_terminate, panic_rollback in windows_shield
  - API: remote-status endpoint, ALLOWED_COMMAND_TYPES
  - Frontend: remote status polling in panic-room.js
  - Structural wiring: modules exist with expected classes/functions
"""

import json
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
PANIC_DISPATCHER_PY = ROOT / "src" / "citadel_archer" / "remote" / "panic_dispatcher.py"
PLAYBOOK_ENGINE_PY = ROOT / "src" / "citadel_archer" / "panic" / "playbook_engine.py"
PANIC_ROUTES_PY = ROOT / "src" / "citadel_archer" / "api" / "panic_routes.py"
REMOTE_SHIELD_ROUTES = ROOT / "src" / "citadel_archer" / "api" / "remote_shield_routes.py"
WINDOWS_SHIELD = ROOT / "src" / "citadel_archer" / "agent" / "windows_shield.py"
PANIC_MANAGER_PY = ROOT / "src" / "citadel_archer" / "panic" / "panic_manager.py"
PANIC_ROOM_JS = ROOT / "frontend" / "js" / "panic-room.js"
MAIN_PY = ROOT / "src" / "citadel_archer" / "api" / "main.py"


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def shield_db():
    """Fresh in-memory RemoteShieldDatabase."""
    from citadel_archer.remote.shield_database import RemoteShieldDatabase
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = RemoteShieldDatabase(db_path=f.name)
    return db


@pytest.fixture
def populated_db(shield_db):
    """DB with 2 agents linked to assets."""
    shield_db.create_agent("agent-1", "pc-1", "10.0.0.1", "token-1")
    shield_db.create_agent("agent-2", "pc-2", "10.0.0.2", "token-2")
    # Simulate asset linking by setting asset_id on agents
    with shield_db._connect() as conn:
        conn.execute("UPDATE remote_shield_agents SET asset_id = ? WHERE agent_id = ?", ("asset_pc1", "agent-1"))
        conn.execute("UPDATE remote_shield_agents SET asset_id = ? WHERE agent_id = ?", ("asset_pc2", "agent-2"))
        conn.commit()
    return shield_db


@pytest.fixture
def dispatcher(populated_db):
    """RemotePanicDispatcher with populated DB."""
    from citadel_archer.remote.panic_dispatcher import RemotePanicDispatcher
    return RemotePanicDispatcher(populated_db)


# ── RemotePanicDispatcher Tests ──────────────────────────────────────


class TestDispatchCommands:
    """Test command queueing via dispatcher."""

    def test_dispatch_queues_panic_isolate(self, dispatcher, populated_db):
        result = dispatcher.dispatch("agent-1", "network", {"target_asset": "asset_pc1"}, "session-1")
        assert result["agent_id"] == "agent-1"
        assert result["command_type"] == "panic_isolate"
        assert result["status"] == "queued"
        assert "command_id" in result
        # Verify command is in DB
        cmds = populated_db.list_commands(agent_id="agent-1")
        assert any(c["command_type"] == "panic_isolate" for c in cmds)

    def test_dispatch_maps_processes_to_terminate(self, dispatcher):
        result = dispatcher.dispatch("agent-1", "processes", {}, "session-1")
        assert result["command_type"] == "panic_terminate"

    def test_dispatch_includes_session_id_in_payload(self, dispatcher, populated_db):
        dispatcher.dispatch("agent-1", "network", {}, "session-abc")
        cmds = populated_db.list_commands(agent_id="agent-1")
        assert cmds[0]["payload"]["session_id"] == "session-abc"

    def test_dispatch_rollback_queues_command(self, dispatcher, populated_db):
        result = dispatcher.dispatch_rollback("agent-1", "session-1")
        assert result["command_type"] == "panic_rollback"
        assert result["status"] == "queued"
        cmds = populated_db.list_commands(agent_id="agent-1")
        assert any(c["command_type"] == "panic_rollback" for c in cmds)

    def test_multiple_dispatches_create_separate_commands(self, dispatcher, populated_db):
        r1 = dispatcher.dispatch("agent-1", "network", {}, "session-1")
        r2 = dispatcher.dispatch("agent-1", "processes", {}, "session-1")
        assert r1["command_id"] != r2["command_id"]
        cmds = populated_db.list_commands(agent_id="agent-1")
        assert len(cmds) >= 2

    def test_dispatch_strips_target_asset_from_payload(self, dispatcher, populated_db):
        dispatcher.dispatch("agent-1", "network", {"target_asset": "asset_pc1", "extra": "data"}, "s1")
        cmds = populated_db.list_commands(agent_id="agent-1")
        payload = cmds[0]["payload"]
        assert "target_asset" not in payload
        assert payload["extra"] == "data"


class TestResolveAgentId:
    """Test asset_id → agent_id resolution."""

    def test_resolve_returns_agent_for_linked_asset(self, dispatcher):
        assert dispatcher.resolve_agent_id("asset_pc1") == "agent-1"
        assert dispatcher.resolve_agent_id("asset_pc2") == "agent-2"

    def test_resolve_returns_none_for_unknown_asset(self, dispatcher):
        assert dispatcher.resolve_agent_id("asset_unknown") is None

    def test_resolve_caches_results(self, dispatcher):
        dispatcher.resolve_agent_id("asset_pc1")
        # Second call should use cache (no DB query)
        assert dispatcher.resolve_agent_id("asset_pc1") == "agent-1"
        assert "asset_pc1" in dispatcher._agent_cache

    def test_clear_cache(self, dispatcher):
        dispatcher.resolve_agent_id("asset_pc1")
        dispatcher.clear_cache()
        assert len(dispatcher._agent_cache) == 0


class TestGetRemoteStatus:
    """Test session command status retrieval."""

    def test_returns_status_for_session(self, dispatcher, populated_db):
        dispatcher.dispatch("agent-1", "network", {}, "session-x")
        dispatcher.dispatch("agent-2", "network", {}, "session-x")
        statuses = dispatcher.get_remote_status("session-x")
        assert len(statuses) == 2
        assert all(s["status"] == "pending" for s in statuses)

    def test_returns_empty_for_unknown_session(self, dispatcher):
        assert dispatcher.get_remote_status("nonexistent") == []

    def test_filters_by_session_id(self, dispatcher):
        dispatcher.dispatch("agent-1", "network", {}, "session-a")
        dispatcher.dispatch("agent-2", "network", {}, "session-b")
        statuses_a = dispatcher.get_remote_status("session-a")
        assert len(statuses_a) == 1
        assert statuses_a[0]["agent_id"] == "agent-1"


# ── PlaybookEngine Integration Tests ─────────────────────────────────


class TestPlaybookEngineDispatch:
    """Test that PlaybookEngine dispatches to agents for agent-backed assets."""

    def test_engine_has_set_panic_dispatcher(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(MagicMock(), {})
        assert hasattr(engine, '_panic_dispatcher')
        assert hasattr(engine, 'set_panic_dispatcher')

    def test_set_panic_dispatcher_stores_reference(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(MagicMock(), {})
        mock_dispatcher = MagicMock()
        engine.set_panic_dispatcher(mock_dispatcher)
        assert engine._panic_dispatcher is mock_dispatcher

    @pytest.mark.asyncio
    async def test_agent_backed_asset_uses_dispatcher(self, populated_db):
        from citadel_archer.panic.playbook_engine import PlaybookEngine, Playbook, Action
        from citadel_archer.remote.panic_dispatcher import RemotePanicDispatcher

        engine = PlaybookEngine(MagicMock(), {})
        dispatcher = RemotePanicDispatcher(populated_db)
        engine.set_panic_dispatcher(dispatcher)

        playbook = Playbook(
            id="test", name="Test", description="", category="test",
            priority=1, requires_confirmation=False,
            actions=[Action(name="isolate", type="network", timeout=5)],
        )
        session = MagicMock()
        session.id = "test-session-123"

        results = await engine.execute_playbook(playbook, session, target_assets=["asset_pc1"])
        assert len(results) == 1
        assert results[0]["status"] == "queued"
        assert results[0]["agent_id"] == "agent-1"
        assert results[0]["asset"] == "asset_pc1"

    @pytest.mark.asyncio
    async def test_local_asset_skips_dispatcher(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine, Playbook, Action

        engine = PlaybookEngine(MagicMock(), {})
        mock_dispatcher = MagicMock()
        engine.set_panic_dispatcher(mock_dispatcher)

        playbook = Playbook(
            id="test", name="Test", description="", category="test",
            priority=1, requires_confirmation=False,
            actions=[Action(name="isolate", type="network", timeout=5)],
        )
        session = MagicMock()
        session.id = "test-session-123"

        # local asset should NOT call dispatcher
        results = await engine.execute_playbook(playbook, session, target_assets=["local"])
        # dispatcher.resolve_agent_id should NOT have been called for "local"
        mock_dispatcher.resolve_agent_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_dispatcher_falls_through(self):
        from citadel_archer.panic.playbook_engine import PlaybookEngine, Playbook, Action

        engine = PlaybookEngine(MagicMock(), {})
        # No dispatcher set — should not crash

        playbook = Playbook(
            id="test", name="Test", description="", category="test",
            priority=1, requires_confirmation=False,
            actions=[Action(name="isolate", type="network", timeout=5)],
        )
        session = MagicMock()
        session.id = "test-session-123"

        # Should fall through to handler (which may not exist for "network" in mock DB)
        results = await engine.execute_playbook(playbook, session, target_assets=["some_asset"])
        # Should get a result (even if error — just not a crash)
        assert len(results) >= 1


# ── Agent Handler Tests ──────────────────────────────────────────────


class TestWindowsShieldPanicHandlers:
    """Test panic command handlers in windows_shield source."""

    def test_panic_isolate_handler_exists(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert '"panic_isolate"' in source
        assert "netsh" in source
        assert "isolated:firewall_locked" in source

    def test_panic_terminate_handler_exists(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert '"panic_terminate"' in source
        assert "taskkill" in source
        assert "terminated:count=" in source

    def test_panic_rollback_handler_exists(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert '"panic_rollback"' in source
        assert "rollback_complete" in source
        assert "CitadelHeartbeat" in source

    def test_panic_isolate_saves_pre_state(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert "pre_panic_firewall_state" in source
        assert 'config["panic_active"] = True' in source

    def test_panic_rollback_restores_state(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert 'config["panic_active"] = False' in source
        assert "allowoutbound" in source


# ── API Route Tests ──────────────────────────────────────────────────


class TestAllowedCommandTypes:
    """Test that panic command types are in the allowlist."""

    def test_panic_types_in_allowlist(self):
        from citadel_archer.api.remote_shield_routes import ALLOWED_COMMAND_TYPES
        assert "panic_isolate" in ALLOWED_COMMAND_TYPES
        assert "panic_terminate" in ALLOWED_COMMAND_TYPES
        assert "panic_rollback" in ALLOWED_COMMAND_TYPES


class TestRemoteStatusEndpoint:
    """Test the /sessions/{id}/remote-status endpoint structure."""

    def test_endpoint_exists_in_routes(self):
        source = PANIC_ROUTES_PY.read_text(encoding="utf-8")
        assert "remote-status" in source
        assert "get_remote_panic_status" in source
        assert "RemotePanicDispatcher" in source


# ── Structural / Wiring Tests ────────────────────────────────────────


class TestStructuralWiring:
    """Source-level wiring checks."""

    def test_panic_dispatcher_module_exists(self):
        assert PANIC_DISPATCHER_PY.exists()
        source = PANIC_DISPATCHER_PY.read_text(encoding="utf-8")
        assert "class RemotePanicDispatcher" in source
        assert "def dispatch(" in source
        assert "def dispatch_rollback(" in source
        assert "def get_remote_status(" in source
        assert "def resolve_agent_id(" in source

    def test_playbook_engine_has_dispatcher_support(self):
        source = PLAYBOOK_ENGINE_PY.read_text(encoding="utf-8")
        assert "_panic_dispatcher" in source
        assert "set_panic_dispatcher" in source
        assert "resolve_agent_id" in source

    def test_panic_manager_has_set_panic_dispatcher(self):
        source = PANIC_MANAGER_PY.read_text(encoding="utf-8")
        assert "set_panic_dispatcher" in source
        assert "_panic_dispatcher" in source

    def test_main_wires_panic_dispatcher(self):
        source = MAIN_PY.read_text(encoding="utf-8")
        assert "RemotePanicDispatcher" in source
        assert "set_panic_dispatcher" in source


# ── Frontend Tests ───────────────────────────────────────────────────


class TestFrontendRemoteStatus:
    """JS structural checks for remote status polling."""

    def test_js_has_remote_status_polling(self):
        source = PANIC_ROOM_JS.read_text(encoding="utf-8")
        assert "startRemoteStatusPolling" in source
        assert "remote-status" in source

    def test_js_polls_on_interval(self):
        source = PANIC_ROOM_JS.read_text(encoding="utf-8")
        assert "_remoteStatusInterval" in source
        assert "setInterval" in source

    def test_js_cleans_up_polling_on_destroy(self):
        source = PANIC_ROOM_JS.read_text(encoding="utf-8")
        assert "clearInterval(_remoteStatusInterval)" in source

    def test_js_starts_polling_after_activation(self):
        source = PANIC_ROOM_JS.read_text(encoding="utf-8")
        assert "startRemoteStatusPolling(response.session_id" in source
