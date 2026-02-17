"""
Tests for Per-Asset Rollback — Phase 3 completion.

Covers:
  - Schema: recovery_states.asset_id column + UNIQUE constraint
  - State isolation: multi-asset states don't overwrite each other
  - Rollback filtering: by component, by asset, both, neither
  - PanicDatabase methods: save_recovery_state, get_recovery_states, mark_state_rolled_back
  - Schema migration: old databases get asset_id added
  - API model: RollbackRequest accepts target_assets
  - PanicManager: _save_recovery_state includes asset_id
  - PanicManager: rollback_panic with target_assets
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from citadel_archer.panic.panic_database import PanicDatabase, PanicSession


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def panic_db(tmp_path):
    """Create a PanicDatabase with a fresh temp database."""
    db = PanicDatabase(db_path=tmp_path / "panic_test.db")
    return db


@pytest.fixture
def session_id(panic_db):
    """Create a panic session and return its session_id."""
    sid = f"test_{uuid4().hex[:8]}"
    session = PanicSession(
        session_id=sid,
        status="active",
        playbooks=["rotate_credentials"],
        started_at=datetime.utcnow(),
        trigger_source="manual",
        user_id="test_user",
        confirmation_token="abc123",
        reason="test panic",
        metadata={"target_assets": ["local", "vps_1", "vps_2"]},
    )
    panic_db.create_session(session)
    return sid


# ===================================================================
# TestRecoveryStatesSchema — asset_id column + UNIQUE constraint
# ===================================================================


class TestRecoveryStatesSchema:
    """Verify recovery_states table has asset_id in schema."""

    def test_asset_id_column_exists(self, panic_db):
        """The recovery_states table should have an asset_id column."""
        from citadel_archer.core.db import connect as db_connect

        conn = db_connect(panic_db.db_path, row_factory=True)
        info = conn.execute("PRAGMA table_info(recovery_states)").fetchall()
        columns = [row["name"] for row in info]
        assert "asset_id" in columns
        conn.close()

    def test_asset_id_default_is_local(self, panic_db):
        """The asset_id column should default to 'local'."""
        from citadel_archer.core.db import connect as db_connect

        conn = db_connect(panic_db.db_path, row_factory=True)
        info = conn.execute("PRAGMA table_info(recovery_states)").fetchall()
        asset_col = [row for row in info if row["name"] == "asset_id"][0]
        assert asset_col["dflt_value"] == "'local'"
        conn.close()

    def test_unique_constraint_includes_asset_id(self, panic_db, session_id):
        """Two states with same session/component/component_id but different asset_ids should coexist."""
        panic_db.save_recovery_state(
            session_id, "credentials", "rotate_ssh",
            asset_id="local", pre_panic_state={"keys": "old_local"}
        )
        panic_db.save_recovery_state(
            session_id, "credentials", "rotate_ssh",
            asset_id="vps_1", pre_panic_state={"keys": "old_vps1"}
        )

        states = panic_db.get_recovery_states(session_id)
        assert len(states) == 2
        asset_ids = {s["asset_id"] for s in states}
        assert asset_ids == {"local", "vps_1"}

    def test_upsert_updates_same_asset(self, panic_db, session_id):
        """ON CONFLICT should update current_state for same component+asset combo."""
        panic_db.save_recovery_state(
            session_id, "credentials", "rotate_ssh",
            asset_id="vps_1", pre_panic_state={"keys": "old"},
        )
        panic_db.save_recovery_state(
            session_id, "credentials", "rotate_ssh",
            asset_id="vps_1", current_state={"keys": "new"},
        )

        states = panic_db.get_recovery_states(session_id)
        assert len(states) == 1
        assert json.loads(states[0]["current_state"]) == {"keys": "new"}


# ===================================================================
# TestStateIsolation — multi-asset states don't clobber each other
# ===================================================================


class TestStateIsolation:
    """Verify per-asset state isolation in multi-asset panic sessions."""

    def test_three_assets_three_states(self, panic_db, session_id):
        """Three different assets produce three independent recovery states."""
        for asset in ["local", "vps_1", "vps_2"]:
            panic_db.save_recovery_state(
                session_id, "network", "isolate",
                asset_id=asset,
                pre_panic_state={"iptables": f"rules_{asset}"},
            )

        states = panic_db.get_recovery_states(session_id)
        assert len(states) == 3

        by_asset = {s["asset_id"]: json.loads(s["pre_panic_state"]) for s in states}
        assert by_asset["local"]["iptables"] == "rules_local"
        assert by_asset["vps_1"]["iptables"] == "rules_vps_1"
        assert by_asset["vps_2"]["iptables"] == "rules_vps_2"

    def test_different_components_same_asset(self, panic_db, session_id):
        """Two different components on the same asset are separate states."""
        panic_db.save_recovery_state(
            session_id, "network", "isolate",
            asset_id="vps_1", pre_panic_state={"type": "network"},
        )
        panic_db.save_recovery_state(
            session_id, "credentials", "rotate_ssh",
            asset_id="vps_1", pre_panic_state={"type": "creds"},
        )

        states = panic_db.get_recovery_states(session_id)
        assert len(states) == 2


# ===================================================================
# TestRollbackFiltering — get_recovery_states with filters
# ===================================================================


class TestRollbackFiltering:
    """Verify filtering recovery states by component and/or asset."""

    @pytest.fixture(autouse=True)
    def _populate_states(self, panic_db, session_id):
        """Populate a realistic multi-asset/multi-component scenario."""
        self.db = panic_db
        self.sid = session_id

        # 2 components × 3 assets = 6 states
        for component, comp_id in [("network", "isolate"), ("credentials", "rotate_ssh")]:
            for asset in ["local", "vps_1", "vps_2"]:
                panic_db.save_recovery_state(
                    session_id, component, comp_id,
                    asset_id=asset,
                    pre_panic_state={"component": component, "asset": asset},
                )

    def test_no_filter_returns_all(self):
        states = self.db.get_recovery_states(self.sid)
        assert len(states) == 6

    def test_filter_by_component(self):
        states = self.db.get_recovery_states(self.sid, components=["network"])
        assert len(states) == 3
        assert all(s["component"] == "network" for s in states)

    def test_filter_by_asset(self):
        states = self.db.get_recovery_states(self.sid, target_assets=["vps_1"])
        assert len(states) == 2
        assert all(s["asset_id"] == "vps_1" for s in states)

    def test_filter_by_component_and_asset(self):
        states = self.db.get_recovery_states(
            self.sid, components=["credentials"], target_assets=["vps_2"]
        )
        assert len(states) == 1
        assert states[0]["component"] == "credentials"
        assert states[0]["asset_id"] == "vps_2"

    def test_filter_multiple_assets(self):
        states = self.db.get_recovery_states(
            self.sid, target_assets=["local", "vps_2"]
        )
        assert len(states) == 4
        asset_ids = {s["asset_id"] for s in states}
        assert asset_ids == {"local", "vps_2"}

    def test_filter_nonexistent_asset_returns_empty(self):
        states = self.db.get_recovery_states(self.sid, target_assets=["nonexistent"])
        assert len(states) == 0


# ===================================================================
# TestMarkRolledBack — individual state marking
# ===================================================================


class TestMarkRolledBack:
    """Verify mark_state_rolled_back updates the correct record."""

    def test_marks_succeeded(self, panic_db, session_id):
        panic_db.save_recovery_state(
            session_id, "network", "isolate",
            asset_id="vps_1", pre_panic_state={"rules": "old"},
        )
        states = panic_db.get_recovery_states(session_id)
        assert len(states) == 1

        panic_db.mark_state_rolled_back(states[0]["id"], succeeded=True)

        # After marking, should NOT appear in available states
        remaining = panic_db.get_recovery_states(session_id)
        assert len(remaining) == 0

    def test_marks_failed(self, panic_db, session_id):
        panic_db.save_recovery_state(
            session_id, "network", "isolate",
            asset_id="local", pre_panic_state={"rules": "old"},
        )
        states = panic_db.get_recovery_states(session_id)
        panic_db.mark_state_rolled_back(states[0]["id"], succeeded=False)

        # Still not available (rollback_available = 0)
        remaining = panic_db.get_recovery_states(session_id)
        assert len(remaining) == 0

    def test_only_affects_specified_state(self, panic_db, session_id):
        """Marking one asset rolled back doesn't affect other assets."""
        for asset in ["local", "vps_1"]:
            panic_db.save_recovery_state(
                session_id, "network", "isolate",
                asset_id=asset, pre_panic_state={"rules": f"old_{asset}"},
            )

        states = panic_db.get_recovery_states(session_id)
        local_state = [s for s in states if s["asset_id"] == "local"][0]
        panic_db.mark_state_rolled_back(local_state["id"])

        remaining = panic_db.get_recovery_states(session_id)
        assert len(remaining) == 1
        assert remaining[0]["asset_id"] == "vps_1"


# ===================================================================
# TestSchemaMigration — old databases get upgraded
# ===================================================================


class TestSchemaMigration:
    """Verify the migration adds asset_id to legacy recovery_states tables."""

    def test_migration_adds_asset_id(self, tmp_path):
        """Create an old-schema DB, then open with PanicDatabase to migrate."""
        db_path = tmp_path / "legacy_panic.db"

        # Create old schema (no asset_id, old UNIQUE constraint)
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE panic_sessions (
                session_id TEXT PRIMARY KEY,
                status TEXT, playbooks TEXT DEFAULT '[]',
                started_at TEXT, completed_at TEXT, progress TEXT DEFAULT '{}',
                actions TEXT DEFAULT '[]', recovery_state TEXT DEFAULT '{}',
                error TEXT, trigger_source TEXT, user_id TEXT,
                confirmation_token TEXT, reason TEXT, metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE recovery_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                component TEXT NOT NULL,
                component_id TEXT NOT NULL,
                pre_panic_state TEXT DEFAULT '{}',
                current_state TEXT DEFAULT '{}',
                rollback_available INTEGER DEFAULT 1,
                rollback_attempted INTEGER DEFAULT 0,
                rollback_succeeded INTEGER DEFAULT 0,
                rollback_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(session_id, component, component_id)
            )
        """)
        # Insert a legacy row (no asset_id)
        conn.execute("""
            INSERT INTO recovery_states (session_id, component, component_id, pre_panic_state)
            VALUES ('legacy_s1', 'network', 'isolate', '{"rules": "old"}')
        """)
        conn.commit()
        conn.close()

        # Open with PanicDatabase — should trigger migration
        db = PanicDatabase(db_path=db_path)

        # Verify asset_id column exists and legacy row has default
        from citadel_archer.core.db import connect as db_connect
        c = db_connect(db_path, row_factory=True)
        rows = c.execute("SELECT * FROM recovery_states").fetchall()
        assert len(rows) == 1
        assert rows[0]["asset_id"] == "local"
        c.close()

    def test_migration_preserves_data(self, tmp_path):
        """Migration should preserve all existing recovery state data."""
        db_path = tmp_path / "legacy2.db"

        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE panic_sessions (
                session_id TEXT PRIMARY KEY,
                status TEXT, playbooks TEXT DEFAULT '[]',
                started_at TEXT, completed_at TEXT, progress TEXT DEFAULT '{}',
                actions TEXT DEFAULT '[]', recovery_state TEXT DEFAULT '{}',
                error TEXT, trigger_source TEXT, user_id TEXT,
                confirmation_token TEXT, reason TEXT, metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE recovery_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                component TEXT NOT NULL,
                component_id TEXT NOT NULL,
                pre_panic_state TEXT DEFAULT '{}',
                current_state TEXT DEFAULT '{}',
                rollback_available INTEGER DEFAULT 1,
                rollback_attempted INTEGER DEFAULT 0,
                rollback_succeeded INTEGER DEFAULT 0,
                rollback_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(session_id, component, component_id)
            )
        """)
        conn.execute("""
            INSERT INTO recovery_states
                (session_id, component, component_id, pre_panic_state, current_state)
            VALUES ('s1', 'creds', 'rotate', '{"ssh": "old_key"}', '{"ssh": "new_key"}')
        """)
        conn.commit()
        conn.close()

        db = PanicDatabase(db_path=db_path)

        from citadel_archer.core.db import connect as db_connect
        c = db_connect(db_path, row_factory=True)
        rows = c.execute("SELECT * FROM recovery_states").fetchall()
        assert len(rows) == 1
        assert json.loads(rows[0]["pre_panic_state"]) == {"ssh": "old_key"}
        assert json.loads(rows[0]["current_state"]) == {"ssh": "new_key"}
        assert rows[0]["rollback_available"] == 1
        c.close()


# ===================================================================
# TestRollbackRequestModel — API model
# ===================================================================


class TestRollbackRequestModel:
    """Verify the RollbackRequest pydantic model accepts target_assets."""

    def test_accepts_target_assets(self):
        from citadel_archer.api.panic_routes import RollbackRequest

        req = RollbackRequest(
            confirmation_token="abc",
            components=["network"],
            target_assets=["vps_1", "vps_2"],
        )
        assert req.target_assets == ["vps_1", "vps_2"]

    def test_target_assets_defaults_to_none(self):
        from citadel_archer.api.panic_routes import RollbackRequest

        req = RollbackRequest(confirmation_token="abc")
        assert req.target_assets is None
        assert req.components is None

    def test_target_assets_with_no_components(self):
        from citadel_archer.api.panic_routes import RollbackRequest

        req = RollbackRequest(
            confirmation_token="abc",
            target_assets=["local"],
        )
        assert req.target_assets == ["local"]
        assert req.components is None


# ===================================================================
# TestPanicManagerSaveState — _save_recovery_state includes asset_id
# ===================================================================


class TestPanicManagerSaveState:
    """Verify PanicManager._save_recovery_state stores asset_id."""

    @pytest.fixture
    def manager_with_db(self, panic_db):
        """Create a PanicManager using the test PanicDatabase."""
        from citadel_archer.panic import PanicManager

        manager = PanicManager(panic_db, {"skip_confirmation": True})
        return manager, panic_db

    @pytest.mark.asyncio
    async def test_save_state_stores_asset_id(self, manager_with_db, session_id):
        manager, db = manager_with_db

        await manager._save_recovery_state(session_id, {
            "component": "network",
            "component_id": "isolate",
            "asset": "vps_1",
            "pre_state": {"rules": "old_vps1"},
            "current_state": None,
        })

        states = db.get_recovery_states(session_id)
        assert len(states) == 1
        assert states[0]["asset_id"] == "vps_1"

    @pytest.mark.asyncio
    async def test_save_state_defaults_to_local(self, manager_with_db, session_id):
        manager, db = manager_with_db

        await manager._save_recovery_state(session_id, {
            "component": "credentials",
            "component_id": "rotate_ssh",
            "pre_state": {"keys": "old"},
            "current_state": None,
        })

        states = db.get_recovery_states(session_id)
        assert len(states) == 1
        assert states[0]["asset_id"] == "local"

    @pytest.mark.asyncio
    async def test_save_multi_asset_no_overwrite(self, manager_with_db, session_id):
        """Saving states for multiple assets with the same component shouldn't clobber."""
        manager, db = manager_with_db

        for asset in ["local", "vps_1", "vps_2"]:
            await manager._save_recovery_state(session_id, {
                "component": "network",
                "component_id": "isolate",
                "asset": asset,
                "pre_state": {"rules": f"rules_{asset}"},
                "current_state": None,
            })

        states = db.get_recovery_states(session_id)
        assert len(states) == 3
        pre_states = {
            s["asset_id"]: json.loads(s["pre_panic_state"]) for s in states
        }
        assert pre_states["local"]["rules"] == "rules_local"
        assert pre_states["vps_1"]["rules"] == "rules_vps_1"
        assert pre_states["vps_2"]["rules"] == "rules_vps_2"


# ===================================================================
# TestPanicManagerRollback — rollback_panic with target_assets
# ===================================================================


class TestPanicManagerRollback:
    """Verify PanicManager.rollback_panic respects target_assets."""

    @pytest.fixture
    def manager_with_states(self, panic_db, session_id):
        """Create manager + populate multi-asset states."""
        from citadel_archer.panic import PanicManager

        manager = PanicManager(panic_db, {"skip_confirmation": True})

        # Mock playbook_engine.rollback_component
        async def mock_rollback(component, recovery_state):
            return {"rolled_back": True, "asset": recovery_state.get("asset", "local")}

        manager.playbook_engine = MagicMock()
        manager.playbook_engine.rollback_component = AsyncMock(side_effect=mock_rollback)

        # Mock _update_session_status (asyncpg-era code uses 'id' not 'session_id')
        manager._update_session_status = AsyncMock()

        # Populate states: 2 components × 2 assets = 4 states
        for component, comp_id in [("network", "isolate"), ("credentials", "rotate_ssh")]:
            for asset in ["local", "vps_1"]:
                panic_db.save_recovery_state(
                    session_id, component, comp_id,
                    asset_id=asset,
                    pre_panic_state={"component": component, "asset": asset},
                )

        return manager, panic_db, session_id

    @pytest.mark.asyncio
    async def test_rollback_all(self, manager_with_states):
        manager, db, sid = manager_with_states

        results = await manager.rollback_panic(
            session_id=sid,
            confirmation_token="x", user_id="test",
        )

        # Should roll back all 4 states
        assert "error" not in results
        assert len(results) == 4
        assert all(r["status"] == "success" for r in results.values())

    @pytest.mark.asyncio
    async def test_rollback_single_asset(self, manager_with_states):
        manager, db, sid = manager_with_states

        results = await manager.rollback_panic(
            session_id=sid,
            target_assets=["vps_1"],
            confirmation_token="x", user_id="test",
        )

        # Should only roll back the 2 vps_1 states
        assert len(results) == 2
        assert all(r["asset_id"] == "vps_1" for r in results.values())

        # Local states should still be available
        remaining = db.get_recovery_states(sid, target_assets=["local"])
        assert len(remaining) == 2

    @pytest.mark.asyncio
    async def test_rollback_single_component_single_asset(self, manager_with_states):
        manager, db, sid = manager_with_states

        results = await manager.rollback_panic(
            session_id=sid,
            components=["credentials"],
            target_assets=["vps_1"],
            confirmation_token="x", user_id="test",
        )

        assert len(results) == 1
        key = list(results.keys())[0]
        assert results[key]["component"] == "credentials"
        assert results[key]["asset_id"] == "vps_1"

        # 3 states should remain
        remaining = db.get_recovery_states(sid)
        assert len(remaining) == 3

    @pytest.mark.asyncio
    async def test_rollback_injects_asset_alias(self, manager_with_states):
        """The recovery_state dict passed to rollback_component should have 'asset' key."""
        manager, db, sid = manager_with_states

        await manager.rollback_panic(
            session_id=sid,
            target_assets=["vps_1"],
            components=["network"],
            confirmation_token="x", user_id="test",
        )

        # Verify the state dict passed to rollback_component has 'asset' key
        call_args = manager.playbook_engine.rollback_component.call_args
        state = call_args.kwargs.get("recovery_state", call_args[1].get("recovery_state"))
        assert state["asset"] == "vps_1"

    @pytest.mark.asyncio
    async def test_partial_failure_doesnt_block_others(self, manager_with_states):
        """If one asset's rollback fails, others should still succeed."""
        manager, db, sid = manager_with_states

        call_count = [0]

        async def mock_rollback_with_failure(component, recovery_state):
            call_count[0] += 1
            asset = recovery_state.get("asset", "local")
            if asset == "local" and component == "network":
                raise RuntimeError("Simulated failure on local network rollback")
            return {"rolled_back": True}

        manager.playbook_engine.rollback_component = AsyncMock(
            side_effect=mock_rollback_with_failure
        )

        results = await manager.rollback_panic(
            session_id=sid,
            confirmation_token="x", user_id="test",
        )

        # One failure, three successes
        statuses = [r["status"] for r in results.values()]
        assert statuses.count("failed") == 1
        assert statuses.count("success") == 3

        # The failed one should be local:network
        failed = {k: v for k, v in results.items() if v["status"] == "failed"}
        assert "network:local" in failed


# ===================================================================
# TestResultKeyFormat — result dict uses component:asset_id keys
# ===================================================================


class TestResultKeyFormat:
    """Verify rollback results are keyed as component:asset_id."""

    @pytest.fixture
    def manager_with_one_state(self, panic_db, session_id):
        from citadel_archer.panic import PanicManager

        manager = PanicManager(panic_db, {"skip_confirmation": True})
        manager.playbook_engine = MagicMock()
        manager.playbook_engine.rollback_component = AsyncMock(return_value={"ok": True})
        manager._update_session_status = AsyncMock()

        panic_db.save_recovery_state(
            session_id, "credentials", "rotate_ssh",
            asset_id="vps_42",
            pre_panic_state={"key": "old"},
        )
        return manager, panic_db, session_id

    @pytest.mark.asyncio
    async def test_key_format(self, manager_with_one_state):
        manager, db, sid = manager_with_one_state

        results = await manager.rollback_panic(
            session_id=sid,
            confirmation_token="x", user_id="test",
        )

        assert "credentials:vps_42" in results
        assert results["credentials:vps_42"]["component"] == "credentials"
        assert results["credentials:vps_42"]["asset_id"] == "vps_42"
