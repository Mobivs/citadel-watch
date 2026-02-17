"""Tests for recovery/reconciliation protocol.

v0.3.42: Tests for RecoveryManager (5-step process), conflict resolution,
full recovery flow, and API routes.
"""

from unittest.mock import MagicMock

import pytest


# ── RecoveryReport Tests ────────────────────────────────────────────


class TestRecoveryReport:

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryReport

        report = RecoveryReport(recovery_id="r1")
        assert report.started_at != ""

    def test_to_dict(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryReport

        report = RecoveryReport(
            recovery_id="r1",
            outage_duration_seconds=300,
            events_synced=10,
        )
        d = report.to_dict()
        assert d["recovery_id"] == "r1"
        assert d["outage_duration_seconds"] == 300
        assert d["events_synced"] == 10
        assert d["steps"] == []


# ── Manager Step-by-Step Tests ──────────────────────────────────────


class TestRecoveryManager:

    def test_initial_state(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager, RecoveryState,
        )

        mgr = RecoveryManager()
        assert mgr.state == RecoveryState.IDLE
        assert mgr.current_report is None

    def test_start_recovery(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager, RecoveryState,
        )

        mgr = RecoveryManager()
        report = mgr.start_recovery("r1", outage_seconds=300)
        assert mgr.state == RecoveryState.SYNCING
        assert report.recovery_id == "r1"
        assert report.outage_duration_seconds == 300

    def test_step1_sync_events(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager, RecoveryState,
        )

        mgr = RecoveryManager()
        mgr.start_recovery("r1")

        events = [{"type": "alert", "node": "vps1"}, {"type": "block", "node": "vps2"}]
        count = mgr.sync_events(events)
        assert count == 2
        assert mgr.state == RecoveryState.REVIEWING

    def test_step2_review_decisions(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager, RecoveryState,
        )

        mgr = RecoveryManager()
        mgr.start_recovery("r1")
        mgr.sync_events([])

        decisions = [
            {"decision_id": "d1", "action": "lower_alert_threshold", "target_node_id": "vps1"},
            {"decision_id": "d2", "action": "rotate_credentials", "target_node_id": "vps2"},
        ]
        result = mgr.review_decisions(decisions)
        assert result["total"] == 2
        assert result["accepted"] == 1  # lower_alert_threshold auto-accepted
        assert result["rolled_back"] == 1  # rotate_credentials auto-rolled-back
        assert mgr.state == RecoveryState.RESOLVING

    def test_step3_resolve_conflicts(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        mgr.start_recovery("r1")
        mgr.sync_events([])
        mgr.review_decisions([
            {"decision_id": "d1", "action": "rotate_credentials", "target_node_id": "vps1"},
        ])

        conflicts = mgr.resolve_conflicts()
        assert len(conflicts) >= 1
        assert conflicts[0]["resolution"] == "rolled_back"

    def test_step4_restore_heartbeats(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager, RecoveryState,
        )

        mgr = RecoveryManager()
        mgr.start_recovery("r1")
        mgr.sync_events([])
        mgr.review_decisions([])
        mgr.resolve_conflicts()

        mock_coord = MagicMock()
        mock_coord.is_running = True
        mock_coord.state_manager.all_peers.return_value = [MagicMock(), MagicMock()]

        result = mgr.restore_heartbeats(coordinator=mock_coord)
        assert result["peers_notified"] == 2
        assert result["coordinator_running"] is True
        assert mgr.state == RecoveryState.COMPLETE

    def test_step5_merge_audit(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        mgr.start_recovery("r1")
        mgr.sync_events([])
        mgr.review_decisions([])
        mgr.resolve_conflicts()
        mgr.restore_heartbeats()

        entries = [{"event": "test", "timestamp": "2025-01-01T00:00:00Z"}] * 5
        count = mgr.merge_audit_log(entries)
        assert count == 5

    def test_complete_recovery(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager, RecoveryState,
        )

        mgr = RecoveryManager()
        mgr.start_recovery("r1")
        mgr.sync_events([])
        mgr.review_decisions([])
        mgr.resolve_conflicts()
        mgr.restore_heartbeats()
        mgr.merge_audit_log([])

        report = mgr.complete_recovery()
        assert report.recovery_id == "r1"
        assert report.completed_at != ""
        assert mgr.state == RecoveryState.IDLE
        assert mgr.current_report is None

    def test_history(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        mgr.run_full_recovery("r1")
        mgr.run_full_recovery("r2")

        history = mgr.get_history()
        assert len(history) == 2
        # Newest first
        assert history[0]["recovery_id"] == "r2"

    def test_get_status(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        status = mgr.get_status()
        assert status["state"] == "idle"
        assert status["current_recovery"] is None

    def test_run_full_recovery(self):
        """Full non-interactive recovery."""
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        events = [{"type": "alert"}]
        decisions = [
            {"decision_id": "d1", "action": "lower_alert_threshold", "target_node_id": "vps1"},
            {"decision_id": "d2", "action": "kill_all_ssh_sessions", "target_node_id": "vps2"},
        ]
        audit_entries = [{"event": "test"}] * 3

        report = mgr.run_full_recovery(
            recovery_id="r-full",
            outage_seconds=600,
            events=events,
            decisions=decisions,
            audit_entries=audit_entries,
        )

        assert report.recovery_id == "r-full"
        assert report.events_synced == 1
        assert report.decisions_reviewed == 2
        assert report.decisions_accepted == 1
        assert report.decisions_rolled_back == 1
        assert report.audit_entries_merged == 3
        assert len(report.steps) == 5

    def test_history_capped(self):
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        mgr._max_history = 3
        for i in range(5):
            mgr.run_full_recovery(f"r{i}")

        history = mgr.get_history(limit=100)
        assert len(history) == 3

    def test_custom_auto_actions(self):
        """Custom auto-accept and auto-rollback lists."""
        from src.citadel_archer.mesh.recovery_protocol import RecoveryManager

        mgr = RecoveryManager()
        mgr.start_recovery("r1")
        mgr.sync_events([])

        decisions = [
            {"decision_id": "d1", "action": "my_custom_action", "target_node_id": "vps1"},
            {"decision_id": "d2", "action": "dangerous_action", "target_node_id": "vps2"},
        ]
        result = mgr.review_decisions(
            decisions,
            auto_accept_actions=["my_custom_action"],
            auto_rollback_actions=["dangerous_action"],
        )
        assert result["accepted"] == 1
        assert result["rolled_back"] == 1


# ── Singleton Tests ─────────────────────────────────────────────────


class TestRecoverySingleton:

    def test_get_set(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            RecoveryManager,
            get_recovery_manager,
            set_recovery_manager,
        )

        mgr = RecoveryManager()
        set_recovery_manager(mgr)
        assert get_recovery_manager() is mgr
        set_recovery_manager(None)

    def test_auto_creates(self):
        from src.citadel_archer.mesh.recovery_protocol import (
            get_recovery_manager,
            set_recovery_manager,
        )

        set_recovery_manager(None)
        mgr = get_recovery_manager()
        assert mgr is not None
        set_recovery_manager(None)


# ── Route Tests ─────────────────────────────────────────────────────


@pytest.fixture
def recovery_client():
    """TestClient for recovery routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator
    from src.citadel_archer.mesh.recovery_protocol import (
        RecoveryManager, set_recovery_manager,
    )

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    mgr = RecoveryManager()
    set_recovery_manager(mgr)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)
    set_recovery_manager(None)


class TestRecoveryRoutes:

    def test_get_status(self, recovery_client):
        resp = recovery_client.get("/api/mesh/recovery/status")
        assert resp.status_code == 200
        assert resp.json()["state"] == "idle"

    def test_start_recovery(self, recovery_client):
        resp = recovery_client.post("/api/mesh/recovery/start", json={
            "recovery_id": "r1",
            "outage_seconds": 300,
        })
        assert resp.status_code == 200
        assert resp.json()["recovery_id"] == "r1"

    def test_full_recovery_flow(self, recovery_client):
        recovery_client.post("/api/mesh/recovery/start", json={
            "recovery_id": "r1",
        })
        recovery_client.post("/api/mesh/recovery/sync-events", json={
            "events": [{"type": "alert"}],
        })
        recovery_client.post("/api/mesh/recovery/review-decisions", json={
            "decisions": [
                {"decision_id": "d1", "action": "lower_alert_threshold", "target_node_id": "vps1"},
            ],
        })
        recovery_client.post("/api/mesh/recovery/resolve-conflicts")
        recovery_client.post("/api/mesh/recovery/restore-heartbeats")
        recovery_client.post("/api/mesh/recovery/merge-audit", json={
            "entries": [{"event": "test"}],
        })
        resp = recovery_client.post("/api/mesh/recovery/complete")
        assert resp.status_code == 200
        assert resp.json()["state"] == "complete"

    def test_run_full_recovery(self, recovery_client):
        resp = recovery_client.post("/api/mesh/recovery/run-full", json={
            "recovery_id": "r-auto",
            "outage_seconds": 600,
        })
        assert resp.status_code == 200
        assert resp.json()["recovery_id"] == "r-auto"
        assert resp.json()["state"] == "complete"

    def test_get_history(self, recovery_client):
        recovery_client.post("/api/mesh/recovery/run-full", json={
            "recovery_id": "r1",
        })
        resp = recovery_client.get("/api/mesh/recovery/history")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
