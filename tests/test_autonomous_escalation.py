"""Tests for autonomous escalation behavior.

v0.3.37: Tests for the EscalationPolicy, AutonomousEscalationHandler,
and escalation API routes.
"""

from unittest.mock import MagicMock, patch

import pytest


# ── Policy Tests ─────────────────────────────────────────────────────


class TestEscalationPolicy:
    """EscalationPolicy dataclass."""

    def test_default_policy(self):
        from src.citadel_archer.mesh.autonomous_escalation import EscalationPolicy

        policy = EscalationPolicy()
        assert policy.alert_threshold_override == "low"
        assert policy.alert_polling_interval == 15
        assert policy.heightened_rule_ttl_minutes == 60
        assert policy.autonomous_rule_ttl_minutes == 240
        assert policy.autonomous_kill_ssh is False
        assert policy.auto_recover is True

    def test_custom_policy(self):
        from src.citadel_archer.mesh.autonomous_escalation import EscalationPolicy

        policy = EscalationPolicy(
            alert_threshold_override="medium",
            heightened_deny_sources=["10.0.0.0/8"],
            autonomous_allow_ips=["192.168.1.1"],
            autonomous_kill_ssh=True,
        )
        assert policy.alert_threshold_override == "medium"
        assert policy.heightened_deny_sources == ["10.0.0.0/8"]
        assert policy.autonomous_allow_ips == ["192.168.1.1"]
        assert policy.autonomous_kill_ssh is True

    def test_observer_policy(self):
        from src.citadel_archer.mesh.autonomous_escalation import OBSERVER_POLICY

        assert OBSERVER_POLICY.alert_threshold_override is None
        assert OBSERVER_POLICY.autonomous_kill_ssh is False


# ── Action Result Tests ──────────────────────────────────────────────


class TestEscalationActionResult:
    """EscalationActionResult dataclass."""

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.autonomous_escalation import EscalationActionResult

        result = EscalationActionResult(
            action="test_action", success=True, node_id="vps1", phase="ALERT",
        )
        assert result.timestamp != ""

    def test_with_details(self):
        from src.citadel_archer.mesh.autonomous_escalation import EscalationActionResult

        result = EscalationActionResult(
            action="lower_alert_threshold",
            success=True,
            node_id="vps1",
            phase="ALERT",
            details={"threshold": "low"},
        )
        assert result.details["threshold"] == "low"


# ── Handler Tests ────────────────────────────────────────────────────


class TestAutonomousEscalationHandler:
    """AutonomousEscalationHandler: policy management and phase handling."""

    def test_default_policy(self):
        from src.citadel_archer.mesh.autonomous_escalation import (
            AutonomousEscalationHandler, DEFAULT_VPS_POLICY,
        )

        handler = AutonomousEscalationHandler()
        policy = handler.get_policy("unknown_node")
        assert policy.alert_threshold_override == DEFAULT_VPS_POLICY.alert_threshold_override

    def test_set_custom_policy(self):
        from src.citadel_archer.mesh.autonomous_escalation import (
            AutonomousEscalationHandler, EscalationPolicy,
        )

        handler = AutonomousEscalationHandler()
        custom = EscalationPolicy(alert_polling_interval=5)
        handler.set_policy("vps1", custom)
        assert handler.get_policy("vps1").alert_polling_interval == 5

    def test_handle_alert_phase(self):
        """ALERT phase: queues threshold and polling commands."""
        from src.citadel_archer.mesh.autonomous_escalation import AutonomousEscalationHandler
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()

        # Mock command queue (shield_database not available in test)
        with patch.object(handler, "_queue_command", return_value=True) as mock_q:
            results = handler.handle_phase_change(
                "vps1", EscalationPhase.NORMAL, EscalationPhase.ALERT,
                MagicMock(missed_count=3),
            )

        assert len(results) == 2
        actions = [r.action for r in results]
        assert "lower_alert_threshold" in actions
        assert "increase_polling_frequency" in actions
        assert all(r.success for r in results)
        assert mock_q.call_count == 2

    def test_handle_heightened_phase(self):
        """HEIGHTENED phase: queues tighten rules command."""
        from src.citadel_archer.mesh.autonomous_escalation import AutonomousEscalationHandler
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()

        with patch.object(handler, "_queue_command", return_value=True):
            with patch.object(handler, "_add_emergency_rules", return_value=[]):
                results = handler.handle_phase_change(
                    "vps1", EscalationPhase.ALERT, EscalationPhase.HEIGHTENED,
                    MagicMock(missed_count=5),
                )

        actions = [r.action for r in results]
        assert "queue_tighten_rules" in actions

    def test_handle_autonomous_phase(self):
        """AUTONOMOUS phase: queues lockdown command."""
        from src.citadel_archer.mesh.autonomous_escalation import AutonomousEscalationHandler
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()

        with patch.object(handler, "_queue_command", return_value=True):
            with patch.object(handler, "_add_lockdown_rules", return_value=[]):
                results = handler.handle_phase_change(
                    "vps1", EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS,
                    MagicMock(missed_count=10),
                )

        actions = [r.action for r in results]
        assert "queue_lockdown_command" in actions

    def test_handle_recovery(self):
        """RECOVERY: restores normal operations."""
        from src.citadel_archer.mesh.autonomous_escalation import AutonomousEscalationHandler
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()

        with patch.object(handler, "_queue_command", return_value=True):
            with patch.object(handler, "_remove_emergency_rules", return_value=0):
                results = handler.handle_phase_change(
                    "vps1", EscalationPhase.AUTONOMOUS, EscalationPhase.NORMAL,
                    MagicMock(missed_count=0),
                )

        actions = [r.action for r in results]
        assert "remove_emergency_rules" in actions
        assert "queue_restore_normal" in actions

    def test_recovery_skipped_when_disabled(self):
        """Recovery skipped when auto_recover=False."""
        from src.citadel_archer.mesh.autonomous_escalation import (
            AutonomousEscalationHandler, EscalationPolicy,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()
        handler.set_policy("vps1", EscalationPolicy(auto_recover=False))

        results = handler.handle_phase_change(
            "vps1", EscalationPhase.ALERT, EscalationPhase.NORMAL,
            MagicMock(missed_count=0),
        )

        assert len(results) == 1
        assert results[0].action == "recovery_skipped"

    def test_queue_command_failure_non_fatal(self):
        """Failed command queue doesn't raise."""
        from src.citadel_archer.mesh.autonomous_escalation import AutonomousEscalationHandler
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()

        # No shield_database available — _queue_command returns False
        results = handler.handle_phase_change(
            "vps1", EscalationPhase.NORMAL, EscalationPhase.ALERT,
            MagicMock(missed_count=3),
        )

        # Should still return results (just marked as failed)
        assert len(results) == 2
        # Commands fail because shield_database isn't configured in tests
        # but the handler should not raise

    def test_heightened_with_deny_sources(self):
        """HEIGHTENED with deny sources adds emergency rules."""
        from src.citadel_archer.mesh.autonomous_escalation import (
            AutonomousEscalationHandler, EscalationPolicy,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()
        handler.set_policy("vps1", EscalationPolicy(
            heightened_deny_sources=["10.0.0.0/8", "172.16.0.0/12"],
        ))

        with patch.object(handler, "_queue_command", return_value=True):
            with patch.object(handler, "_add_emergency_rules", return_value=[1, 2]) as mock_rules:
                results = handler.handle_phase_change(
                    "vps1", EscalationPhase.ALERT, EscalationPhase.HEIGHTENED,
                    MagicMock(missed_count=5),
                )

        # Should have called add_emergency_rules
        mock_rules.assert_called_once()
        rule_result = [r for r in results if r.action == "add_emergency_firewall_rules"]
        assert len(rule_result) == 1
        assert rule_result[0].success is True
        assert rule_result[0].details["rules_added"] == 2

    def test_autonomous_with_allow_ips(self):
        """AUTONOMOUS with allow IPs adds lockdown rules."""
        from src.citadel_archer.mesh.autonomous_escalation import (
            AutonomousEscalationHandler, EscalationPolicy,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        handler = AutonomousEscalationHandler()
        handler.set_policy("vps1", EscalationPolicy(
            autonomous_allow_ips=["192.168.1.1"],
        ))

        with patch.object(handler, "_queue_command", return_value=True):
            with patch.object(handler, "_add_lockdown_rules", return_value=[1]) as mock_lock:
                results = handler.handle_phase_change(
                    "vps1", EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS,
                    MagicMock(missed_count=10),
                )

        mock_lock.assert_called_once()
        lock_result = [r for r in results if r.action == "apply_lockdown_rules"]
        assert len(lock_result) == 1
        assert lock_result[0].details["allow_ips"] == ["192.168.1.1"]


# ── Singleton Tests ──────────────────────────────────────────────────


class TestEscalationSingleton:
    """get/set_escalation_handler singleton."""

    def test_singleton(self):
        from src.citadel_archer.mesh.autonomous_escalation import (
            AutonomousEscalationHandler,
            get_escalation_handler,
            set_escalation_handler,
        )

        handler = AutonomousEscalationHandler()
        set_escalation_handler(handler)
        assert get_escalation_handler() is handler
        set_escalation_handler(None)

    def test_auto_creates(self):
        from src.citadel_archer.mesh.autonomous_escalation import (
            get_escalation_handler,
            set_escalation_handler,
        )

        set_escalation_handler(None)
        handler = get_escalation_handler()
        assert handler is not None
        set_escalation_handler(None)


# ── Route Tests ──────────────────────────────────────────────────────


@pytest.fixture
def escalation_client():
    """TestClient with mesh coordinator for escalation routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)


class TestEscalationRoutes:
    """Escalation policy API routes."""

    def test_get_default_policy(self, escalation_client):
        resp = escalation_client.get("/api/mesh/escalation/vps1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_id"] == "vps1"
        assert data["alert_threshold_override"] == "low"
        assert data["auto_recover"] is True

    def test_set_custom_policy(self, escalation_client):
        resp = escalation_client.put("/api/mesh/escalation/vps1", json={
            "alert_polling_interval": 5,
            "heightened_deny_sources": ["10.0.0.0/8"],
            "autonomous_kill_ssh": True,
        })
        assert resp.status_code == 200

        # Verify it was saved
        resp = escalation_client.get("/api/mesh/escalation/vps1")
        data = resp.json()
        assert data["alert_polling_interval"] == 5
        assert data["heightened_deny_sources"] == ["10.0.0.0/8"]
        assert data["autonomous_kill_ssh"] is True

    def test_policies_per_node(self, escalation_client):
        """Different nodes can have different policies."""
        escalation_client.put("/api/mesh/escalation/vps1", json={
            "alert_polling_interval": 5,
        })
        escalation_client.put("/api/mesh/escalation/vps2", json={
            "alert_polling_interval": 10,
        })

        resp1 = escalation_client.get("/api/mesh/escalation/vps1")
        resp2 = escalation_client.get("/api/mesh/escalation/vps2")
        assert resp1.json()["alert_polling_interval"] == 5
        assert resp2.json()["alert_polling_interval"] == 10
