"""Tests for secondary brain designation — fallback VPS coordinator.

v0.3.39: Tests for SecondaryBrainConfig, SecondaryBrainManager,
brain API routes, and integration with mesh phase-change callbacks.
"""

from unittest.mock import MagicMock, patch

import pytest


# ── Config Tests ────────────────────────────────────────────────────


class TestSecondaryBrainConfig:
    """SecondaryBrainConfig dataclass."""

    def test_default_config(self):
        from src.citadel_archer.mesh.secondary_brain import SecondaryBrainConfig

        config = SecondaryBrainConfig()
        assert config.node_id == ""
        assert config.activation_threshold == 10
        assert config.rate_limit_rpm == 10
        assert config.max_coordination_hours == 24
        assert config.require_desktop_approval is True
        assert "rotate_credentials" in config.denied_actions
        assert "lower_alert_threshold" in config.allowed_actions

    def test_to_dict_hides_api_key(self):
        """to_dict should expose api_key_configured, not the raw key."""
        from src.citadel_archer.mesh.secondary_brain import SecondaryBrainConfig

        config = SecondaryBrainConfig(
            node_id="vps1",
            api_key_encrypted="encrypted-key-data",
        )
        d = config.to_dict()
        assert d["node_id"] == "vps1"
        assert d["api_key_configured"] is True
        assert "api_key_encrypted" not in d

    def test_custom_config(self):
        from src.citadel_archer.mesh.secondary_brain import SecondaryBrainConfig

        config = SecondaryBrainConfig(
            node_id="vps2",
            activation_threshold=5,
            rate_limit_rpm=5,
            allowed_actions=["lower_alert_threshold"],
            denied_actions=["rotate_credentials", "queue_lockdown_command"],
        )
        assert config.node_id == "vps2"
        assert config.activation_threshold == 5
        assert len(config.denied_actions) == 2


# ── BrainState Tests ────────────────────────────────────────────────


class TestBrainState:
    """BrainRole and BrainState enums."""

    def test_brain_roles(self):
        from src.citadel_archer.mesh.secondary_brain import BrainRole

        assert BrainRole.PRIMARY.value == "primary"
        assert BrainRole.SECONDARY.value == "secondary"
        assert BrainRole.AGENT.value == "agent"

    def test_brain_states(self):
        from src.citadel_archer.mesh.secondary_brain import BrainState

        assert BrainState.STANDBY.value == "standby"
        assert BrainState.ACTIVATING.value == "activating"
        assert BrainState.ACTIVE.value == "active"
        assert BrainState.DEACTIVATING.value == "deactivating"
        assert BrainState.DISABLED.value == "disabled"


# ── SanitizedAsset Tests ────────────────────────────────────────────


class TestSanitizedAsset:
    """SanitizedAsset dataclass."""

    def test_to_dict(self):
        from src.citadel_archer.mesh.secondary_brain import SanitizedAsset

        asset = SanitizedAsset(
            asset_id="vps1",
            hostname="server1.example.com",
            ip_address="10.0.0.1",
            port=22,
            agent_version="0.3.39",
            last_status="online",
            public_key_fingerprint="SHA256:abc123",
            tags=["production"],
        )
        d = asset.to_dict()
        assert d["asset_id"] == "vps1"
        assert d["hostname"] == "server1.example.com"
        assert d["public_key_fingerprint"] == "SHA256:abc123"
        assert "production" in d["tags"]


# ── CoordinationDecision Tests ──────────────────────────────────────


class TestCoordinationDecision:
    """CoordinationDecision dataclass."""

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.secondary_brain import CoordinationDecision

        decision = CoordinationDecision(
            decision_id="d1",
            action="lower_alert_threshold",
            target_node_id="vps1",
        )
        assert decision.timestamp != ""

    def test_to_dict(self):
        from src.citadel_archer.mesh.secondary_brain import CoordinationDecision

        decision = CoordinationDecision(
            decision_id="d1",
            action="add_emergency_firewall_rules",
            target_node_id="vps2",
            reason="Desktop offline",
            parameters={"sources": ["10.0.0.0/8"]},
            outcome="executed",
        )
        d = decision.to_dict()
        assert d["decision_id"] == "d1"
        assert d["action"] == "add_emergency_firewall_rules"
        assert d["outcome"] == "executed"
        assert d["reviewed"] is False


# ── Manager Tests ───────────────────────────────────────────────────


class TestSecondaryBrainManager:
    """SecondaryBrainManager: designation, activation, decisions."""

    def test_default_state_is_disabled(self):
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        assert mgr.state == BrainState.DISABLED
        assert mgr.designated_node_id is None

    def test_designate(self):
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainConfig, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        config = SecondaryBrainConfig(node_id="vps1")
        mgr.designate(config)
        assert mgr.state == BrainState.STANDBY
        assert mgr.designated_node_id == "vps1"

    def test_remove_designation(self):
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainConfig, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(node_id="vps1"))
        mgr.remove_designation()
        assert mgr.state == BrainState.DISABLED
        assert mgr.designated_node_id is None

    def test_activate_on_desktop_autonomous(self):
        """Desktop entering AUTONOMOUS activates the secondary brain."""
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainConfig, SecondaryBrainManager,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(node_id="vps1"))

        peer = MagicMock(is_desktop=True, missed_count=10)
        result = mgr.handle_phase_change(
            "desktop", EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS, peer,
        )
        assert result is not None
        assert "activated" in result
        assert mgr.state == BrainState.ACTIVE

    def test_deactivate_on_desktop_recovery(self):
        """Desktop returning to NORMAL deactivates the secondary brain."""
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainConfig, SecondaryBrainManager,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(node_id="vps1"))

        # Activate first
        peer = MagicMock(is_desktop=True, missed_count=10)
        mgr.handle_phase_change(
            "desktop", EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS, peer,
        )
        assert mgr.state == BrainState.ACTIVE

        # Desktop recovers
        peer.missed_count = 0
        result = mgr.handle_phase_change(
            "desktop", EscalationPhase.AUTONOMOUS, EscalationPhase.NORMAL, peer,
        )
        assert result is not None
        assert "deactivated" in result
        assert mgr.state == BrainState.STANDBY

    def test_ignores_non_desktop_peers(self):
        """Only desktop peer phase changes trigger activation."""
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainConfig, SecondaryBrainManager,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(node_id="vps1"))

        # Non-desktop peer
        peer = MagicMock(is_desktop=False, missed_count=10)
        result = mgr.handle_phase_change(
            "vps2", EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS, peer,
        )
        assert result is None
        assert mgr.state == BrainState.STANDBY

    def test_disabled_ignores_everything(self):
        from src.citadel_archer.mesh.secondary_brain import (
            BrainState, SecondaryBrainManager,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        mgr = SecondaryBrainManager()  # DISABLED by default

        peer = MagicMock(is_desktop=True, missed_count=10)
        result = mgr.handle_phase_change(
            "desktop", EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS, peer,
        )
        assert result is None
        assert mgr.state == BrainState.DISABLED

    def test_get_status(self):
        from src.citadel_archer.mesh.secondary_brain import (
            SecondaryBrainConfig, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(node_id="vps1"))
        status = mgr.get_status()
        assert status["state"] == "standby"
        assert status["config"]["node_id"] == "vps1"
        assert status["pending_decisions"] == 0
        assert status["asset_count"] == 0

    # ── Decision Logging ──────────────────────────────────────────

    def test_log_and_get_decisions(self):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.log_decision(CoordinationDecision(
            decision_id="d1", action="lower_alert_threshold", target_node_id="vps1",
        ))
        mgr.log_decision(CoordinationDecision(
            decision_id="d2", action="add_emergency_firewall_rules", target_node_id="vps2",
        ))

        all_decisions = mgr.get_all_decisions()
        assert len(all_decisions) == 2
        # Newest first
        assert all_decisions[0]["decision_id"] == "d2"

        pending = mgr.get_pending_decisions()
        assert len(pending) == 2

    def test_review_decision(self):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.log_decision(CoordinationDecision(
            decision_id="d1", action="test_action", target_node_id="vps1",
        ))

        found = mgr.review_decision("d1", action="accepted")
        assert found is True
        assert mgr.get_pending_decisions() == []

    def test_review_decision_rollback(self):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.log_decision(CoordinationDecision(
            decision_id="d1", action="test_action", target_node_id="vps1",
            outcome="executed",
        ))

        mgr.review_decision("d1", action="rolled_back")
        decisions = mgr.get_all_decisions()
        assert decisions[0]["outcome"] == "rolled_back"
        assert decisions[0]["reviewed"] is True

    def test_review_all_decisions(self):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        for i in range(5):
            mgr.log_decision(CoordinationDecision(
                decision_id=f"d{i}", action="test", target_node_id="vps1",
            ))

        count = mgr.review_all_decisions()
        assert count == 5
        assert mgr.get_pending_decisions() == []

    def test_review_nonexistent_decision(self):
        from src.citadel_archer.mesh.secondary_brain import SecondaryBrainManager

        mgr = SecondaryBrainManager()
        assert mgr.review_decision("nonexistent") is False

    def test_decision_log_capped(self):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr._max_decisions = 5
        for i in range(10):
            mgr.log_decision(CoordinationDecision(
                decision_id=f"d{i}", action="test", target_node_id="vps1",
            ))
        all_d = mgr.get_all_decisions(limit=100)
        assert len(all_d) == 5

    # ── Action Permissions ────────────────────────────────────────

    def test_is_action_allowed(self):
        from src.citadel_archer.mesh.secondary_brain import (
            SecondaryBrainConfig, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(node_id="vps1"))

        assert mgr.is_action_allowed("lower_alert_threshold") is True
        assert mgr.is_action_allowed("rotate_credentials") is False

    def test_is_action_allowed_not_in_list(self):
        from src.citadel_archer.mesh.secondary_brain import (
            SecondaryBrainConfig, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        mgr.designate(SecondaryBrainConfig(
            node_id="vps1",
            allowed_actions=["lower_alert_threshold"],
        ))

        # Not in allowed list → denied
        assert mgr.is_action_allowed("queue_lockdown_command") is False

    # ── Asset Registry ────────────────────────────────────────────

    def test_asset_registry(self):
        from src.citadel_archer.mesh.secondary_brain import (
            SanitizedAsset, SecondaryBrainManager,
        )

        mgr = SecondaryBrainManager()
        assets = [
            SanitizedAsset(asset_id="vps1", hostname="s1", ip_address="10.0.0.1"),
            SanitizedAsset(asset_id="vps2", hostname="s2", ip_address="10.0.0.2"),
        ]
        mgr.update_asset_registry(assets)

        registry = mgr.get_asset_registry()
        assert len(registry) == 2
        assert registry[0]["asset_id"] == "vps1"

    def test_sanitize_from_inventory(self):
        from src.citadel_archer.mesh.secondary_brain import SecondaryBrainManager

        mgr = SecondaryBrainManager()

        # Mock inventory with list_assets
        mock_inv = MagicMock()
        mock_inv.list_assets.return_value = [
            {
                "asset_id": "vps1",
                "hostname": "server1",
                "ip_address": "10.0.0.1",
                "port": 22,
                "agent_version": "0.3.39",
                "status": "online",
                "public_key_fingerprint": "SHA256:abc",
                "tags": ["prod"],
                # Sensitive fields that should NOT be in output
                "password": "secret123",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            },
        ]

        assets = mgr.sanitize_from_inventory(mock_inv)
        assert len(assets) == 1
        assert assets[0].asset_id == "vps1"
        assert assets[0].ip_address == "10.0.0.1"
        # Verify no secrets leak through
        d = assets[0].to_dict()
        assert "password" not in d
        assert "private_key" not in d


# ── Singleton Tests ─────────────────────────────────────────────────


class TestSecondaryBrainSingleton:

    def test_get_set(self):
        from src.citadel_archer.mesh.secondary_brain import (
            SecondaryBrainManager,
            get_secondary_brain_manager,
            set_secondary_brain_manager,
        )

        mgr = SecondaryBrainManager()
        set_secondary_brain_manager(mgr)
        assert get_secondary_brain_manager() is mgr
        set_secondary_brain_manager(None)

    def test_auto_creates(self):
        from src.citadel_archer.mesh.secondary_brain import (
            get_secondary_brain_manager,
            set_secondary_brain_manager,
        )

        set_secondary_brain_manager(None)
        mgr = get_secondary_brain_manager()
        assert mgr is not None
        set_secondary_brain_manager(None)


# ── Route Tests ─────────────────────────────────────────────────────


@pytest.fixture
def brain_client():
    """TestClient with mesh coordinator for secondary brain routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator
    from src.citadel_archer.mesh.secondary_brain import (
        SecondaryBrainManager, set_secondary_brain_manager,
    )

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    # Add a peer so we can designate it
    coord.add_peer(node_id="vps1", ip_address="10.0.0.1", port=9378)
    set_mesh_coordinator(coord)

    mgr = SecondaryBrainManager()
    set_secondary_brain_manager(mgr)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)
    set_secondary_brain_manager(None)


class TestSecondaryBrainRoutes:

    def test_get_status_default(self, brain_client):
        resp = brain_client.get("/api/mesh/secondary-brain")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "disabled"

    def test_designate_and_get_status(self, brain_client):
        resp = brain_client.put("/api/mesh/secondary-brain", json={
            "node_id": "vps1",
            "activation_threshold": 8,
        })
        assert resp.status_code == 200
        assert resp.json()["state"] == "standby"

        resp = brain_client.get("/api/mesh/secondary-brain")
        data = resp.json()
        assert data["state"] == "standby"
        assert data["config"]["node_id"] == "vps1"

    def test_designate_nonexistent_peer(self, brain_client):
        resp = brain_client.put("/api/mesh/secondary-brain", json={
            "node_id": "nonexistent",
        })
        assert resp.status_code == 404

    def test_remove_designation(self, brain_client):
        brain_client.put("/api/mesh/secondary-brain", json={"node_id": "vps1"})
        resp = brain_client.delete("/api/mesh/secondary-brain")
        assert resp.status_code == 200
        assert resp.json()["state"] == "disabled"

    def test_get_decisions_empty(self, brain_client):
        resp = brain_client.get("/api/mesh/secondary-brain/decisions")
        assert resp.status_code == 200
        assert resp.json()["decisions"] == []

    def test_review_decision(self, brain_client):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, get_secondary_brain_manager,
        )

        mgr = get_secondary_brain_manager()
        mgr.log_decision(CoordinationDecision(
            decision_id="d1", action="test_action", target_node_id="vps1",
        ))

        resp = brain_client.post(
            "/api/mesh/secondary-brain/decisions/d1/review?action=accepted"
        )
        assert resp.status_code == 200

    def test_review_all_decisions(self, brain_client):
        from src.citadel_archer.mesh.secondary_brain import (
            CoordinationDecision, get_secondary_brain_manager,
        )

        mgr = get_secondary_brain_manager()
        for i in range(3):
            mgr.log_decision(CoordinationDecision(
                decision_id=f"d{i}", action="test", target_node_id="vps1",
            ))

        resp = brain_client.post("/api/mesh/secondary-brain/decisions/review-all")
        assert resp.status_code == 200
        assert resp.json()["count"] == 3

    def test_get_asset_registry(self, brain_client):
        resp = brain_client.get("/api/mesh/secondary-brain/assets")
        assert resp.status_code == 200
        assert resp.json()["assets"] == []
