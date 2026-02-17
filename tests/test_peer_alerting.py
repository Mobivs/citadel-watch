"""Tests for peer alerting — surviving nodes notify each other of failures.

v0.3.38: Tests for PeerAlert, PeerAlertBroadcaster, alert API route,
and integration with MeshCoordinator phase-change callback.
"""

from unittest.mock import MagicMock, patch

import pytest


# ── AlertType Tests ─────────────────────────────────────────────────


class TestAlertType:
    """AlertType well-known constants."""

    def test_alert_types_exist(self):
        from src.citadel_archer.mesh.peer_alerting import AlertType

        assert AlertType.PEER_UNREACHABLE == "peer_unreachable"
        assert AlertType.PEER_ESCALATED == "peer_escalated"
        assert AlertType.PEER_RECOVERED == "peer_recovered"


# ── PeerAlert Tests ─────────────────────────────────────────────────


class TestPeerAlert:
    """PeerAlert dataclass."""

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlert

        alert = PeerAlert(
            alert_type="peer_unreachable",
            subject_node_id="vps1",
            reporter_node_id="desktop",
            phase="ALERT",
            previous_phase="NORMAL",
            missed_count=3,
        )
        assert alert.timestamp != ""

    def test_explicit_timestamp(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlert

        alert = PeerAlert(
            alert_type="peer_recovered",
            subject_node_id="vps1",
            reporter_node_id="desktop",
            phase="NORMAL",
            previous_phase="ALERT",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert alert.timestamp == "2025-01-01T00:00:00Z"

    def test_to_dict(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlert

        alert = PeerAlert(
            alert_type="peer_escalated",
            subject_node_id="vps2",
            reporter_node_id="desktop",
            phase="HEIGHTENED",
            previous_phase="ALERT",
            missed_count=5,
            details={"reason": "test"},
        )
        d = alert.to_dict()
        assert d["alert_type"] == "peer_escalated"
        assert d["subject_node_id"] == "vps2"
        assert d["reporter_node_id"] == "desktop"
        assert d["phase"] == "HEIGHTENED"
        assert d["previous_phase"] == "ALERT"
        assert d["missed_count"] == 5
        assert d["details"] == {"reason": "test"}
        assert "timestamp" in d

    def test_default_details_empty(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlert

        alert = PeerAlert(
            alert_type="peer_unreachable",
            subject_node_id="vps1",
            reporter_node_id="desktop",
            phase="ALERT",
            previous_phase="NORMAL",
        )
        assert alert.details == {}


# ── Broadcaster Tests ───────────────────────────────────────────────


class TestPeerAlertBroadcaster:
    """PeerAlertBroadcaster: phase handling, alert log, broadcasting."""

    def test_creates_unreachable_alert_for_alert_phase(self):
        """ALERT phase → PEER_UNREACHABLE type (not NORMAL, not HEIGHTENED+)."""
        from src.citadel_archer.mesh.peer_alerting import (
            AlertType, PeerAlertBroadcaster,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        alert = broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.NORMAL,
            EscalationPhase.ALERT,
            MagicMock(missed_count=3),
        )

        assert alert is not None
        assert alert.alert_type == AlertType.PEER_UNREACHABLE
        assert alert.subject_node_id == "vps1"
        assert alert.reporter_node_id == "desktop"
        assert alert.phase == "ALERT"
        assert alert.previous_phase == "NORMAL"

    def test_creates_escalated_alert_for_heightened(self):
        from src.citadel_archer.mesh.peer_alerting import (
            AlertType, PeerAlertBroadcaster,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        alert = broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.ALERT,
            EscalationPhase.HEIGHTENED,
            MagicMock(missed_count=5),
        )
        assert alert.alert_type == AlertType.PEER_ESCALATED

    def test_creates_escalated_alert_for_autonomous(self):
        from src.citadel_archer.mesh.peer_alerting import (
            AlertType, PeerAlertBroadcaster,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        alert = broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.HEIGHTENED,
            EscalationPhase.AUTONOMOUS,
            MagicMock(missed_count=10),
        )
        assert alert.alert_type == AlertType.PEER_ESCALATED

    def test_creates_recovered_alert_for_normal(self):
        from src.citadel_archer.mesh.peer_alerting import (
            AlertType, PeerAlertBroadcaster,
        )
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        alert = broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.ALERT,
            EscalationPhase.NORMAL,
            MagicMock(missed_count=0),
        )
        assert alert.alert_type == AlertType.PEER_RECOVERED

    def test_alert_stored_in_log(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.NORMAL,
            EscalationPhase.ALERT,
            MagicMock(missed_count=3),
        )
        broadcaster.handle_phase_change(
            "vps2",
            EscalationPhase.NORMAL,
            EscalationPhase.ALERT,
            MagicMock(missed_count=3),
        )

        alerts = broadcaster.get_recent_alerts(limit=10)
        assert len(alerts) == 2
        # Newest first
        assert alerts[0]["subject_node_id"] == "vps2"
        assert alerts[1]["subject_node_id"] == "vps1"

    def test_alert_log_capped(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        broadcaster._max_log_size = 5

        for i in range(10):
            broadcaster.handle_phase_change(
                f"vps{i}",
                EscalationPhase.NORMAL,
                EscalationPhase.ALERT,
                MagicMock(missed_count=3),
            )

        alerts = broadcaster.get_recent_alerts(limit=100)
        assert len(alerts) == 5

    def test_broadcast_sends_to_surviving_peers(self):
        """Broadcasting sends to all peers except the subject node."""
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")

        # Create mock peers
        peer1 = MagicMock(node_id="vps1", ip_address="10.0.0.1", port=9378)
        peer2 = MagicMock(node_id="vps2", ip_address="10.0.0.2", port=9378)
        peer3 = MagicMock(node_id="vps3", ip_address="10.0.0.3", port=9378)

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock

            broadcaster.handle_phase_change(
                "vps1",  # Subject — should be excluded from broadcast
                EscalationPhase.NORMAL,
                EscalationPhase.ALERT,
                MagicMock(missed_count=3),
                all_peers=[peer1, peer2, peer3],
            )

            # Should have sent to vps2 and vps3 (not vps1)
            assert mock_sock.sendto.call_count == 2
            mock_sock.close.assert_called_once()

    def test_broadcast_no_peers_no_error(self):
        """No peers → no broadcast, no error."""
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        # all_peers=None → no broadcast, should not raise
        alert = broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.NORMAL,
            EscalationPhase.ALERT,
            MagicMock(missed_count=3),
            all_peers=None,
        )
        assert alert is not None

    def test_broadcast_with_psk_signs_packet(self):
        """When PSK is set, broadcast packets should be signed."""
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        psk = b"test-key-32-bytes-long-for-hmac!"
        broadcaster = PeerAlertBroadcaster(node_id="desktop", psk=psk)

        peer = MagicMock(node_id="vps2", ip_address="10.0.0.2", port=9378)

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock

            broadcaster.handle_phase_change(
                "vps1",
                EscalationPhase.NORMAL,
                EscalationPhase.ALERT,
                MagicMock(missed_count=3),
                all_peers=[peer],
            )

            # Verify packet was sent (with signature)
            assert mock_sock.sendto.call_count == 1
            sent_data = mock_sock.sendto.call_args[0][0]
            # Parse the sent packet to verify it has a signature
            import json
            packet_dict = json.loads(sent_data.decode("utf-8"))
            assert packet_dict.get("signature", "") != ""

    def test_broadcast_socket_error_non_fatal(self):
        """Socket errors during broadcast are caught, not raised."""
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        peer = MagicMock(node_id="vps2", ip_address="10.0.0.2", port=9378)

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.sendto.side_effect = OSError("network down")
            mock_socket_cls.return_value = mock_sock

            # Should not raise
            alert = broadcaster.handle_phase_change(
                "vps1",
                EscalationPhase.NORMAL,
                EscalationPhase.ALERT,
                MagicMock(missed_count=3),
                all_peers=[peer],
            )
            assert alert is not None

    def test_update_psk(self):
        from src.citadel_archer.mesh.peer_alerting import PeerAlertBroadcaster

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        assert broadcaster._psk is None
        broadcaster.update_psk(b"new-key")
        assert broadcaster._psk == b"new-key"


# ── Singleton Tests ─────────────────────────────────────────────────


class TestPeerAlertSingleton:
    """get/set_peer_alert_broadcaster singleton."""

    def test_get_set(self):
        from src.citadel_archer.mesh.peer_alerting import (
            PeerAlertBroadcaster,
            get_peer_alert_broadcaster,
            set_peer_alert_broadcaster,
        )

        broadcaster = PeerAlertBroadcaster(node_id="desktop")
        set_peer_alert_broadcaster(broadcaster)
        assert get_peer_alert_broadcaster() is broadcaster
        set_peer_alert_broadcaster(None)

    def test_default_none(self):
        from src.citadel_archer.mesh.peer_alerting import (
            get_peer_alert_broadcaster,
            set_peer_alert_broadcaster,
        )

        set_peer_alert_broadcaster(None)
        assert get_peer_alert_broadcaster() is None


# ── Route Tests ─────────────────────────────────────────────────────


@pytest.fixture
def alert_client():
    """TestClient with mesh coordinator + broadcaster for alert routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator
    from src.citadel_archer.mesh.peer_alerting import (
        PeerAlertBroadcaster, set_peer_alert_broadcaster,
    )

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    broadcaster = PeerAlertBroadcaster(node_id="desktop")
    set_peer_alert_broadcaster(broadcaster)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)
    set_peer_alert_broadcaster(None)


class TestAlertRoutes:
    """Peer alert API routes."""

    def test_get_alerts_empty(self, alert_client):
        resp = alert_client.get("/api/mesh/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alerts"] == []
        assert data["total"] == 0

    def test_get_alerts_after_phase_change(self, alert_client):
        """Alerts populated after a broadcaster handles a phase change."""
        from src.citadel_archer.mesh.mesh_state import EscalationPhase
        from src.citadel_archer.mesh.peer_alerting import get_peer_alert_broadcaster

        broadcaster = get_peer_alert_broadcaster()
        broadcaster.handle_phase_change(
            "vps1",
            EscalationPhase.NORMAL,
            EscalationPhase.ALERT,
            MagicMock(missed_count=3),
        )

        resp = alert_client.get("/api/mesh/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["alerts"][0]["subject_node_id"] == "vps1"
        assert data["alerts"][0]["alert_type"] == "peer_unreachable"

    def test_get_alerts_with_limit(self, alert_client):
        from src.citadel_archer.mesh.mesh_state import EscalationPhase
        from src.citadel_archer.mesh.peer_alerting import get_peer_alert_broadcaster

        broadcaster = get_peer_alert_broadcaster()
        for i in range(5):
            broadcaster.handle_phase_change(
                f"vps{i}",
                EscalationPhase.NORMAL,
                EscalationPhase.ALERT,
                MagicMock(missed_count=3),
            )

        resp = alert_client.get("/api/mesh/alerts?limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    def test_get_alerts_no_broadcaster(self):
        """When broadcaster is None, return empty."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
        from src.citadel_archer.api.security import verify_session_token
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator
        from src.citadel_archer.mesh.peer_alerting import set_peer_alert_broadcaster

        coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
        coord.start()
        set_mesh_coordinator(coord)
        set_peer_alert_broadcaster(None)

        test_app = FastAPI()
        test_app.include_router(router)
        test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
        client = TestClient(test_app)

        resp = client.get("/api/mesh/alerts")
        assert resp.status_code == 200
        assert resp.json()["alerts"] == []

        coord.stop()
        set_mesh_coordinator(None)
