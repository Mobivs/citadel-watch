"""
Tests for firewall API endpoints.

Uses FastAPI TestClient with mocked services.
Auth bypassed via dependency_overrides (follows test_asset_routes_fixes.py pattern).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from citadel_archer.api.main import app
from citadel_archer.api.security import verify_session_token


@pytest.fixture
def client():
    """TestClient with auth bypass."""
    app.dependency_overrides[verify_session_token] = lambda: "test-token"
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def unauth_client():
    """TestClient without auth."""
    app.dependency_overrides.pop(verify_session_token, None)
    return TestClient(app)


class TestFirewallRoutes:
    """Firewall API endpoints."""

    def test_add_rule_requires_auth(self, unauth_client):
        resp = unauth_client.post("/api/firewall/rules/vps1", json={"source": "1.1.1.1"})
        assert resp.status_code in (401, 403, 503)

    @patch("citadel_archer.api.firewall_routes._get_firewall_mgr")
    def test_add_rule(self, mock_get_mgr, client):
        mock_mgr = MagicMock()
        mock_mgr.add_rule.return_value = 42
        mock_get_mgr.return_value = mock_mgr

        resp = client.post("/api/firewall/rules/vps1", json={
            "action": "deny",
            "source": "1.2.3.0/24",
            "protocol": "tcp",
            "port": "22",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 42
        assert data["source"] == "1.2.3.0/24"

    @patch("citadel_archer.api.firewall_routes._get_shield_db")
    def test_list_rules(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_firewall_rules.return_value = [
            {"id": 1, "asset_id": "vps1", "action": "deny", "source": "1.1.1.0/24",
             "protocol": "tcp", "port": "22", "direction": "in", "priority": 100,
             "enabled": True, "auto_generated": False, "expires_at": None,
             "comment": "", "created_at": "2026-01-01"},
        ]
        mock_get_db.return_value = mock_db

        resp = client.get("/api/firewall/rules/vps1")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    @patch("citadel_archer.api.firewall_routes._get_shield_db")
    def test_update_rule(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.update_firewall_rule.return_value = True
        mock_get_db.return_value = mock_db

        resp = client.put("/api/firewall/rules/1", json={"source": "9.9.9.9"})
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    @patch("citadel_archer.api.firewall_routes._get_shield_db")
    def test_delete_rule(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.delete_firewall_rule.return_value = True
        mock_get_db.return_value = mock_db

        resp = client.delete("/api/firewall/rules/1")
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    @patch("citadel_archer.api.firewall_routes._get_shield_db")
    def test_delete_rule_not_found(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.delete_firewall_rule.return_value = False
        mock_get_db.return_value = mock_db

        resp = client.delete("/api/firewall/rules/999")
        assert resp.status_code == 404

    @patch("citadel_archer.api.firewall_routes._get_firewall_mgr")
    def test_push_rules(self, mock_get_mgr, client):
        mock_mgr = AsyncMock()
        mock_mgr.push_rules = AsyncMock(return_value={
            "success": True, "pushed_count": 3, "error": "",
        })
        mock_get_mgr.return_value = mock_mgr

        resp = client.post("/api/firewall/push/vps1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["pushed_count"] == 3

    def test_invalid_action_rejected(self, client):
        # This should be caught by Pydantic validation before hitting _get_firewall_mgr
        resp = client.post("/api/firewall/rules/vps1", json={
            "action": "invalid_action",
            "source": "1.1.1.1",
        })
        assert resp.status_code == 422
