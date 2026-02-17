"""
Tests for SSH hardening API endpoints.

Uses FastAPI TestClient with mocked orchestrator and services.
Auth bypassed via dependency_overrides (follows test_asset_routes_fixes.py pattern).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from citadel_archer.api.main import app
from citadel_archer.api.security import verify_session_token


@pytest.fixture
def client():
    """TestClient with auth bypass via dependency override."""
    app.dependency_overrides[verify_session_token] = lambda: "test-token"
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def unauth_client():
    """TestClient without auth — for testing 401 responses."""
    app.dependency_overrides.pop(verify_session_token, None)
    return TestClient(app)


class TestHardeningAPI:
    """SSH hardening API endpoints."""

    def test_apply_hardening_requires_auth(self, unauth_client):
        resp = unauth_client.post("/api/hardening/ssh/vps_1", json={})
        assert resp.status_code in (401, 403, 503)

    @patch("citadel_archer.api.ssh_hardening_routes._get_orchestrator")
    def test_apply_hardening_success(self, mock_get_orch, client):
        from citadel_archer.remote.ssh_hardening import HardeningResult
        mock_orch = AsyncMock()
        mock_orch.harden_asset = AsyncMock(return_value=HardeningResult(
            success=True,
            asset_id="vps_1",
            changes_applied=["sshd_config backed up", "access verified"],
        ))
        mock_get_orch.return_value = mock_orch

        resp = client.post(
            "/api/hardening/ssh/vps_1",
            json={"disable_password_auth": True, "max_auth_tries": 3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "sshd_config backed up" in data["changes_applied"]

    @patch("citadel_archer.api.ssh_hardening_routes._get_orchestrator")
    def test_rollback_hardening(self, mock_get_orch, client):
        from citadel_archer.remote.ssh_hardening import RollbackResult
        mock_orch = AsyncMock()
        mock_orch.rollback_hardening = AsyncMock(return_value=RollbackResult(
            success=True, asset_id="vps_1", details="restored",
        ))
        mock_get_orch.return_value = mock_orch

        resp = client.delete("/api/hardening/ssh/vps_1")
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    @patch("citadel_archer.api.ssh_hardening_routes._get_shield_db")
    @patch("citadel_archer.api.ssh_hardening_routes._get_orchestrator")
    def test_get_status(self, mock_get_orch, mock_get_db, client):
        from citadel_archer.remote.ssh_hardening import HardeningStatus
        mock_orch = AsyncMock()
        mock_orch.get_hardening_status = AsyncMock(return_value=HardeningStatus(
            password_auth_enabled=False,
            ssh_port=2222,
        ))
        mock_get_orch.return_value = mock_orch

        mock_db = MagicMock()
        mock_db.get_hardening_config.return_value = {
            "asset_id": "vps_1",
            "config": {"max_auth_tries": 3},
            "status": "applied",
            "applied_at": "2026-01-01",
        }
        mock_get_db.return_value = mock_db

        resp = client.get("/api/hardening/ssh/vps_1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["db_status"] == "applied"
        assert data["remote_status"]["ssh_port"] == 2222

    @patch("citadel_archer.api.ssh_hardening_routes._get_shield_db")
    def test_list_all_statuses(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.list_hardening_configs.return_value = [
            {"asset_id": "a1", "config": {}, "status": "applied", "applied_at": None},
            {"asset_id": "a2", "config": {}, "status": "pending", "applied_at": None},
        ]
        mock_get_db.return_value = mock_db

        resp = client.get("/api/hardening/ssh")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    @patch("citadel_archer.api.ssh_hardening_routes._get_orchestrator")
    def test_apply_with_invalid_port(self, mock_get_orch, client):
        resp = client.post(
            "/api/hardening/ssh/vps_1",
            json={"custom_ssh_port": 99999},
        )
        assert resp.status_code == 422  # Validation error

    @patch("citadel_archer.api.ssh_hardening_routes._get_orchestrator")
    def test_apply_hardening_failure(self, mock_get_orch, client):
        from citadel_archer.remote.ssh_hardening import HardeningResult
        mock_orch = AsyncMock()
        mock_orch.harden_asset = AsyncMock(return_value=HardeningResult(
            success=False,
            asset_id="vps_fail",
            error="SSH connection timeout",
        ))
        mock_get_orch.return_value = mock_orch

        resp = client.post(
            "/api/hardening/ssh/vps_fail",
            json={},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "timeout" in data["error"]

    def test_list_requires_auth(self, unauth_client):
        resp = unauth_client.get("/api/hardening/ssh")
        assert resp.status_code in (401, 403, 503)
