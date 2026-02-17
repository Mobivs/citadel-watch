"""
Tests for onboarding API endpoints.

Uses FastAPI TestClient with mocked orchestrator.
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


class TestOnboardingRoutes:
    """Onboarding API endpoints."""

    def test_start_requires_auth(self, unauth_client):
        resp = unauth_client.post("/api/onboarding/start", json={"asset_id": "vps1"})
        assert resp.status_code in (401, 403, 503)

    @patch("citadel_archer.api.onboarding_routes._get_orchestrator")
    def test_start_onboarding(self, mock_get_orch, client):
        from citadel_archer.remote.onboarding import OnboardingResult
        mock_orch = AsyncMock()
        mock_orch.start_onboarding = AsyncMock(return_value=OnboardingResult(
            session_id="sess-123",
            asset_id="vps1",
            success=True,
            status="completed",
            steps={
                "validate": {"status": "completed", "message": "OK"},
                "connect": {"status": "completed", "message": "OK"},
                "deploy": {"status": "completed", "message": "OK"},
                "harden": {"status": "completed", "message": "OK"},
                "firewall": {"status": "completed", "message": "OK"},
                "verify": {"status": "completed", "message": "OK"},
            },
        ))
        mock_get_orch.return_value = mock_orch

        resp = client.post("/api/onboarding/start", json={"asset_id": "vps1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["session_id"] == "sess-123"

    @patch("citadel_archer.api.onboarding_routes._get_shield_db")
    def test_get_status(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_onboarding_session.return_value = {
            "session_id": "sess-123",
            "asset_id": "vps1",
            "status": "completed",
            "steps": {
                "validate": {"status": "completed", "message": "OK"},
            },
            "config": {"asset_id": "vps1"},
            "started_at": "2026-01-01",
            "completed_at": "2026-01-01",
        }
        mock_get_db.return_value = mock_db

        resp = client.get("/api/onboarding/sess-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"

    @patch("citadel_archer.api.onboarding_routes._get_shield_db")
    def test_get_status_not_found(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.get_onboarding_session.return_value = None
        mock_get_db.return_value = mock_db

        resp = client.get("/api/onboarding/nonexistent")
        assert resp.status_code == 404

    @patch("citadel_archer.api.onboarding_routes._get_orchestrator")
    def test_retry_step(self, mock_get_orch, client):
        from citadel_archer.remote.onboarding import StepResult
        mock_orch = AsyncMock()
        mock_orch.retry_step = AsyncMock(return_value=StepResult(
            step="deploy", status="completed", message="Agent deployed",
        ))
        mock_get_orch.return_value = mock_orch

        resp = client.post("/api/onboarding/sess-123/retry/deploy")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["step"] == "deploy"

    @patch("citadel_archer.api.onboarding_routes._get_shield_db")
    def test_list_sessions(self, mock_get_db, client):
        mock_db = MagicMock()
        mock_db.list_onboarding_sessions.return_value = [
            {
                "session_id": "s1", "asset_id": "vps1", "status": "completed",
                "steps": {}, "config": {}, "started_at": None, "completed_at": None,
            },
            {
                "session_id": "s2", "asset_id": "vps2", "status": "partial",
                "steps": {}, "config": {}, "started_at": None, "completed_at": None,
            },
        ]
        mock_get_db.return_value = mock_db

        resp = client.get("/api/onboarding/sessions/list")
        assert resp.status_code == 200
        assert len(resp.json()) == 2
