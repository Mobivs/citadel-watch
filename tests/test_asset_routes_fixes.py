"""Tests for asset_routes.py code review fixes.

Covers:
  - Issue #11: SSHManagerError subtypes map to proper HTTP status codes
    (previously all collapsed to 502)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from citadel_archer.api.asset_routes import router, set_inventory, get_ssh_manager
from citadel_archer.remote.ssh_manager import (
    SSHManagerError,
    AssetNotFoundError,
    NoCredentialError,
    VaultLockedError,
    ConnectionFailedError,
    CommandTimeoutError,
)


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def app():
    """Minimal FastAPI app with asset routes + auth bypass."""
    from citadel_archer.api.security import verify_session_token

    test_app = FastAPI()
    test_app.include_router(router)

    # Override session token check
    test_app.dependency_overrides[verify_session_token] = lambda: "test-token"

    yield test_app

    test_app.dependency_overrides.clear()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def mock_inventory():
    """Provide a mock inventory with one test asset."""
    inv = MagicMock()
    asset = MagicMock()
    asset.to_dict.return_value = {"asset_id": "a1", "name": "test-vps"}
    inv.get.return_value = asset
    inv.all.return_value = [asset]
    inv.stats.return_value = {"total": 1}

    set_inventory(inv)
    yield inv
    set_inventory(None)


# ── Tests ────────────────────────────────────────────────────────────

class TestSSHManagerErrorHTTPCodes:
    """Each SSHManagerError subtype should produce the correct HTTP code."""

    @pytest.mark.parametrize("exc_class,expected_status", [
        (AssetNotFoundError, 404),
        (NoCredentialError, 422),
        (VaultLockedError, 503),
        (CommandTimeoutError, 504),
        (ConnectionFailedError, 502),
        (SSHManagerError, 502),  # fallback
    ])
    def test_error_code_mapping(
        self, client, mock_inventory, exc_class, expected_status
    ):
        """test_connection endpoint returns the right HTTP code for each error."""
        mock_ssh = MagicMock()
        mock_ssh.test_connection = AsyncMock(side_effect=exc_class("boom"))

        with patch(
            "citadel_archer.api.asset_routes.get_ssh_manager",
            return_value=mock_ssh,
        ):
            resp = client.post("/api/assets/a1/test-connection")

        assert resp.status_code == expected_status
        assert "boom" in resp.json()["detail"]

    def test_successful_connection(self, client, mock_inventory):
        """Happy path returns 200 with system info."""
        from citadel_archer.remote.ssh_manager import ConnectionTestResult

        mock_ssh = MagicMock()
        mock_ssh.test_connection = AsyncMock(return_value=ConnectionTestResult(
            success=True,
            asset_id="a1",
            ssh_fingerprint="SHA256:abc",
            remote_os="Ubuntu 22.04",
            uptime="up 5 days",
            hostname="myhost",
            remote_shield_detected=False,
            agent_version="",
            latency_ms=42,
        ))

        with patch(
            "citadel_archer.api.asset_routes.get_ssh_manager",
            return_value=mock_ssh,
        ):
            resp = client.post("/api/assets/a1/test-connection")

        assert resp.status_code == 200
        data = resp.json()
        assert data["connection_status"] == "success"
        assert data["remote_os"] == "Ubuntu 22.04"
        assert data["latency_ms"] == 42

    def test_connection_failed_result(self, client, mock_inventory):
        """When SSH connects but test fails, returns 200 with failure info."""
        from citadel_archer.remote.ssh_manager import ConnectionTestResult

        mock_ssh = MagicMock()
        mock_ssh.test_connection = AsyncMock(return_value=ConnectionTestResult(
            success=False,
            asset_id="a1",
            error="all probes failed",
            latency_ms=99,
        ))

        with patch(
            "citadel_archer.api.asset_routes.get_ssh_manager",
            return_value=mock_ssh,
        ):
            resp = client.post("/api/assets/a1/test-connection")

        assert resp.status_code == 200
        data = resp.json()
        assert data["connection_status"] == "failed"
        assert "all probes failed" in data["error"]

    def test_asset_not_found_before_ssh(self, client, mock_inventory):
        """If asset doesn't exist in inventory, 404 before SSH is attempted."""
        mock_inventory.get.return_value = None

        resp = client.post("/api/assets/nonexistent/test-connection")

        assert resp.status_code == 404
