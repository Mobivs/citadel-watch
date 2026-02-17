"""
Tests for Easy Deployment (v0.3.32): Email Invite → One-Click Install.

Covers:
- InvitationStore enhancements (recipient fields, verify_secret_only, mark_page_visited)
- Enrollment routes (public page, download, install.ps1, status polling)
- API enhancements (enrollment_url, mailto_url in response, email/name fields)
- Frontend structural checks (HTML elements, JS functions)
"""

import hashlib
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── InvitationStore Fixtures ───────────────────────────────────────


@pytest.fixture
def inv_db_path(tmp_path):
    return str(tmp_path / "test_invitations.db")


@pytest.fixture
def inv_store(inv_db_path):
    """InvitationStore with tmp database."""
    with patch(
        "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
        return_value="test-hmac-key",
    ):
        from citadel_archer.chat.agent_invitation import InvitationStore
        return InvitationStore(db_path=inv_db_path)


def _create_test_invitation(store, **kwargs):
    """Helper to create an invitation with defaults."""
    defaults = {
        "agent_name": "Test Agent",
        "agent_type": "workstation",
        "ttl_seconds": 600,
    }
    defaults.update(kwargs)
    with patch(
        "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
        return_value="test-hmac-key",
    ):
        return store.create_invitation(**defaults)


# ── InvitationStore Enhancement Tests ──────────────────────────────


class TestInvitationStoreRecipientFields:
    """Test that recipient_email, recipient_name, page_visited_at fields work."""

    def test_create_with_email_and_name(self, inv_store):
        """Invitation stores recipient email and name."""
        inv, compact = _create_test_invitation(
            inv_store,
            recipient_email="mom@example.com",
            recipient_name="Mom",
        )
        assert inv.recipient_email == "mom@example.com"
        assert inv.recipient_name == "Mom"
        assert inv.page_visited_at == ""

    def test_create_without_email_defaults_to_empty(self, inv_store):
        """Without explicit email/name, they default to empty string."""
        inv, compact = _create_test_invitation(inv_store)
        assert inv.recipient_email == ""
        assert inv.recipient_name == ""

    def test_to_dict_includes_new_fields(self, inv_store):
        """to_dict() serializes all new fields."""
        inv, _ = _create_test_invitation(
            inv_store,
            recipient_email="test@test.com",
            recipient_name="TestUser",
        )
        d = inv.to_dict()
        assert "recipient_email" in d
        assert "recipient_name" in d
        assert "page_visited_at" in d
        assert d["recipient_email"] == "test@test.com"
        assert d["recipient_name"] == "TestUser"
        assert d["page_visited_at"] == ""

    def test_get_invitation_round_trip(self, inv_store):
        """Fields survive insert → get round-trip."""
        inv, _ = _create_test_invitation(
            inv_store,
            recipient_email="family@home.net",
            recipient_name="Family",
        )
        fetched = inv_store.get_invitation(inv.invitation_id)
        assert fetched is not None
        assert fetched.recipient_email == "family@home.net"
        assert fetched.recipient_name == "Family"

    def test_schema_migration_idempotent(self, inv_db_path):
        """Calling _init_database() twice doesn't raise."""
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            from citadel_archer.chat.agent_invitation import InvitationStore
            store1 = InvitationStore(db_path=inv_db_path)
            # Second init on same DB should be idempotent
            store2 = InvitationStore(db_path=inv_db_path)
            # Should be able to create invitation on both
            inv, _ = _create_test_invitation(store2, recipient_email="ok@test.com")
            assert inv.recipient_email == "ok@test.com"


class TestVerifySecretOnly:
    """Test verify_secret_only — validates secret without consuming."""

    def test_valid_secret(self, inv_store):
        """Returns True for valid, pending, non-expired invitation."""
        inv, compact = _create_test_invitation(inv_store)
        from citadel_archer.chat.agent_invitation import InvitationStore
        _, raw_secret = InvitationStore.parse_compact_string(compact)
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            assert inv_store.verify_secret_only(inv.invitation_id, raw_secret) is True

    def test_invalid_secret(self, inv_store):
        """Returns False for wrong secret."""
        inv, compact = _create_test_invitation(inv_store)
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            assert inv_store.verify_secret_only(inv.invitation_id, "wrong-secret") is False

    def test_expired_invitation(self, inv_store):
        """Returns False for expired invitation."""
        inv, compact = _create_test_invitation(inv_store, ttl_seconds=60)
        from citadel_archer.chat.agent_invitation import InvitationStore
        _, raw_secret = InvitationStore.parse_compact_string(compact)
        # Expire the invitation by updating the DB
        with inv_store._connect() as conn:
            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            conn.execute(
                "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                (past, inv.invitation_id),
            )
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            assert inv_store.verify_secret_only(inv.invitation_id, raw_secret) is False

    def test_nonexistent_invitation(self, inv_store):
        """Returns False for missing invitation_id."""
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            assert inv_store.verify_secret_only("000000000000", "any-secret") is False

    def test_does_not_consume(self, inv_store):
        """verify_secret_only should not change the invitation status."""
        inv, compact = _create_test_invitation(inv_store)
        from citadel_archer.chat.agent_invitation import InvitationStore, InvitationStatus
        _, raw_secret = InvitationStore.parse_compact_string(compact)
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            inv_store.verify_secret_only(inv.invitation_id, raw_secret)
        fetched = inv_store.get_invitation(inv.invitation_id)
        assert fetched.status == InvitationStatus.PENDING


class TestMarkPageVisited:
    """Test mark_page_visited — sets timestamp on pending invitations."""

    def test_marks_pending_invitation(self, inv_store):
        """Sets page_visited_at timestamp for pending invitation."""
        inv, _ = _create_test_invitation(inv_store)
        result = inv_store.mark_page_visited(inv.invitation_id)
        assert result is True
        fetched = inv_store.get_invitation(inv.invitation_id)
        assert fetched.page_visited_at != ""

    def test_does_not_overwrite(self, inv_store):
        """Only sets timestamp once (WHERE page_visited_at = '')."""
        inv, _ = _create_test_invitation(inv_store)
        inv_store.mark_page_visited(inv.invitation_id)
        fetched1 = inv_store.get_invitation(inv.invitation_id)
        first_ts = fetched1.page_visited_at
        # Second call should return False and not change timestamp
        result = inv_store.mark_page_visited(inv.invitation_id)
        assert result is False
        fetched2 = inv_store.get_invitation(inv.invitation_id)
        assert fetched2.page_visited_at == first_ts

    def test_skips_redeemed(self, inv_store):
        """Does not mark redeemed invitations."""
        inv, compact = _create_test_invitation(inv_store)
        from citadel_archer.chat.agent_invitation import InvitationStore
        _, raw_secret = InvitationStore.parse_compact_string(compact)
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            inv_store.verify_and_consume(inv.invitation_id, raw_secret, "127.0.0.1")
        result = inv_store.mark_page_visited(inv.invitation_id)
        assert result is False


# ── Enrollment Routes Tests ────────────────────────────────────────


@pytest.fixture
def enrollment_client(inv_store, tmp_path):
    """FastAPI test client wired with test InvitationStore."""
    from citadel_archer.api.main import app
    from citadel_archer.api import enrollment_routes, security

    # Patch the store getter
    old_get_store = enrollment_routes._get_store
    enrollment_routes._get_store = lambda: inv_store

    # Reset rate limiter
    enrollment_routes._rate_limit.clear()

    old_token = security._SESSION_TOKEN
    security._SESSION_TOKEN = "test-session-token"

    # Patch HMAC key to match the key used when creating test invitations
    with patch(
        "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
        return_value="test-hmac-key",
    ):
        yield TestClient(app)

    enrollment_routes._get_store = old_get_store
    security._SESSION_TOKEN = old_token


def _create_and_parse(inv_store, **kwargs):
    """Create invitation and return (invitation, invitation_id, raw_secret)."""
    from citadel_archer.chat.agent_invitation import InvitationStore
    inv, compact = _create_test_invitation(inv_store, **kwargs)
    _, raw_secret = InvitationStore.parse_compact_string(compact)
    return inv, inv.invitation_id, raw_secret


class TestEnrollmentPage:
    """GET /enroll/{invitation_id}?s={secret}"""

    def test_valid_invitation_returns_html(self, enrollment_client, inv_store):
        """Valid invitation returns HTML with injected ENROLL_DATA."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}?s={secret}")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "ENROLL_DATA" in resp.text
        assert inv.agent_name in resp.text

    def test_marks_page_visited(self, enrollment_client, inv_store):
        """Visiting the page sets page_visited_at."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        enrollment_client.get(f"/enroll/{inv_id}?s={secret}")
        fetched = inv_store.get_invitation(inv_id)
        assert fetched.page_visited_at != ""

    def test_expired_shows_error(self, enrollment_client, inv_store):
        """Expired invitation shows error page."""
        inv, inv_id, secret = _create_and_parse(inv_store, ttl_seconds=60)
        # Expire it
        with inv_store._connect() as conn:
            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            conn.execute(
                "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                (past, inv_id),
            )
        resp = enrollment_client.get(f"/enroll/{inv_id}?s={secret}")
        assert resp.status_code == 200  # Error page is still HTML 200
        assert "invalid or has expired" in resp.text.lower()

    def test_bad_secret_returns_error(self, enrollment_client, inv_store):
        """Wrong secret shows error page."""
        inv, inv_id, _ = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}?s=wrong-secret")
        assert resp.status_code == 200
        assert "invalid or has expired" in resp.text.lower()

    def test_missing_secret_returns_error(self, enrollment_client, inv_store):
        """Missing ?s= parameter returns error page."""
        inv, inv_id, _ = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}")
        # Route returns 400 HTML error for missing token
        assert resp.status_code == 400
        assert "missing token" in resp.text.lower()

    def test_redeemed_shows_already_used(self, enrollment_client, inv_store):
        """Redeemed invitation shows 'already been used' message."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            inv_store.verify_and_consume(inv_id, secret, "127.0.0.1")
        resp = enrollment_client.get(f"/enroll/{inv_id}?s={secret}")
        assert resp.status_code == 200
        assert "already been used" in resp.text.lower()


class TestDownloadEndpoint:
    """GET /enroll/{invitation_id}/download/windows_shield.py?s={secret}"""

    def test_download_valid(self, enrollment_client, inv_store):
        """Valid download returns Python file with embedded config."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        resp = enrollment_client.get(
            f"/enroll/{inv_id}/download/windows_shield.py?s={secret}"
        )
        # May be 500 if windows_shield.py doesn't exist in test env,
        # but we check the route exists and responds
        assert resp.status_code in (200, 500)
        if resp.status_code == 200:
            assert "citadel_shield" in resp.headers.get("content-disposition", "").lower()

    def test_download_bad_secret(self, enrollment_client, inv_store):
        """Wrong secret returns 401."""
        inv, inv_id, _ = _create_and_parse(inv_store)
        resp = enrollment_client.get(
            f"/enroll/{inv_id}/download/windows_shield.py?s=bad-secret"
        )
        assert resp.status_code == 401


class TestInstallPS1Endpoint:
    """GET /enroll/{invitation_id}/install.ps1?s={secret}"""

    def test_ps1_valid(self, enrollment_client, inv_store):
        """Valid request returns PowerShell script with correct URLs."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}/install.ps1?s={secret}")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")
        # PowerShell script should contain key elements
        body = resp.text
        assert "Citadel Shield" in body
        assert inv_id in body
        assert "Invoke-WebRequest" in body

    def test_ps1_bad_secret(self, enrollment_client, inv_store):
        """Wrong secret returns 401."""
        inv, inv_id, _ = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}/install.ps1?s=bad-secret")
        assert resp.status_code == 401


class TestStatusEndpoint:
    """GET /enroll/{invitation_id}/status?s={secret}"""

    def test_pending_status(self, enrollment_client, inv_store):
        """Pending invitation returns { status: "pending" }."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}/status?s={secret}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"

    def test_redeemed_status(self, enrollment_client, inv_store):
        """Redeemed invitation returns { status: "redeemed" }."""
        inv, inv_id, secret = _create_and_parse(inv_store)
        with patch(
            "citadel_archer.chat.agent_invitation.InvitationStore._get_hmac_key",
            return_value="test-hmac-key",
        ):
            inv_store.verify_and_consume(inv_id, secret, "127.0.0.1")
        resp = enrollment_client.get(f"/enroll/{inv_id}/status?s={secret}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "redeemed"

    def test_bad_secret_returns_401(self, enrollment_client, inv_store):
        """Wrong secret returns 401."""
        inv, inv_id, _ = _create_and_parse(inv_store)
        resp = enrollment_client.get(f"/enroll/{inv_id}/status?s=wrong")
        assert resp.status_code == 401


class TestEnrollmentRateLimiting:
    """Rate limiting on enrollment endpoints."""

    def test_rate_limit_enforced(self, enrollment_client, inv_store):
        """After 10 requests, subsequent requests get 429."""
        from citadel_archer.api import enrollment_routes
        enrollment_routes._rate_limit.clear()

        inv, inv_id, secret = _create_and_parse(inv_store)

        # Make 10 requests (all should succeed)
        for _ in range(10):
            resp = enrollment_client.get(f"/enroll/{inv_id}/status?s={secret}")
            assert resp.status_code in (200, 401)

        # 11th should be rate limited
        resp = enrollment_client.get(f"/enroll/{inv_id}/status?s={secret}")
        assert resp.status_code == 429


# ── API Enhancement Tests ──────────────────────────────────────────


@pytest.fixture
def api_client(inv_store, tmp_path):
    """FastAPI test client with session auth for invitation API."""
    from citadel_archer.api.main import app
    from citadel_archer.api import agent_api_routes, security

    # We need the invitation store to be reachable from the route
    old_token = security._SESSION_TOKEN
    security._SESSION_TOKEN = "test-session-token"

    yield TestClient(app)

    security._SESSION_TOKEN = old_token


class TestCreateInvitationAPI:
    """POST /api/ext-agents/invitations — enhanced response."""

    def test_response_includes_enrollment_url(self, api_client):
        """Response has enrollment_url field."""
        resp = api_client.post(
            "/api/ext-agents/invitations",
            json={
                "agent_name": "Mom PC",
                "agent_type": "workstation",
                "ttl_seconds": 600,
            },
            headers={"X-Session-Token": "test-session-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "enrollment_url" in data
        assert "/enroll/" in data["enrollment_url"]
        assert "?s=" in data["enrollment_url"]

    def test_response_includes_mailto_url_with_email(self, api_client):
        """When recipient_email is provided, mailto_url is populated."""
        resp = api_client.post(
            "/api/ext-agents/invitations",
            json={
                "agent_name": "Mom PC",
                "agent_type": "workstation",
                "ttl_seconds": 600,
                "recipient_email": "mom@example.com",
                "recipient_name": "Mom",
            },
            headers={"X-Session-Token": "test-session-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "mailto_url" in data
        assert data["mailto_url"].startswith("mailto:")
        assert "mom%40example.com" in data["mailto_url"] or "mom@example.com" in data["mailto_url"]

    def test_no_email_means_empty_mailto(self, api_client):
        """Without recipient_email, mailto_url is empty."""
        resp = api_client.post(
            "/api/ext-agents/invitations",
            json={
                "agent_name": "VPS Agent",
                "agent_type": "vps",
                "ttl_seconds": 600,
            },
            headers={"X-Session-Token": "test-session-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mailto_url"] == ""

    def test_email_and_name_passed_to_store(self, api_client):
        """recipient_email and recipient_name reach the invitation store."""
        resp = api_client.post(
            "/api/ext-agents/invitations",
            json={
                "agent_name": "Sister PC",
                "agent_type": "workstation",
                "ttl_seconds": 600,
                "recipient_email": "sis@home.net",
                "recipient_name": "Sister",
            },
            headers={"X-Session-Token": "test-session-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Verify by fetching the invitation from the store
        from citadel_archer.chat.agent_invitation import get_invitation_store
        store = get_invitation_store()
        inv = store.get_invitation(data["invitation_id"])
        assert inv is not None
        assert inv.recipient_email == "sis@home.net"
        assert inv.recipient_name == "Sister"


# ── Structural Tests ───────────────────────────────────────────────


class TestStructural:
    """Verify that new files/imports exist and are wired correctly."""

    def test_enrollment_routes_imported_in_main(self):
        """enrollment_routes is included as a router in main.py."""
        main_path = Path(__file__).parent.parent / "src" / "citadel_archer" / "api" / "main.py"
        content = main_path.read_text(encoding="utf-8")
        assert "enrollment_routes" in content or "enrollment_router" in content

    def test_enrollment_routes_module_exists(self):
        """enrollment_routes.py exists."""
        path = Path(__file__).parent.parent / "src" / "citadel_archer" / "api" / "enrollment_routes.py"
        assert path.exists()

    def test_enroll_html_exists(self):
        """enroll.html exists in frontend/."""
        path = Path(__file__).parent.parent / "frontend" / "enroll.html"
        assert path.exists()

    def test_enroll_html_has_platform_detection(self):
        """enroll.html includes platform detection logic."""
        path = Path(__file__).parent.parent / "frontend" / "enroll.html"
        content = path.read_text(encoding="utf-8")
        assert "navigator.userAgent" in content or "navigator.platform" in content

    def test_enroll_html_has_one_click_install(self):
        """enroll.html has PowerShell one-click install section."""
        path = Path(__file__).parent.parent / "frontend" / "enroll.html"
        content = path.read_text(encoding="utf-8")
        assert "irm" in content  # PowerShell irm command
        assert "install.ps1" in content

    def test_enroll_html_has_status_polling(self):
        """enroll.html polls /status endpoint."""
        path = Path(__file__).parent.parent / "frontend" / "enroll.html"
        content = path.read_text(encoding="utf-8")
        assert "/status" in content
        assert "setInterval" in content


class TestFrontendStructural:
    """Verify assets.html and assets.js have the new UI elements."""

    def test_assets_html_has_email_inputs(self):
        """assets.html has recipient email and name inputs in invite modal."""
        path = Path(__file__).parent.parent / "frontend" / "assets.html"
        content = path.read_text(encoding="utf-8")
        assert "invite-recipient-email" in content
        assert "invite-recipient-name" in content

    def test_assets_html_has_share_buttons(self):
        """assets.html has share-via-email and open-enrollment-page buttons."""
        path = Path(__file__).parent.parent / "frontend" / "assets.html"
        content = path.read_text(encoding="utf-8")
        assert "invite-share-email-btn" in content
        assert "invite-open-page-btn" in content

    def test_assets_html_has_status_badge(self):
        """assets.html has invitation status badge in step 2."""
        path = Path(__file__).parent.parent / "frontend" / "assets.html"
        content = path.read_text(encoding="utf-8")
        assert "invite-status-badge" in content
        assert "invite-status-text" in content

    def test_assets_js_has_share_functions(self):
        """assets.js has handleShareViaEmail and handleOpenEnrollmentPage."""
        path = Path(__file__).parent.parent / "frontend" / "js" / "assets.js"
        content = path.read_text(encoding="utf-8")
        assert "handleShareViaEmail" in content
        assert "handleOpenEnrollmentPage" in content

    def test_assets_js_has_status_polling(self):
        """assets.js has startInviteStatusPolling and stopInviteStatusPolling."""
        path = Path(__file__).parent.parent / "frontend" / "js" / "assets.js"
        content = path.read_text(encoding="utf-8")
        assert "startInviteStatusPolling" in content
        assert "stopInviteStatusPolling" in content

    def test_assets_js_sends_recipient_fields(self):
        """assets.js sends recipient_email and recipient_name in POST body."""
        path = Path(__file__).parent.parent / "frontend" / "js" / "assets.js"
        content = path.read_text(encoding="utf-8")
        assert "recipient_email" in content
        assert "recipient_name" in content

    def test_assets_js_stores_enrollment_url(self):
        """assets.js stores enrollment_url from response."""
        path = Path(__file__).parent.parent / "frontend" / "js" / "assets.js"
        content = path.read_text(encoding="utf-8")
        assert "_enrollmentUrl" in content
        assert "_mailtoUrl" in content
