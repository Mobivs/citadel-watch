"""
Tests for Secure Invitation-Based Agent Enrollment (v0.3.22).

Covers:
- InvitationStore database initialization and schema
- Invitation creation (format, secret hashing, HMAC binding, TTL)
- Compact string parsing (valid + error cases)
- Verification and consumption (success, expiry, lockout, wrong secret, HMAC)
- One-time use guarantee (reuse rejection, concurrent attempts)
- Failed attempt tracking and lockout
- Admin operations (list, revoke, get, cleanup)
- API: POST /invitations (create, auth required, validation)
- API: GET /invitations (list, auth required, filtering)
- API: DELETE /invitations/{id} (revoke, auth required)
- API: POST /enroll (success, no auth needed, rate limit, error cases)
"""

import hashlib
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from citadel_archer.chat.agent_invitation import (
    COMPACT_STRING_VERSION,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TTL_SECONDS,
    AgentInvitation,
    InvitationStatus,
    InvitationStore,
    get_invitation_store,
)
from citadel_archer.chat.agent_registry import AgentRegistry
from citadel_archer.chat.agent_rate_limiter import AgentRateLimiter


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def inv_db_path(tmp_path):
    return str(tmp_path / "test_invitations.db")


@pytest.fixture
def store(inv_db_path):
    from citadel_archer.api import security
    old_token = security._SESSION_TOKEN
    security._SESSION_TOKEN = "test-hmac-key-for-invitations"
    store = InvitationStore(db_path=inv_db_path)
    yield store
    security._SESSION_TOKEN = old_token


@pytest.fixture
def agent_db_path(tmp_path):
    return str(tmp_path / "test_agents.db")


@pytest.fixture
def registry(agent_db_path):
    return AgentRegistry(db_path=agent_db_path)


@pytest.fixture
def limiter():
    return AgentRateLimiter()


@pytest.fixture
def session_token():
    return "test-session-token-for-invitations"


@pytest.fixture
def client(store, registry, limiter, session_token):
    """FastAPI test client with DI overrides for invitation testing."""
    from citadel_archer.api.main import app
    from citadel_archer.api import agent_api_routes
    from citadel_archer.api import security

    # Save old values
    old_registry = agent_api_routes._registry
    old_limiter = agent_api_routes._rate_limiter
    old_enroll_limiter = agent_api_routes._enroll_limiter
    old_token = security._SESSION_TOKEN

    # Inject test singletons
    agent_api_routes._registry = registry
    agent_api_routes._rate_limiter = limiter
    agent_api_routes._enroll_limiter = AgentRateLimiter()
    security._SESSION_TOKEN = session_token

    # Patch get_invitation_store to return our test store
    with patch(
        "citadel_archer.chat.agent_invitation.get_invitation_store",
        return_value=store,
    ):
        yield TestClient(app)

    # Restore
    agent_api_routes._registry = old_registry
    agent_api_routes._rate_limiter = old_limiter
    agent_api_routes._enroll_limiter = old_enroll_limiter
    security._SESSION_TOKEN = old_token


def _auth_header(session_token):
    return {"X-Session-Token": session_token}


# ── Database Initialization ──────────────────────────────────────────


class TestDatabaseInit:
    def test_creates_database_file(self, tmp_path):
        db_path = str(tmp_path / "sub" / "dir" / "inv.db")
        store = InvitationStore(db_path=db_path)
        assert store.db_path.exists()

    def test_creates_parent_directories(self, tmp_path):
        db_path = str(tmp_path / "deep" / "nested" / "inv.db")
        InvitationStore(db_path=db_path)
        assert (tmp_path / "deep" / "nested").is_dir()

    def test_idempotent_init(self, inv_db_path):
        from citadel_archer.api import security
        old_token = security._SESSION_TOKEN
        security._SESSION_TOKEN = "test-hmac-key"
        try:
            store1 = InvitationStore(db_path=inv_db_path)
            store2 = InvitationStore(db_path=inv_db_path)
            # Both should work without error
            inv1, _ = store1.create_invitation("A", "forge")
            inv2, _ = store2.create_invitation("B", "forge")
            assert inv1.invitation_id != inv2.invitation_id
        finally:
            security._SESSION_TOKEN = old_token


# ── Invitation Creation ──────────────────────────────────────────────


class TestInvitationCreation:
    def test_creates_invitation(self, store):
        inv, compact = store.create_invitation("VPS-Agent", "claude_code")
        assert inv.agent_name == "VPS-Agent"
        assert inv.agent_type == "claude_code"
        assert inv.status == InvitationStatus.PENDING
        assert inv.failed_attempts == 0

    def test_compact_string_format(self, store):
        _, compact = store.create_invitation("Agent", "forge")
        parts = compact.split(":")
        assert len(parts) == 3
        assert parts[0] == COMPACT_STRING_VERSION
        assert len(parts[1]) == 12  # invitation_id hex length

    def test_secret_not_stored_raw(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        # Extract raw_secret from compact string
        raw_secret = compact.split(":")[2]
        # secret_hash should be SHA-256 of raw_secret, not the raw value
        expected_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
        assert inv.secret_hash == expected_hash
        assert inv.secret_hash != raw_secret

    def test_sha256_hash_stored(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        raw_secret = compact.split(":")[2]
        computed = hashlib.sha256(raw_secret.encode()).hexdigest()
        assert inv.secret_hash == computed

    def test_hmac_tag_present(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        assert len(inv.hmac_tag) == 64  # SHA-256 hex digest

    def test_default_ttl(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        assert inv.ttl_seconds == DEFAULT_TTL_SECONDS

    def test_custom_ttl(self, store):
        inv, _ = store.create_invitation("Agent", "forge", ttl_seconds=3600)
        assert inv.ttl_seconds == 3600

    def test_ttl_clamped_min(self, store):
        inv, _ = store.create_invitation("Agent", "forge", ttl_seconds=1)
        assert inv.ttl_seconds >= 60

    def test_ttl_clamped_max(self, store):
        inv, _ = store.create_invitation("Agent", "forge", ttl_seconds=999999)
        assert inv.ttl_seconds <= 86400

    def test_expiry_set(self, store):
        inv, _ = store.create_invitation("Agent", "forge", ttl_seconds=600)
        created = datetime.fromisoformat(inv.created_at)
        expires = datetime.fromisoformat(inv.expires_at)
        delta = (expires - created).total_seconds()
        assert 599 <= delta <= 601

    def test_unique_ids(self, store):
        ids = set()
        for _ in range(10):
            inv, _ = store.create_invitation("Agent", "forge")
            ids.add(inv.invitation_id)
        assert len(ids) == 10

    def test_invalid_agent_type_rejected(self, store):
        with pytest.raises(ValueError, match="Invalid agent_type"):
            store.create_invitation("Agent", "invalid_type")


# ── Compact String Parsing ───────────────────────────────────────────


class TestCompactStringParsing:
    def test_valid_parse(self, store):
        _, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        assert len(inv_id) == 12
        assert len(raw_secret) > 0

    def test_wrong_version(self):
        with pytest.raises(ValueError, match="Unknown invitation version"):
            InvitationStore.parse_compact_string("CITADEL-99:abcdef012345:secret123")

    def test_missing_parts(self):
        with pytest.raises(ValueError, match="Invalid invitation format"):
            InvitationStore.parse_compact_string("CITADEL-1:onlyonepart")

    def test_invalid_hex_id(self):
        with pytest.raises(ValueError, match="Invalid invitation ID"):
            InvitationStore.parse_compact_string("CITADEL-1:not-hex-id!:secret123")

    def test_empty_secret(self):
        with pytest.raises(ValueError, match="Invalid enrollment secret"):
            InvitationStore.parse_compact_string("CITADEL-1:abcdef012345:")


# ── Verification and Consumption ─────────────────────────────────────


class TestVerification:
    def test_success(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        ok, err, result = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok is True
        assert err == ""
        assert result.status == InvitationStatus.REDEEMED
        assert result.redeemed_by_ip == "1.2.3.4"

    def test_reuse_rejected(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        # First use — success
        ok1, _, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok1 is True
        # Second use — rejected
        ok2, err2, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.5")
        assert ok2 is False
        assert err2 == "already_redeemed"

    def test_revoked_rejected(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        store.revoke_invitation(inv_id)
        ok, err, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok is False
        assert err == "revoked"

    def test_expired_rejected(self, store):
        inv, compact = store.create_invitation("Agent", "forge", ttl_seconds=60)
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        # Simulate expiry by setting expires_at to the past
        with store._lock:
            with store._connect() as conn:
                past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                conn.execute(
                    "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                    (past, inv_id),
                )
        ok, err, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok is False
        assert err == "expired"

    def test_locked_rejected(self, store):
        inv, compact = store.create_invitation("Agent", "forge", max_attempts=1)
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        # Use wrong secret to trigger lockout
        store.verify_and_consume(inv_id, "wrong-secret", "1.2.3.4")
        # Now correct secret should fail (locked)
        ok, err, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok is False
        assert err == "locked"

    def test_wrong_secret(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, _ = InvitationStore.parse_compact_string(compact)
        ok, err, _ = store.verify_and_consume(inv_id, "totally-wrong-secret", "1.2.3.4")
        assert ok is False
        assert err == "invalid_secret"

    def test_not_found(self, store):
        ok, err, _ = store.verify_and_consume("000000000000", "secret", "1.2.3.4")
        assert ok is False
        assert err == "not_found"

    def test_hmac_mismatch_on_tampered_id(self, store):
        """Verify that using a valid secret with a different invitation_id fails."""
        inv1, compact1 = store.create_invitation("Agent1", "forge")
        inv2, compact2 = store.create_invitation("Agent2", "forge")
        # Extract secret from inv1 but try with inv2's ID
        _, secret1 = InvitationStore.parse_compact_string(compact1)
        inv2_id, _ = InvitationStore.parse_compact_string(compact2)
        ok, err, _ = store.verify_and_consume(inv2_id, secret1, "1.2.3.4")
        assert ok is False
        assert err == "invalid_secret"


# ── One-Time Use Guarantee ───────────────────────────────────────────


class TestOneTimeUse:
    def test_second_verify_fails(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        ok1, _, _ = store.verify_and_consume(inv_id, raw_secret, "10.0.0.1")
        assert ok1 is True
        ok2, err2, _ = store.verify_and_consume(inv_id, raw_secret, "10.0.0.2")
        assert ok2 is False
        assert err2 == "already_redeemed"

    def test_concurrent_verify(self, store):
        """Only one of two concurrent verifications should succeed."""
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)

        results = []

        def try_verify(ip):
            ok, err, _ = store.verify_and_consume(inv_id, raw_secret, ip)
            results.append((ok, err))

        t1 = threading.Thread(target=try_verify, args=("10.0.0.1",))
        t2 = threading.Thread(target=try_verify, args=("10.0.0.2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        successes = sum(1 for ok, _ in results if ok)
        assert successes == 1


# ── Expiry ───────────────────────────────────────────────────────────


class TestExpiry:
    def test_ttl_expiry(self, store):
        inv, compact = store.create_invitation("Agent", "forge", ttl_seconds=60)
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        # Expire by backdating
        with store._lock:
            with store._connect() as conn:
                past = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
                conn.execute(
                    "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                    (past, inv_id),
                )
        ok, err, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok is False
        assert err == "expired"

    def test_cleanup_marks_expired(self, store):
        inv, _ = store.create_invitation("Agent", "forge", ttl_seconds=60)
        # Backdate expiry
        with store._lock:
            with store._connect() as conn:
                past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                conn.execute(
                    "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                    (past, inv.invitation_id),
                )
        count = store.cleanup_expired()
        assert count == 1
        updated = store.get_invitation(inv.invitation_id)
        assert updated.status == InvitationStatus.EXPIRED

    def test_cleanup_count(self, store):
        # Create 3 invitations, expire 2
        for i in range(3):
            store.create_invitation(f"Agent{i}", "forge")
        invs = store.list_invitations()
        with store._lock:
            with store._connect() as conn:
                past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                for inv in invs[:2]:
                    conn.execute(
                        "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                        (past, inv.invitation_id),
                    )
        count = store.cleanup_expired()
        assert count == 2


# ── Failed Attempt Tracking ──────────────────────────────────────────


class TestFailedAttemptTracking:
    def test_increments_on_wrong_secret(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, _ = InvitationStore.parse_compact_string(compact)
        store.verify_and_consume(inv_id, "bad-secret", "1.2.3.4")
        updated = store.get_invitation(inv_id)
        assert updated.failed_attempts == 1

    def test_lockout_after_max_attempts(self, store):
        inv, compact = store.create_invitation("Agent", "forge", max_attempts=3)
        inv_id, _ = InvitationStore.parse_compact_string(compact)
        for _ in range(3):
            store.verify_and_consume(inv_id, "bad-secret", "1.2.3.4")
        updated = store.get_invitation(inv_id)
        assert updated.status == InvitationStatus.LOCKED

    def test_locked_stays_locked(self, store):
        inv, compact = store.create_invitation("Agent", "forge", max_attempts=1)
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        # Trigger lockout
        store.verify_and_consume(inv_id, "bad-secret", "1.2.3.4")
        # Even with correct secret
        ok, err, _ = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        assert ok is False
        assert err == "locked"

    def test_ip_recorded(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, _ = InvitationStore.parse_compact_string(compact)
        store.verify_and_consume(inv_id, "bad-secret", "192.168.1.50")
        updated = store.get_invitation(inv_id)
        assert updated.last_attempt_ip == "192.168.1.50"

    def test_timestamp_recorded(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, _ = InvitationStore.parse_compact_string(compact)
        store.verify_and_consume(inv_id, "bad-secret", "1.2.3.4")
        updated = store.get_invitation(inv_id)
        assert updated.last_attempt_at != ""


# ── Admin Operations ─────────────────────────────────────────────────


class TestAdminOperations:
    def test_list_empty(self, store):
        result = store.list_invitations()
        assert result == []

    def test_list_all(self, store):
        store.create_invitation("A", "forge")
        store.create_invitation("B", "forge")
        result = store.list_invitations()
        assert len(result) == 2

    def test_list_filtered(self, store):
        inv, compact = store.create_invitation("A", "forge")
        store.create_invitation("B", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        pending = store.list_invitations(status_filter=InvitationStatus.PENDING)
        assert len(pending) == 1
        redeemed = store.list_invitations(status_filter=InvitationStatus.REDEEMED)
        assert len(redeemed) == 1

    def test_revoke_pending(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        revoked = store.revoke_invitation(inv.invitation_id)
        assert revoked is True
        updated = store.get_invitation(inv.invitation_id)
        assert updated.status == InvitationStatus.REVOKED

    def test_revoke_non_pending_fails(self, store):
        inv, compact = store.create_invitation("Agent", "forge")
        inv_id, raw_secret = InvitationStore.parse_compact_string(compact)
        store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
        # Already redeemed — can't revoke
        revoked = store.revoke_invitation(inv_id)
        assert revoked is False

    def test_get_by_id(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        result = store.get_invitation(inv.invitation_id)
        assert result is not None
        assert result.agent_name == "Agent"

    def test_get_nonexistent(self, store):
        result = store.get_invitation("000000000000")
        assert result is None

    def test_set_resulting_agent_id(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        store.set_resulting_agent_id(inv.invitation_id, "agent-123")
        updated = store.get_invitation(inv.invitation_id)
        assert updated.resulting_agent_id == "agent-123"


# ── to_dict ──────────────────────────────────────────────────────────


class TestToDict:
    def test_no_secret_in_dict(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        d = inv.to_dict()
        assert "secret_hash" not in d
        assert "hmac_tag" not in d

    def test_dict_fields(self, store):
        inv, _ = store.create_invitation("Agent", "forge")
        d = inv.to_dict()
        assert d["invitation_id"] == inv.invitation_id
        assert d["agent_name"] == "Agent"
        assert d["status"] == "pending"


# ── API: POST /invitations ───────────────────────────────────────────


class TestCreateInvitationEndpoint:
    def test_success(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "VPS-Bot", "agent_type": "claude_code"},
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "compact_string" in data
        assert data["compact_string"].startswith("CITADEL-1:")
        assert data["agent_name"] == "VPS-Bot"
        assert data["agent_type"] == "claude_code"

    def test_requires_auth(self, client):
        resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge"},
        )
        assert resp.status_code == 401

    def test_invalid_type(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "bad_type"},
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 400

    def test_custom_ttl(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/invitations",
            json={
                "agent_name": "Bot",
                "agent_type": "forge",
                "ttl_seconds": 3600,
            },
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json()["ttl_seconds"] == 3600


# ── API: GET /invitations ────────────────────────────────────────────


class TestListInvitationsEndpoint:
    def test_empty_list(self, client, session_token):
        resp = client.get(
            "/api/ext-agents/invitations",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_returns_data(self, client, session_token):
        # Create an invitation first
        client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge"},
            headers=_auth_header(session_token),
        )
        resp = client.get(
            "/api/ext-agents/invitations",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_requires_auth(self, client):
        resp = client.get("/api/ext-agents/invitations")
        assert resp.status_code == 401


# ── API: DELETE /invitations/{id} ────────────────────────────────────


class TestRevokeEndpoint:
    def test_success(self, client, session_token):
        create_resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge"},
            headers=_auth_header(session_token),
        )
        inv_id = create_resp.json()["invitation_id"]
        resp = client.delete(
            f"/api/ext-agents/invitations/{inv_id}",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    def test_not_found(self, client, session_token):
        resp = client.delete(
            "/api/ext-agents/invitations/000000000000",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 404

    def test_requires_auth(self, client):
        resp = client.delete("/api/ext-agents/invitations/abc123")
        assert resp.status_code == 401


# ── API: POST /enroll ────────────────────────────────────────────────


class TestEnrollEndpoint:
    def test_success_with_bearer_token(self, client, session_token):
        # Create invitation
        create_resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "VPS-Bot", "agent_type": "claude_code"},
            headers=_auth_header(session_token),
        )
        compact = create_resp.json()["compact_string"]

        # Enroll — no auth header needed
        resp = client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": compact},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_id" in data
        assert "api_token" in data
        assert data["agent_name"] == "VPS-Bot"
        assert data["agent_type"] == "claude_code"

    def test_no_auth_needed(self, client, session_token):
        create_resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge"},
            headers=_auth_header(session_token),
        )
        compact = create_resp.json()["compact_string"]
        # No auth headers
        resp = client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": compact},
        )
        assert resp.status_code == 200

    def test_invalid_string_format(self, client):
        resp = client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": "not-a-valid-invitation-string-at-all"},
        )
        assert resp.status_code == 400
        assert "format" in resp.json()["detail"].lower()

    def test_expired_invitation(self, client, session_token, store):
        create_resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge"},
            headers=_auth_header(session_token),
        )
        compact = create_resp.json()["compact_string"]
        inv_id = create_resp.json()["invitation_id"]

        # Backdate expiry
        with store._lock:
            with store._connect() as conn:
                past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
                conn.execute(
                    "UPDATE agent_invitations SET expires_at = ? WHERE invitation_id = ?",
                    (past, inv_id),
                )

        resp = client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": compact},
        )
        assert resp.status_code == 401

    def test_wrong_secret(self, client, session_token):
        create_resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge"},
            headers=_auth_header(session_token),
        )
        inv_id = create_resp.json()["invitation_id"]
        # Craft a string with correct ID but wrong secret
        bad_compact = f"CITADEL-1:{inv_id}:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        resp = client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": bad_compact},
        )
        assert resp.status_code == 401

    def test_locked_invitation(self, client, session_token, store):
        create_resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "Bot", "agent_type": "forge", "max_attempts": 1},
            headers=_auth_header(session_token),
        )
        inv_id = create_resp.json()["invitation_id"]
        compact = create_resp.json()["compact_string"]

        # Trigger lockout with wrong secret
        bad_compact = f"CITADEL-1:{inv_id}:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": bad_compact},
        )

        # Now even correct should be locked
        resp = client.post(
            "/api/ext-agents/enroll",
            json={"invitation_string": compact},
        )
        assert resp.status_code == 423

    def test_rate_limited(self, client, session_token):
        from citadel_archer.api import agent_api_routes

        # Create a limiter that always rejects
        class AlwaysReject(AgentRateLimiter):
            def check(self, key, limit):
                return False, 0

        old = agent_api_routes._enroll_limiter
        agent_api_routes._enroll_limiter = AlwaysReject()

        try:
            resp = client.post(
                "/api/ext-agents/enroll",
                json={"invitation_string": "CITADEL-1:abcdef012345:validsecretsecretvalidXYZ"},
            )
            assert resp.status_code == 429
        finally:
            agent_api_routes._enroll_limiter = old
