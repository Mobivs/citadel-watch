"""
Tests for External AI Agent REST API routes (Trigger 1b).

Covers:
- Registration requires session token (401 without)
- Send requires valid Bearer token (401 with bad)
- Send creates ChatMessage with correct from_id
- Rate limit returns 429
- Revoked agent gets 401
- List/delete/rotate-token work
- Invalid msg_type rejected
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from citadel_archer.chat.agent_registry import AgentRegistry
from citadel_archer.chat.agent_rate_limiter import AgentRateLimiter


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_agents.db")


@pytest.fixture
def registry(db_path):
    return AgentRegistry(db_path=db_path)


@pytest.fixture
def limiter():
    return AgentRateLimiter()


@pytest.fixture
def session_token():
    return "test-session-token-12345"


@pytest.fixture
def client(registry, limiter, session_token):
    """FastAPI test client with DI overrides."""
    from citadel_archer.api.main import app
    from citadel_archer.api import agent_api_routes
    from citadel_archer.api import security

    # Inject test singletons
    old_registry = agent_api_routes._registry
    old_limiter = agent_api_routes._rate_limiter
    old_token = security._SESSION_TOKEN

    agent_api_routes._registry = registry
    agent_api_routes._rate_limiter = limiter
    security._SESSION_TOKEN = session_token

    yield TestClient(app)

    # Restore
    agent_api_routes._registry = old_registry
    agent_api_routes._rate_limiter = old_limiter
    security._SESSION_TOKEN = old_token


def _auth_header(session_token):
    return {"X-Session-Token": session_token}


def _bearer_header(token):
    return {"Authorization": f"Bearer {token}"}


# ── Registration ──────────────────────────────────────────────────────


class TestRegister:
    def test_register_success(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/register",
            json={"name": "Forge-1", "agent_type": "forge"},
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_id" in data
        assert "api_token" in data
        assert data["name"] == "Forge-1"
        assert data["agent_type"] == "forge"
        assert data["rate_limit_per_min"] == 60

    def test_register_requires_session_token(self, client):
        resp = client.post(
            "/api/ext-agents/register",
            json={"name": "Forge-1", "agent_type": "forge"},
        )
        assert resp.status_code == 401

    def test_register_invalid_session_token(self, client):
        resp = client.post(
            "/api/ext-agents/register",
            json={"name": "Forge-1", "agent_type": "forge"},
            headers={"X-Session-Token": "wrong-token"},
        )
        assert resp.status_code == 401

    def test_register_invalid_agent_type(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/register",
            json={"name": "Bad", "agent_type": "invalid"},
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 400

    def test_register_custom_rate_limit(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/register",
            json={"name": "Custom", "agent_type": "custom", "rate_limit_per_min": 100},
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json()["rate_limit_per_min"] == 100


# ── Send Message ──────────────────────────────────────────────────────


class TestSendMessage:
    def test_send_requires_bearer_token(self, client):
        resp = client.post(
            "/api/ext-agents/send",
            json={"text": "Hello"},
        )
        assert resp.status_code == 401

    def test_send_invalid_bearer_token(self, client):
        resp = client.post(
            "/api/ext-agents/send",
            json={"text": "Hello"},
            headers=_bearer_header("bogus-token"),
        )
        assert resp.status_code == 401

    def test_send_success(self, client, session_token, registry):
        # Register agent first
        agent_id, token = registry.register_agent("Forge", "forge")

        # Mock ChatManager.send to avoid full pipeline
        with patch(
            "citadel_archer.api.chat_routes.get_chat_manager"
        ) as mock_get_cm:
            mock_cm = MagicMock()
            mock_cm.send = AsyncMock()
            mock_get_cm.return_value = mock_cm

            resp = client.post(
                "/api/ext-agents/send",
                json={"text": "Desktop agent is offline"},
                headers=_bearer_header(token),
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "sent"
        assert "message_id" in data

        # Verify ChatMessage was created correctly
        mock_cm.send.assert_called_once()
        msg = mock_cm.send.call_args[0][0]
        assert msg.from_id == f"ext-agent:{agent_id}"
        assert msg.to_id == "citadel"
        assert msg.msg_type.value == "text"
        assert msg.payload["text"] == "Desktop agent is offline"
        assert msg.payload["agent_name"] == "Forge"
        assert msg.payload["agent_type"] == "forge"

    def test_send_records_message_stats(self, client, registry):
        agent_id, token = registry.register_agent("Forge", "forge")

        with patch(
            "citadel_archer.api.chat_routes.get_chat_manager"
        ) as mock_get_cm:
            mock_cm = MagicMock()
            mock_cm.send = AsyncMock()
            mock_get_cm.return_value = mock_cm

            client.post(
                "/api/ext-agents/send",
                json={"text": "test"},
                headers=_bearer_header(token),
            )

        agent = registry.get_agent(agent_id)
        assert agent["message_count"] == 1

    def test_send_invalid_msg_type(self, client, registry):
        _, token = registry.register_agent("Forge", "forge")

        with patch(
            "citadel_archer.api.chat_routes.get_chat_manager"
        ) as mock_get_cm:
            mock_cm = MagicMock()
            mock_cm.send = AsyncMock()
            mock_get_cm.return_value = mock_cm

            resp = client.post(
                "/api/ext-agents/send",
                json={"text": "test", "msg_type": "invalid_type"},
                headers=_bearer_header(token),
            )

        assert resp.status_code == 400

    def test_send_event_type(self, client, registry):
        agent_id, token = registry.register_agent("Forge", "forge")

        with patch(
            "citadel_archer.api.chat_routes.get_chat_manager"
        ) as mock_get_cm:
            mock_cm = MagicMock()
            mock_cm.send = AsyncMock()
            mock_get_cm.return_value = mock_cm

            resp = client.post(
                "/api/ext-agents/send",
                json={"text": "Critical threat detected", "msg_type": "event"},
                headers=_bearer_header(token),
            )

        assert resp.status_code == 200
        msg = mock_get_cm.return_value.send.call_args[0][0]
        assert msg.msg_type.value == "event"


# ── Rate Limiting ─────────────────────────────────────────────────────


class TestRateLimiting:
    def test_rate_limit_returns_429(self, client, registry, limiter):
        agent_id, token = registry.register_agent("Forge", "forge", rate_limit_per_min=2)

        with patch(
            "citadel_archer.api.chat_routes.get_chat_manager"
        ) as mock_get_cm:
            mock_cm = MagicMock()
            mock_cm.send = AsyncMock()
            mock_get_cm.return_value = mock_cm

            # Send 2 messages (within limit)
            for _ in range(2):
                resp = client.post(
                    "/api/ext-agents/send",
                    json={"text": "test"},
                    headers=_bearer_header(token),
                )
                assert resp.status_code == 200

            # 3rd should be rate limited
            resp = client.post(
                "/api/ext-agents/send",
                json={"text": "test"},
                headers=_bearer_header(token),
            )
            assert resp.status_code == 429
            assert "Retry-After" in resp.headers


# ── Revoked Agent ─────────────────────────────────────────────────────


class TestRevokedAgent:
    def test_revoked_agent_cannot_send(self, client, registry):
        agent_id, token = registry.register_agent("Forge", "forge")
        registry.revoke_agent(agent_id)

        resp = client.post(
            "/api/ext-agents/send",
            json={"text": "test"},
            headers=_bearer_header(token),
        )
        assert resp.status_code == 401


# ── List Agents ───────────────────────────────────────────────────────


class TestListAgents:
    def test_list_empty(self, client, session_token):
        resp = client.get(
            "/api/ext-agents/",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_agents(self, client, session_token, registry):
        registry.register_agent("A", "forge")
        registry.register_agent("B", "openclaw")

        resp = client.get(
            "/api/ext-agents/",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        names = {a["name"] for a in data}
        assert names == {"A", "B"}

    def test_list_requires_session_token(self, client):
        resp = client.get("/api/ext-agents/")
        assert resp.status_code == 401


# ── Delete (Revoke) ──────────────────────────────────────────────────


class TestDelete:
    def test_delete_agent(self, client, session_token, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")

        resp = client.delete(
            f"/api/ext-agents/{agent_id}",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

        agent = registry.get_agent(agent_id)
        assert agent["status"] == "revoked"

    def test_delete_nonexistent(self, client, session_token):
        resp = client.delete(
            "/api/ext-agents/nonexistent",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 404

    def test_delete_requires_session_token(self, client, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        resp = client.delete(f"/api/ext-agents/{agent_id}")
        assert resp.status_code == 401


# ── Token Rotation ────────────────────────────────────────────────────


class TestRotateToken:
    def test_rotate_returns_new_token(self, client, session_token, registry):
        agent_id, old_token = registry.register_agent("Forge", "forge")

        resp = client.post(
            f"/api/ext-agents/{agent_id}/rotate-token",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["api_token"] != old_token
        assert data["agent_id"] == agent_id

    def test_old_token_fails_after_rotation(self, client, session_token, registry):
        agent_id, old_token = registry.register_agent("Forge", "forge")

        client.post(
            f"/api/ext-agents/{agent_id}/rotate-token",
            headers=_auth_header(session_token),
        )

        resp = client.post(
            "/api/ext-agents/send",
            json={"text": "test"},
            headers=_bearer_header(old_token),
        )
        assert resp.status_code == 401

    def test_new_token_works_after_rotation(self, client, session_token, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")

        resp = client.post(
            f"/api/ext-agents/{agent_id}/rotate-token",
            headers=_auth_header(session_token),
        )
        new_token = resp.json()["api_token"]

        with patch(
            "citadel_archer.api.chat_routes.get_chat_manager"
        ) as mock_get_cm:
            mock_cm = MagicMock()
            mock_cm.send = AsyncMock()
            mock_get_cm.return_value = mock_cm

            resp = client.post(
                "/api/ext-agents/send",
                json={"text": "test"},
                headers=_bearer_header(new_token),
            )
        assert resp.status_code == 200

    def test_rotate_nonexistent(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/nonexistent/rotate-token",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 404

    def test_rotate_requires_session_token(self, client, registry):
        agent_id, _ = registry.register_agent("Forge", "forge")
        resp = client.post(f"/api/ext-agents/{agent_id}/rotate-token")
        assert resp.status_code == 401

    def test_rotate_revoked_agent_fails(self, client, session_token, registry):
        """C2 fix: Token rotation must fail on revoked agents."""
        agent_id, _ = registry.register_agent("Forge", "forge")
        registry.revoke_agent(agent_id)

        resp = client.post(
            f"/api/ext-agents/{agent_id}/rotate-token",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 404


# ── Participants Integration ──────────────────────────────────────────


class TestParticipants:
    def test_ext_agents_appear_in_participants(self, client, session_token, registry):
        """S9: External agents should appear in /api/chat/participants."""
        registry.register_agent("Forge-1", "forge")

        resp = client.get(
            "/api/chat/participants",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        participants = resp.json()["participants"]
        ext_agents = [p for p in participants if p.get("type") == "external_agent"]
        assert len(ext_agents) == 1
        assert ext_agents[0]["label"] == "Forge-1"
        assert ext_agents[0]["agent_type"] == "forge"
        assert ext_agents[0]["id"].startswith("ext-agent:")

    def test_revoked_agents_hidden_from_participants(self, client, session_token, registry):
        """Revoked agents should not appear in the participants list."""
        agent_id, _ = registry.register_agent("Forge-1", "forge")
        registry.revoke_agent(agent_id)

        resp = client.get(
            "/api/chat/participants",
            headers=_auth_header(session_token),
        )
        assert resp.status_code == 200
        participants = resp.json()["participants"]
        ext_agents = [p for p in participants if p.get("type") == "external_agent"]
        assert len(ext_agents) == 0
