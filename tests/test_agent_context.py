"""
Tests for Agent Context Delivery System (v0.3.44).

Covers:
- Default AI and Shield templates: content, placeholders, structure
- generate_context(): AI vs Shield type selection, placeholder filling,
  custom template override, extra_vars, fallback on error
- Template accessors: get/set/reset for both AI and Shield templates
- API routes: GET /context (agent auth), GET/PUT/DELETE /context/templates (admin)
- Shield routes: operational_context in enrollment response, GET /shield/agents/context
- Onboarding prompts: generate_onboarding_prompt(), default templates, route integration
"""

import pytest
from unittest.mock import patch, MagicMock

from citadel_archer.chat.agent_context import (
    DEFAULT_AI_TEMPLATE,
    DEFAULT_SHIELD_TEMPLATE,
    DEFAULT_AI_ONBOARDING_PROMPT,
    DEFAULT_SHIELD_ONBOARDING_PROMPT,
    PREF_KEY_AI_TEMPLATE,
    PREF_KEY_SHIELD_TEMPLATE,
    generate_context,
    generate_onboarding_prompt,
    get_ai_template,
    set_ai_template,
    reset_ai_template,
    get_shield_template,
    set_shield_template,
    reset_shield_template,
    _SafeDict,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def mock_prefs(tmp_path):
    """Create a real UserPreferences backed by a temp database."""
    from citadel_archer.core.user_preferences import UserPreferences
    prefs = UserPreferences(db_path=str(tmp_path / "test_prefs.db"))
    with patch("citadel_archer.chat.agent_context._get_prefs", return_value=prefs):
        yield prefs


# ── Default Template Content ─────────────────────────────────────────


class TestDefaultAITemplate:
    """Verify the default AI template has the right structure and content."""

    def test_contains_identity_section(self):
        assert "Citadel Archer" in DEFAULT_AI_TEMPLATE
        assert "{agent_name}" in DEFAULT_AI_TEMPLATE

    def test_contains_api_reference(self):
        assert "/api/ext-agents/" in DEFAULT_AI_TEMPLATE
        assert "heartbeat" in DEFAULT_AI_TEMPLATE
        assert "inbox" in DEFAULT_AI_TEMPLATE
        assert "capabilities" in DEFAULT_AI_TEMPLATE
        assert "delegate" in DEFAULT_AI_TEMPLATE

    def test_contains_shield_endpoints(self):
        assert "/api/shield/threats/remote-shield" in DEFAULT_AI_TEMPLATE
        assert "patch-status" in DEFAULT_AI_TEMPLATE

    def test_contains_auth_instructions(self):
        assert "Authorization: Bearer" in DEFAULT_AI_TEMPLATE

    def test_contains_rules(self):
        assert "NEVER" in DEFAULT_AI_TEMPLATE
        assert "credentials" in DEFAULT_AI_TEMPLATE.lower() or "API token" in DEFAULT_AI_TEMPLATE

    def test_contains_escalation_protocol(self):
        assert "autonomous" in DEFAULT_AI_TEMPLATE.lower()
        assert "coordinator" in DEFAULT_AI_TEMPLATE.lower()

    def test_has_all_standard_placeholders(self):
        for placeholder in ["{agent_name}", "{agent_id}", "{agent_type}",
                            "{coordinator_url}", "{security_level}"]:
            assert placeholder in DEFAULT_AI_TEMPLATE

    def test_getting_started_section(self):
        assert "Getting Started" in DEFAULT_AI_TEMPLATE


class TestDefaultShieldTemplate:
    """Verify the default Shield template has the right structure."""

    def test_contains_identity_section(self):
        assert "{agent_name}" in DEFAULT_SHIELD_TEMPLATE
        assert "{agent_id}" in DEFAULT_SHIELD_TEMPLATE

    def test_contains_operational_params(self):
        assert "Heartbeat interval" in DEFAULT_SHIELD_TEMPLATE
        assert "Scan interval" in DEFAULT_SHIELD_TEMPLATE

    def test_contains_api_endpoints(self):
        assert "/api/shield/" in DEFAULT_SHIELD_TEMPLATE
        assert "heartbeat" in DEFAULT_SHIELD_TEMPLATE
        assert "threats/remote-shield" in DEFAULT_SHIELD_TEMPLATE
        assert "commands/ack" in DEFAULT_SHIELD_TEMPLATE

    def test_contains_threat_report_format(self):
        assert "severity" in DEFAULT_SHIELD_TEMPLATE
        assert "category" in DEFAULT_SHIELD_TEMPLATE

    def test_has_all_standard_placeholders(self):
        for placeholder in ["{agent_name}", "{agent_id}", "{agent_type}",
                            "{coordinator_url}", "{security_level}"]:
            assert placeholder in DEFAULT_SHIELD_TEMPLATE


# ── SafeDict ─────────────────────────────────────────────────────────


class TestSafeDict:
    def test_returns_value_for_existing_key(self):
        d = _SafeDict(a="hello")
        assert d["a"] == "hello"

    def test_returns_placeholder_for_missing_key(self):
        d = _SafeDict(a="hello")
        assert d["missing"] == "{missing}"

    def test_format_map_with_missing_keys(self):
        template = "Hello {name}, your id is {id}"
        result = template.format_map(_SafeDict(name="Alice"))
        assert result == "Hello Alice, your id is {id}"


# ── generate_context() ──────────────────────────────────────────────


class TestGenerateContext:
    def test_ai_type_gets_ai_template(self, mock_prefs):
        context = generate_context(
            agent_id="test-123",
            agent_name="TestBot",
            agent_type="claude_code",
        )
        # AI template mentions "Remote Agent Instructions"
        assert "Remote Agent Instructions" in context
        # Agent name should be filled in
        assert "TestBot" in context
        assert "test-123" in context

    def test_shield_type_gets_shield_template(self, mock_prefs):
        context = generate_context(
            agent_id="shield-456",
            agent_name="MyVPS",
            agent_type="vps",
        )
        # Shield template mentions "Shield Agent Configuration"
        assert "Shield Agent Configuration" in context
        assert "MyVPS" in context
        assert "shield-456" in context

    def test_forge_type_gets_ai_template(self, mock_prefs):
        context = generate_context(
            agent_id="forge-789",
            agent_name="ForgeBot",
            agent_type="forge",
        )
        assert "Remote Agent Instructions" in context

    def test_workstation_type_gets_shield_template(self, mock_prefs):
        context = generate_context(
            agent_id="ws-001",
            agent_name="Workstation",
            agent_type="workstation",
        )
        assert "Shield Agent Configuration" in context

    def test_unknown_type_gets_ai_template(self, mock_prefs):
        """Unknown agent types should get the AI template (safer default)."""
        context = generate_context(
            agent_id="unknown-001",
            agent_name="Mystery",
            agent_type="totally_unknown",
        )
        assert "Remote Agent Instructions" in context

    def test_coordinator_url_filled(self, mock_prefs):
        context = generate_context(
            agent_id="test-123",
            agent_name="TestBot",
            agent_type="claude_code",
            coordinator_url="https://citadel.example.com",
        )
        assert "https://citadel.example.com" in context

    def test_security_level_filled(self, mock_prefs):
        context = generate_context(
            agent_id="test-123",
            agent_name="TestBot",
            agent_type="claude_code",
            security_level="Sentinel",
        )
        assert "Sentinel" in context

    def test_empty_coordinator_url(self, mock_prefs):
        """Should not crash with empty coordinator_url."""
        context = generate_context(
            agent_id="test-123",
            agent_name="TestBot",
            agent_type="claude_code",
            coordinator_url="",
        )
        assert "TestBot" in context

    def test_extra_vars_injected(self, mock_prefs):
        """Extra vars should be available for custom templates."""
        # Set a custom template that uses an extra var
        mock_prefs.set(PREF_KEY_AI_TEMPLATE, "Hello {agent_name}, region={region}")
        context = generate_context(
            agent_id="test-123",
            agent_name="TestBot",
            agent_type="claude_code",
            extra_vars={"region": "us-east-1"},
        )
        assert "region=us-east-1" in context

    def test_trailing_slash_stripped_from_url(self, mock_prefs):
        context = generate_context(
            agent_id="test-123",
            agent_name="TestBot",
            agent_type="claude_code",
            coordinator_url="https://citadel.example.com/",
        )
        # Should not have double slashes in URL paths
        assert "https://citadel.example.com/" not in context or \
               "https://citadel.example.com/api" in context


# ── Template Accessors ───────────────────────────────────────────────


class TestTemplateAccessors:
    def test_get_ai_template_default(self, mock_prefs):
        """Without custom, returns default."""
        result = get_ai_template()
        assert result == DEFAULT_AI_TEMPLATE

    def test_set_and_get_ai_template(self, mock_prefs):
        custom = "Custom AI template for {agent_name}"
        set_ai_template(custom)
        assert get_ai_template() == custom

    def test_reset_ai_template(self, mock_prefs):
        set_ai_template("Custom")
        reset_ai_template()
        assert get_ai_template() == DEFAULT_AI_TEMPLATE

    def test_get_shield_template_default(self, mock_prefs):
        result = get_shield_template()
        assert result == DEFAULT_SHIELD_TEMPLATE

    def test_set_and_get_shield_template(self, mock_prefs):
        custom = "Custom Shield template for {agent_name}"
        set_shield_template(custom)
        assert get_shield_template() == custom

    def test_reset_shield_template(self, mock_prefs):
        set_shield_template("Custom")
        reset_shield_template()
        assert get_shield_template() == DEFAULT_SHIELD_TEMPLATE

    def test_custom_template_used_in_generate(self, mock_prefs):
        """generate_context should pick up admin-customized template."""
        custom = "CUSTOM: Agent {agent_name} (ID: {agent_id})"
        set_ai_template(custom)
        context = generate_context(
            agent_id="x",
            agent_name="Bot",
            agent_type="claude_code",
        )
        assert context == "CUSTOM: Agent Bot (ID: x)"


# ── API Route Tests ──────────────────────────────────────────────────


@pytest.fixture
def session_token():
    return "test-session-token-for-context"


@pytest.fixture
def client(tmp_path, session_token):
    """FastAPI test client with DI overrides for agent context tests."""
    from fastapi.testclient import TestClient
    from citadel_archer.api.main import app
    from citadel_archer.api import agent_api_routes, security
    from citadel_archer.chat.agent_registry import AgentRegistry
    from citadel_archer.chat.agent_rate_limiter import AgentRateLimiter
    from citadel_archer.core.user_preferences import UserPreferences

    # Create test singletons
    registry = AgentRegistry(db_path=str(tmp_path / "test_agents.db"))
    limiter = AgentRateLimiter()
    prefs = UserPreferences(db_path=str(tmp_path / "test_prefs.db"))

    # Save originals
    old_registry = agent_api_routes._registry
    old_limiter = agent_api_routes._rate_limiter
    old_token = security._SESSION_TOKEN

    # Inject test singletons
    agent_api_routes._registry = registry
    agent_api_routes._rate_limiter = limiter
    security._SESSION_TOKEN = session_token

    # Patch UserPreferences to use test instance
    with patch(
        "citadel_archer.chat.agent_context._get_prefs",
        return_value=prefs,
    ):
        yield TestClient(app)

    # Restore
    agent_api_routes._registry = old_registry
    agent_api_routes._rate_limiter = old_limiter
    security._SESSION_TOKEN = old_token


def _admin_header(session_token):
    return {"X-Session-Token": session_token}


def _bearer_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestContextEndpoint:
    """Test GET /api/ext-agents/context (agent-authenticated)."""

    def test_context_requires_auth(self, client):
        resp = client.get("/api/ext-agents/context")
        assert resp.status_code == 401

    def test_context_returns_instructions(self, client, session_token):
        # Register an agent first
        resp = client.post(
            "/api/ext-agents/register",
            json={"name": "TestBot", "agent_type": "claude_code"},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200
        token = resp.json()["api_token"]

        # Fetch context
        resp = client.get(
            "/api/ext-agents/context",
            headers=_bearer_header(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "operational_context" in data
        assert "Citadel Archer" in data["operational_context"]
        assert "TestBot" in data["operational_context"]


class TestTemplateManagementEndpoints:
    """Test admin template CRUD endpoints."""

    def test_list_templates_requires_session(self, client):
        resp = client.get("/api/ext-agents/context/templates")
        assert resp.status_code == 401

    def test_list_templates(self, client, session_token):
        resp = client.get(
            "/api/ext-agents/context/templates",
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "templates" in data
        assert "ai" in data["templates"]
        assert "shield" in data["templates"]
        assert data["templates"]["ai"]["is_custom"] is False
        assert data["templates"]["shield"]["is_custom"] is False
        assert "Citadel Archer" in data["templates"]["ai"]["template"]

    def test_update_ai_template(self, client, session_token):
        custom = "Custom AI instructions for {agent_name} (id: {agent_id})"
        resp = client.put(
            "/api/ext-agents/context/templates/ai",
            json={"template": custom},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200

        # Verify it's now custom
        resp = client.get(
            "/api/ext-agents/context/templates",
            headers=_admin_header(session_token),
        )
        data = resp.json()
        assert data["templates"]["ai"]["is_custom"] is True
        assert data["templates"]["ai"]["template"] == custom

    def test_update_shield_template(self, client, session_token):
        custom = "Custom Shield instructions for {agent_name}"
        resp = client.put(
            "/api/ext-agents/context/templates/shield",
            json={"template": custom},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200

    def test_update_invalid_type(self, client, session_token):
        resp = client.put(
            "/api/ext-agents/context/templates/invalid",
            json={"template": "A valid length template body for testing"},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 400

    def test_reset_ai_template(self, client, session_token):
        # Set custom first
        client.put(
            "/api/ext-agents/context/templates/ai",
            json={"template": "Custom for {agent_name}"},
            headers=_admin_header(session_token),
        )

        # Reset
        resp = client.delete(
            "/api/ext-agents/context/templates/ai",
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200

        # Verify back to default
        resp = client.get(
            "/api/ext-agents/context/templates",
            headers=_admin_header(session_token),
        )
        assert resp.json()["templates"]["ai"]["is_custom"] is False

    def test_reset_invalid_type(self, client, session_token):
        resp = client.delete(
            "/api/ext-agents/context/templates/invalid",
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 400

    def test_template_too_short(self, client, session_token):
        resp = client.put(
            "/api/ext-agents/context/templates/ai",
            json={"template": "short"},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 422  # Pydantic validation: min_length=10


# ── Shield Route Context Tests ───────────────────────────────────────


class TestShieldEnrollmentContext:
    """Test that Shield enrollment responses include operational_context."""

    def test_register_includes_context(self, tmp_path):
        """Direct registration should include operational_context."""
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app
        from citadel_archer.api import remote_shield_routes
        from citadel_archer.remote.shield_database import RemoteShieldDatabase
        from citadel_archer.core.user_preferences import UserPreferences

        db = RemoteShieldDatabase(db_path=str(tmp_path / "shield.db"))
        prefs = UserPreferences(db_path=str(tmp_path / "prefs.db"))

        old_db = remote_shield_routes._shield_db
        remote_shield_routes._shield_db = db

        with patch(
            "citadel_archer.chat.agent_context._get_prefs",
            return_value=prefs,
        ):
            client = TestClient(app)
            resp = client.post(
                "/api/agents/register",
                json={
                    "hostname": "test-vps-01",
                    "ip": "10.0.0.1",
                    "platform": "linux",
                },
            )

        remote_shield_routes._shield_db = old_db

        assert resp.status_code == 200
        data = resp.json()
        assert "operational_context" in data
        assert len(data["operational_context"]) > 50
        # Shield template content
        assert "Shield Agent Configuration" in data["operational_context"]
        assert "test-vps-01" in data["operational_context"]
        # Coordinator URL should be populated from request.base_url
        assert "http://testserver" in data["operational_context"]


# ── Onboarding Prompt Templates ─────────────────────────────────────


class TestDefaultAIOnboardingTemplate:
    """Verify the default AI onboarding prompt has the right structure."""

    def test_contains_citadel_archer_description(self):
        assert "Citadel Archer" in DEFAULT_AI_ONBOARDING_PROMPT
        assert "cybersecurity" in DEFAULT_AI_ONBOARDING_PROMPT.lower()

    def test_establishes_trust_via_first_person(self):
        """Prompt must be written as if the operator is speaking directly."""
        lower = DEFAULT_AI_ONBOARDING_PROMPT.lower()
        assert "self-hosted" in lower
        assert "i built" in lower or "my own" in lower or "my self-hosted" in lower

    def test_framed_as_task(self):
        """Must start with a task framing so Claude Code treats it as a request."""
        assert DEFAULT_AI_ONBOARDING_PROMPT.strip().startswith("Please execute")

    def test_contains_enrollment_instructions(self):
        assert "/api/ext-agents/enroll" in DEFAULT_AI_ONBOARDING_PROMPT
        assert "invitation_string" in DEFAULT_AI_ONBOARDING_PROMPT

    def test_contains_post_enrollment_steps(self):
        assert "heartbeat" in DEFAULT_AI_ONBOARDING_PROMPT
        assert "capabilities" in DEFAULT_AI_ONBOARDING_PROMPT
        assert "inbox" in DEFAULT_AI_ONBOARDING_PROMPT

    def test_contains_curl_example(self):
        assert "curl" in DEFAULT_AI_ONBOARDING_PROMPT

    def test_has_all_placeholders(self):
        for placeholder in ["{agent_name}",
                            "{coordinator_url}", "{invitation_string}",
                            "{ttl_minutes}"]:
            assert placeholder in DEFAULT_AI_ONBOARDING_PROMPT

    def test_warns_about_api_token(self):
        assert "api_token" in DEFAULT_AI_ONBOARDING_PROMPT
        assert "only shown once" in DEFAULT_AI_ONBOARDING_PROMPT.lower() or \
               "shown only once" in DEFAULT_AI_ONBOARDING_PROMPT.lower()

    def test_no_urgency_language(self):
        """Prompt should avoid social-engineering-style urgency framing."""
        lower = DEFAULT_AI_ONBOARDING_PROMPT.lower()
        assert "expires in" not in lower
        assert "hurry" not in lower


class TestDefaultShieldOnboardingTemplate:
    """Verify the default Shield onboarding prompt has the right structure."""

    def test_contains_shield_enrollment(self):
        assert "Shield" in DEFAULT_SHIELD_ONBOARDING_PROMPT
        assert "Citadel Archer" in DEFAULT_SHIELD_ONBOARDING_PROMPT

    def test_establishes_trust_context(self):
        lower = DEFAULT_SHIELD_ONBOARDING_PROMPT.lower()
        assert "self-hosted" in lower
        assert "operator" in lower

    def test_contains_enrollment_curl(self):
        assert "curl" in DEFAULT_SHIELD_ONBOARDING_PROMPT
        assert "/api/shield/agents/enroll" in DEFAULT_SHIELD_ONBOARDING_PROMPT

    def test_contains_script_option(self):
        assert "citadel_shield.py" in DEFAULT_SHIELD_ONBOARDING_PROMPT

    def test_has_all_placeholders(self):
        for placeholder in ["{agent_name}", "{agent_type}",
                            "{coordinator_url}", "{invitation_string}",
                            "{ttl_minutes}"]:
            assert placeholder in DEFAULT_SHIELD_ONBOARDING_PROMPT

    def test_explains_hostname_ip_purpose(self):
        """Prompt should explain why hostname/IP are sent (to reassure safety filters)."""
        lower = DEFAULT_SHIELD_ONBOARDING_PROMPT.lower()
        assert "identify" in lower or "dashboard" in lower


# ── generate_onboarding_prompt() ────────────────────────────────────


class TestGenerateOnboardingPrompt:
    def test_ai_type_gets_ai_onboarding(self, mock_prefs):
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:abc:xyz",
            agent_name="TestBot",
            agent_type="claude_code",
            coordinator_url="https://my.citadel.com",
            ttl_seconds=600,
        )
        assert "Remote Security Agent" in prompt
        assert "TestBot" in prompt
        assert "CITADEL-1:abc:xyz" in prompt
        assert "https://my.citadel.com" in prompt
        assert "10 minutes" in prompt

    def test_shield_type_gets_shield_onboarding(self, mock_prefs):
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:def:uvw",
            agent_name="MyVPS",
            agent_type="vps",
            coordinator_url="https://shield.example.com",
            ttl_seconds=300,
        )
        assert "Shield Agent" in prompt
        assert "MyVPS" in prompt
        assert "CITADEL-1:def:uvw" in prompt
        assert "https://shield.example.com" in prompt

    def test_invitation_string_in_curl_command(self, mock_prefs):
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:testid:testsecret",
            agent_name="Bot",
            agent_type="claude_code",
            coordinator_url="https://c.example.com",
        )
        # The invitation string should appear in the curl example
        assert "CITADEL-1:testid:testsecret" in prompt
        assert "curl" in prompt

    def test_ttl_minutes_calculated(self, mock_prefs):
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:a:b",
            agent_name="Bot",
            agent_type="forge",
            ttl_seconds=1800,
        )
        assert "30 minutes" in prompt

    def test_ttl_minimum_one_minute(self, mock_prefs):
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:a:b",
            agent_name="Bot",
            agent_type="forge",
            ttl_seconds=30,  # 30 seconds → should show 1 minute minimum
        )
        assert "1 minute" in prompt

    def test_trailing_slash_stripped(self, mock_prefs):
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:a:b",
            agent_name="Bot",
            agent_type="claude_code",
            coordinator_url="https://citadel.example.com/",
        )
        # Should have clean URLs without double slashes before /api
        assert "https://citadel.example.com/api" in prompt

    def test_empty_coordinator_url(self, mock_prefs):
        """Should not crash with empty coordinator URL."""
        prompt = generate_onboarding_prompt(
            invitation_string="CITADEL-1:a:b",
            agent_name="Bot",
            agent_type="claude_code",
            coordinator_url="",
        )
        assert "Bot" in prompt
        assert "CITADEL-1:a:b" in prompt


# ── Invitation Route agent_prompt Tests ─────────────────────────────


class TestInvitationAgentPrompt:
    """Test that creating an invitation returns agent_prompt."""

    def test_invitation_includes_agent_prompt(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "RemoteBot", "agent_type": "claude_code"},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_prompt" in data
        assert len(data["agent_prompt"]) > 100
        # Should contain agent name and enrollment instructions
        assert "RemoteBot" in data["agent_prompt"]
        assert "enroll" in data["agent_prompt"].lower()
        # Should contain the invitation string
        assert data["compact_string"] in data["agent_prompt"]

    def test_shield_invitation_includes_agent_prompt(self, client, session_token):
        resp = client.post(
            "/api/ext-agents/invitations",
            json={"agent_name": "MyVPS", "agent_type": "vps"},
            headers=_admin_header(session_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_prompt" in data
        assert len(data["agent_prompt"]) > 50
        assert "MyVPS" in data["agent_prompt"]
        assert "Shield" in data["agent_prompt"]
