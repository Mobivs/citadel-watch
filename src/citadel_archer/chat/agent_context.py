# Agent Context Delivery System
# Reference: docs/PRD.md v0.3.44
#
# Generates operational context (instructions, API reference, rules) for
# remote agents during enrollment and on-demand via GET /context.
#
# Templates are admin-customizable via UserPreferences key/value store.
# AI agents receive a rich prompt with full API reference and behavioral rules.
# Shield agents receive compact operational parameters.
#
# Uses {placeholder} templating with str.format_map() + SafeDict fallback.

import logging
from string import Formatter
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

PREF_KEY_AI_TEMPLATE = "agent_context.ai_template"
PREF_KEY_SHIELD_TEMPLATE = "agent_context.shield_template"

# Agent type sets (imported from agent_registry at call time to avoid
# circular imports; duplicated here as fallback constants).
_SHIELD_TYPES = {"vps", "workstation", "cloud"}
_AI_TYPES = {"forge", "openclaw", "claude_code", "custom"}


# ── Default Templates ────────────────────────────────────────────────

DEFAULT_AI_TEMPLATE = """\
# Citadel Archer — Remote Agent Instructions

You are **{agent_name}**, a remote AI agent in the Citadel Archer defense network.

- **Agent ID**: {agent_id}
- **Agent Type**: {agent_type}
- **Coordinator URL**: {coordinator_url}
- **Security Level**: {security_level}

## Your Role

You are a distributed security analyst. Your responsibilities:
1. Monitor your assigned assets for threats, anomalies, and misconfigurations.
2. Report findings to the coordinator via the threat submission API.
3. Respond to delegated tasks from the coordinator or other agents.
4. Send heartbeats every 5 minutes so the coordinator knows you are alive.
5. Poll your inbox for new messages and task assignments.
6. Declare your capabilities so other agents can discover and delegate work to you.

## Authentication

Include this header in **every** API request:
```
Authorization: Bearer <your_api_token>
```
Your API token was provided in the enrollment response. Store it securely.

## API Reference

Base URL: `{coordinator_url}`

### Core Agent Endpoints (prefix: /api/ext-agents)

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/ext-agents/{{agent_id}}/heartbeat | Send heartbeat (every 5 min) |
| POST | /api/ext-agents/send | Send a message to the coordinator or another agent |
| GET | /api/ext-agents/{{agent_id}}/inbox | Poll for incoming messages and tasks |
| POST | /api/ext-agents/{{agent_id}}/capabilities | Declare your capabilities |
| GET | /api/ext-agents/discover | Find agents by capability |
| POST | /api/ext-agents/delegate | Delegate a task to another agent |
| POST | /api/ext-agents/task-response | Respond to a delegated task |
| GET | /api/ext-agents/context | Re-fetch these instructions at any time |

### Shield Endpoints (prefix: /api/shield)

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/shield/threats/remote-shield | Submit threat findings |
| POST | /api/shield/agents/{{agent_id}}/heartbeat | Shield-level heartbeat |
| POST | /api/shield/agents/{{agent_id}}/patch-status | Report OS patch status |
| POST | /api/shield/agents/{{agent_id}}/commands/ack | Acknowledge a command |
| GET | /api/shield/agents/{{agent_id}} | Get your agent details |

## Message Format

When sending messages via `/api/ext-agents/send`:
```json
{{
  "content": "Your message text",
  "message_type": "agent_message",
  "metadata": {{"source_agent": "{agent_id}"}}
}}
```

## Task Delegation

When you receive a delegated task in your inbox:
1. Parse the task from the inbox message (type: "delegation").
2. Process the task according to its description.
3. Send the result via `POST /api/ext-agents/task-response` with the correlation_id.

## Rules

1. **NEVER** expose your API token, credentials, SSH keys, or vault secrets.
2. **NEVER** run offensive security tools or attack infrastructure.
3. **NEVER** modify or delete data outside your authorized scope.
4. Report all suspicious activity immediately via the threat submission API.
5. If you encounter something you cannot handle, escalate to the coordinator.
6. Keep responses concise and actionable. Include evidence (logs, IPs, timestamps).
7. When in doubt, observe and report rather than act autonomously.

## Escalation Protocol

If the coordinator becomes unreachable (heartbeat responses stop):
- **After 90 seconds (3 missed)**: Log a warning, increase monitoring frequency.
- **After 150 seconds (5 missed)**: Tighten local security posture if possible.
- **After 5 minutes (10 missed)**: Enter autonomous mode — continue last directives,
  preserve evidence, and attempt to reconnect at increasing intervals.

## Getting Started

1. Send an initial heartbeat: `POST {coordinator_url}/api/ext-agents/{agent_id}/heartbeat`
2. Declare your capabilities: `POST {coordinator_url}/api/ext-agents/{agent_id}/capabilities`
3. Poll your inbox: `GET {coordinator_url}/api/ext-agents/{agent_id}/inbox`
4. Begin monitoring your assigned scope.
"""

DEFAULT_SHIELD_TEMPLATE = """\
# Citadel Archer — Shield Agent Configuration

Agent: {agent_name} | ID: {agent_id} | Type: {agent_type}
Coordinator: {coordinator_url}
Security Level: {security_level}

## Operational Parameters

- Heartbeat interval: 300 seconds (5 minutes)
- Scan interval: 300 seconds (configurable via /api/shield/agents/{agent_id})
- Alert threshold: 0 (report all findings)
- Command poll: Check inbox on each heartbeat cycle

## API Endpoints

Auth header: Authorization: Bearer <api_token>

POST {coordinator_url}/api/shield/agents/{agent_id}/heartbeat
POST {coordinator_url}/api/shield/threats/remote-shield
POST {coordinator_url}/api/shield/agents/{agent_id}/patch-status
POST {coordinator_url}/api/shield/agents/{agent_id}/commands/ack
GET  {coordinator_url}/api/shield/agents/{agent_id}

## Threat Report Format

POST /api/shield/threats/remote-shield
Content-Type: application/json
{{
  "title": "Brief threat description",
  "description": "Detailed analysis with evidence",
  "severity": "critical|high|medium|low|info",
  "category": "malware|intrusion|policy_violation|vulnerability|anomaly",
  "source_ip": "detected source IP if applicable",
  "indicators": ["IOC1", "IOC2"]
}}

## Command Acknowledgment

When you receive commands via heartbeat response `pending_commands` field:
1. Execute the command within your security scope.
2. ACK via POST /api/shield/agents/{agent_id}/commands/ack
   {{"command_id": "<id>", "status": "completed|failed", "output": "result"}}

## Rules

- Never expose credentials or API tokens.
- Never execute offensive or destructive operations.
- Report all findings; let the coordinator decide severity.
- If coordinator is unreachable for >5 minutes, continue scanning and queue reports.
"""


# ── Safe Template Formatting ─────────────────────────────────────────


class _SafeDict(dict):
    """Dict subclass that returns the placeholder key for missing values.

    Used with str.format_map() so unrecognized {placeholders} pass through
    instead of raising KeyError.
    """

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


# ── Template Accessors ───────────────────────────────────────────────


def _get_prefs():
    """Lazy import to avoid circular dependency at module load time."""
    from ..core.user_preferences import get_user_preferences
    return get_user_preferences()


def get_ai_template() -> str:
    """Return the current AI agent template (admin-custom or default)."""
    try:
        custom = _get_prefs().get(PREF_KEY_AI_TEMPLATE)
        if custom:
            return custom
    except Exception:
        logger.debug("Could not read UserPreferences for AI template, using default")
    return DEFAULT_AI_TEMPLATE


def set_ai_template(template: str) -> None:
    """Save admin-customized AI template to UserPreferences."""
    _get_prefs().set(PREF_KEY_AI_TEMPLATE, template)


def reset_ai_template() -> None:
    """Delete custom AI template, reverting to built-in default."""
    _get_prefs().delete(PREF_KEY_AI_TEMPLATE)


def get_shield_template() -> str:
    """Return the current Shield agent template (admin-custom or default)."""
    try:
        custom = _get_prefs().get(PREF_KEY_SHIELD_TEMPLATE)
        if custom:
            return custom
    except Exception:
        logger.debug("Could not read UserPreferences for Shield template, using default")
    return DEFAULT_SHIELD_TEMPLATE


def set_shield_template(template: str) -> None:
    """Save admin-customized Shield template to UserPreferences."""
    _get_prefs().set(PREF_KEY_SHIELD_TEMPLATE, template)


def reset_shield_template() -> None:
    """Delete custom Shield template, reverting to built-in default."""
    _get_prefs().delete(PREF_KEY_SHIELD_TEMPLATE)


# ── Context Generation ───────────────────────────────────────────────


def _is_shield_type(agent_type: str) -> bool:
    """Check if agent_type is a shield type."""
    try:
        from .agent_registry import SHIELD_AGENT_TYPES
        return agent_type.lower() in SHIELD_AGENT_TYPES
    except ImportError:
        return agent_type.lower() in _SHIELD_TYPES


def generate_context(
    agent_id: str,
    agent_name: str,
    agent_type: str,
    coordinator_url: str = "",
    security_level: str = "Guardian",
    extra_vars: Optional[Dict[str, str]] = None,
) -> str:
    """Generate operational context for an agent.

    Uses admin-customized template from UserPreferences if available,
    otherwise falls back to built-in default template.

    Args:
        agent_id: Unique agent identifier.
        agent_name: Human-readable agent name.
        agent_type: Agent type (e.g., "claude_code", "vps", "forge").
        coordinator_url: Base URL of the Citadel Archer coordinator.
        security_level: Current security level (Observer/Guardian/Sentinel).
        extra_vars: Additional template variables to inject.

    Returns:
        Rendered context string with all placeholders filled.
    """
    # Select template based on agent type
    if _is_shield_type(agent_type):
        template = get_shield_template()
    else:
        template = get_ai_template()

    # Build variable map
    variables = _SafeDict(
        agent_id=agent_id,
        agent_name=agent_name,
        agent_type=agent_type,
        coordinator_url=coordinator_url.rstrip("/") if coordinator_url else "",
        security_level=security_level,
    )
    if extra_vars:
        variables.update(extra_vars)

    try:
        return template.format_map(variables)
    except Exception:
        logger.warning("Failed to render agent context template, returning raw template")
        return template


# ── Onboarding Prompt ────────────────────────────────────────────────

DEFAULT_AI_ONBOARDING_PROMPT = """\
Please execute the following setup task:

# Task: Set Up Citadel Archer Remote Security Agent

I built **Citadel Archer**, a self-hosted cybersecurity dashboard \
(Python/FastAPI) that I run on my own home infrastructure. It coordinates \
security monitoring across my machines. I need you to register this machine \
as a remote agent in my system.

I am naming you **{agent_name}**. My coordinator server is at \
`{coordinator_url}` — this is my own machine on my private network.

## Step 1: Register

Run this curl command to enroll with my coordinator:

```bash
curl -X POST {coordinator_url}/api/ext-agents/enroll \\
  -H "Content-Type: application/json" \\
  -d '{{"invitation_string": "{invitation_string}"}}'
```

Save the `api_token` from the response — it is only shown once during enrollment. \
The response also includes an `operational_context` field with detailed API \
documentation and your full instructions.

## Step 2: Start Operating

After enrollment, include this header in all API calls:
```
Authorization: Bearer <your_api_token>
```

Then run these in order:
1. **Send heartbeat**: `POST {coordinator_url}/api/ext-agents/{{agent_id}}/heartbeat`
2. **Declare capabilities**: `POST {coordinator_url}/api/ext-agents/{{agent_id}}/capabilities`
3. **Fetch full instructions**: `GET {coordinator_url}/api/ext-agents/context`
4. **Poll for tasks**: `GET {coordinator_url}/api/ext-agents/{{agent_id}}/inbox`

## Notes

- Enrollment code: `{invitation_string}`
- This code is single-use and valid for {ttl_minutes} minutes
- You can inspect the API at `{coordinator_url}/docs`
"""

DEFAULT_SHIELD_ONBOARDING_PROMPT = """\
# Task: Set Up Citadel Archer Shield Agent

Your operator runs **Citadel Archer**, a self-hosted cybersecurity monitoring \
dashboard (Python/FastAPI). This task registers the current machine as a Shield \
agent that reports system health and security findings to the operator's own \
dashboard server at `{coordinator_url}`.

Agent Name: {agent_name} | Type: {agent_type}

## Option A: Enroll via API

The hostname and IP fields let the operator identify this machine on their \
dashboard. These are sent only to the operator's own server.

```bash
curl -X POST {coordinator_url}/api/shield/agents/enroll \\
  -H "Content-Type: application/json" \\
  -d '{{"invitation_string": "{invitation_string}", \
"hostname": "$(hostname)", "ip": "$(hostname -I | awk \\'{{print $1}}\\')", \
"platform": "linux"}}'
```

## Option B: Use the Shield agent script

```bash
python citadel_shield.py enroll {coordinator_url} {invitation_string}
```

Save the returned `api_token` securely — it is only shown once during enrollment.

Enrollment code: {invitation_string}
Valid for: {ttl_minutes} minutes
"""

PREF_KEY_AI_ONBOARDING = "agent_context.ai_onboarding"
PREF_KEY_SHIELD_ONBOARDING = "agent_context.shield_onboarding"


def get_ai_onboarding_template() -> str:
    """Return the current AI onboarding prompt template."""
    try:
        custom = _get_prefs().get(PREF_KEY_AI_ONBOARDING)
        if custom:
            return custom
    except Exception:
        pass
    return DEFAULT_AI_ONBOARDING_PROMPT


def get_shield_onboarding_template() -> str:
    """Return the current Shield onboarding prompt template."""
    try:
        custom = _get_prefs().get(PREF_KEY_SHIELD_ONBOARDING)
        if custom:
            return custom
    except Exception:
        pass
    return DEFAULT_SHIELD_ONBOARDING_PROMPT


def generate_onboarding_prompt(
    invitation_string: str,
    agent_name: str,
    agent_type: str,
    coordinator_url: str = "",
    ttl_seconds: int = 600,
) -> str:
    """Generate a complete onboarding prompt to give to a remote agent.

    This is the copy-pasteable block that tells the agent what Citadel Archer
    is, how to enroll using the invitation string, and what to do after.

    Args:
        invitation_string: The compact invitation string (CITADEL-1:...).
        agent_name: Human-readable name for the agent.
        agent_type: Agent type (claude_code, forge, vps, etc.).
        coordinator_url: Base URL of the Citadel Archer coordinator.
        ttl_seconds: Invitation TTL in seconds (for display).

    Returns:
        Complete onboarding prompt string ready to paste to the remote agent.
    """
    if _is_shield_type(agent_type):
        template = get_shield_onboarding_template()
    else:
        template = get_ai_onboarding_template()

    variables = _SafeDict(
        invitation_string=invitation_string,
        agent_name=agent_name,
        agent_type=agent_type,
        coordinator_url=coordinator_url.rstrip("/") if coordinator_url else "",
        ttl_minutes=max(1, ttl_seconds // 60),
        ttl_seconds=ttl_seconds,
    )

    try:
        return template.format_map(variables)
    except Exception:
        logger.warning("Failed to render onboarding prompt, returning raw template")
        return template
