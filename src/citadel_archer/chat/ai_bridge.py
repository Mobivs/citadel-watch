# PRD: AI Brain — SecureChat Bridge
# Reference: docs/PRD.md v0.2.6, AI-Centric Architecture
#
# Connects the SecureChat message layer to AI backends (Claude API + Ollama).
#
# Listens for messages requiring command-level attention:
#   - User TEXT messages (questions, requests, conversation)
#   - Agent ESCALATION events (critical/high from agent poller)
#
# Builds context (chat history + system state), calls AI with tools,
# routes responses back through ChatManager as "assistant" messages.
#
# Backend priority:
#   1. Claude API (cloud) — primary, highest capability
#   2. Ollama (local) — fallback when Claude unavailable or no API key
#
# Gracefully degrades: if neither backend is available, the bridge is disabled
# and chat commands (add vps, deploy agent) still work normally.

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .ai_audit import get_ai_audit_logger
from .message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_ASSISTANT,
    PARTICIPANT_CITADEL,
    PARTICIPANT_USER,
)

if TYPE_CHECKING:
    from .chat_manager import ChatManager

logger = logging.getLogger(__name__)


# ── Security Helpers ───────────────────────────────────────────────────

def _is_localhost_url(url: str) -> bool:
    """Check if a URL points to localhost/loopback.

    SECURITY: Used to gate Ollama connections. Only localhost is allowed
    by default — remote Ollama servers require explicit opt-in via
    OLLAMA_ALLOW_REMOTE=1 to prevent accidental data leakage to
    untrusted LLM endpoints.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return host in (
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",  # As a connect-to address, resolves to local machine
        )
    except Exception:
        return False


# ── Inference Tiers ────────────────────────────────────────────────────
#
# Tier 0 — zero inference: template responses from cached state (no API call)
# Tier 1 — Haiku: simple single-event queries, status summaries, explanations
# Tier 2 — Sonnet: multi-event correlation, incident investigation, complex analysis
#
# Cost targets: Tier 0 70-80%, Tier 1 15-20%, Tier 2 5-10%, Opus never.

import re as _re

_MODEL_HAIKU = "claude-haiku-4-5-20251001"
_MODEL_SONNET = "claude-sonnet-4-5-20250929"

# Keywords that signal complex analysis requiring Sonnet.
_SONNET_KEYWORDS = (
    "investigat", "correlat", "attack chain", "posture", "threat hunt",
    "incident", "compromise", "breach", "malware", "intrusion",
    "privilege escalat", "lateral movement", "persistence", "root cause",
    "pattern", "timeline", "forensic", "audit trail", "compare",
)

# Tier 0 patterns: pure data-retrieval queries, no AI judgment needed.
# Each entry is (compiled_regex, handler_fn(state) -> str).
# Only fire if the ENTIRE query is clearly a data lookup — conservative list.
def _t0_status(s: dict) -> str:
    threat = s.get("threat_level", "unknown").upper()
    uptime = s.get("uptime", "unknown")
    assets = s.get("assets", [])
    online = sum(1 for a in assets if a.get("status") in ("online", "active"))
    level = s.get("security_level", "guardian").title()
    return (
        f"**System Status**\n"
        f"Threat Level: {threat}\n"
        f"Security Mode: {level}\n"
        f"Assets: {len(assets)} managed ({online} online)\n"
        f"Uptime: {uptime}"
    )

def _t0_threat(s: dict) -> str:
    return f"Current threat level: **{s.get('threat_level', 'unknown').upper()}**"

def _t0_asset_count(s: dict) -> str:
    assets = s.get("assets", [])
    online = sum(1 for a in assets if a.get("status") in ("online", "active"))
    return f"{len(assets)} managed asset(s), {online} online."

_TIER0_RULES = [
    (_re.compile(
        r"^\s*(what('?s| is) (the )?)?(system |current )?status\??\s*$",
        _re.IGNORECASE,
    ), _t0_status),
    (_re.compile(
        r"^\s*(what('?s| is) (the )?)?(current )?threat.?level\??\s*$",
        _re.IGNORECASE,
    ), _t0_threat),
    (_re.compile(
        r"^\s*(how many (assets?|machines?|devices?)|asset count)\??\s*$",
        _re.IGNORECASE,
    ), _t0_asset_count),
]


# ── System Prompt ──────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are the Citadel Archer AI — the defensive brain of a personal security platform.

## Your Role
- Analyze security events and explain them in plain, calm language.
- Advise the user on threats, hardening, and best practices.
- Take action within your security level guardrails (use tools).
- When something is normal, say so clearly. When dangerous, explain what and why.
- Keep responses concise (2-4 sentences for simple questions, more for analysis).

## Personality
- Trusted security advisor, not an alarm system.
- Speak like a knowledgeable friend, not a technical manual.
- Be direct and honest. Don't hedge unnecessarily.
- When you've taken action, state what you did and why.

## Security Level: {security_level}
- Observer: Analyze and explain only. Do NOT take autonomous actions.
- Guardian: May block known threats, deploy agents, rotate credentials if breach detected.
- Sentinel: Full autonomy — kill processes, block IPs, modify firewall, auto-escalate.

## Current System State
{system_state}

## Rules
- NEVER reveal Vault secrets, SSH private keys, or API keys.
- NEVER run offensive security tools.
- If you don't know, say so. Don't invent threat details.
- Use tools to get fresh data before answering questions about system state.
- Prefer action over questions when confidence is high and security level allows.
"""


# ── Tool Definitions (Anthropic API format) ────────────────────────────

TOOLS = [
    {
        "name": "get_system_status",
        "description": (
            "Get current security status: threat level (green/yellow/red), "
            "guardian active status, server uptime, and asset count."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_asset_list",
        "description": (
            "Get all managed assets (machines in the asset inventory). Each entry "
            "represents one physical or virtual machine. has_shield_daemon=True means "
            "a Citadel Shield daemon is running on that machine (deployed via the "
            "Assets tab one-liner). Use get_vps_summary() to see enrolled AI agents "
            "and Shield daemon details together."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_agent_events",
        "description": (
            "Get recent security events from a specific asset's Citadel Shield "
            "agent. Returns threat type, severity, detail, and actions taken."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "The asset ID to query events for.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 20).",
                },
            },
            "required": ["asset_id"],
        },
    },
    {
        "name": "deploy_agent",
        "description": (
            "Deploy the Citadel Shield protection agent to a VPS asset. "
            "Requires Guardian or Sentinel security level. The asset must "
            "have an SSH credential linked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "The asset ID to deploy the agent to.",
                },
            },
            "required": ["asset_id"],
        },
    },
    {
        "name": "get_vps_summary",
        "description": (
            "Get an overview of all enrolled security agents: citadel_daemon agents "
            "(vps/cloud type enrolled via one-liner) appear under enrolled_agents. "
            "Use get_daemon_threats() to see what those daemons have actually found. "
            "SSH-deployed Shield agents appear under shield_daemon_agents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_daemon_threats",
        "description": (
            "Get security findings reported by enrolled Citadel Daemon agents "
            "(Linux VPS/cloud machines running citadel_daemon.py). Covers all "
            "daemon sensors: auth_log (SSH brute force, failed logins), processes "
            "(crypto miners, high CPU, suspicious ports), cron (tampered jobs), "
            "file_integrity (changed system files), patches (pending updates). "
            "Use this whenever the user asks about VPS security, what the daemon "
            "found, remote threats, or patch status. Optionally filter by agent_id."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Filter to one daemon's agent_id (optional).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 30).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "execute_defensive_action",
        "description": (
            "Execute a pre-approved defensive response on one or more enrolled daemon agents. "
            "Low-risk actions (kill_process, block_ip, disable_cron_job, collect_forensics) "
            "execute automatically on the next heartbeat. Medium-risk actions "
            "(rotate_ssh_keys, restart_service, apply_patches) are queued for user "
            "approval first. Supports distributed response via the 'assets' parameter — "
            "use assets=[\"all\"] to target every enrolled daemon at once (e.g. block an "
            "attacker IP across all machines). Use get_defensive_playbook() first. "
            "NEVER use this for offensive operations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": (
                        "Single target: daemon agent_id, hostname, or asset name. "
                        "Use get_vps_summary() to list valid agents. "
                        "Omit when using 'assets' for multi-target dispatch."
                    ),
                },
                "assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Multi-target list: array of agent_ids, hostnames, or names. "
                        "Use [\"all\"] to target every enrolled daemon. "
                        "Ideal for distributed blocks (block attacker IP everywhere). "
                        "If provided, takes precedence over asset_id."
                    ),
                },
                "action_id": {
                    "type": "string",
                    "description": (
                        "Action to execute. One of: kill_process, block_ip, "
                        "disable_cron_job, collect_forensics, rotate_ssh_keys, "
                        "restart_service, apply_patches."
                    ),
                },
                "parameters": {
                    "type": "object",
                    "description": "Action parameters (e.g. {pid: 1234} for kill_process).",
                },
                "threat_id": {
                    "type": "string",
                    "description": "Optional: the threat event that triggered this action.",
                },
                "require_approval": {
                    "type": "boolean",
                    "description": (
                        "Override approval requirement. Cannot disable approval "
                        "for medium-risk actions."
                    ),
                },
            },
            "required": ["action_id"],
        },
    },
    {
        "name": "get_defensive_playbook",
        "description": (
            "Get the list of all pre-approved defensive actions with their risk "
            "levels, approval requirements, and parameter definitions. Use this "
            "before execute_defensive_action to confirm the action exists and check "
            "what parameters are needed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action_id": {
                    "type": "string",
                    "description": "Return details for a specific action only (optional).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_action_history",
        "description": (
            "Get the audit trail of defensive actions executed (or pending/denied) "
            "on daemon agents. Shows action_id, status (queued/sent/success/failed/"
            "pending_approval/denied), target agent, parameters, timestamps, and "
            "execution results. Use this to check if a previous action succeeded."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "Filter to a specific agent_id (optional).",
                },
                "action_id": {
                    "type": "string",
                    "description": "Filter to a specific action type (optional).",
                },
                "status": {
                    "type": "string",
                    "description": (
                        "Filter by status: queued, sent, success, failed, "
                        "pending_approval, denied (optional)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default 20).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_local_events",
        "description": (
            "Get recent security events from the local Guardian (file monitor, "
            "process monitor) on this Windows machine. Returns event type, "
            "severity, timestamp, message, and file path when available. "
            "Use this when the user asks about local file changes, process "
            "activity, or when a Local Guardian alert has been escalated."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 20, max 100).",
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Filter by minimum severity: 'info', 'warning', 'alert', "
                        "'critical'. Omit to return all severities."
                    ),
                },
            },
            "required": [],
        },
    },
]


# ── AI Bridge Class ────────────────────────────────────────────────────


class AIBridge:
    """Connects SecureChat to the AI Brain (Claude API).

    Listens for messages needing AI attention, builds context,
    calls Claude with tools, routes responses back through chat.

    Args:
        chat_manager: The ChatManager instance to listen on and send through.
        api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
        model: Claude model to use. Falls back to CITADEL_AI_MODEL env var.
    """

    def __init__(
        self,
        chat_manager: "ChatManager",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self._chat = chat_manager
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model or os.environ.get(
            "CITADEL_AI_MODEL", "claude-sonnet-4-5-20250929"
        )
        self._client = None
        self._enabled = False
        self._processing = False  # one-at-a-time guard
        self._pending_msg: Optional[ChatMessage] = None  # queued while processing
        self._shield_db = None  # cached RemoteShieldDatabase instance

        # Ollama local LLM backend (fallback when Claude is unavailable)
        self._ollama = None
        self._active_backend = "none"  # "claude", "ollama", or "none"

        if self._api_key:
            try:
                import anthropic

                self._client = anthropic.AsyncAnthropic(api_key=self._api_key)
                self._enabled = True
                self._active_backend = "claude"
                logger.info("AI Bridge initialized (model=%s)", self._model)
            except ImportError:
                logger.warning(
                    "anthropic package not installed — run: pip install anthropic. "
                    "Trying Ollama fallback."
                )

        # Initialize Ollama backend (always, for fallback or primary use)
        try:
            from .ollama_backend import OllamaBackend
            ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")

            # SECURITY: Only allow localhost connections by default.
            # Remote Ollama servers must be explicitly allowed via env var.
            if not _is_localhost_url(ollama_url):
                allow_remote = os.environ.get("OLLAMA_ALLOW_REMOTE", "").lower()
                if allow_remote not in ("1", "true", "yes"):
                    logger.warning(
                        "Ollama URL %s is not localhost. Set OLLAMA_ALLOW_REMOTE=1 "
                        "to allow remote connections. Ollama disabled for security.",
                        ollama_url,
                    )
                    ollama_url = None

            if ollama_url:
                self._ollama = OllamaBackend(base_url=ollama_url)
                if not self._enabled:
                    # No Claude API — Ollama is primary
                    self._enabled = True
                    self._active_backend = "ollama"
                    logger.info(
                        "AI Bridge initialized with Ollama fallback (url=%s)",
                        ollama_url,
                    )
                else:
                    logger.info("Ollama backend available as fallback (url=%s)", ollama_url)
        except Exception:
            logger.debug("Ollama backend not available", exc_info=True)

        if not self._enabled:
            logger.info(
                "No AI backend configured. AI Bridge disabled. "
                "Set ANTHROPIC_API_KEY or install Ollama to enable AI responses."
            )

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def active_backend(self) -> str:
        """Current active AI backend: 'claude', 'ollama', or 'none'."""
        return self._active_backend

    async def ollama_status(self) -> Dict[str, Any]:
        """Return Ollama backend status for API display."""
        if self._ollama is None:
            return {"available": False, "reason": "Ollama backend not initialized"}
        return await self._ollama.status()

    async def set_ollama_model(self, model: str) -> Dict[str, Any]:
        """Switch the Ollama model. Validates the model exists first."""
        if self._ollama is None:
            return {"error": "Ollama backend not initialized"}
        # Validate model exists locally before switching
        if not await self._ollama.has_model(model):
            available = await self._ollama.list_models()
            return {
                "error": f"Model '{model}' not found locally",
                "available": [m.name for m in available],
            }
        old = self._ollama.model
        self._ollama.model = model
        logger.info("Ollama model changed: %s -> %s", old, model)
        return {"previous": old, "current": model}

    async def list_ollama_models(self) -> Dict[str, Any]:
        """List available Ollama models for API display."""
        if self._ollama is None:
            return {"models": [], "current": None}
        models = await self._ollama.list_models()
        return {
            "models": [m.to_dict() for m in models],
            "current": self._ollama.model,
        }

    # ── Registration ───────────────────────────────────────────────────

    def register(self):
        """Register as a wildcard listener on ChatManager."""
        if not self._enabled:
            return
        self._chat.subscribe("*", self._on_message)
        logger.info("AI Bridge registered on ChatManager")

    # ── Message Handler ────────────────────────────────────────────────

    async def _on_message(self, msg: ChatMessage):
        """Decide if a message needs AI attention, dispatch if so."""
        # Never respond to our own messages (prevents loops)
        if msg.from_id == PARTICIPANT_ASSISTANT:
            return

        # If already processing, queue the latest message (replaces previous queued)
        if self._processing:
            self._pending_msg = msg
            return

        needs_ai = False

        # 1. User sent plain text (not a command — commands already handled)
        if msg.from_id == PARTICIPANT_USER and msg.msg_type == MessageType.TEXT:
            needs_ai = True

        # 2. Agent escalation event (critical/high posted by poller)
        if msg.from_id == PARTICIPANT_CITADEL and msg.msg_type == MessageType.EVENT:
            text = (msg.text or "").lower()
            if "critical" in text or "high" in text:
                needs_ai = True

        # 3. External AI agent sent a text message (Trigger 1b)
        if msg.from_id.startswith("ext-agent:") and msg.msg_type == MessageType.TEXT:
            needs_ai = True

        if not needs_ai:
            return

        # SCS token quota check — prevent budget exhaustion
        from .scs_quota import get_scs_quota_tracker

        quota = get_scs_quota_tracker()
        estimated = quota.estimate_tokens(msg.text or "")
        allowed, info = quota.check(msg.from_id, estimated_tokens=estimated)
        if not allowed:
            logger.warning(
                "SCS quota exceeded for %s: %s", msg.from_id, info["reason"]
            )
            try:
                await self._chat.send_system(
                    f"[Rate limit] {info['reason']} Try again in a few minutes."
                )
            except Exception:
                pass  # best-effort notification
            return

        # Show thinking indicator immediately — response may take 5-30s
        self._broadcast_thinking(True, "Analyzing...")

        # Process in background to avoid blocking the listener pipeline
        asyncio.create_task(self._process(msg))

    # ── Core Processing Loop ───────────────────────────────────────────

    async def _process(self, trigger: ChatMessage):
        """Build context → call Claude → handle response."""
        self._processing = True
        try:
            # 1. Gather system state
            state = self._gather_system_state()

            # 2. Build conversation history in Claude message format
            # Exclude the trigger message (it's appended separately below)
            history = self._build_history(exclude_id=trigger.id)

            # 3. Append the trigger message
            trigger_text = trigger.text or json.dumps(trigger.payload)
            if trigger.from_id == PARTICIPANT_CITADEL:
                trigger_text = f"[System escalation — {trigger.msg_type.value}] {trigger_text}"
            history.append({"role": "user", "content": trigger_text})

            # 3b. Tier 0 — zero-inference fast path (user messages only).
            # System escalations and agent messages always need AI reasoning.
            if trigger.from_id == PARTICIPANT_USER:
                t0 = self._tier0_response(trigger.text or "", state)
                if t0 is not None:
                    ai_msg = ChatMessage(
                        from_id=PARTICIPANT_ASSISTANT,
                        to_id=PARTICIPANT_USER,
                        msg_type=MessageType.RESPONSE,
                        payload={"text": t0},
                    )
                    await self._chat.send(ai_msg)
                    return  # no API call

            # 4. Build system prompt
            security_level = state.get("security_level", "guardian")
            system = SYSTEM_PROMPT.format(
                security_level=security_level.title(),
                system_state=self._format_state(state),
            )

            # 5. Determine trigger type for audit logging + select inference tier
            selected_model: Optional[str] = None
            if trigger.from_id == PARTICIPANT_USER:
                trigger_type = "user_text"
                selected_model = self._select_model(trigger.text or "", state)
                logger.debug("Inference tier: %s", selected_model)
                # Refine the thinking indicator with the actual tier being used
                if selected_model == _MODEL_SONNET:
                    self._broadcast_thinking(True, "Running deep analysis (Sonnet)...")
                else:
                    self._broadcast_thinking(True, "Analyzing (Haiku)...")
            elif trigger.from_id.startswith("ext-agent:"):
                trigger_type = "agent_text"
            else:
                trigger_type = "citadel_event"

            # 6. Call Claude with tool loop (model=None → Sonnet for escalations/agents)
            final_text = await self._call_with_tools(
                system, history, trigger_type, trigger.id,
                participant_id=trigger.from_id,
                model=selected_model,
            )

            # 7. Send AI response to chat
            if final_text:
                ai_msg = ChatMessage(
                    from_id=PARTICIPANT_ASSISTANT,
                    to_id=PARTICIPANT_USER,
                    msg_type=MessageType.RESPONSE,
                    payload={"text": final_text},
                )
                await self._chat.send(ai_msg)

        except asyncio.TimeoutError:
            logger.warning("AI Bridge: Claude API call timed out")
            try:
                await self._chat.send_system(
                    "AI assistant timed out. Try again or check your connection."
                )
            except Exception:
                pass
        except Exception:
            logger.exception("AI Bridge processing error")
            try:
                await self._chat.send_system(
                    "AI assistant encountered an error. Check logs for details."
                )
            except Exception:
                pass
        finally:
            self._processing = False
            self._broadcast_thinking(False)
            # Process any queued message
            pending = self._pending_msg
            self._pending_msg = None
            if pending:
                asyncio.create_task(self._process(pending))

    # ── Context Building ───────────────────────────────────────────────

    def _gather_system_state(self) -> Dict[str, Any]:
        """Snapshot current system state for the AI context."""
        state: Dict[str, Any] = {}

        # Security level
        try:
            from ..core import get_security_manager

            state["security_level"] = get_security_manager().current_level.value
        except Exception:
            state["security_level"] = "guardian"

        # Threat level + uptime
        try:
            from ..api.main import _calculate_threat_level, _format_uptime

            state["threat_level"] = _calculate_threat_level()
            state["uptime"] = _format_uptime()
        except Exception:
            state["threat_level"] = "unknown"
            state["uptime"] = "unknown"

        # Managed assets (summary only — details available via tools)
        asset_list = []
        try:
            from ..api.asset_routes import get_inventory

            for a in get_inventory().all():
                asset_list.append({
                    "id": a.asset_id,
                    "name": a.name,
                    "ip": a.ip_address,
                    "type": getattr(a, "asset_type", "unknown"),
                    "status": getattr(a.status, "value", str(a.status)),
                    "has_shield_daemon": bool(getattr(a, "remote_shield_agent_id", None)),
                    "source": "inventory",
                })
        except Exception:
            pass

        # AI agents (AgentRegistry) are NOT assets — they are participants.
        # Per PRD: one asset = one managed_assets record. AI agents appear in
        # get_vps_summary() under enrolled_agents, not in the asset list.

        state["assets"] = asset_list

        # Enrolled citadel_daemon agents (Shield type: vps/cloud/workstation)
        # shown here so the AI knows about remote machines without a tool call.
        try:
            from ..api.agent_api_routes import get_agent_registry
            _shield_types = {"vps", "cloud", "workstation"}
            state["enrolled_daemons"] = [
                {
                    "name":     a.get("name", a["agent_id"]),
                    "hostname": a.get("hostname") or "",
                    "type":     a.get("agent_type"),
                    "last_seen": a.get("last_seen") or a.get("enrolled_at", ""),
                }
                for a in get_agent_registry().list_agents()
                if a.get("agent_type") in _shield_types
                and a.get("status") != "revoked"
            ]
        except Exception:
            state["enrolled_daemons"] = []

        return state

    def _build_history(self, exclude_id: Optional[str] = None) -> List[Dict[str, str]]:
        """Convert recent chat messages to Claude's alternating message format.

        Claude requires: user/assistant messages alternating, starting with user.
        System messages are prefixed with [System] and folded into user turns.
        Consecutive same-role messages are merged.

        Args:
            exclude_id: Message ID to exclude (the trigger message, which is
                        appended separately to avoid duplication).
        """
        recent = self._chat.get_recent(limit=20)
        if exclude_id:
            recent = [m for m in recent if m.id != exclude_id]
        raw: List[Dict[str, str]] = []

        for msg in recent:
            text = msg.text or json.dumps(msg.payload)

            if msg.from_id == PARTICIPANT_ASSISTANT:
                role = "assistant"
            elif msg.from_id == PARTICIPANT_USER:
                role = "user"
            else:
                # System/citadel/agent messages → user role with label
                role = "user"
                label = "System"
                if msg.from_id.startswith("ext-agent:"):
                    label = f"ExtAgent {msg.payload.get('agent_name', msg.from_id[10:])}"
                elif msg.from_id.startswith("agent:"):
                    label = f"Agent {msg.from_id[6:]}"
                text = f"[{label}: {msg.msg_type.value}] {text}"

            raw.append({"role": role, "content": text})

        # Merge consecutive same-role messages (Claude requirement)
        merged: List[Dict[str, str]] = []
        for entry in raw:
            if merged and merged[-1]["role"] == entry["role"]:
                merged[-1]["content"] += f"\n{entry['content']}"
            else:
                merged.append(dict(entry))

        # Ensure first message is user role
        if merged and merged[0]["role"] != "user":
            merged.insert(0, {"role": "user", "content": "[Chat history begins]"})

        # Ensure we don't end on assistant (the trigger message will follow)
        if merged and merged[-1]["role"] == "assistant":
            merged.append({"role": "user", "content": "[Awaiting new input]"})

        return merged

    def _format_state(self, state: Dict[str, Any]) -> str:
        """Render system state as concise text for the system prompt."""
        lines = [
            f"Threat Level: {state.get('threat_level', 'unknown')}",
            f"Server Uptime: {state.get('uptime', 'unknown')}",
        ]

        assets = state.get("assets", [])
        if assets:
            lines.append(f"Managed Assets ({len(assets)}):")
            for a in assets:
                agent = "agent deployed" if a.get("has_agent") else "no agent"
                lines.append(
                    f"  - {a['name']} ({a['ip']}) — {a['status']}, {agent}"
                )
        else:
            lines.append("Managed Assets: none")

        daemons = state.get("enrolled_daemons", [])
        if daemons:
            lines.append(f"Enrolled Citadel Daemons ({len(daemons)}):")
            for d in daemons:
                lines.append(
                    f"  - {d['name']} ({d.get('type', 'vps')}) "
                    f"hostname={d.get('hostname', '?')} "
                    f"last_seen={d.get('last_seen', 'never')}"
                )
            lines.append(
                "  Use get_daemon_threats() to see what these daemons have found."
            )

        return "\n".join(lines)

    # ── Inference Tier Routing ───────────────────────────────────────────

    def _tier0_response(self, text: str, state: dict) -> Optional[str]:
        """Try to answer with a template response (no AI inference).

        Returns a formatted string if the query matches a Tier 0 pattern,
        or None if the query needs AI reasoning.
        """
        for pattern, handler in _TIER0_RULES:
            if pattern.match(text):
                return handler(state)
        return None

    def _broadcast_thinking(self, active: bool, detail: str = "") -> None:
        """Push a chat_thinking event to all WebSocket clients.

        active=True  — show thinking indicator with optional detail text.
        active=False — hide indicator (analysis complete or failed).

        Best-effort: never raises, never blocks.
        """
        if not self._chat._ws_broadcast:
            return
        try:
            payload = {"type": "chat_thinking", "active": active, "detail": detail}
            result = self._chat._ws_broadcast(payload)
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)
        except Exception:
            pass

    def _select_model(self, text: str, state: dict) -> str:
        """Choose Haiku or Sonnet based on query complexity.

        Tier 2 (Sonnet) — complex multi-event analysis, investigation keywords,
            or high-severity escalations with active threat context.
        Tier 1 (Haiku) — everything else that reaches the AI.
        """
        text_lower = text.lower()

        # Sonnet for queries with investigation / correlation keywords
        if any(kw in text_lower for kw in _SONNET_KEYWORDS):
            return _MODEL_SONNET

        # Sonnet when the system is under active threat and user is asking
        # about alerts, events, or threats — context matters
        if state.get("threat_level") in ("critical", "high") and any(
            kw in text_lower for kw in ("alert", "threat", "critical", "high", "event")
        ):
            return _MODEL_SONNET

        return _MODEL_HAIKU

    # ── Claude API Call with Tool Loop ──────────────────────────────────

    async def _call_with_tools(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str = "unknown",
        trigger_message_id: str = "",
        participant_id: str = "user",
        model: Optional[str] = None,
    ) -> Optional[str]:
        """Call AI backend with tool loop. Tries Claude first, falls back to Ollama.

        Backend priority:
          1. Claude API (cloud) — if API key configured and client available
          2. Ollama (local) — fallback when Claude fails or unavailable

        SECURITY: All Ollama calls are audit-logged. Sensitive data (secrets,
        keys) must never appear in messages — this is enforced upstream by
        the system prompt rules and tool handlers.
        """
        audit = get_ai_audit_logger()
        from .scs_quota import get_scs_quota_tracker

        quota = get_scs_quota_tracker()

        # -- Try Claude first --
        if self._client:
            result = await self._call_claude(
                system, messages, trigger_type, trigger_message_id,
                participant_id, audit, quota,
                model=model,
            )
            if result is not None:
                return result
            # Claude failed — try Ollama fallback
            if self._ollama:
                logger.info("Claude API failed, falling back to Ollama")

        # -- Ollama fallback (or primary if no Claude) --
        if self._ollama:
            result = await self._call_ollama(
                system, messages, trigger_type, trigger_message_id,
                participant_id, audit, quota,
            )
            return result

        return None

    async def _call_claude(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str,
        trigger_message_id: str,
        participant_id: str,
        audit,
        quota,
        model: Optional[str] = None,
    ) -> Optional[str]:
        """Call Claude API with tool loop. Returns text or None on failure.

        Args:
            model: Override the default model for this call. None → self._model.
                   Pass _MODEL_HAIKU for Tier 1 or _MODEL_SONNET for Tier 2.
        """
        _model = model or self._model
        try:
            ctx = audit.start_call(trigger_type, trigger_message_id, _model, 0)
            try:
                response = await asyncio.wait_for(
                    self._client.messages.create(
                        model=_model,
                        max_tokens=8192,
                        system=system,
                        messages=messages,
                        tools=TOOLS,
                    ),
                    timeout=90,
                )
                record = audit.finish_call(ctx, response=response)
                if record:
                    quota.record(participant_id, record.total_tokens)
            except Exception as exc:
                audit.finish_call(ctx, error=type(exc).__name__)
                raise

            # Tool use loop — Claude may call tools before giving final answer
            max_iterations = 5  # safety valve
            iteration = 0

            while response.stop_reason == "tool_use" and iteration < max_iterations:
                iteration += 1

                # Re-check quota before each tool-loop API call
                allowed, _qinfo = quota.check(participant_id, estimated_tokens=2000)
                if not allowed:
                    logger.warning(
                        "SCS quota exhausted during tool loop for %s",
                        participant_id,
                    )
                    break

                # Execute each tool call
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        logger.info(
                            "AI tool call: %s(%s)", block.name, block.input
                        )
                        result = await self._execute_tool(block.name, block.input)
                        tool_results.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": json.dumps(result, default=str),
                            }
                        )

                # Continue conversation with tool results
                messages = messages + [
                    {"role": "assistant", "content": response.content},
                    {"role": "user", "content": tool_results},
                ]

                ctx = audit.start_call(
                    "tool_loop", trigger_message_id, _model, iteration
                )
                try:
                    response = await asyncio.wait_for(
                        self._client.messages.create(
                            model=_model,
                            max_tokens=8192,
                            system=system,
                            messages=messages,
                            tools=TOOLS,
                        ),
                        timeout=90,
                    )
                    record = audit.finish_call(ctx, response=response)
                    if record:
                        quota.record(participant_id, record.total_tokens)
                except Exception as exc:
                    audit.finish_call(ctx, error=type(exc).__name__)
                    raise

            # Extract final text from response
            texts = []
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    texts.append(block.text)

            self._active_backend = "claude"
            return "\n".join(texts) if texts else None

        except Exception:
            logger.exception("Claude API call failed")
            return None

    async def _call_ollama(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str,
        trigger_message_id: str,
        participant_id: str,
        audit,
        quota,
    ) -> Optional[str]:
        """Call Ollama backend with tool loop. Returns text or None on failure.

        SECURITY: Audit-logged identically to Claude calls. The Ollama backend
        only connects to localhost by default (enforced in __init__).
        """
        if not await self._ollama.is_available():
            logger.warning("Ollama backend not available")
            return None

        # Audit log the Ollama call
        ollama_model = self._ollama.model
        ctx = audit.start_call(
            f"ollama_{trigger_type}", trigger_message_id, ollama_model, 0
        )

        try:
            # Convert messages: strip any Claude-specific content blocks
            # (Ollama expects plain {role, content} dicts)
            clean_messages = []
            for m in messages:
                content = m.get("content", "")
                if isinstance(content, list):
                    # Claude tool_result format — flatten to text
                    parts = []
                    for block in content:
                        if isinstance(block, dict):
                            parts.append(block.get("content", str(block)))
                        else:
                            parts.append(str(block))
                    content = "\n".join(parts)
                elif not isinstance(content, str):
                    content = str(content)
                clean_messages.append({"role": m["role"], "content": content})

            # Tool executor for the Ollama tool loop
            async def tool_executor(name, args):
                return await self._execute_tool(name, args)

            response = await self._ollama.chat_with_tools(
                messages=clean_messages,
                system=system,
                tools=TOOLS,
                tool_executor=tool_executor,
                max_iterations=5,
                max_tokens=8192,
                temperature=0.3,
            )

            if response is None:
                audit.finish_call(ctx, error="OllamaNoResponse")
                return None

            # Record token usage for quota
            total_tokens = response.input_tokens + response.output_tokens
            audit.finish_call(ctx, ollama_response={
                "model": response.model,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
            })
            quota.record(participant_id, total_tokens)

            self._active_backend = "ollama"
            return response.text

        except Exception:
            logger.exception("Ollama call failed")
            audit.finish_call(ctx, error="OllamaException")
            return None

    # ── Tool Execution ─────────────────────────────────────────────────

    # Human-readable status text for each tool (shown in thinking indicator).
    _TOOL_LABELS: Dict[str, str] = {
        "get_system_status":        "Checking system status...",
        "get_asset_list":           "Fetching asset inventory...",
        "get_agent_events":         "Pulling security events...",
        "deploy_agent":             "Deploying agent...",
        "get_vps_summary":          "Gathering VPS summary...",
        "get_daemon_threats":       "Pulling daemon threat reports...",
        "execute_defensive_action": "Executing defensive action...",
        "get_defensive_playbook":   "Loading defensive playbook...",
        "get_action_history":       "Pulling action history...",
        "get_local_events":         "Reading local event log...",
    }

    async def _execute_tool(self, name: str, tool_input: Dict) -> Any:
        """Dispatch a tool call to the appropriate handler."""
        self._broadcast_thinking(True, self._TOOL_LABELS.get(name, f"Running {name}..."))
        handlers = {
            "get_system_status":        self._tool_system_status,
            "get_asset_list":           self._tool_asset_list,
            "get_agent_events":         self._tool_agent_events,
            "deploy_agent":             self._tool_deploy_agent,
            "get_vps_summary":          self._tool_vps_summary,
            "get_daemon_threats":       self._tool_daemon_threats,
            "execute_defensive_action": self._tool_execute_defensive_action,
            "get_defensive_playbook":   self._tool_get_defensive_playbook,
            "get_action_history":       self._tool_get_action_history,
            "get_local_events":         self._tool_local_events,
        }

        handler = handlers.get(name)
        if not handler:
            return {"error": f"Unknown tool: {name}"}

        try:
            return await handler(tool_input)
        except Exception as exc:
            logger.warning("Tool %s failed: %s", name, exc)
            return {"error": str(exc)}

    async def _tool_system_status(self, _input: Dict) -> Dict:
        state = self._gather_system_state()
        return {
            "threat_level": state.get("threat_level"),
            "security_level": state.get("security_level"),
            "uptime": state.get("uptime"),
            "asset_count": len(state.get("assets", [])),
        }

    async def _tool_asset_list(self, _input: Dict) -> List[Dict]:
        state = self._gather_system_state()
        return state.get("assets", [])

    def _get_shield_db(self):
        """Lazy-load and cache the RemoteShieldDatabase instance."""
        if self._shield_db is None:
            from ..remote.shield_database import RemoteShieldDatabase
            self._shield_db = RemoteShieldDatabase()
        return self._shield_db

    async def _tool_agent_events(self, tool_input: Dict) -> Dict:
        asset_id = tool_input.get("asset_id", "")
        limit = tool_input.get("limit", 20)

        db = self._get_shield_db()
        agent_id = f"shield_{asset_id}"
        threats = db.list_threats(agent_id=agent_id, limit=limit)
        agent = db.get_agent(agent_id)

        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in threats:
            sev = t.get("severity", 5)
            if sev >= 9:
                severity_counts["critical"] += 1
            elif sev >= 7:
                severity_counts["high"] += 1
            elif sev >= 4:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1

        return {
            "asset_id": asset_id,
            "agent": {
                "agent_id": agent_id,
                "hostname": agent.get("hostname", "") if agent else "",
                "version": agent.get("version", "") if agent else "",
                "last_heartbeat": agent.get("last_heartbeat", "") if agent else "",
                "status": "online" if agent else "unknown",
            },
            "threats": threats,
            "severity_breakdown": severity_counts,
            "total_threats": len(threats),
        }

    async def _tool_deploy_agent(self, tool_input: Dict) -> Dict:
        # Gate by security level
        try:
            from ..core import get_security_manager

            level = get_security_manager().current_level.value
            if level == "observer":
                return {
                    "error": (
                        "Cannot deploy agents in Observer mode. "
                        "Switch to Guardian or Sentinel first."
                    )
                }
        except Exception:
            pass

        asset_id = tool_input.get("asset_id", "")

        from ..api.asset_routes import get_inventory, get_ssh_manager
        from ..remote.agent_deployer import AgentDeployer

        inv = get_inventory()
        asset = inv.get(asset_id)
        if not asset:
            # Check if this is an enrolled AI agent (Tailscale / API-enrolled).
            # Those aren't SSH-managed so AgentDeployer can't reach them, but
            # the user can still deploy the citadel daemon via the one-liner.
            try:
                from ..api.agent_api_routes import get_agent_registry
                enrolled = get_agent_registry().get_agent(asset_id)
                if enrolled:
                    ip = enrolled.get("ip_address") or "unknown"
                    name = enrolled.get("name", asset_id)
                    return {
                        "action": "one_liner_required",
                        "reason": (
                            f"{name} is an API-enrolled AI agent, not an "
                            "SSH-managed asset. To deploy the citadel daemon "
                            "on it, use the one-liner setup script."
                        ),
                        "agent_name": name,
                        "agent_ip": ip,
                        "steps": [
                            "1. Open the Assets tab and create a new invitation "
                            "with type=vps (or workstation) for this machine.",
                            "2. Copy the one-liner command from the invitation modal.",
                            "3. SSH to the machine (or run directly on it) and "
                            "paste the one-liner. It installs and starts the "
                            "citadel daemon automatically.",
                            "4. Verify with: systemctl status citadel-daemon",
                        ],
                    }
            except Exception:
                pass
            return {"error": f"Asset not found: {asset_id}"}

        if not asset.ssh_credential_id:
            return {
                "error": (
                    f"Asset {asset_id} has no SSH credential. "
                    "Use 'add vps <ip>' to onboard it first."
                )
            }

        ssh = get_ssh_manager()
        deployer = AgentDeployer(ssh, chat_manager=self._chat)
        return await deployer.deploy(asset_id)

    async def _tool_vps_summary(self, _input: Dict) -> Dict:
        db = self._get_shield_db()
        shield_agents = db.list_agents()
        all_threats = db.list_threats(status="open", limit=200)

        # Group threats by shield daemon agent
        per_agent = {}
        for a in shield_agents:
            agent_id = a["agent_id"]
            agent_threats = [t for t in all_threats if t.get("agent_id") == agent_id]
            per_agent[a.get("hostname", agent_id)] = {
                "agent_id": agent_id,
                "type": "shield_daemon",
                "last_heartbeat": a.get("last_heartbeat", ""),
                "version": a.get("version", ""),
                "open_threats": len(agent_threats),
                "critical": sum(1 for t in agent_threats if t.get("severity", 0) >= 9),
                "high": sum(1 for t in agent_threats if 7 <= t.get("severity", 0) < 9),
            }

        # Also include enrolled AI agents (claude_code, forge, custom) from
        # AgentRegistry.  These live in a separate store from shield daemons
        # but represent real connected machines the user cares about.
        enrolled: list = []
        try:
            from ..api.agent_api_routes import get_agent_registry
            for agent in get_agent_registry().list_agents():
                if agent.get("status") == "revoked":
                    continue
                enrolled.append({
                    "agent_id": agent["agent_id"],
                    "name": agent.get("name", agent["agent_id"]),
                    "type": agent.get("agent_type", "enrolled"),
                    "status": agent.get("status", "enrolled"),
                    "ip": agent.get("ip_address") or "",
                    "hostname": agent.get("hostname") or "",
                })
        except Exception:
            pass

        return {
            "total_agents": len(shield_agents) + len(enrolled),
            "shield_daemon_agents": len(shield_agents),
            "enrolled_ai_agents": len(enrolled),
            "total_open_threats": len(all_threats),
            "agents": per_agent,
            "enrolled_agents": enrolled,
        }

    async def _tool_daemon_threats(self, tool_input: Dict) -> Dict:
        """Return threat reports from enrolled citadel_daemon agents."""
        limit = min(int(tool_input.get("limit", 30)), 100)
        agent_id_filter = tool_input.get("agent_id", "")

        try:
            from ..core.audit_log import get_audit_logger, EventType
            audit = get_audit_logger()
            raw = audit.query_events(
                event_types=[EventType.REMOTE_THREAT, EventType.REMOTE_PATCH],
                limit=limit * 3,
            )
        except Exception as exc:
            return {"error": str(exc), "threats": [], "total": 0}

        threats = []
        for entry in raw:
            details = entry.get("details", {})
            if details.get("source") != "citadel_daemon":
                continue
            if agent_id_filter and details.get("agent_id") != agent_id_filter:
                continue
            host = details.get("hostname", "unknown")
            threats.append({
                "hostname":    host,
                "agent_id":    details.get("agent_id"),
                "agent_name":  details.get("agent_name", host),
                "type":        details.get("threat_type", entry.get("event_type")),
                "severity":    entry.get("severity"),
                "title":       entry.get("message", "").replace(f"[daemon:{host}] ", ""),
                "timestamp":   entry.get("timestamp"),
                "details":     {k: v for k, v in details.items()
                                if k not in ("source", "agent_id", "agent_name",
                                             "hostname", "threat_type", "severity",
                                             "timestamp")},
            })
            if len(threats) >= limit:
                break

        # Per-host summary
        by_host: Dict[str, Dict] = {}
        for t in threats:
            h = t["hostname"]
            if h not in by_host:
                by_host[h] = {
                    "hostname":    h,
                    "agent_id":    t.get("agent_id"),
                    "agent_name":  t.get("agent_name", h),
                    "total":       0,
                    "critical":    0,
                    "alert":       0,
                    "investigate": 0,
                    "info":        0,
                }
            by_host[h]["total"] += 1
            sev = t.get("severity", "")
            if sev in by_host[h]:
                by_host[h][sev] += 1

        if not threats:
            return {
                "total": 0,
                "by_host": [],
                "threats": [],
                "note": "No daemon threats reported yet — daemon may be running clean "
                        "or hasn't completed its first scan cycle.",
            }

        return {
            "total":    len(threats),
            "by_host":  list(by_host.values()),
            "threats":  threats,
        }

    async def _tool_execute_defensive_action(self, tool_input: Dict) -> Dict:
        """Queue a defensive action for one or more enrolled daemons."""
        asset_id = tool_input.get("asset_id", "").strip()
        assets_list = tool_input.get("assets")          # list or None
        action_id = tool_input.get("action_id", "").strip()
        parameters = tool_input.get("parameters") or {}
        threat_id = tool_input.get("threat_id", "")
        approval_override = tool_input.get("require_approval")

        from ..agent.defensive_playbook import PLAYBOOK, is_allowed, requires_approval
        from ..agent.actions_database import queue_action, init_db

        if not is_allowed(action_id):
            return {
                "error": f"Unknown action '{action_id}'. "
                         f"Available: {sorted(PLAYBOOK.keys())}",
            }

        entry = PLAYBOOK[action_id]
        needs_approval = requires_approval(action_id, approval_override)

        try:
            from ..api.agent_api_routes import get_agent_registry
            all_agents = get_agent_registry().list_agents()
        except Exception:
            all_agents = []

        targets = self._resolve_targets(asset_id, assets_list, all_agents)
        if not targets:
            if not asset_id and not assets_list:
                return {
                    "error": "No target specified. Provide 'asset_id' for a single daemon "
                             "or 'assets' (e.g. [\"all\"]) for multiple daemons.",
                }
            return {
                "error": f"No enrolled daemon matched {asset_id or assets_list!r}. "
                         "Use get_vps_summary() to list enrolled agents.",
            }

        init_db()

        if len(targets) == 1:
            agent_id, agent_name = targets[0]
            return await self._queue_single_action(
                agent_id, agent_name, action_id, entry, parameters, needs_approval, threat_id,
            )

        return await self._queue_distributed_action(
            targets, action_id, entry, parameters, needs_approval, threat_id,
        )

    def _resolve_targets(
        self, asset_id: str, assets_list, all_agents: List[Dict]
    ) -> List[tuple]:
        """Return [(agent_id, agent_name)] for the requested targets.

        Priority: assets_list > asset_id.
        Only daemon agents (vps/cloud/workstation) are valid targets.
        """
        daemon_agents = [
            a for a in all_agents
            if a.get("agent_type") in ("vps", "cloud", "workstation")
            and a.get("status") != "revoked"
        ]

        if assets_list is not None:
            # Normalise: accept string "all" or list ["all"]
            if assets_list == "all" or assets_list == ["all"]:
                return [
                    (a["agent_id"], a.get("name", a["agent_id"]))
                    for a in daemon_agents
                ]
            seen: set = set()
            targets = []
            for identifier in assets_list:
                identifier = str(identifier).strip()
                for a in daemon_agents:
                    if (
                        a.get("agent_id") == identifier
                        or a.get("hostname", "").lower() == identifier.lower()
                        or a.get("name", "").lower() == identifier.lower()
                    ):
                        aid = a["agent_id"]
                        if aid not in seen:
                            seen.add(aid)
                            targets.append((aid, a.get("name", identifier)))
                        break
            return targets

        if asset_id:
            for a in daemon_agents:
                if (
                    a.get("agent_id") == asset_id
                    or a.get("hostname", "").lower() == asset_id.lower()
                    or a.get("name", "").lower() == asset_id.lower()
                ):
                    return [(a["agent_id"], a.get("name", asset_id))]
            return []  # No match — do not fabricate a target for an unknown ID

        return []

    async def _queue_single_action(
        self, agent_id: str, agent_name: str, action_id: str,
        entry: Dict, parameters: Dict, needs_approval: bool, threat_id: str,
    ) -> Dict:
        """Queue action on one agent and return standard response dict."""
        from ..agent.actions_database import queue_action
        uuid = queue_action(
            agent_id=agent_id,
            action_id=action_id,
            parameters=parameters,
            require_approval=needs_approval,
            risk_level=entry.get("risk", "low"),
            description=entry.get("description", action_id),
            threat_id=threat_id,
        )
        if needs_approval:
            await self._send_approval_request(uuid, action_id, entry, parameters, agent_name)
            return {
                "status": "pending_approval",
                "action_uuid": uuid,
                "agent": agent_name,
                "message": (
                    "Approval request sent. The user must approve before the command "
                    "is delivered to the daemon."
                ),
            }
        return {
            "status": "queued",
            "action_uuid": uuid,
            "agent": agent_name,
            "action_id": action_id,
            "message": (
                "Command queued. It will be delivered on the daemon's next heartbeat "
                "(up to 5 minutes). Use get_action_history() to check the result."
            ),
        }

    async def _queue_distributed_action(
        self, targets: List[tuple], action_id: str, entry: Dict,
        parameters: Dict, needs_approval: bool, threat_id: str,
    ) -> Dict:
        """Queue the same action on multiple agents and return a summary."""
        from ..agent.actions_database import queue_action
        results = []
        for agent_id, agent_name in targets:
            uuid = queue_action(
                agent_id=agent_id,
                action_id=action_id,
                parameters=parameters,
                require_approval=needs_approval,
                risk_level=entry.get("risk", "low"),
                description=entry.get("description", action_id),
                threat_id=threat_id,
            )
            if needs_approval:
                await self._send_approval_request(
                    uuid, action_id, entry, parameters, agent_name,
                )
            results.append({
                "agent":       agent_name,
                "agent_id":    agent_id,
                "action_uuid": uuid,
                "status":      "pending_approval" if needs_approval else "queued",
            })

        deliver_note = (
            "Approval cards sent — one per agent. Approve each to authorize execution."
            if needs_approval else
            "Commands will be delivered to each daemon on its next heartbeat (up to 5 min)."
        )
        return {
            "status":       "distributed",
            "action_id":    action_id,
            "target_count": len(targets),
            "actions":      results,
            "message":      f"Queued {action_id} on {len(targets)} daemon(s). {deliver_note}",
        }

    async def _send_approval_request(
        self,
        action_uuid: str,
        action_id: str,
        playbook_entry: Dict,
        parameters: Dict,
        agent_name: str,
    ) -> None:
        """Broadcast an approval-request message into the chat sidebar."""
        try:
            from ..chat.message import ChatMessage, MessageType, PARTICIPANT_CITADEL
            desc = playbook_entry.get("description", action_id)
            risk = playbook_entry.get("risk", "medium").upper()
            param_lines = "\n".join(
                f"  - **{k}**: `{v}`" for k, v in parameters.items()
            ) or "  *(no parameters)*"
            text = (
                f"**Action Approval Required** ({risk} RISK)\n\n"
                f"**Action:** {action_id}\n"
                f"**Target:** {agent_name}\n"
                f"**Description:** {desc}\n\n"
                f"**Parameters:**\n{param_lines}\n\n"
                f"*This action requires your approval before it is sent to the daemon.*"
            )
            msg = ChatMessage(
                from_id=PARTICIPANT_CITADEL,
                msg_type=MessageType.RESPONSE,
                payload={
                    "text": text,
                    "action_type": "approval_request",
                    "action_uuid": action_uuid,
                    "action_id": action_id,
                    "agent_name": agent_name,
                },
            )
            await self._chat.send(msg)
        except Exception:
            logger.exception("Failed to send approval request message")

    async def _tool_get_defensive_playbook(self, tool_input: Dict) -> Dict:
        """Return the defensive action playbook."""
        from ..agent.defensive_playbook import PLAYBOOK
        action_id = tool_input.get("action_id", "").strip()
        if action_id:
            entry = PLAYBOOK.get(action_id)
            if not entry:
                return {"error": f"Unknown action '{action_id}'"}
            return {action_id: entry}
        return {
            "playbook": PLAYBOOK,
            "summary": {
                "auto_execute": [k for k, v in PLAYBOOK.items() if not v["require_approval"]],
                "require_approval": [k for k, v in PLAYBOOK.items() if v["require_approval"]],
            },
        }

    async def _tool_get_action_history(self, tool_input: Dict) -> Dict:
        """Return the audit trail of defensive actions."""
        from ..agent.actions_database import list_actions, init_db
        init_db()
        agent_id = tool_input.get("asset_id", "")
        action_id_filter = tool_input.get("action_id", "")
        status_filter = tool_input.get("status", "")
        limit = min(int(tool_input.get("limit", 20)), 100)

        actions = list_actions(
            agent_id=agent_id,
            action_id=action_id_filter,
            status=status_filter,
            limit=limit,
        )
        summary: Dict[str, int] = {}
        for a in actions:
            s = a.get("status", "unknown")
            summary[s] = summary.get(s, 0) + 1

        return {
            "total": len(actions),
            "status_summary": summary,
            "actions": [
                {
                    "action_uuid": a["action_uuid"],
                    "agent_id":    a["agent_id"],
                    "action_id":   a["action_id"],
                    "status":      a["status"],
                    "risk":        a["risk_level"],
                    "created_at":  a["created_at"],
                    "executed_at": a.get("executed_at"),
                    "result":      a.get("result"),
                }
                for a in actions
            ],
        }

    async def _tool_local_events(self, tool_input: Dict) -> Dict:
        """Return recent local Guardian events from the audit log."""
        limit = min(int(tool_input.get("limit", 20)), 100)
        severity_filter = tool_input.get("severity", "").lower()

        # Severity ordering for minimum-severity filtering
        _SEV_ORDER = {"info": 0, "warning": 1, "alert": 2, "critical": 3}
        min_sev = _SEV_ORDER.get(severity_filter, -1)

        try:
            from ..core.audit_log import get_audit_logger, EventType
            audit = get_audit_logger()
            # Query guardian-related event types (file + process sensor events)
            guardian_types = [
                EventType.FILE_CREATED,
                EventType.FILE_MODIFIED,
                EventType.FILE_DELETED,
                EventType.FILE_QUARANTINED,
                EventType.PROCESS_STARTED,
                EventType.PROCESS_KILLED,
                EventType.PROCESS_SUSPICIOUS,
            ]
            raw_events = audit.query_events(event_types=guardian_types, limit=limit * 3)
        except Exception as exc:
            logger.warning("get_local_events: audit query failed: %s", exc)
            return {"error": str(exc), "events": []}

        events_out = []
        for ev in raw_events:
            sev = ev.get("severity", "info").lower()
            if min_sev >= 0 and _SEV_ORDER.get(sev, 0) < min_sev:
                continue

            details = ev.get("details", {}) or {}
            events_out.append({
                "timestamp": ev.get("timestamp", ""),
                "event_type": ev.get("event_type", ""),
                "severity": sev,
                "message": ev.get("message", ""),
                "file_path": (
                    details.get("file_path")
                    or details.get("path")
                    or details.get("file")
                    or ""
                ),
                "details": details,
            })
            if len(events_out) >= limit:
                break

        return {
            "total": len(events_out),
            "events": events_out,
        }
