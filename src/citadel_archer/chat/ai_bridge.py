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
            "Get all managed assets (VPS servers, local machine) with their "
            "current status, IP address, and whether an agent is deployed."
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
            "Get an overview of all VPS agents: health status, open threat counts, "
            "severity breakdown. Use this for a bird's-eye view before drilling into "
            "specific assets."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
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

            # 4. Build system prompt
            security_level = state.get("security_level", "guardian")
            system = SYSTEM_PROMPT.format(
                security_level=security_level.title(),
                system_state=self._format_state(state),
            )

            # 5. Determine trigger type for audit logging
            if trigger.from_id == PARTICIPANT_USER:
                trigger_type = "user_text"
            elif trigger.from_id.startswith("ext-agent:"):
                trigger_type = "agent_text"
            else:
                trigger_type = "citadel_event"

            # 6. Call Claude with tool loop
            final_text = await self._call_with_tools(
                system, history, trigger_type, trigger.id,
                participant_id=trigger.from_id,
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
        try:
            from ..api.asset_routes import get_inventory

            assets = get_inventory().all()
            state["assets"] = [
                {
                    "id": a.asset_id,
                    "name": a.name,
                    "ip": a.ip_address,
                    "type": a.asset_type,
                    "status": a.status,
                    "has_agent": bool(a.remote_shield_agent_id),
                }
                for a in assets
            ]
        except Exception:
            state["assets"] = []

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

        return "\n".join(lines)

    # ── Claude API Call with Tool Loop ──────────────────────────────────

    async def _call_with_tools(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str = "unknown",
        trigger_message_id: str = "",
        participant_id: str = "user",
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
    ) -> Optional[str]:
        """Call Claude API with tool loop. Returns text or None on failure."""
        try:
            ctx = audit.start_call(trigger_type, trigger_message_id, self._model, 0)
            try:
                response = await asyncio.wait_for(
                    self._client.messages.create(
                        model=self._model,
                        max_tokens=1024,
                        system=system,
                        messages=messages,
                        tools=TOOLS,
                    ),
                    timeout=30,
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
                    "tool_loop", trigger_message_id, self._model, iteration
                )
                try:
                    response = await asyncio.wait_for(
                        self._client.messages.create(
                            model=self._model,
                            max_tokens=1024,
                            system=system,
                            messages=messages,
                            tools=TOOLS,
                        ),
                        timeout=30,
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
                max_tokens=1024,
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

    async def _execute_tool(self, name: str, tool_input: Dict) -> Any:
        """Dispatch a tool call to the appropriate handler."""
        handlers = {
            "get_system_status": self._tool_system_status,
            "get_asset_list": self._tool_asset_list,
            "get_agent_events": self._tool_agent_events,
            "deploy_agent": self._tool_deploy_agent,
            "get_vps_summary": self._tool_vps_summary,
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
        agents = db.list_agents()
        all_threats = db.list_threats(status="open", limit=200)

        # Group threats by agent
        per_agent = {}
        for a in agents:
            agent_id = a["agent_id"]
            agent_threats = [t for t in all_threats if t.get("agent_id") == agent_id]
            per_agent[a.get("hostname", agent_id)] = {
                "agent_id": agent_id,
                "last_heartbeat": a.get("last_heartbeat", ""),
                "version": a.get("version", ""),
                "open_threats": len(agent_threats),
                "critical": sum(1 for t in agent_threats if t.get("severity", 0) >= 9),
                "high": sum(1 for t in agent_threats if 7 <= t.get("severity", 0) < 9),
            }

        return {
            "total_agents": len(agents),
            "total_open_threats": len(all_threats),
            "agents": per_agent,
        }
