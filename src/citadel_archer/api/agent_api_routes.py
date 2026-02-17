# PRD: Trigger 1b — External AI Agent REST API
# Reference: docs/PRD.md, Trigger Model
#
# REST endpoints for external AI agents (Forge, OpenClaw, Claude Code)
# to send messages into SecureChat and trigger the AI Brain.
#
# Admin endpoints (register, list, revoke, rotate) use session token auth.
# Agent endpoint (send) uses Bearer token auth with rate limiting.
#
# The "ext-agent:" prefix distinguishes these from Remote Shield monitoring
# agents ("agent:"), which are security scanners, not conversational AI.

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ..chat.agent_registry import AgentRegistry
from ..chat.agent_rate_limiter import AgentRateLimiter
from ..chat.message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_CITADEL,
)
from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ext-agents", tags=["external-agents"])

# ── Singletons ────────────────────────────────────────────────────────

_registry: Optional[AgentRegistry] = None
_rate_limiter: Optional[AgentRateLimiter] = None


def get_agent_registry() -> AgentRegistry:
    """Get or create the AgentRegistry singleton."""
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
    return _registry


def set_agent_registry(reg: AgentRegistry):
    """Allow DI for testing."""
    global _registry
    _registry = reg


def get_rate_limiter() -> AgentRateLimiter:
    """Get or create the AgentRateLimiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = AgentRateLimiter()
    return _rate_limiter


def set_rate_limiter(limiter: AgentRateLimiter):
    """Allow DI for testing."""
    global _rate_limiter
    _rate_limiter = limiter


# Enrollment rate limiter — separate from agent rate limiter, keyed by IP
_enroll_limiter: Optional[AgentRateLimiter] = None
ENROLL_RATE_LIMIT_PER_MIN = 10


def get_enroll_limiter() -> AgentRateLimiter:
    """Get or create the enrollment rate limiter (keyed by IP)."""
    global _enroll_limiter
    if _enroll_limiter is None:
        _enroll_limiter = AgentRateLimiter()
    return _enroll_limiter


def set_enroll_limiter(limiter: AgentRateLimiter):
    """Allow DI for testing."""
    global _enroll_limiter
    _enroll_limiter = limiter


# ── Request / Response Models ─────────────────────────────────────────


class RegisterAgentRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Agent display name")
    agent_type: str = Field(..., description="Agent type: forge, openclaw, claude_code, custom")
    rate_limit_per_min: Optional[int] = Field(
        None, ge=1, le=600, description="Max messages per minute (default by type)"
    )


class RegisterAgentResponse(BaseModel):
    agent_id: str
    api_token: str
    name: str
    agent_type: str
    rate_limit_per_min: int
    message: str


class AgentInfoResponse(BaseModel):
    agent_id: str
    name: str
    agent_type: str
    rate_limit_per_min: int
    status: str
    created_at: Optional[str] = None
    last_message_at: Optional[str] = None
    message_count: int = 0


class SendMessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000, description="Message text")
    msg_type: str = Field("text", description="Message type (text or event)")


class SendMessageResponse(BaseModel):
    message_id: str
    status: str


class RotateTokenResponse(BaseModel):
    agent_id: str
    api_token: str
    message: str


# ── Invitation Models ─────────────────────────────────────────────────


class CreateInvitationRequest(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=100, description="Display name for the agent")
    agent_type: str = Field(..., description="Agent type: forge, openclaw, claude_code, custom")
    ttl_seconds: int = Field(600, ge=60, le=86400, description="Time-to-live in seconds (default 10 min)")
    max_attempts: int = Field(5, ge=1, le=20, description="Max failed verification attempts before lockout")
    recipient_email: str = Field("", max_length=254, description="Recipient email address (optional)")
    recipient_name: str = Field("", max_length=100, description="Recipient name (optional)")


class CreateInvitationResponse(BaseModel):
    invitation_id: str
    compact_string: str
    agent_name: str
    agent_type: str
    expires_at: str
    ttl_seconds: int
    message: str
    enrollment_url: str = ""
    mailto_url: str = ""


class EnrollAgentRequest(BaseModel):
    invitation_string: str = Field(..., min_length=20, max_length=200, description="Compact invitation string (CITADEL-1:...)")


class EnrollAgentResponse(BaseModel):
    agent_id: str
    api_token: str
    agent_name: str
    agent_type: str
    message: str


# ── Auth Dependencies ─────────────────────────────────────────────────


async def verify_external_agent_token(
    authorization: Optional[str] = Header(None),
) -> dict:
    """Verify Bearer token and enforce rate limit for external agents.

    Returns the agent dict from the registry on success.

    Raises:
        HTTPException 401: Missing/invalid/revoked token.
        HTTPException 429: Rate limit exceeded.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0] != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format (use 'Bearer <token>')",
        )

    token = parts[1]
    registry = get_agent_registry()
    agent = registry.verify_token(token)

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API token",
        )

    # Rate limit check
    limiter = get_rate_limiter()
    allowed, remaining = limiter.check(
        agent["agent_id"], agent["rate_limit_per_min"]
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({agent['rate_limit_per_min']}/min)",
            headers={"Retry-After": "60"},
        )

    return agent


# ── Admin Endpoints (session token auth) ──────────────────────────────


@router.post("/register", response_model=RegisterAgentResponse)
async def register_agent(
    req: RegisterAgentRequest,
    _token: str = Depends(verify_session_token),
):
    """Register a new external AI agent.

    Admin-only. Returns the agent_id and raw API token (shown once).
    """
    registry = get_agent_registry()

    try:
        agent_id, raw_token = registry.register_agent(
            name=req.name,
            agent_type=req.agent_type,
            rate_limit_per_min=req.rate_limit_per_min,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    agent = registry.get_agent(agent_id)

    # Audit log
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.INFO,
            f"External agent registered: {req.name} ({agent_id}, type={req.agent_type})",
            details={
                "action": "ext_agent_registered",
                "agent_id": agent_id,
                "name": req.name,
                "agent_type": req.agent_type,
            },
        )
    except Exception:
        logger.warning("Failed to log audit event for agent registration")

    return RegisterAgentResponse(
        agent_id=agent_id,
        api_token=raw_token,
        name=req.name,
        agent_type=req.agent_type,
        rate_limit_per_min=agent["rate_limit_per_min"],
        message=f"Agent '{req.name}' registered. Save this API token — it won't be shown again.",
    )


@router.get("/", response_model=List[AgentInfoResponse])
async def list_agents(
    _token: str = Depends(verify_session_token),
):
    """List all registered external agents."""
    registry = get_agent_registry()
    agents = registry.list_agents()
    return [
        AgentInfoResponse(
            agent_id=a["agent_id"],
            name=a["name"],
            agent_type=a["agent_type"],
            rate_limit_per_min=a["rate_limit_per_min"],
            status=a["status"],
            created_at=a.get("created_at"),
            last_message_at=a.get("last_message_at"),
            message_count=a.get("message_count", 0),
        )
        for a in agents
    ]


@router.delete("/{agent_id}")
async def revoke_agent(
    agent_id: str,
    _token: str = Depends(verify_session_token),
):
    """Revoke an external agent (disables its API token)."""
    registry = get_agent_registry()
    revoked = registry.revoke_agent(agent_id)

    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    # Audit log
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.ALERT,
            f"External agent revoked: {agent_id}",
            details={"action": "ext_agent_revoked", "agent_id": agent_id},
        )
    except Exception:
        logger.warning("Failed to log audit event for agent revocation")

    return {"agent_id": agent_id, "status": "revoked", "message": "Agent revoked"}


@router.post("/{agent_id}/rotate-token", response_model=RotateTokenResponse)
async def rotate_token(
    agent_id: str,
    _token: str = Depends(verify_session_token),
):
    """Generate a new API token for an agent, invalidating the old one."""
    registry = get_agent_registry()
    new_token = registry.rotate_token(agent_id)

    if new_token is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )

    # Audit log
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.INFO,
            f"External agent token rotated: {agent_id}",
            details={"action": "ext_agent_token_rotated", "agent_id": agent_id},
        )
    except Exception:
        logger.warning("Failed to log audit event for token rotation")

    return RotateTokenResponse(
        agent_id=agent_id,
        api_token=new_token,
        message="Token rotated. Save this new API token — it won't be shown again.",
    )


# ── Agent Endpoint (Bearer token auth) ────────────────────────────────


@router.post("/send", response_model=SendMessageResponse)
async def send_message(
    req: SendMessageRequest,
    agent: dict = Depends(verify_external_agent_token),
):
    """Send a message to SecureChat as an external AI agent.

    Requires Bearer token authentication. The message is delivered to
    SecureChat, triggering AI Brain analysis for TEXT messages.
    """
    # Validate msg_type
    try:
        msg_type = MessageType(req.msg_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid msg_type '{req.msg_type}'. Use 'text' or 'event'.",
        )

    # Build ChatMessage with ext-agent: prefix
    agent_id = agent["agent_id"]
    msg = ChatMessage(
        from_id=f"ext-agent:{agent_id}",
        to_id=PARTICIPANT_CITADEL,
        msg_type=msg_type,
        payload={
            "text": req.text,
            "agent_name": agent["name"],
            "agent_type": agent["agent_type"],
        },
    )

    # Send through ChatManager
    from .chat_routes import get_chat_manager

    chat_mgr = get_chat_manager()
    await chat_mgr.send(msg)

    # Record message in registry
    registry = get_agent_registry()
    registry.record_message(agent_id)

    logger.info(
        "External agent message: %s (%s) sent %s",
        agent["name"],
        agent_id,
        msg_type.value,
    )

    return SendMessageResponse(
        message_id=msg.id,
        status="sent",
    )


# ── Inter-Agent Communication Protocol ────────────────────────────────


class CapabilityItem(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Capability name")
    description: str = Field("", max_length=500)
    domains: List[str] = Field(default_factory=list, max_length=10)
    sla_seconds: int = Field(300, ge=1, le=3600)


class RegisterCapabilitiesRequest(BaseModel):
    capabilities: List[CapabilityItem] = Field(
        ..., min_length=1, max_length=20,
        description="List of capabilities to register",
    )


class DelegateTaskRequest(BaseModel):
    to_agent: str = Field(..., min_length=1, description="Target agent participant ID (e.g., ext-agent:abc123)")
    capability: str = Field(..., min_length=1, max_length=100, description="Capability to invoke")
    payload: dict = Field(default_factory=dict, description="Task input data")
    timeout_seconds: int = Field(300, ge=1, le=3600, description="Timeout in seconds")


class TaskResponseRequest(BaseModel):
    task_id: str = Field(..., description="Task ID to respond to")
    status: str = Field(..., description="Task status: accepted, completed, failed")
    result: Optional[dict] = Field(None, description="Result data (for completed)")
    error: Optional[str] = Field(None, max_length=1000, description="Error message (for failed)")


class HeartbeatRequest(BaseModel):
    version: str = Field("", max_length=50)
    status_detail: str = Field("", max_length=200)
    capabilities: Optional[List[CapabilityItem]] = None


@router.post("/{agent_id}/capabilities")
async def register_capabilities(
    agent_id: str,
    req: RegisterCapabilitiesRequest,
    agent: dict = Depends(verify_external_agent_token),
):
    """Declare capabilities for an agent.

    Agents call this to advertise what tasks they can handle.
    Other agents can discover them via the /discover endpoint.
    """
    # Verify the authenticated agent matches the path
    if agent["agent_id"] != agent_id:
        raise HTTPException(403, "Cannot register capabilities for a different agent")

    from ..chat.inter_agent import AgentCapability, get_inter_agent_protocol

    protocol = get_inter_agent_protocol()
    caps = [
        AgentCapability(
            name=c.name,
            description=c.description,
            domains=c.domains,
            sla_seconds=c.sla_seconds,
        )
        for c in req.capabilities
    ]
    participant_id = f"ext-agent:{agent_id}"
    stored = protocol.register_capabilities(participant_id, caps)
    return {
        "agent_id": agent_id,
        "capabilities": [c.to_dict() for c in stored],
    }


@router.get("/discover")
async def discover_agents(
    capability: str,
    domain: Optional[str] = None,
    online_only: bool = True,
    _token: str = Depends(verify_session_token),
):
    """Discover agents by capability.

    Find agents that have declared a specific capability,
    optionally filtered by domain and online status.
    """
    from ..chat.inter_agent import get_inter_agent_protocol

    protocol = get_inter_agent_protocol()
    results = protocol.discover(capability, domain=domain, online_only=online_only)
    return {"agents": results, "total": len(results)}


@router.post("/delegate")
async def delegate_task(
    req: DelegateTaskRequest,
    agent: dict = Depends(verify_external_agent_token),
):
    """Delegate a task from the authenticated agent to another agent.

    Creates a DELEGATION message routed to the target agent with
    request-response correlation tracking.
    """
    from ..chat.inter_agent import get_inter_agent_protocol

    protocol = get_inter_agent_protocol()
    from_agent = f"ext-agent:{agent['agent_id']}"

    try:
        task = await protocol.delegate(
            from_agent=from_agent,
            to_agent=req.to_agent,
            capability=req.capability,
            payload=req.payload,
            timeout_seconds=req.timeout_seconds,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return task.to_dict()


@router.post("/task-response")
async def respond_to_task(
    req: TaskResponseRequest,
    agent: dict = Depends(verify_external_agent_token),
):
    """Respond to a delegated task (accept, complete, or fail).

    The responding agent sends this after receiving a DELEGATION message
    from their inbox.
    """
    from ..chat.inter_agent import get_inter_agent_protocol

    protocol = get_inter_agent_protocol()

    task = protocol.get_task(req.task_id)
    if task is None:
        raise HTTPException(404, "Task not found")

    # Verify the responding agent is the target
    agent_participant = f"ext-agent:{agent['agent_id']}"
    if task.to_agent != agent_participant:
        raise HTTPException(403, "This task is not delegated to you")

    if req.status == "accepted":
        result = protocol.accept_task(req.task_id)
    elif req.status == "completed":
        if req.result is None:
            raise HTTPException(400, "Result required for completed status")
        result = protocol.complete_task(req.task_id, req.result)
    elif req.status == "failed":
        result = protocol.fail_task(req.task_id, req.error or "Unknown error")
    else:
        raise HTTPException(400, f"Invalid status: {req.status}. Use: accepted, completed, failed")

    if result is None:
        raise HTTPException(
            409,
            f"Task cannot transition to '{req.status}' from current state",
        )

    # Send ACK/RESPONSE back to requesting agent via ChatManager
    from .chat_routes import get_chat_manager
    chat_mgr = get_chat_manager()

    ack_msg = ChatMessage(
        from_id=agent_participant,
        to_id=task.from_agent,
        msg_type=MessageType.ACK if req.status == "accepted" else MessageType.RESPONSE,
        payload={
            "text": f"Task {req.task_id}: {req.status}",
            "task_id": req.task_id,
            "task_status": req.status,
            "result": req.result,
            "error": req.error,
            "agent_name": agent["name"],
        },
        reply_to=req.task_id,
        correlation_id=task.correlation_id,
    )

    # Buffer in requesting agent's inbox
    protocol._buffer_message(task.from_agent, ack_msg)

    await chat_mgr.send(ack_msg)

    return result.to_dict()


@router.get("/{agent_id}/inbox")
async def get_inbox(
    agent_id: str,
    limit: int = Query(50, ge=1, le=200),
    agent: dict = Depends(verify_external_agent_token),
):
    """Get buffered messages for an agent (polling endpoint).

    Returns and clears messages from the agent's inbox.
    Agents poll this endpoint to receive delegation requests
    and task responses.
    """
    if agent["agent_id"] != agent_id:
        raise HTTPException(403, "Cannot access another agent's inbox")

    from ..chat.inter_agent import get_inter_agent_protocol

    protocol = get_inter_agent_protocol()
    agent_participant = f"ext-agent:{agent_id}"
    messages = protocol.get_inbox(agent_participant, limit=limit)

    return {
        "messages": [m.to_dict() for m in messages],
        "count": len(messages),
    }


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    req: HeartbeatRequest,
    agent: dict = Depends(verify_external_agent_token),
):
    """Record an agent heartbeat (marks agent as online).

    Agents should call this every 1-2 minutes to maintain online status.
    Optionally updates capabilities and metadata.
    """
    if agent["agent_id"] != agent_id:
        raise HTTPException(403, "Cannot heartbeat for a different agent")

    from ..chat.inter_agent import AgentCapability, get_inter_agent_protocol

    protocol = get_inter_agent_protocol()
    caps = None
    if req.capabilities:
        caps = [
            AgentCapability(
                name=c.name,
                description=c.description,
                domains=c.domains,
                sla_seconds=c.sla_seconds,
            )
            for c in req.capabilities
        ]

    participant_id = f"ext-agent:{agent_id}"
    presence = protocol.heartbeat(
        agent_id=participant_id,
        version=req.version,
        status_detail=req.status_detail,
        capabilities=caps,
    )
    return presence.to_dict()


@router.get("/protocol/stats")
async def protocol_stats(
    _token: str = Depends(verify_session_token),
):
    """Get inter-agent protocol statistics."""
    from ..chat.inter_agent import get_inter_agent_protocol
    return get_inter_agent_protocol().stats()


@router.get("/protocol/tasks")
async def list_tasks(
    agent_id: Optional[str] = None,
    task_status: Optional[str] = None,
    _token: str = Depends(verify_session_token),
):
    """List delegated tasks with optional filtering."""
    from ..chat.inter_agent import TaskStatus, get_inter_agent_protocol

    protocol = get_inter_agent_protocol()
    status_filter = None
    if task_status:
        try:
            status_filter = TaskStatus(task_status)
        except ValueError:
            raise HTTPException(400, f"Invalid task status: {task_status}")

    tasks = protocol.list_tasks(agent_id=agent_id, status=status_filter)
    return {"tasks": [t.to_dict() for t in tasks], "total": len(tasks)}


@router.get("/protocol/online")
async def list_online_agents(
    _token: str = Depends(verify_session_token),
):
    """List all online agents with their capabilities."""
    from ..chat.inter_agent import get_inter_agent_protocol
    agents = get_inter_agent_protocol().list_online_agents()
    return {"agents": agents, "total": len(agents)}


# ── Invitation-Based Enrollment ──────────────────────────────────────


@router.post("/invitations", response_model=CreateInvitationResponse)
async def create_invitation(
    req: CreateInvitationRequest,
    request: Request,
    _token: str = Depends(verify_session_token),
):
    """Create a one-time invitation for agent enrollment.

    Admin-only. Returns a compact string to copy-paste to the VPS terminal.
    The string is shown once — it cannot be retrieved later.
    """
    from ..chat.agent_invitation import get_invitation_store

    store = get_invitation_store()

    try:
        invitation, compact_string = store.create_invitation(
            agent_name=req.agent_name,
            agent_type=req.agent_type,
            ttl_seconds=req.ttl_seconds,
            max_attempts=req.max_attempts,
            created_by="admin",
            recipient_email=req.recipient_email,
            recipient_name=req.recipient_name,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Audit log
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.INFO,
            f"Agent invitation created: {invitation.invitation_id} "
            f"for {req.agent_name} (type={req.agent_type}, ttl={req.ttl_seconds}s)",
            details={
                "action": "invitation_created",
                "invitation_id": invitation.invitation_id,
                "agent_name": req.agent_name,
                "agent_type": req.agent_type,
                "ttl_seconds": req.ttl_seconds,
            },
        )
    except Exception:
        logger.warning("Failed to log audit event for invitation creation")

    # Build enrollment URL and mailto link (v0.3.32 Easy Deployment)
    from ..chat.agent_invitation import InvitationStore
    _, raw_secret = InvitationStore.parse_compact_string(compact_string)
    base_url = str(request.base_url).rstrip("/")
    enrollment_url = f"{base_url}/enroll/{invitation.invitation_id}?s={raw_secret}"

    mailto_url = ""
    if req.recipient_email:
        import urllib.parse
        name = req.recipient_name or "there"
        body = (
            f"Hi {name},\n\n"
            f"I've set up Citadel Archer to protect our home network. "
            f"Click this link to install the security agent on your computer:\n\n"
            f"{enrollment_url}\n\n"
            f"This link expires in {req.ttl_seconds // 60} minutes.\n\n"
            f"— Sent from Citadel Archer"
        )
        mailto_url = (
            f"mailto:{urllib.parse.quote(req.recipient_email)}"
            f"?subject={urllib.parse.quote('Join Citadel Home Security')}"
            f"&body={urllib.parse.quote(body)}"
        )

    return CreateInvitationResponse(
        invitation_id=invitation.invitation_id,
        compact_string=compact_string,
        agent_name=req.agent_name,
        agent_type=req.agent_type,
        expires_at=invitation.expires_at,
        ttl_seconds=invitation.ttl_seconds,
        message=(
            f"Invitation created for '{req.agent_name}'. "
            "Share the enrollment link or copy the compact string. "
            f"Expires in {req.ttl_seconds}s."
        ),
        enrollment_url=enrollment_url,
        mailto_url=mailto_url,
    )


@router.get("/invitations")
async def list_invitations(
    invitation_status: Optional[str] = None,
    _token: str = Depends(verify_session_token),
):
    """List invitations with optional status filter."""
    from ..chat.agent_invitation import InvitationStatus, get_invitation_store

    store = get_invitation_store()
    status_filter = None

    if invitation_status:
        try:
            status_filter = InvitationStatus(invitation_status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter: {invitation_status}",
            )

    # Opportunistically clean up expired invitations
    store.cleanup_expired()

    invitations = store.list_invitations(status_filter=status_filter)
    return {
        "invitations": [inv.to_dict() for inv in invitations],
        "total": len(invitations),
    }


@router.delete("/invitations/{invitation_id}")
async def revoke_invitation(
    invitation_id: str,
    _token: str = Depends(verify_session_token),
):
    """Revoke a pending invitation (admin-only).

    Only pending invitations can be revoked. Already redeemed,
    expired, or locked invitations cannot be revoked.
    """
    from ..chat.agent_invitation import get_invitation_store

    store = get_invitation_store()
    revoked = store.revoke_invitation(invitation_id)

    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found or not in pending status",
        )

    # Audit log
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.ALERT,
            f"Agent invitation revoked: {invitation_id}",
            details={"action": "invitation_revoked", "invitation_id": invitation_id},
        )
    except Exception:
        logger.warning("Failed to log audit event for invitation revocation")

    return {
        "invitation_id": invitation_id,
        "status": "revoked",
        "message": "Invitation revoked",
    }


@router.post("/enroll", response_model=EnrollAgentResponse)
async def enroll_agent(
    req: EnrollAgentRequest,
    request: Request,
):
    """Enroll an external AI agent using an invitation string.

    **No authentication required.** Rate-limited by client IP.

    The invitation string is a one-time token provided by an admin.
    On success, returns a permanent Bearer token for the agent.

    Error responses are intentionally generic to prevent information leakage:
    - 400: Invalid invitation string format
    - 401: "Invalid or expired invitation" (not found, wrong secret, expired, revoked)
    - 423: "Invitation locked" (too many failed attempts)
    - 429: Rate limited
    """
    from ..chat.agent_invitation import InvitationStore, get_invitation_store

    # IP rate limiting (separate from agent rate limiter)
    client_ip = request.client.host if request.client else "unknown"
    limiter = get_enroll_limiter()
    allowed, _remaining = limiter.check(client_ip, ENROLL_RATE_LIMIT_PER_MIN)
    if not allowed:
        # Audit: rate limited
        try:
            from ..core.audit_log import log_security_event, EventType, EventSeverity
            log_security_event(
                EventType.AI_DECISION,
                EventSeverity.ALERT,
                f"Enrollment rate limited: {client_ip}",
                details={"action": "enroll_rate_limited", "ip": client_ip},
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many enrollment attempts. Try again later.",
            headers={"Retry-After": "60"},
        )

    # Parse compact string
    try:
        invitation_id, raw_secret = InvitationStore.parse_compact_string(
            req.invitation_string
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid invitation string format",
        )

    # Verify and consume
    store = get_invitation_store()
    success, error_code, invitation = store.verify_and_consume(
        invitation_id, raw_secret, client_ip,
    )

    if not success:
        # Audit: failed enrollment
        try:
            from ..core.audit_log import log_security_event, EventType, EventSeverity
            severity = EventSeverity.CRITICAL if error_code == "locked" else EventSeverity.ALERT
            log_security_event(
                EventType.AI_DECISION,
                severity,
                f"Enrollment failed: {error_code} (invitation={invitation_id}, ip={client_ip})",
                details={
                    "action": "enroll_failed",
                    "invitation_id": invitation_id,
                    "error_code": error_code,
                    "ip": client_ip,
                },
            )
        except Exception:
            pass

        if error_code == "locked":
            raise HTTPException(
                status_code=423,  # Locked
                detail="Invitation locked due to too many failed attempts",
            )

        # Generic error for all other failures (prevents info leakage)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired invitation",
        )

    # Register the agent via AgentRegistry
    registry = get_agent_registry()
    try:
        agent_id, raw_token = registry.register_agent(
            name=invitation.agent_name,
            agent_type=invitation.agent_type,
        )
    except Exception as e:
        logger.error(
            "Agent registration failed after invitation consumed: %s (invitation=%s)",
            e, invitation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment failed during agent registration. Contact administrator.",
        )

    # Link invitation to resulting agent
    store.set_resulting_agent_id(invitation_id, agent_id)

    # Audit: successful enrollment
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.INFO,
            f"Agent enrolled via invitation: {invitation.agent_name} "
            f"(agent_id={agent_id}, invitation={invitation_id}, ip={client_ip})",
            details={
                "action": "agent_enrolled",
                "agent_id": agent_id,
                "invitation_id": invitation_id,
                "agent_name": invitation.agent_name,
                "agent_type": invitation.agent_type,
                "ip": client_ip,
            },
        )
    except Exception:
        logger.warning("Failed to log audit event for agent enrollment")

    return EnrollAgentResponse(
        agent_id=agent_id,
        api_token=raw_token,
        agent_name=invitation.agent_name,
        agent_type=invitation.agent_type,
        message=(
            f"Agent '{invitation.agent_name}' enrolled successfully. "
            "Save this API token — it won't be shown again."
        ),
    )
