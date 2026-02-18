# Remote Shield Agent API Routes
# Phase 2.2: VPS Monitoring Agent System
#
# Endpoints for Remote Shield agents to register, report threats, and send heartbeats.
# Agents deployed on VPS submit detected threats to central dashboard.
#
# v0.2.5: Auto-links agents to managed assets on registration.
# v0.3.1: SQLite persistence — agent/threat data survives restarts.
#          API tokens are SHA-256 hashed before storage.

import logging
from typing import List, Literal, Optional
from fastapi import APIRouter, HTTPException, status, Header, Depends, Request
from pydantic import BaseModel, Field
from datetime import datetime
import secrets
import uuid
from enum import Enum

from ..intel.assets import (
    Asset,
    AssetInventory,
    AssetPlatform,
    AssetStatus,
    AssetType,
)
from ..remote.shield_database import RemoteShieldDatabase
from ..chat.agent_registry import SHIELD_AGENT_TYPES
from ..chat.agent_rate_limiter import AgentRateLimiter
from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["remote-shield"])

# Persistent database (replaces in-memory dicts)
_shield_db: Optional[RemoteShieldDatabase] = None

# Asset inventory singleton (shared with asset_routes)
_asset_inventory: Optional[AssetInventory] = None


def get_shield_db() -> RemoteShieldDatabase:
    """Get or create the RemoteShieldDatabase singleton."""
    global _shield_db
    if _shield_db is None:
        _shield_db = RemoteShieldDatabase()
    return _shield_db


def set_shield_db(db: RemoteShieldDatabase):
    """Allow DI for testing."""
    global _shield_db
    _shield_db = db


def get_asset_inventory() -> AssetInventory:
    """Get or create the shared AssetInventory singleton."""
    global _asset_inventory
    if _asset_inventory is None:
        _asset_inventory = AssetInventory()
    return _asset_inventory


def set_asset_inventory(inv: AssetInventory):
    """Allow DI for testing."""
    global _asset_inventory
    _asset_inventory = inv


def _generate_shield_context(
    agent_id: str, hostname: str, platform: str = "vps",
    coordinator_url: str = "",
) -> str:
    """Generate operational context for a Shield agent (best-effort)."""
    try:
        from ..chat.agent_context import generate_context
        return generate_context(
            agent_id=agent_id,
            agent_name=hostname,
            agent_type=platform if platform in SHIELD_AGENT_TYPES else "vps",
            coordinator_url=coordinator_url,
        )
    except Exception:
        logger.warning("Failed to generate shield context for %s", agent_id)
        return ""


# Enums
class ThreatType(str, Enum):
    """Types of threats detected by Remote Shield agents."""
    # Linux/general
    PORT_SCAN_ANOMALY = "port_scan_anomaly"
    PROCESS_ANOMALY = "process_anomaly"
    FILE_INTEGRITY = "file_integrity"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    VULNERABILITY = "vulnerability"
    CONFIG_CHANGE = "config_change"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    # Windows-specific (v0.3.24)
    DEFENDER_DISABLED = "defender_disabled"
    FIREWALL_DISABLED = "firewall_disabled"
    LOGON_FAILURE = "logon_failure"
    AUDIT_LOG_CLEARED = "audit_log_cleared"
    SUSPICIOUS_SOFTWARE = "suspicious_software"
    WINDOWS_UPDATE_OVERDUE = "windows_update_overdue"


class AgentStatus(str, Enum):
    """Status of Remote Shield agent."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    OFFLINE = "offline"


class ThreatStatus(str, Enum):
    """Status of detected threat."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# Pydantic models
class AgentRegistration(BaseModel):
    """Agent registration request."""
    hostname: str = Field(..., description="Agent hostname")
    ip: str = Field(..., description="Agent IP address")
    public_key: Optional[str] = Field(None, description="Public key for mTLS (future)")


class Agent(BaseModel):
    """Agent information response."""
    id: str
    hostname: str
    ip_address: str
    platform: str = "linux"
    status: AgentStatus
    last_heartbeat: Optional[datetime]
    registered_at: datetime
    last_scan_at: Optional[datetime]
    patch_status: Optional[dict] = None


class ThreatDetails(BaseModel):
    """Threat details (flexible JSON)."""
    pass  # Allows arbitrary JSON


class ThreatReport(BaseModel):
    """Threat report from agent."""
    type: ThreatType = Field(..., description="Type of threat")
    severity: int = Field(..., ge=1, le=10, description="Severity level 1-10")
    title: str = Field(..., description="Threat title")
    details: Optional[dict] = Field(None, description="Threat-specific details")
    hostname: str = Field(..., description="Hostname where threat was detected")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RemoteThreat(BaseModel):
    """Remote threat record (database representation)."""
    id: str
    agent_id: str
    type: ThreatType
    severity: int
    title: str
    details: Optional[dict]
    hostname: str
    detected_at: datetime
    reported_at: datetime
    status: ThreatStatus
    created_at: datetime


class ThreatSubmissionResponse(BaseModel):
    """Response to threat submission."""
    id: str
    status: str
    message: str


class HeartbeatResponse(BaseModel):
    """Response to agent heartbeat."""
    status: str
    next_scan_interval: int = Field(default=300, description="Seconds until next scan")
    alert_threshold: int = Field(default=0, description="Min severity to report (0=all)")
    pending_commands: List[dict] = Field(default_factory=list, description="Commands for agent")


class AgentRegistrationResponse(BaseModel):
    """Response to agent registration."""
    agent_id: str
    api_token: str
    asset_id: Optional[str] = None
    message: str
    operational_context: str = Field(
        default="",
        description="Agent instructions and operational parameters",
    )


class PatchStatusReport(BaseModel):
    """Patch status data sent by agent."""
    pending_count: int = Field(0, description="Number of pending updates")
    installed_count: int = Field(0, description="Updates installed in last 30 days")
    last_check_date: Optional[str] = Field(None, description="Last WU check ISO timestamp")
    last_install_date: Optional[str] = Field(None, description="Last install ISO timestamp")
    reboot_required: bool = Field(False, description="Reboot needed to finish updates")
    oldest_pending_days: int = Field(0, description="Days since oldest pending update published")
    check_status: str = Field("unknown", description="ok | error | unknown")
    pending_titles: List[str] = Field(default_factory=list, description="Titles of pending updates")


class CommandAck(BaseModel):
    """Agent acknowledges command execution."""
    command_id: str
    result: str = Field("", description="Execution result or error message")


class QueueCommandRequest(BaseModel):
    """Dashboard request to queue a command for an agent."""
    command_type: str = Field(..., description="Command type (e.g. check_updates)")
    payload: dict = Field(default_factory=dict)


ALLOWED_COMMAND_TYPES = {
    "check_updates", "threat_alert", "apply_policy",
    "panic_isolate", "panic_terminate", "panic_rollback",
}


# Authentication dependency
def verify_agent_token(authorization: Optional[str] = Header(None)) -> str:
    """
    Verify agent API token from Authorization header.
    Expected format: "Bearer <token>"
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0] != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format (use 'Bearer <token>')"
        )

    token = parts[1]
    db = get_shield_db()
    agent_id = db.verify_token(token)
    if agent_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token"
        )

    return agent_id


# Routes
def _auto_link_agent(
    agent_id: str, hostname: str, ip_address: str, platform: str = "linux"
) -> Optional[str]:
    """Search for or create a managed asset, then link this agent to it.

    Returns the asset_id that was linked.
    """
    inv = get_asset_inventory()

    # 1. Search by IP first (more specific)
    asset = inv.find_by_ip(ip_address) if ip_address else None

    # 2. Fall back to hostname search
    if asset is None and hostname:
        asset = inv.find_by_hostname(hostname)

    if asset is not None:
        # Found existing asset — link agent and mark protected
        inv.link_remote_shield_agent(asset.asset_id, agent_id)
        inv.set_status(asset.asset_id, AssetStatus.PROTECTED)
        logger.info(f"Auto-linked agent {agent_id} to existing asset {asset.asset_id}")

        # Store asset_id in agent record
        db = get_shield_db()
        db.update_agent_asset_id(agent_id, asset.asset_id)

        return asset.asset_id

    # 3. No matching asset — create one with correct platform
    platform_map = {
        "windows": (AssetPlatform.WINDOWS, AssetType.WORKSTATION),
        "linux": (AssetPlatform.VPS, AssetType.VPS),
        "macos": (AssetPlatform.MAC, AssetType.WORKSTATION),
    }
    asset_platform, asset_type = platform_map.get(
        platform, (AssetPlatform.VPS, AssetType.VPS)
    )

    new_asset = Asset(
        name=hostname or ip_address or f"Agent {agent_id[:8]}",
        hostname=hostname,
        ip_address=ip_address,
        platform=asset_platform,
        asset_type=asset_type,
        status=AssetStatus.PROTECTED,
        remote_shield_agent_id=agent_id,
    )
    asset_id = inv.register(new_asset)
    logger.info(f"Created new asset {asset_id} for agent {agent_id} (platform={platform})")

    # Store asset_id in agent record
    db = get_shield_db()
    db.update_agent_asset_id(agent_id, asset_id)

    return asset_id


@router.post("/agents/register", response_model=AgentRegistrationResponse)
async def register_agent(registration: AgentRegistration, request: Request):
    """
    Register a new Remote Shield agent.
    Called by agent on startup to get unique agent_id and API token.

    v0.2.5: Auto-links agent to managed asset by IP/hostname.
    v0.3.1: Agent data persisted to SQLite. Token hashed before storage.

    Returns:
        - agent_id: Unique identifier for this agent
        - api_token: Bearer token for API authentication
        - asset_id: Linked managed asset ID
    """
    db = get_shield_db()
    base_url = str(request.base_url).rstrip("/")

    # Check if agent already registered (by hostname)
    existing = db.get_agent_by_hostname(registration.hostname)
    if existing:
        agent_id = existing["id"]
        # Regenerate token for existing agent (invalidates old token)
        api_token = secrets.token_urlsafe(32)
        db.update_agent_token(agent_id, api_token)

        # Re-link asset (in case it was deleted/recreated)
        asset_id = _auto_link_agent(agent_id, registration.hostname, registration.ip)

        context = _generate_shield_context(
            agent_id, registration.hostname, "vps", base_url,
        )

        return AgentRegistrationResponse(
            agent_id=agent_id,
            api_token=api_token,
            asset_id=asset_id,
            message=f"Agent {registration.hostname} re-registered with new token",
            operational_context=context,
        )

    # Create new agent
    agent_id = str(uuid.uuid4())
    api_token = secrets.token_urlsafe(32)

    db.create_agent(
        agent_id=agent_id,
        hostname=registration.hostname,
        ip_address=registration.ip,
        api_token=api_token,
        public_key=registration.public_key,
    )

    # Auto-link to managed asset
    asset_id = _auto_link_agent(agent_id, registration.hostname, registration.ip)

    context = _generate_shield_context(
        agent_id, registration.hostname, "vps", base_url,
    )

    return AgentRegistrationResponse(
        agent_id=agent_id,
        api_token=api_token,
        asset_id=asset_id,
        message=f"Agent {registration.hostname} registered successfully",
        operational_context=context,
    )


@router.post("/threats/remote-shield", response_model=ThreatSubmissionResponse)
async def submit_threat(
    threat: ThreatReport,
    agent_id: str = Depends(verify_agent_token)
):
    """
    Submit a detected threat from Remote Shield agent.
    Requires Bearer token authentication.

    Args:
        threat: Threat details from agent
        agent_id: Extracted from Bearer token (via dependency)

    Returns:
        - id: Threat ID in database
        - status: Submission status (success/queued)
    """
    db = get_shield_db()
    threat_id = str(uuid.uuid4())

    db.create_threat({
        "threat_id": threat_id,
        "agent_id": agent_id,
        "type": threat.type.value,
        "severity": threat.severity,
        "title": threat.title,
        "details": threat.details,
        "hostname": threat.hostname,
        "detected_at": threat.timestamp,
    })

    # Update agent's last_scan_at
    db.update_agent_last_scan(agent_id)

    # Bridge remote threat into EventAggregator for cross-system correlation
    try:
        from .dashboard_ext import services as _svc, _normalize_remote_severity
        _agg = _svc.event_aggregator
        if _agg is not None:
            agent_data = db.get_agent(agent_id)
            linked_asset = (agent_data or {}).get("asset_id") or agent_id
            _agg.ingest(
                event_type=f"remote.{threat.type.value}",
                severity=_normalize_remote_severity(threat.severity),
                asset_id=linked_asset,
                message=threat.title,
                details={
                    **(threat.details or {}),
                    "hostname": threat.hostname,
                    "agent_id": agent_id,
                    "original_severity": threat.severity,
                    "remote_threat_id": threat_id,
                },
                timestamp=threat.timestamp.isoformat(),
            )
    except Exception:
        logger.debug("EventAggregator bridge failed for threat %s", threat_id, exc_info=True)

    # Broadcast to main WebSocket for unified timeline (best-effort)
    try:
        from .main import manager  # lazy import avoids circular
        await manager.broadcast({
            "type": "threat:remote-shield",
            "data": {
                "id": threat_id,
                "agent_id": agent_id,
                "type": threat.type.value,
                "severity": threat.severity,
                "title": threat.title,
                "hostname": threat.hostname,
                "detected_at": threat.timestamp.isoformat(),
            },
        })
    except Exception:
        pass  # WS broadcast is best-effort; agent submission must not fail

    return ThreatSubmissionResponse(
        id=threat_id,
        status="success",
        message=f"Threat {threat.type} recorded successfully"
    )


@router.get("/agents", response_model=List[Agent])
async def list_agents():
    """
    List all registered Remote Shield agents.
    Returns agent status, last heartbeat, registration time.
    """
    db = get_shield_db()
    agents = db.list_agents()

    return [
        Agent(
            id=a["id"],
            hostname=a["hostname"],
            ip_address=a["ip_address"],
            platform=a.get("platform", "linux"),
            status=a["status"],
            last_heartbeat=a.get("last_heartbeat"),
            registered_at=a["registered_at"],
            last_scan_at=a.get("last_scan_at"),
            patch_status=a.get("patch_status"),
        )
        for a in agents
    ]


@router.get("/agents/{agent_id}", response_model=Agent)
async def get_agent(agent_id: str):
    """
    Get details for a specific agent.
    """
    db = get_shield_db()
    agent = db.get_agent(agent_id)

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    return Agent(
        id=agent["id"],
        hostname=agent["hostname"],
        ip_address=agent["ip_address"],
        platform=agent.get("platform", "linux"),
        status=agent["status"],
        last_heartbeat=agent.get("last_heartbeat"),
        registered_at=agent["registered_at"],
        last_scan_at=agent.get("last_scan_at"),
        patch_status=agent.get("patch_status"),
    )


@router.post("/agents/{agent_id}/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(
    agent_id: str,
    verified_id: str = Depends(verify_agent_token)
):
    """
    Agent sends heartbeat (I'm alive).
    Updates last_heartbeat timestamp for agent.

    Returns:
        - status: "ok"
        - next_scan_interval: Seconds until next scan (configurable by backend)
    """
    # Verify the token belongs to the agent_id in the URL
    if verified_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent can only heartbeat for itself"
        )

    db = get_shield_db()
    agent = db.get_agent(agent_id)

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    # Update last_heartbeat
    db.update_agent_heartbeat(agent_id)

    # Update linked asset's last_seen
    inv = get_asset_inventory()
    for asset in inv.all():
        if asset.remote_shield_agent_id == agent_id:
            asset.touch()
            inv._persist_asset(asset)
            break

    threshold = agent.get("alert_threshold", 0)

    # Dequeue pending commands for this agent
    pending = db.get_pending_commands(agent_id, limit=5)

    return HeartbeatResponse(
        status="ok",
        next_scan_interval=300,  # 5 minutes
        alert_threshold=threshold,
        pending_commands=pending,
    )


@router.put("/agents/{agent_id}/alert-threshold")
async def set_agent_alert_threshold(
    agent_id: str,
    body: dict,
    _token: str = Depends(verify_session_token),
):
    """Set the alert severity threshold for an agent (admin only).

    Events with severity below this threshold are suppressed by the agent.
    0 = report everything, 5 = medium+high+critical only, 8 = critical only.
    """
    threshold = body.get("threshold", 0)
    if not isinstance(threshold, int) or threshold < 0 or threshold > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="threshold must be an integer 0-10",
        )

    db = get_shield_db()
    agent = db.get_agent(agent_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    db.set_agent_alert_threshold(agent_id, threshold)
    return {"agent_id": agent_id, "alert_threshold": threshold}


# ── Patch Status & Command Queue ──────────────────────────────────


@router.post("/agents/{agent_id}/patch-status")
async def report_patch_status(
    agent_id: str,
    report: PatchStatusReport,
    verified_id: str = Depends(verify_agent_token),
):
    """Agent reports its current Windows Update status."""
    if verified_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent can only report its own patch status",
        )
    db = get_shield_db()
    db.update_patch_status(agent_id, report.model_dump())
    return {"status": "ok"}


@router.get("/agents/{agent_id}/patch-status")
async def get_agent_patch_status(
    agent_id: str,
    _token: str = Depends(verify_session_token),
):
    """Get patch status for a specific agent (session auth)."""
    db = get_shield_db()
    ps = db.get_patch_status(agent_id)
    if ps is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )
    return ps


@router.post("/agents/{agent_id}/commands")
async def queue_agent_command(
    agent_id: str,
    req: QueueCommandRequest,
    _token: str = Depends(verify_session_token),
):
    """Queue a command for an agent (dashboard-initiated, session auth)."""
    if req.command_type not in ALLOWED_COMMAND_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown command type: {req.command_type}. Allowed: {sorted(ALLOWED_COMMAND_TYPES)}",
        )
    db = get_shield_db()
    agent = db.get_agent(agent_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )
    command_id = str(uuid.uuid4())
    cmd = db.queue_command(command_id, agent_id, req.command_type, req.payload)
    return cmd


@router.post("/agents/{agent_id}/commands/ack")
async def acknowledge_command(
    agent_id: str,
    ack: CommandAck,
    verified_id: str = Depends(verify_agent_token),
):
    """Agent acknowledges command execution."""
    if verified_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent can only acknowledge its own commands",
        )
    db = get_shield_db()
    success = db.acknowledge_command(ack.command_id, ack.result)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Command {ack.command_id} not found or already acknowledged",
        )
    return {"status": "acknowledged", "command_id": ack.command_id}


@router.get("/threats/remote-shield", response_model=List[RemoteThreat])
async def list_remote_threats(
    agent_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    List threats detected by Remote Shield agents.
    Supports filtering by agent_id, threat_type, status.

    Query parameters:
        - agent_id: Filter by specific agent
        - threat_type: Filter by threat type
        - status: Filter by threat status (open, acknowledged, resolved)
        - limit: Max results (default 100)
        - offset: Pagination offset (default 0)
    """
    db = get_shield_db()
    threats = db.list_threats(
        agent_id=agent_id,
        threat_type=threat_type,
        status=status,
        limit=limit,
        offset=offset,
    )

    return [
        RemoteThreat(
            id=t["id"],
            agent_id=t["agent_id"],
            type=t["type"],
            severity=t["severity"],
            title=t["title"],
            details=t["details"],
            hostname=t["hostname"],
            detected_at=t["detected_at"],
            reported_at=t["reported_at"],
            status=t["status"],
            created_at=t["created_at"],
        )
        for t in threats
    ]


@router.get("/threats/remote-shield/{threat_id}", response_model=RemoteThreat)
async def get_threat(threat_id: str):
    """
    Get details for a specific threat.
    """
    db = get_shield_db()
    t = db.get_threat(threat_id)

    if t is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    return RemoteThreat(
        id=t["id"],
        agent_id=t["agent_id"],
        type=t["type"],
        severity=t["severity"],
        title=t["title"],
        details=t["details"],
        hostname=t["hostname"],
        detected_at=t["detected_at"],
        reported_at=t["reported_at"],
        status=t["status"],
        created_at=t["created_at"],
    )


@router.patch("/threats/remote-shield/{threat_id}/status")
async def update_threat_status(
    threat_id: str,
    new_status: str = "acknowledged"
):
    """
    Update threat status (acknowledge, resolve, etc).
    """
    db = get_shield_db()
    t = db.get_threat(threat_id)

    if t is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    try:
        ThreatStatus(new_status)  # validate
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{new_status}'. Must be: {', '.join([s.value for s in ThreatStatus])}"
        )

    db.update_threat_status(threat_id, new_status)

    return {
        "id": threat_id,
        "status": new_status,
        "message": "Threat status updated"
    }


# ── Shield Agent Enrollment (via invitation) ─────────────────────────

_shield_enroll_limiter: Optional[AgentRateLimiter] = None
SHIELD_ENROLL_RATE_LIMIT = 10  # per minute per IP


def get_shield_enroll_limiter() -> AgentRateLimiter:
    global _shield_enroll_limiter
    if _shield_enroll_limiter is None:
        _shield_enroll_limiter = AgentRateLimiter()
    return _shield_enroll_limiter


def set_shield_enroll_limiter(limiter: AgentRateLimiter):
    """Allow DI for testing."""
    global _shield_enroll_limiter
    _shield_enroll_limiter = limiter


class ShieldEnrollRequest(BaseModel):
    """Request to enroll a Remote Shield agent via invitation."""
    invitation_string: str = Field(..., min_length=20, max_length=200)
    hostname: str = Field(..., min_length=1, max_length=253, pattern=r'^[a-zA-Z0-9._-]+$')
    ip: str = Field("", description="Agent IP address")
    platform: Literal["linux", "windows", "macos"] = Field(
        "linux", description="Agent platform"
    )


@router.post("/agents/enroll", response_model=AgentRegistrationResponse)
async def enroll_shield_agent(req: ShieldEnrollRequest, request: Request):
    """Enroll a Remote Shield agent using an invitation string.

    No authentication required. Rate-limited by client IP.
    Verifies the invitation, creates a Remote Shield agent, and
    auto-links to a managed asset with the correct platform.

    Returns agent_id + api_token (Bearer token for future API calls).
    """
    # Rate limit by client IP
    client_ip = request.client.host if request.client else "unknown"
    limiter = get_shield_enroll_limiter()
    allowed, remaining = limiter.check(client_ip, SHIELD_ENROLL_RATE_LIMIT)
    if not allowed:
        try:
            from ..core.audit_log import log_security_event, EventType, EventSeverity
            log_security_event(
                EventType.AUTH, EventSeverity.ALERT,
                "Shield enrollment rate limit exceeded",
                details={"ip": client_ip},
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many enrollment attempts. Try again later.",
        )

    # Parse invitation string
    try:
        from ..chat.agent_invitation import InvitationStore, get_invitation_store
        invitation_id, raw_secret = InvitationStore.parse_compact_string(
            req.invitation_string
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid invitation string format",
        )

    # Pre-check: verify this invitation is for a Shield agent BEFORE consuming
    store = get_invitation_store()
    pre_check = store.get_invitation(invitation_id)
    if pre_check is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired invitation",
        )
    if pre_check.agent_type not in SHIELD_AGENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This invitation is not for a Shield agent. Use /api/ext-agents/enroll instead.",
        )

    # Verify and consume the invitation
    success, error_code, invitation = store.verify_and_consume(
        invitation_id, raw_secret, client_ip
    )

    if not success:
        try:
            from ..core.audit_log import log_security_event, EventType, EventSeverity
            log_security_event(
                EventType.AUTH, EventSeverity.ALERT,
                f"Shield enrollment failed: {error_code}",
                details={
                    "invitation_id": invitation_id,
                    "ip": client_ip,
                    "error": error_code,
                },
            )
        except Exception:
            pass

        if error_code == "locked":
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Invitation locked due to too many failed attempts",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired invitation",
        )

    # Create Remote Shield agent
    db = get_shield_db()
    agent_id = f"shield_{uuid.uuid4().hex[:12]}"
    api_token = secrets.token_urlsafe(32)

    try:
        db.create_agent(
            agent_id=agent_id,
            hostname=req.hostname,
            ip_address=req.ip,
            api_token=api_token,
            platform=req.platform,
        )
    except Exception as e:
        logger.error(
            "Shield agent creation failed after invitation consumed: %s (invitation=%s)",
            e, invitation_id,
        )
        # Revert the consumed invitation so it can be retried
        try:
            store.revert_consumed(invitation_id)
        except Exception as revert_err:
            logger.error("Failed to revert invitation %s: %s", invitation_id, revert_err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Enrollment failed during agent registration. Please retry.",
        )

    # Auto-link to managed asset with correct platform
    asset_id = _auto_link_agent(agent_id, req.hostname, req.ip, req.platform)

    # Update invitation with resulting agent_id
    try:
        store.set_resulting_agent_id(invitation_id, agent_id)
    except Exception:
        pass  # Non-critical — invitation is already consumed

    # Audit log
    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AUTH, EventSeverity.INFO,
            f"Shield agent enrolled via invitation: {agent_id}",
            details={
                "agent_id": agent_id,
                "hostname": req.hostname,
                "platform": req.platform,
                "invitation_id": invitation_id,
                "ip": client_ip,
                "asset_id": asset_id,
            },
        )
    except Exception:
        pass

    logger.info(
        "Shield agent %s enrolled via invitation %s (platform=%s, asset=%s)",
        agent_id, invitation_id, req.platform, asset_id,
    )

    context = _generate_shield_context(
        agent_id, req.hostname, req.platform,
        str(request.base_url).rstrip("/"),
    )

    return AgentRegistrationResponse(
        agent_id=agent_id,
        api_token=api_token,
        asset_id=asset_id,
        message=f"Shield agent {req.hostname} enrolled successfully (platform: {req.platform})",
        operational_context=context,
    )


# ── Agent Context Endpoint ───────────────────────────────────────────


@router.get("/shield/agents/context")
async def get_shield_agent_context(
    request: Request,
    agent_id: str = Depends(verify_agent_token),
):
    """Return operational context for the calling Shield agent.

    Allows an authenticated agent to re-fetch its instructions at any time.
    """
    db = get_shield_db()
    agent = db.get_agent(agent_id)
    hostname = agent["hostname"] if agent else agent_id
    platform = agent.get("platform", "vps") if agent else "vps"
    base_url = str(request.base_url).rstrip("/")

    context = _generate_shield_context(agent_id, hostname, platform, base_url)
    return {"operational_context": context}
