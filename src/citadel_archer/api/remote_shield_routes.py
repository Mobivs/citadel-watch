# Remote Shield Agent API Routes
# Phase 2.2: VPS Monitoring Agent System
#
# Endpoints for Remote Shield agents to register, report threats, and send heartbeats.
# Agents deployed on VPS submit detected threats to central dashboard.

from typing import List, Optional
from fastapi import APIRouter, HTTPException, status, Header, Depends
from pydantic import BaseModel, Field
from datetime import datetime
import secrets
import uuid
from enum import Enum

router = APIRouter(prefix="/api", tags=["remote-shield"])

# In-memory storage (replace with database in production)
agents_db = {}  # agent_id -> agent_info
remote_threats_db = {}  # threat_id -> threat_info
agent_tokens = {}  # api_token -> agent_id


# Enums
class ThreatType(str, Enum):
    """Types of threats detected by Remote Shield agents."""
    PORT_SCAN_ANOMALY = "port_scan_anomaly"
    PROCESS_ANOMALY = "process_anomaly"
    FILE_INTEGRITY = "file_integrity"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    VULNERABILITY = "vulnerability"
    CONFIG_CHANGE = "config_change"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


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
    status: AgentStatus
    last_heartbeat: Optional[datetime]
    registered_at: datetime
    last_scan_at: Optional[datetime]


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


class AgentRegistrationResponse(BaseModel):
    """Response to agent registration."""
    agent_id: str
    api_token: str
    message: str


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
    if token not in agent_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token"
        )

    return agent_tokens[token]  # Return agent_id


# Routes
@router.post("/agents/register", response_model=AgentRegistrationResponse)
async def register_agent(registration: AgentRegistration):
    """
    Register a new Remote Shield agent.
    Called by agent on startup to get unique agent_id and API token.

    Returns:
        - agent_id: Unique identifier for this agent
        - api_token: Bearer token for API authentication
    """
    # Check if agent already registered (by hostname)
    existing = [a for a in agents_db.values() if a["hostname"] == registration.hostname]
    if existing:
        agent_id = existing[0]["id"]
        # Regenerate token for existing agent
        api_token = secrets.token_urlsafe(32)
        agent_tokens[api_token] = agent_id
        return AgentRegistrationResponse(
            agent_id=agent_id,
            api_token=api_token,
            message=f"Agent {registration.hostname} re-registered with new token"
        )

    # Create new agent
    agent_id = str(uuid.uuid4())
    api_token = secrets.token_urlsafe(32)

    agents_db[agent_id] = {
        "id": agent_id,
        "hostname": registration.hostname,
        "ip_address": registration.ip,
        "api_token": api_token,
        "public_key": registration.public_key,
        "status": AgentStatus.ACTIVE,
        "last_heartbeat": datetime.utcnow(),
        "registered_at": datetime.utcnow(),
        "last_scan_at": None,
    }

    agent_tokens[api_token] = agent_id

    return AgentRegistrationResponse(
        agent_id=agent_id,
        api_token=api_token,
        message=f"Agent {registration.hostname} registered successfully"
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
    threat_id = str(uuid.uuid4())
    now = datetime.utcnow()

    remote_threats_db[threat_id] = {
        "id": threat_id,
        "agent_id": agent_id,
        "type": threat.type,
        "severity": threat.severity,
        "title": threat.title,
        "details": threat.details,
        "hostname": threat.hostname,
        "detected_at": threat.timestamp,
        "reported_at": now,
        "status": ThreatStatus.OPEN,
        "created_at": now,
    }

    # Update agent's last_scan_at
    if agent_id in agents_db:
        agents_db[agent_id]["last_scan_at"] = now

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
    return [
        Agent(
            id=a["id"],
            hostname=a["hostname"],
            ip_address=a["ip_address"],
            status=a["status"],
            last_heartbeat=a.get("last_heartbeat"),
            registered_at=a["registered_at"],
            last_scan_at=a.get("last_scan_at"),
        )
        for a in agents_db.values()
    ]


@router.get("/agents/{agent_id}", response_model=Agent)
async def get_agent(agent_id: str):
    """
    Get details for a specific agent.
    """
    if agent_id not in agents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    agent = agents_db[agent_id]
    return Agent(
        id=agent["id"],
        hostname=agent["hostname"],
        ip_address=agent["ip_address"],
        status=agent["status"],
        last_heartbeat=agent.get("last_heartbeat"),
        registered_at=agent["registered_at"],
        last_scan_at=agent.get("last_scan_at"),
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

    if agent_id not in agents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    # Update last_heartbeat
    agents_db[agent_id]["last_heartbeat"] = datetime.utcnow()
    agents_db[agent_id]["status"] = AgentStatus.ACTIVE

    return HeartbeatResponse(
        status="ok",
        next_scan_interval=300  # 5 minutes
    )


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
    threats = list(remote_threats_db.values())

    # Apply filters
    if agent_id:
        threats = [t for t in threats if t["agent_id"] == agent_id]
    if threat_type:
        threats = [t for t in threats if t["type"] == threat_type]
    if status:
        threats = [t for t in threats if t["status"] == status]

    # Sort by reported_at (newest first)
    threats.sort(key=lambda x: x["reported_at"], reverse=True)

    # Paginate
    threats = threats[offset:offset + limit]

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
    if threat_id not in remote_threats_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    t = remote_threats_db[threat_id]
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
    if threat_id not in remote_threats_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat {threat_id} not found"
        )

    try:
        remote_threats_db[threat_id]["status"] = ThreatStatus(new_status)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{new_status}'. Must be: {', '.join([s.value for s in ThreatStatus])}"
        )

    return {
        "id": threat_id,
        "status": new_status,
        "message": "Threat status updated"
    }
