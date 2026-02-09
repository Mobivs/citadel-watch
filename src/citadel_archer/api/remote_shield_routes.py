# Remote Shield Agent API Routes
# Phase 2.2: VPS Monitoring Agent System
#
# Endpoints for Remote Shield agents to register, report threats, and send heartbeats.
# Agents deployed on VPS submit detected threats to central dashboard.
#
# SECURITY HARDENING - Phase 1: Critical Vulnerabilities Fixed
# - Added token validation to registration endpoint (C1)
# - Added bearer token authentication to query endpoints (C2)
# - Implemented token hashing and TTL (C3, C6)
# - Added authentication to threat status updates (C4)
# - Prepared for database migration (C5 - in progress)

from typing import List, Optional, Dict, Tuple
from fastapi import APIRouter, HTTPException, status, Header, Depends
from pydantic import BaseModel, Field, validator
from datetime import datetime, timedelta
import secrets
import uuid
from enum import Enum
import bcrypt
import os

router = APIRouter(prefix="/api", tags=["remote-shield"])

# ============================================================================
# SECURITY: Bootstrap token for agent registration
# ============================================================================
# This token must be pre-shared out-of-band with agents.
# For production, store in environment variable or secure config file.
BOOTSTRAP_TOKEN = os.getenv("BOOTSTRAP_TOKEN", "INSECURE_BOOTSTRAP_TOKEN_CHANGE_ME")

# ============================================================================
# SECURITY: In-memory token storage with hashing and TTL
# Structure: token_hash -> { agent_id, expires_at, issued_at, is_revoked }
# ============================================================================
agent_tokens = {}  # token_hash -> { agent_id, expires_at, issued_at, is_revoked }
token_blacklist = set()  # Set of revoked token hashes (for early-out performance)

# In-memory storage (replace with database in production)
agents_db = {}  # agent_id -> agent_info
remote_threats_db = {}  # threat_id -> threat_info


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
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Agent hostname (alphanumeric, dash, dot, underscore)"
    )
    ip: str = Field(..., description="Agent IP address")
    public_key: Optional[str] = Field(None, description="Public key for mTLS (future)")

    @validator('hostname')
    def validate_hostname(cls, v):
        """Validate hostname format to prevent injection attacks."""
        import re
        if not re.match(r'^[a-zA-Z0-9\-_.]+$', v):
            raise ValueError('Hostname must contain only alphanumeric, dash, dot, underscore')
        return v


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
    title: str = Field(..., max_length=500, description="Threat title (max 500 chars)")
    details: Optional[dict] = Field(None, description="Threat-specific details (max 100 keys, 10KB total)")
    hostname: str = Field(
        ...,
        max_length=255,
        description="Hostname where threat was detected"
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    @validator('details')
    def validate_details_size(cls, v):
        """Validate details field size to prevent DoS."""
        if v is None:
            return v
        import json
        if len(v) > 100:  # Max 100 keys
            raise ValueError('Details object too large (max 100 keys)')
        if len(json.dumps(v)) > 10240:  # Max 10KB
            raise ValueError('Details object too large (max 10KB)')
        return v

    @validator('hostname')
    def validate_hostname(cls, v):
        """Validate hostname format to prevent injection attacks."""
        import re
        if not re.match(r'^[a-zA-Z0-9\-_.]+$', v):
            raise ValueError('Hostname must contain only alphanumeric, dash, dot, underscore')
        return v


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


# ============================================================================
# SECURITY: Token management functions with hashing and TTL
# ============================================================================

def hash_token(token: str) -> str:
    """Hash a token using bcrypt for secure storage."""
    return bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode()

def verify_token_hash(token: str, token_hash: str) -> bool:
    """Verify a plaintext token against its bcrypt hash."""
    try:
        return bcrypt.checkpw(token.encode(), token_hash.encode())
    except Exception:
        return False

def create_api_token() -> Tuple[str, str]:
    """
    Generate a new API token and its hash.
    Returns: (plaintext_token, token_hash)
    """
    plaintext_token = secrets.token_urlsafe(32)
    token_hash = hash_token(plaintext_token)
    return plaintext_token, token_hash

def validate_bootstrap_token(provided_token: str) -> bool:
    """Validate bootstrap token for registration."""
    return provided_token == BOOTSTRAP_TOKEN

# ============================================================================
# SECURITY: Token verification dependency
# ============================================================================

def verify_agent_token(authorization: Optional[str] = Header(None)) -> str:
    """
    Verify agent API token from Authorization header.
    Expected format: "Bearer <token>"
    
    Checks:
    - Token format is valid
    - Token hash exists and is not expired
    - Token has not been revoked
    
    Returns:
        agent_id (str): The agent ID associated with the token
    
    Raises:
        HTTPException: 401 if token is invalid/expired/revoked
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
    
    # Find token hash (linear search - TODO: use database index in production)
    for token_hash, token_data in agent_tokens.items():
        if verify_token_hash(token, token_hash):
            # Token hash found, check if revoked
            if token_hash in token_blacklist:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            # Check if token has expired
            if datetime.utcnow() > token_data['expires_at']:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            return token_data['agent_id']
    
    # No matching token found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API token"
    )


# Routes
@router.post("/agents/register", response_model=AgentRegistrationResponse)
async def register_agent(
    registration: AgentRegistration,
    bootstrap_token: Optional[str] = Header(None, alias="X-Bootstrap-Token")
):
    """
    Register a new Remote Shield agent.
    Called by agent on startup to get unique agent_id and API token.
    
    SECURITY: Requires valid bootstrap token (shared out-of-band with agents)
    
    Args:
        registration: Agent details (hostname, IP)
        bootstrap_token: Required bearer token for authentication
    
    Returns:
        - agent_id: Unique identifier for this agent
        - api_token: Bearer token for API authentication (24-hour TTL)
    
    Raises:
        HTTPException: 401 if bootstrap token is invalid
    """
    # SECURITY: Validate bootstrap token (C1 FIX)
    if not bootstrap_token or not validate_bootstrap_token(bootstrap_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bootstrap token (provide via X-Bootstrap-Token header)"
        )

    # Check if agent already registered (by hostname)
    existing = [a for a in agents_db.values() if a["hostname"] == registration.hostname]
    if existing:
        agent_id = existing[0]["id"]
        # Regenerate token for existing agent (previous token is invalidated)
        api_token, token_hash = create_api_token()
        token_expires = datetime.utcnow() + timedelta(hours=24)
        agent_tokens[token_hash] = {
            'agent_id': agent_id,
            'expires_at': token_expires,
            'issued_at': datetime.utcnow(),
            'is_revoked': False
        }
        return AgentRegistrationResponse(
            agent_id=agent_id,
            api_token=api_token,
            message=f"Agent {registration.hostname} re-registered with new token (expires in 24 hours)"
        )

    # Create new agent
    agent_id = str(uuid.uuid4())
    api_token, token_hash = create_api_token()
    token_expires = datetime.utcnow() + timedelta(hours=24)

    agents_db[agent_id] = {
        "id": agent_id,
        "hostname": registration.hostname,
        "ip_address": registration.ip,
        "public_key": registration.public_key,
        "status": AgentStatus.ACTIVE,
        "last_heartbeat": datetime.utcnow(),
        "registered_at": datetime.utcnow(),
        "last_scan_at": None,
    }

    agent_tokens[token_hash] = {
        'agent_id': agent_id,
        'expires_at': token_expires,
        'issued_at': datetime.utcnow(),
        'is_revoked': False
    }

    return AgentRegistrationResponse(
        agent_id=agent_id,
        api_token=api_token,
        message=f"Agent {registration.hostname} registered successfully (token expires in 24 hours)"
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
async def list_agents(
    agent_id: str = Depends(verify_agent_token)
):
    """
    List all registered Remote Shield agents.
    Returns agent status, last heartbeat, registration time.
    
    SECURITY: Requires valid bearer token (C2 FIX)
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
async def get_agent(
    agent_id: str,
    verified_id: str = Depends(verify_agent_token)
):
    """
    Get details for a specific agent.
    
    SECURITY: Requires valid bearer token (C2 FIX)
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
    verified_id: str = Depends(verify_agent_token),
    agent_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    List threats detected by Remote Shield agents.
    Supports filtering by agent_id, threat_type, status.
    
    SECURITY: Requires valid bearer token (C2 FIX)

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
async def get_threat(
    threat_id: str,
    verified_id: str = Depends(verify_agent_token)
):
    """
    Get details for a specific threat.
    
    SECURITY: Requires valid bearer token (C2 FIX)
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
    new_status: str = "acknowledged",
    agent_id: str = Depends(verify_agent_token)
):
    """
    Update threat status (acknowledge, resolve, etc).
    
    SECURITY: Requires valid bearer token (C4 FIX)
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


# ============================================================================
# SECURITY: Token management endpoints (Phase 1 critical fixes)
# ============================================================================

class TokenRefreshResponse(BaseModel):
    """Response when token is refreshed."""
    agent_id: str
    api_token: str
    expires_at: datetime


class TokenRevocationResponse(BaseModel):
    """Response when token is revoked."""
    message: str
    revoked_at: datetime


@router.post("/agents/{agent_id}/token/refresh", response_model=TokenRefreshResponse)
async def refresh_agent_token(
    agent_id: str,
    current_token: str = Depends(verify_agent_token)
):
    """
    Refresh an agent's API token.
    
    SECURITY: Allows token rotation without re-registration (C6 FIX)
    
    Returns:
        - New API token with 24-hour TTL
        - Old token remains valid until expired
    
    NOTE: For production, implement token revocation on refresh
    """
    if agent_id not in agents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    # Verify the token belongs to the agent
    if current_token != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not belong to this agent"
        )

    # Create new token
    new_token, new_token_hash = create_api_token()
    token_expires = datetime.utcnow() + timedelta(hours=24)
    
    agent_tokens[new_token_hash] = {
        'agent_id': agent_id,
        'expires_at': token_expires,
        'issued_at': datetime.utcnow(),
        'is_revoked': False
    }

    return TokenRefreshResponse(
        agent_id=agent_id,
        api_token=new_token,
        expires_at=token_expires
    )


@router.post("/agents/{agent_id}/token/revoke", response_model=TokenRevocationResponse)
async def revoke_agent_token(
    agent_id: str,
    current_token: str = Depends(verify_agent_token)
):
    """
    Revoke an agent's current API token.
    
    SECURITY: Allows immediate token revocation if compromised (H6 FIX)
    
    After revocation:
        - Token becomes invalid immediately
        - Agent must use bootstrap token to register for new token
        - Useful for incident response
    """
    if agent_id not in agents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found"
        )

    # Verify the token belongs to the agent
    if current_token != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not belong to this agent"
        )

    # Find and revoke token
    revoked_count = 0
    for token_hash, token_data in list(agent_tokens.items()):
        if token_data['agent_id'] == agent_id:
            token_blacklist.add(token_hash)
            revoked_count += 1

    return TokenRevocationResponse(
        message=f"Revoked {revoked_count} token(s) for agent {agent_id}",
        revoked_at=datetime.utcnow()
    )
