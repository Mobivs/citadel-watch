"""
Node Onboarding API — Endpoints for onboarding remote VPS/computers.

Follows the router pattern from ssh_hardening_routes.py.
"""

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


# ── Pydantic Models ────────────────────────────────────────────────

class OnboardingStartRequest(BaseModel):
    asset_id: str
    skip_hardening: bool = False
    skip_firewall: bool = False
    hardening_config: Optional[dict] = None
    default_firewall_rules: Optional[List[dict]] = None


class StepStatus(BaseModel):
    status: str
    message: str = ""
    timestamp: Optional[str] = None


class OnboardingStatusResponse(BaseModel):
    session_id: str
    asset_id: str
    status: str
    steps: Dict[str, StepStatus] = {}
    config: Optional[dict] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class OnboardingStartResponse(BaseModel):
    session_id: str
    asset_id: str
    success: bool
    status: str
    steps: Dict[str, dict] = {}
    error: str = ""


class RetryResponse(BaseModel):
    step: str
    status: str
    message: str = ""


# ── Dependencies ───────────────────────────────────────────────────

def _get_orchestrator():
    """Build the onboarding orchestrator from dashboard services."""
    from .dashboard_ext import services

    ssh_mgr = services.get("ssh_manager")
    shield_db = services.get("shield_db")
    inventory = services.get("asset_inventory")
    vault = services.get("vault")
    chat = services.get("chat_manager")

    if not ssh_mgr or not shield_db or not inventory:
        raise HTTPException(
            status_code=503,
            detail="Required services not available (ssh_manager, shield_db, asset_inventory)",
        )

    # Build sub-components
    from ..remote.agent_deployer import AgentDeployer
    deployer = AgentDeployer(ssh_mgr, chat)

    hardening_orch = None
    try:
        from ..remote.ssh_hardening import SSHHardeningOrchestrator
        hardening_orch = SSHHardeningOrchestrator(ssh_mgr, shield_db, vault, chat)
    except Exception:
        pass

    firewall_mgr = None
    try:
        from ..remote.firewall_manager import DesktopFirewallManager
        firewall_mgr = DesktopFirewallManager(ssh_mgr, shield_db)
    except Exception:
        pass

    # Get WebSocket broadcast function
    ws_broadcast = None
    try:
        from .main import manager
        ws_broadcast = manager.broadcast
    except Exception:
        pass

    from ..remote.onboarding import OnboardingOrchestrator
    return OnboardingOrchestrator(
        ssh_manager=ssh_mgr,
        shield_db=shield_db,
        inventory=inventory,
        vault=vault,
        agent_deployer=deployer,
        hardening_orch=hardening_orch,
        firewall_mgr=firewall_mgr,
        chat_manager=chat,
        ws_broadcast=ws_broadcast,
    )


def _get_shield_db():
    """Get the shield database."""
    from .dashboard_ext import services
    db = services.get("shield_db")
    if not db:
        raise HTTPException(status_code=503, detail="Shield database not available")
    return db


# ── Endpoints ──────────────────────────────────────────────────────

@router.post("/start", response_model=OnboardingStartResponse)
async def start_onboarding(
    request: OnboardingStartRequest,
    _token: str = Depends(verify_session_token),
):
    """Start onboarding for a remote asset."""
    from ..remote.onboarding import OnboardingConfig

    orch = _get_orchestrator()
    config = OnboardingConfig(
        asset_id=request.asset_id,
        skip_hardening=request.skip_hardening,
        skip_firewall=request.skip_firewall,
        hardening_config=request.hardening_config,
        default_firewall_rules=request.default_firewall_rules,
    )

    result = await orch.start_onboarding(config)

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.ALERT if result.success else EventSeverity.WARNING,
            f"Node onboarding {result.status}: {request.asset_id}",
            details={
                "asset_id": request.asset_id,
                "session_id": result.session_id,
                "status": result.status,
            },
        )
    except Exception:
        pass

    return OnboardingStartResponse(
        session_id=result.session_id,
        asset_id=result.asset_id,
        success=result.success,
        status=result.status,
        steps=result.steps,
        error=result.error,
    )


# NOTE: /sessions/list MUST be defined before /{session_id} to avoid
# FastAPI matching "sessions" as a session_id path parameter.
@router.get("/sessions/list", response_model=List[OnboardingStatusResponse])
async def list_onboarding_sessions(
    asset_id: Optional[str] = None,
    status: Optional[str] = None,
    _token: str = Depends(verify_session_token),
):
    """List all onboarding sessions."""
    db = _get_shield_db()
    sessions = db.list_onboarding_sessions(asset_id=asset_id, status=status)

    results = []
    for s in sessions:
        steps = {}
        for step_name, step_data in s.get("steps", {}).items():
            if isinstance(step_data, dict):
                steps[step_name] = StepStatus(**step_data)

        results.append(OnboardingStatusResponse(
            session_id=s["session_id"],
            asset_id=s["asset_id"],
            status=s["status"],
            steps=steps,
            config=s.get("config"),
            started_at=s.get("started_at"),
            completed_at=s.get("completed_at"),
        ))
    return results


@router.get("/{session_id}", response_model=OnboardingStatusResponse)
async def get_onboarding_status(
    session_id: str,
    _token: str = Depends(verify_session_token),
):
    """Get onboarding session status."""
    db = _get_shield_db()
    session = db.get_onboarding_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Convert steps dict to StepStatus models
    steps = {}
    for step_name, step_data in session.get("steps", {}).items():
        if isinstance(step_data, dict):
            steps[step_name] = StepStatus(**step_data)

    return OnboardingStatusResponse(
        session_id=session["session_id"],
        asset_id=session["asset_id"],
        status=session["status"],
        steps=steps,
        config=session.get("config"),
        started_at=session.get("started_at"),
        completed_at=session.get("completed_at"),
    )


@router.post("/{session_id}/retry/{step}", response_model=RetryResponse)
async def retry_onboarding_step(
    session_id: str,
    step: str,
    _token: str = Depends(verify_session_token),
):
    """Retry a failed onboarding step."""
    orch = _get_orchestrator()
    result = await orch.retry_step(session_id, step)
    return RetryResponse(
        step=result.step,
        status=result.status,
        message=result.message,
    )
