"""
SSH Hardening API — Endpoints for managing SSH hardening on remote VPS assets.

Follows the router pattern from remote_shield_routes.py.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hardening", tags=["ssh-hardening"])


# ── Pydantic Models ────────────────────────────────────────────────

class HardeningConfigRequest(BaseModel):
    disable_password_auth: bool = True
    permit_root_login: str = Field("prohibit-password", description="no or prohibit-password")
    max_auth_tries: int = Field(3, ge=1, le=10)
    custom_ssh_port: Optional[int] = Field(None, ge=1, le=65535)
    enable_port_knocking: bool = False
    knock_sequence: List[int] = Field(default=[7000, 8000, 9000])
    knock_timeout: int = Field(15, ge=5, le=60)
    fail2ban_threshold: int = Field(5, ge=1, le=100)
    fail2ban_window: int = Field(300, ge=60, le=3600)
    ban_durations: List[int] = Field(default=[300, 3600, 86400])
    permanent_ban_after: int = Field(5, ge=2, le=20)
    ip_whitelist: List[str] = Field(default=[])

    @field_validator("permit_root_login")
    @classmethod
    def validate_permit_root_login(cls, v):
        allowed = {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}
        if v not in allowed:
            raise ValueError(f"permit_root_login must be one of {allowed}")
        return v


class HardenResultResponse(BaseModel):
    success: bool
    asset_id: str
    changes_applied: List[str] = []
    warnings: List[str] = []
    error: str = ""


class HardeningStatusResponse(BaseModel):
    asset_id: str
    db_status: Optional[str] = None
    config: Optional[dict] = None
    applied_at: Optional[str] = None
    remote_status: Optional[dict] = None


class RollbackResponse(BaseModel):
    success: bool
    asset_id: str
    details: str = ""
    error: str = ""


# ── Dependency: get orchestrator ───────────────────────────────────

def _get_orchestrator():
    """Lazy-load the SSH hardening orchestrator from dashboard services."""
    from .dashboard_ext import services
    ssh_mgr = services.get("ssh_manager")
    shield_db = services.get("shield_db")
    vault = services.get("vault")
    chat = services.get("chat_manager")

    if not ssh_mgr or not shield_db:
        raise HTTPException(
            status_code=503,
            detail="SSH manager or shield database not available",
        )

    from ..remote.ssh_hardening import SSHHardeningOrchestrator
    return SSHHardeningOrchestrator(ssh_mgr, shield_db, vault, chat)


def _get_shield_db():
    """Get the shield database from dashboard services."""
    from .dashboard_ext import services
    db = services.get("shield_db")
    if not db:
        raise HTTPException(status_code=503, detail="Shield database not available")
    return db


# ── Endpoints ──────────────────────────────────────────────────────

@router.post("/ssh/{asset_id}", response_model=HardenResultResponse)
async def apply_ssh_hardening(
    asset_id: str,
    config: HardeningConfigRequest,
    _token: str = Depends(verify_session_token),
):
    """Apply SSH hardening to a remote asset."""
    from ..remote.ssh_hardening import HardeningConfig

    orchestrator = _get_orchestrator()
    hconfig = HardeningConfig(
        disable_password_auth=config.disable_password_auth,
        permit_root_login=config.permit_root_login,
        max_auth_tries=config.max_auth_tries,
        custom_ssh_port=config.custom_ssh_port,
        enable_port_knocking=config.enable_port_knocking,
        knock_sequence=config.knock_sequence,
        knock_timeout=config.knock_timeout,
        fail2ban_threshold=config.fail2ban_threshold,
        fail2ban_window=config.fail2ban_window,
        ban_durations=config.ban_durations,
        permanent_ban_after=config.permanent_ban_after,
        ip_whitelist=config.ip_whitelist,
    )

    result = await orchestrator.harden_asset(asset_id, hconfig)

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.ALERT if result.success else EventSeverity.WARNING,
            f"SSH hardening {'applied' if result.success else 'failed'}: {asset_id}",
            details={"asset_id": asset_id, "success": result.success,
                      "changes": result.changes_applied, "error": result.error},
        )
    except Exception:
        pass

    return HardenResultResponse(
        success=result.success,
        asset_id=result.asset_id,
        changes_applied=result.changes_applied,
        warnings=result.warnings,
        error=result.error,
    )


@router.delete("/ssh/{asset_id}", response_model=RollbackResponse)
async def rollback_ssh_hardening(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Rollback SSH hardening on a remote asset."""
    orchestrator = _get_orchestrator()
    result = await orchestrator.rollback_hardening(asset_id)

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.ALERT,
            f"SSH hardening rollback for {asset_id}: {'success' if result.success else 'failed'}",
            details={"asset_id": asset_id, "success": result.success, "error": result.error},
        )
    except Exception:
        pass

    return RollbackResponse(
        success=result.success,
        asset_id=result.asset_id,
        details=result.details,
        error=result.error,
    )


@router.get("/ssh/{asset_id}", response_model=HardeningStatusResponse)
async def get_hardening_status(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Get current SSH hardening status for an asset."""
    orchestrator = _get_orchestrator()
    db = _get_shield_db()

    # DB config
    db_config = db.get_hardening_config(asset_id)

    # Live remote status
    remote_status = None
    try:
        live = await orchestrator.get_hardening_status(asset_id)
        remote_status = {
            "password_auth_enabled": live.password_auth_enabled,
            "root_login": live.root_login,
            "max_auth_tries": live.max_auth_tries,
            "ssh_port": live.ssh_port,
            "pubkey_auth": live.pubkey_auth,
            "key_installed": live.key_installed,
            "port_knocking_active": live.port_knocking_active,
            "fail2ban_enhanced": live.fail2ban_enhanced,
            "sshd_config_backup_exists": live.sshd_config_backup_exists,
        }
    except Exception as exc:
        logger.warning("Could not fetch live status for %s: %s", asset_id, exc)

    return HardeningStatusResponse(
        asset_id=asset_id,
        db_status=db_config["status"] if db_config else None,
        config=db_config["config"] if db_config else None,
        applied_at=db_config["applied_at"] if db_config else None,
        remote_status=remote_status,
    )


@router.get("/ssh", response_model=List[HardeningStatusResponse])
async def list_hardening_statuses(
    _token: str = Depends(verify_session_token),
):
    """List hardening configs for all assets."""
    db = _get_shield_db()
    configs = db.list_hardening_configs()
    return [
        HardeningStatusResponse(
            asset_id=c["asset_id"],
            db_status=c["status"],
            config=c["config"],
            applied_at=c["applied_at"],
        )
        for c in configs
    ]
