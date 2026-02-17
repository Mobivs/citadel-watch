"""
Firewall Management API — Endpoints for managing VPS firewall rules.

Follows the router pattern from ssh_hardening_routes.py.
"""

import logging
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


# ── Pydantic Models ────────────────────────────────────────────────

class FirewallRuleRequest(BaseModel):
    action: str = Field("deny", description="deny, allow, or rate_limit")
    source: str = Field(..., description="IP, CIDR, or geo:XX country code")
    protocol: str = Field("any", description="tcp, udp, icmp, or any")
    port: str = Field("", description="Port or port range (e.g. 22, 80,443, 1024:2048)")
    direction: str = Field("in", description="in or out")
    priority: int = Field(100, ge=1, le=999)
    enabled: bool = True
    comment: str = ""

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        if v not in ("deny", "allow", "rate_limit"):
            raise ValueError("action must be one of: deny, allow, rate_limit")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v):
        """Validate source is an IP, CIDR, 'any', or geo:XX pattern."""
        if not v or not v.strip():
            raise ValueError("source must not be empty")
        v = v.strip()
        if v == "any":
            return v
        if re.match(r'^geo:[A-Za-z]{2}$', v):
            return v
        if re.match(r'^[\d./]+$', v) or re.match(r'^[\da-fA-F:./]+$', v):
            return v
        raise ValueError("source must be an IP address, CIDR, 'any', or 'geo:XX'")

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        if v not in ("tcp", "udp", "icmp", "any"):
            raise ValueError("protocol must be one of: tcp, udp, icmp, any")
        return v

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v):
        if v not in ("in", "out"):
            raise ValueError("direction must be 'in' or 'out'")
        return v


class FirewallRuleResponse(BaseModel):
    id: int
    asset_id: str
    action: str
    source: str
    protocol: str = "any"
    port: str = ""
    direction: str = "in"
    priority: int = 100
    enabled: bool = True
    auto_generated: bool = False
    expires_at: Optional[str] = None
    comment: str = ""
    created_at: Optional[str] = None


class FirewallRuleUpdateRequest(BaseModel):
    action: Optional[str] = None
    source: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None
    direction: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=999)
    enabled: Optional[bool] = None
    comment: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        if v is not None and v not in ("deny", "allow", "rate_limit"):
            raise ValueError("action must be one of: deny, allow, rate_limit")
        return v

    @field_validator("source")
    @classmethod
    def validate_source(cls, v):
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("source must not be empty")
            if v == "any":
                return v
            if re.match(r'^geo:[A-Za-z]{2}$', v):
                return v
            if re.match(r'^[\d./]+$', v) or re.match(r'^[\da-fA-F:./]+$', v):
                return v
            raise ValueError("source must be an IP address, CIDR, 'any', or 'geo:XX'")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        if v is not None and v not in ("tcp", "udp", "icmp", "any"):
            raise ValueError("protocol must be one of: tcp, udp, icmp, any")
        return v

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v):
        if v is not None and v not in ("in", "out"):
            raise ValueError("direction must be 'in' or 'out'")
        return v


class PushResult(BaseModel):
    success: bool
    pushed_count: int = 0
    error: str = ""


# ── Dependencies ───────────────────────────────────────────────────

def _get_firewall_mgr():
    """Get the desktop firewall manager from dashboard services."""
    from .dashboard_ext import services
    ssh_mgr = services.get("ssh_manager")
    shield_db = services.get("shield_db")
    if not ssh_mgr or not shield_db:
        raise HTTPException(status_code=503, detail="SSH manager or shield database not available")
    from ..remote.firewall_manager import DesktopFirewallManager
    return DesktopFirewallManager(ssh_mgr, shield_db)


def _get_shield_db():
    """Get the shield database."""
    from .dashboard_ext import services
    db = services.get("shield_db")
    if not db:
        raise HTTPException(status_code=503, detail="Shield database not available")
    return db


# ── Endpoints ──────────────────────────────────────────────────────

@router.post("/rules/{asset_id}", response_model=FirewallRuleResponse)
async def add_firewall_rule(
    asset_id: str,
    rule: FirewallRuleRequest,
    _token: str = Depends(verify_session_token),
):
    """Add a firewall rule for a VPS asset."""
    mgr = _get_firewall_mgr()
    rule_dict = rule.model_dump()
    rule_id = mgr.add_rule(asset_id, rule_dict)

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION, EventSeverity.INFO,
            f"Firewall rule added for {asset_id}: {rule.action} {rule.source}",
            details={"asset_id": asset_id, "rule_id": rule_id, "action": rule.action},
        )
    except Exception:
        pass

    return FirewallRuleResponse(
        id=rule_id,
        asset_id=asset_id,
        **rule_dict,
    )


@router.get("/rules/{asset_id}", response_model=List[FirewallRuleResponse])
async def list_firewall_rules(
    asset_id: str,
    enabled_only: bool = True,
    _token: str = Depends(verify_session_token),
):
    """List firewall rules for a VPS asset."""
    db = _get_shield_db()
    rules = db.get_firewall_rules(asset_id, enabled_only=enabled_only)
    return [FirewallRuleResponse(**r) for r in rules]


@router.put("/rules/{rule_id}", response_model=dict)
async def update_firewall_rule(
    rule_id: int,
    updates: FirewallRuleUpdateRequest,
    _token: str = Depends(verify_session_token),
):
    """Update a firewall rule."""
    db = _get_shield_db()
    update_dict = {k: v for k, v in updates.model_dump().items() if v is not None}
    if not update_dict:
        raise HTTPException(status_code=400, detail="No fields to update")
    success = db.update_firewall_rule(rule_id, update_dict)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "rule_id": rule_id}


@router.delete("/rules/{rule_id}")
async def delete_firewall_rule(
    rule_id: int,
    _token: str = Depends(verify_session_token),
):
    """Delete a firewall rule."""
    db = _get_shield_db()
    success = db.delete_firewall_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "rule_id": rule_id}


@router.post("/push/{asset_id}", response_model=PushResult)
async def push_firewall_rules(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Compile and push all enabled rules to the VPS."""
    mgr = _get_firewall_mgr()
    result = await mgr.push_rules(asset_id)

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION,
            EventSeverity.ALERT if result["success"] else EventSeverity.WARNING,
            f"Firewall rules push {'succeeded' if result['success'] else 'failed'}: {asset_id}",
            details={"asset_id": asset_id, "pushed_count": result["pushed_count"]},
        )
    except Exception:
        pass

    return PushResult(**result)
