"""Group Policy API Routes — manage security profiles for Remote Shield agents.

v0.3.30: Create/update/delete policy groups, manage membership, apply policies
to all group members, and track compliance status.
"""

import logging
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..remote.group_policy import GroupPolicyEngine
from .remote_shield_routes import get_shield_db
from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/policies", tags=["group-policies"])

SUPPORTED_RULE_TYPES = {"alert_threshold", "update_schedule", "firewall_rules"}


def _validate_rules(rules: dict):
    """Reject unknown rule types."""
    unknown = set(rules.keys()) - SUPPORTED_RULE_TYPES
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown rule types: {sorted(unknown)}. Supported: {sorted(SUPPORTED_RULE_TYPES)}",
        )


# ── Pydantic Models ───────────────────────────────────────────────────

class PolicyGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field("", max_length=500)
    rules: dict = Field(default_factory=dict)
    priority: int = Field(100, ge=1, le=1000)


class PolicyGroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    rules: Optional[dict] = None
    priority: Optional[int] = Field(None, ge=1, le=1000)


class AddMembersRequest(BaseModel):
    agent_ids: List[str] = Field(..., min_length=1)


# ── Group CRUD ────────────────────────────────────────────────────────

@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_policy_group(
    body: PolicyGroupCreate,
    _token: str = Depends(verify_session_token),
):
    _validate_rules(body.rules)
    db = get_shield_db()
    group_id = uuid.uuid4().hex[:12]
    group = db.create_policy_group(
        group_id=group_id,
        name=body.name,
        description=body.description,
        rules=body.rules,
        priority=body.priority,
    )
    return group


@router.get("/groups")
async def list_policy_groups(
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    groups = db.list_policy_groups()
    # Enrich with member count
    for g in groups:
        g["member_count"] = len(db.get_group_members(g["group_id"]))
    return {"groups": groups, "total": len(groups)}


@router.get("/groups/{group_id}")
async def get_policy_group(
    group_id: str,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    group = db.get_policy_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    group["members"] = db.get_group_members(group_id)
    group["member_count"] = len(group["members"])
    return group


@router.put("/groups/{group_id}")
async def update_policy_group(
    group_id: str,
    body: PolicyGroupUpdate,
    _token: str = Depends(verify_session_token),
):
    if body.rules is not None:
        _validate_rules(body.rules)
    db = get_shield_db()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    ok = db.update_policy_group(group_id, **updates)
    if not ok:
        raise HTTPException(status_code=404, detail="Group not found")
    return db.get_policy_group(group_id)


@router.delete("/groups/{group_id}")
async def delete_policy_group(
    group_id: str,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    ok = db.delete_policy_group(group_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Group not found")
    return {"deleted": True, "group_id": group_id}


# ── Membership ────────────────────────────────────────────────────────

@router.post("/groups/{group_id}/members")
async def add_group_members(
    group_id: str,
    body: AddMembersRequest,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    group = db.get_policy_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    added = 0
    not_found = []
    for agent_id in body.agent_ids:
        if db.get_agent(agent_id) is None:
            not_found.append(agent_id)
            continue
        if db.add_group_member(group_id, agent_id):
            added += 1
    result = {"added": added, "total_requested": len(body.agent_ids)}
    if not_found:
        result["not_found"] = not_found
    return result


@router.delete("/groups/{group_id}/members/{agent_id}")
async def remove_group_member(
    group_id: str,
    agent_id: str,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    ok = db.remove_group_member(group_id, agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Member not found in group")
    return {"removed": True, "agent_id": agent_id}


# ── Policy Application ───────────────────────────────────────────────

@router.post("/groups/{group_id}/apply")
async def apply_policy(
    group_id: str,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    group = db.get_policy_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    engine = GroupPolicyEngine(shield_db=db)
    result = engine.apply_policy(group_id)
    return result


@router.get("/groups/{group_id}/compliance")
async def get_compliance(
    group_id: str,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    group = db.get_policy_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    engine = GroupPolicyEngine(shield_db=db)
    return engine.get_compliance_summary(group_id)


# ── Per-Agent Effective Policy ────────────────────────────────────────

@router.get("/agents/{agent_id}/effective-policy")
async def get_effective_policy(
    agent_id: str,
    _token: str = Depends(verify_session_token),
):
    db = get_shield_db()
    engine = GroupPolicyEngine(shield_db=db)
    effective = engine.resolve_effective_rules(agent_id)
    groups = db.get_agent_groups(agent_id)
    return {
        "agent_id": agent_id,
        "effective_rules": effective,
        "groups": [{"group_id": g["group_id"], "name": g["name"], "priority": g["priority"]} for g in groups],
    }
