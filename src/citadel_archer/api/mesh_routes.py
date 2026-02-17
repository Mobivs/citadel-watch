"""Defense Mesh API routes — peer management and mesh status.

v0.3.35: REST endpoints for the mesh heartbeat protocol.
Follows performance_routes.py pattern (standalone router, Pydantic models, session auth).
"""

import ipaddress
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mesh", tags=["mesh"])


# ── Pydantic Models ──────────────────────────────────────────────────


class MeshPeerRequest(BaseModel):
    node_id: str
    ip_address: str
    port: int = 9378
    is_desktop: bool = False
    label: str = ""

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class MeshPeerResponse(BaseModel):
    node_id: str
    ip_address: str
    port: int = 9378
    is_desktop: bool = False
    label: str = ""
    last_seen: Optional[str] = None
    last_sequence: int = 0
    missed_count: int = 0
    escalation_phase: str = "NORMAL"
    model_tier: Optional[str] = None
    registered_at: str = ""
    last_payload: dict = Field(default_factory=dict)


class MeshStatusResponse(BaseModel):
    node_id: str
    is_running: bool
    total_peers: int = 0
    by_phase: dict = Field(default_factory=dict)
    packets_received: int = 0
    packets_invalid: int = 0
    packets_rejected: int = 0
    psk_fingerprint: Optional[str] = None


class MeshConfigRequest(BaseModel):
    interval: Optional[int] = None  # 5-300 seconds


class MeshConfigResponse(BaseModel):
    interval: int = 30
    port: int = 9378
    thresholds: dict = Field(default_factory=dict)


# ── Coordinator Access ───────────────────────────────────────────────

_mesh_coordinator = None


def get_mesh_coordinator():
    return _mesh_coordinator


def set_mesh_coordinator(coord):
    global _mesh_coordinator
    _mesh_coordinator = coord


def _require_coordinator():
    coord = get_mesh_coordinator()
    if coord is None:
        raise HTTPException(status_code=503, detail="Mesh coordinator not started")
    return coord


# ── Routes ───────────────────────────────────────────────────────────


@router.get("/status")
async def mesh_status(
    _user: dict = Depends(verify_session_token),
):
    """Mesh summary: running state, peer counts by escalation phase."""
    coord = _require_coordinator()
    summary = coord.state_manager.mesh_summary()
    stats = coord.receiver_stats
    return MeshStatusResponse(
        node_id=coord.node_id,
        is_running=coord.is_running,
        total_peers=summary["total_peers"],
        by_phase=summary["by_phase"],
        packets_received=stats["packets_received"],
        packets_invalid=stats["packets_invalid"],
        packets_rejected=stats.get("packets_rejected", 0),
        psk_fingerprint=coord.psk_fingerprint,
    )


@router.get("/peers")
async def list_peers(
    _user: dict = Depends(verify_session_token),
):
    """List all mesh peers with current state."""
    coord = _require_coordinator()
    peers = coord.state_manager.all_peers()
    return [p.to_dict() for p in peers]


@router.get("/peers/{node_id}")
async def get_peer(
    node_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Single peer detail + heartbeat history."""
    coord = _require_coordinator()
    peer = coord.state_manager.get_peer(node_id)
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")

    result = peer.to_dict()

    # Attach heartbeat history from database
    try:
        from ..mesh.mesh_database import get_mesh_database
        db = get_mesh_database()
        result["heartbeat_history"] = db.get_heartbeat_history(node_id, limit=20)
    except Exception:
        result["heartbeat_history"] = []

    return result


@router.post("/peers")
async def add_peer(
    req: MeshPeerRequest,
    _user: dict = Depends(verify_session_token),
):
    """Add a mesh peer."""
    coord = _require_coordinator()
    peer = coord.add_peer(
        node_id=req.node_id,
        ip_address=req.ip_address,
        port=req.port,
        is_desktop=req.is_desktop,
        label=req.label,
    )

    # Persist to database
    try:
        from ..mesh.mesh_database import get_mesh_database
        db = get_mesh_database()
        db.add_peer(
            node_id=req.node_id,
            ip_address=req.ip_address,
            port=req.port,
            is_desktop=req.is_desktop,
            label=req.label,
        )
    except Exception:
        logger.warning("Failed to persist mesh peer %s", req.node_id, exc_info=True)

    return peer.to_dict()


@router.delete("/peers/{node_id}")
async def remove_peer(
    node_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Remove a mesh peer."""
    coord = _require_coordinator()
    removed = coord.remove_peer(node_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Peer not found")

    # Remove from database
    try:
        from ..mesh.mesh_database import get_mesh_database
        db = get_mesh_database()
        db.remove_peer(node_id)
    except Exception:
        logger.warning("Failed to remove mesh peer %s from DB", node_id, exc_info=True)

    return {"status": "removed", "node_id": node_id}


@router.get("/config")
async def get_config(
    _user: dict = Depends(verify_session_token),
):
    """Current mesh configuration."""
    coord = _require_coordinator()
    t = coord.state_manager._thresholds
    return MeshConfigResponse(
        interval=coord.interval,
        port=coord.port,
        thresholds={
            "alert_after": t.alert_after,
            "heightened_after": t.heightened_after,
            "autonomous_after": t.autonomous_after,
        },
    )


@router.put("/config")
async def update_config(
    req: MeshConfigRequest,
    _user: dict = Depends(verify_session_token),
):
    """Update mesh interval (5-300s). Persists to UserPreferences."""
    coord = _require_coordinator()

    if req.interval is not None:
        clamped = max(5, min(req.interval, 300))
        coord.update_interval(clamped)

        # Persist
        try:
            from ..core.user_preferences import get_user_preferences
            prefs = get_user_preferences()
            prefs.set("mesh_interval", str(clamped))
        except Exception:
            pass

    return {"status": "updated", "interval": coord.interval}


@router.get("/psk")
async def get_psk_status(
    _user: dict = Depends(verify_session_token),
):
    """PSK status: fingerprint only (never expose the raw key via API)."""
    coord = _require_coordinator()
    return {
        "psk_configured": coord.psk_fingerprint is not None,
        "psk_fingerprint": coord.psk_fingerprint,
    }


@router.post("/psk/rotate")
async def rotate_psk(
    _user: dict = Depends(verify_session_token),
):
    """Generate a new PSK and apply it to sender + receiver.

    Returns the raw key (base64) exactly once so it can be distributed
    to peers.  After this response, the key is only stored locally.
    """
    from ..mesh.mesh_keys import generate_psk, psk_to_base64, get_psk_fingerprint, PREFS_KEY

    coord = _require_coordinator()
    new_psk = generate_psk()
    coord.update_psk(new_psk)

    # Persist
    try:
        from ..core.user_preferences import get_user_preferences
        prefs = get_user_preferences()
        prefs.set(PREFS_KEY, psk_to_base64(new_psk))
    except Exception:
        logger.warning("Failed to persist rotated mesh PSK", exc_info=True)

    return {
        "status": "rotated",
        "psk_base64": psk_to_base64(new_psk),
        "psk_fingerprint": get_psk_fingerprint(new_psk),
    }


# ── Peer Alert Routes ───────────────────────────────────────────────


@router.get("/alerts")
async def get_peer_alerts(
    limit: int = 20,
    _user: dict = Depends(verify_session_token),
):
    """Recent peer alerts (newest first)."""
    from ..mesh.peer_alerting import get_peer_alert_broadcaster

    broadcaster = get_peer_alert_broadcaster()
    if broadcaster is None:
        return {"alerts": [], "total": 0}
    alerts = broadcaster.get_recent_alerts(limit=limit)
    return {"alerts": alerts, "total": len(alerts)}


# ── Escalation Policy Routes ────────────────────────────────────────


class EscalationPolicyRequest(BaseModel):
    alert_threshold_override: Optional[str] = "low"
    alert_polling_interval: int = 15
    heightened_deny_sources: List[str] = Field(default_factory=list)
    heightened_rule_ttl_minutes: int = 60
    autonomous_allow_ips: List[str] = Field(default_factory=list)
    autonomous_rule_ttl_minutes: int = 240
    autonomous_kill_ssh: bool = False
    auto_recover: bool = True


@router.get("/escalation/{node_id}")
async def get_escalation_policy(
    node_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Get the escalation policy for a specific node."""
    from ..mesh.autonomous_escalation import get_escalation_handler

    handler = get_escalation_handler()
    policy = handler.get_policy(node_id)
    return {
        "node_id": node_id,
        "alert_threshold_override": policy.alert_threshold_override,
        "alert_polling_interval": policy.alert_polling_interval,
        "heightened_deny_sources": policy.heightened_deny_sources,
        "heightened_rule_ttl_minutes": policy.heightened_rule_ttl_minutes,
        "autonomous_allow_ips": policy.autonomous_allow_ips,
        "autonomous_rule_ttl_minutes": policy.autonomous_rule_ttl_minutes,
        "autonomous_kill_ssh": policy.autonomous_kill_ssh,
        "auto_recover": policy.auto_recover,
    }


@router.put("/escalation/{node_id}")
async def set_escalation_policy(
    node_id: str,
    req: EscalationPolicyRequest,
    _user: dict = Depends(verify_session_token),
):
    """Set the escalation policy for a specific node."""
    from ..mesh.autonomous_escalation import (
        get_escalation_handler, EscalationPolicy,
    )

    handler = get_escalation_handler()
    policy = EscalationPolicy(
        alert_threshold_override=req.alert_threshold_override,
        alert_polling_interval=req.alert_polling_interval,
        heightened_deny_sources=req.heightened_deny_sources,
        heightened_rule_ttl_minutes=req.heightened_rule_ttl_minutes,
        autonomous_allow_ips=req.autonomous_allow_ips,
        autonomous_rule_ttl_minutes=req.autonomous_rule_ttl_minutes,
        autonomous_kill_ssh=req.autonomous_kill_ssh,
        auto_recover=req.auto_recover,
    )
    handler.set_policy(node_id, policy)
    return {"status": "updated", "node_id": node_id}


# ── Secondary Brain Routes ──────────────────────────────────────────


class SecondaryBrainRequest(BaseModel):
    node_id: str
    activation_threshold: int = 10
    rate_limit_rpm: int = 10
    allowed_actions: List[str] = Field(default_factory=lambda: [
        "lower_alert_threshold",
        "increase_polling_frequency",
        "queue_tighten_rules",
        "add_emergency_firewall_rules",
    ])
    denied_actions: List[str] = Field(default_factory=lambda: [
        "rotate_credentials",
        "kill_all_ssh_sessions",
    ])
    max_coordination_hours: int = 24
    require_desktop_approval: bool = True


@router.get("/secondary-brain")
async def get_secondary_brain_status(
    _user: dict = Depends(verify_session_token),
):
    """Get secondary brain designation status."""
    from ..mesh.secondary_brain import get_secondary_brain_manager

    mgr = get_secondary_brain_manager()
    return mgr.get_status()


@router.put("/secondary-brain")
async def designate_secondary_brain(
    req: SecondaryBrainRequest,
    _user: dict = Depends(verify_session_token),
):
    """Designate a VPS as the secondary brain."""
    from ..mesh.secondary_brain import (
        get_secondary_brain_manager, SecondaryBrainConfig,
    )

    # Verify the node exists in the mesh
    coord = _require_coordinator()
    peer = coord.state_manager.get_peer(req.node_id)
    if peer is None:
        raise HTTPException(status_code=404, detail=f"Peer {req.node_id} not found in mesh")

    mgr = get_secondary_brain_manager()
    config = SecondaryBrainConfig(
        node_id=req.node_id,
        activation_threshold=req.activation_threshold,
        rate_limit_rpm=req.rate_limit_rpm,
        allowed_actions=req.allowed_actions,
        denied_actions=req.denied_actions,
        max_coordination_hours=req.max_coordination_hours,
        require_desktop_approval=req.require_desktop_approval,
    )
    mgr.designate(config)

    # Sync sanitized asset registry
    try:
        from .asset_routes import get_inventory
        inv = get_inventory()
        assets = mgr.sanitize_from_inventory(inv)
        mgr.update_asset_registry(assets)
    except Exception:
        logger.debug("Failed to sync asset registry to secondary brain", exc_info=True)

    return {"status": "designated", "node_id": req.node_id, "state": mgr.state.value}


@router.delete("/secondary-brain")
async def remove_secondary_brain(
    _user: dict = Depends(verify_session_token),
):
    """Remove secondary brain designation."""
    from ..mesh.secondary_brain import get_secondary_brain_manager

    mgr = get_secondary_brain_manager()
    mgr.remove_designation()
    return {"status": "removed", "state": mgr.state.value}


@router.get("/secondary-brain/decisions")
async def get_brain_decisions(
    pending_only: bool = False,
    limit: int = 50,
    _user: dict = Depends(verify_session_token),
):
    """Get coordination decisions made by the secondary brain."""
    from ..mesh.secondary_brain import get_secondary_brain_manager

    mgr = get_secondary_brain_manager()
    if pending_only:
        decisions = mgr.get_pending_decisions()
    else:
        decisions = mgr.get_all_decisions(limit=limit)
    return {"decisions": decisions, "total": len(decisions)}


@router.post("/secondary-brain/decisions/{decision_id}/review")
async def review_brain_decision(
    decision_id: str,
    action: str = "accepted",
    _user: dict = Depends(verify_session_token),
):
    """Review a decision made by the secondary brain."""
    from ..mesh.secondary_brain import get_secondary_brain_manager

    if action not in ("accepted", "rolled_back"):
        raise HTTPException(status_code=400, detail="action must be 'accepted' or 'rolled_back'")

    mgr = get_secondary_brain_manager()
    found = mgr.review_decision(decision_id, action=action)
    if not found:
        raise HTTPException(status_code=404, detail="Decision not found")
    return {"status": "reviewed", "decision_id": decision_id, "action": action}


@router.post("/secondary-brain/decisions/review-all")
async def review_all_brain_decisions(
    _user: dict = Depends(verify_session_token),
):
    """Bulk-accept all pending decisions."""
    from ..mesh.secondary_brain import get_secondary_brain_manager

    mgr = get_secondary_brain_manager()
    count = mgr.review_all_decisions()
    return {"status": "reviewed", "count": count}


@router.get("/secondary-brain/assets")
async def get_brain_asset_registry(
    _user: dict = Depends(verify_session_token),
):
    """Get the sanitized asset registry shared with the secondary brain."""
    from ..mesh.secondary_brain import get_secondary_brain_manager

    mgr = get_secondary_brain_manager()
    assets = mgr.get_asset_registry()
    return {"assets": assets, "total": len(assets)}


# ── Brain Hardening Routes ──────────────────────────────────────────


class SSHPolicyRequest(BaseModel):
    key_only_auth: bool = True
    non_standard_port: int = 2222
    fail2ban_max_retry: int = 3
    fail2ban_ban_time: int = 3600
    fail2ban_find_time: int = 600
    allowed_users: List[str] = Field(default_factory=lambda: ["citadel"])


@router.get("/hardening")
async def get_hardening_status(
    _user: dict = Depends(verify_session_token),
):
    """Get secondary brain hardening status."""
    from ..mesh.brain_hardening import get_brain_hardening_manager

    mgr = get_brain_hardening_manager()
    return mgr.get_status()


@router.put("/hardening/ssh-policy")
async def update_ssh_policy(
    req: SSHPolicyRequest,
    _user: dict = Depends(verify_session_token),
):
    """Update SSH hardening policy for the secondary brain."""
    from ..mesh.brain_hardening import SSHHardeningPolicy, get_brain_hardening_manager

    mgr = get_brain_hardening_manager()
    policy = SSHHardeningPolicy(
        key_only_auth=req.key_only_auth,
        non_standard_port=req.non_standard_port,
        fail2ban_max_retry=req.fail2ban_max_retry,
        fail2ban_ban_time=req.fail2ban_ban_time,
        fail2ban_find_time=req.fail2ban_find_time,
        allowed_users=req.allowed_users,
    )
    mgr.set_ssh_policy(policy)
    return {"status": "updated", "policy": policy.to_dict()}


@router.get("/hardening/rate-limiter")
async def get_rate_limiter_stats(
    _user: dict = Depends(verify_session_token),
):
    """Get API rate limiter statistics."""
    from ..mesh.brain_hardening import get_brain_hardening_manager

    mgr = get_brain_hardening_manager()
    return mgr.get_rate_limiter_stats()


@router.put("/hardening/rate-limiter")
async def update_rate_limit(
    rpm: int = 10,
    _user: dict = Depends(verify_session_token),
):
    """Update API rate limit (requests per minute)."""
    from ..mesh.brain_hardening import get_brain_hardening_manager

    clamped = max(1, min(rpm, 60))
    mgr = get_brain_hardening_manager()
    mgr.update_rate_limit(clamped)
    return {"status": "updated", "rpm": clamped}


@router.get("/hardening/commands")
async def get_hardening_commands(
    _user: dict = Depends(verify_session_token),
):
    """Generate shell commands to apply hardening on the secondary brain VPS."""
    from ..mesh.brain_hardening import get_brain_hardening_manager

    mgr = get_brain_hardening_manager()
    commands = mgr.generate_hardening_commands()
    return {"commands": commands, "total": len(commands)}


@router.get("/hardening/audit")
async def get_hardening_audit(
    limit: int = 50,
    _user: dict = Depends(verify_session_token),
):
    """Get hardening audit log entries."""
    from ..mesh.brain_hardening import get_brain_hardening_manager

    mgr = get_brain_hardening_manager()
    entries = mgr.get_audit_log(limit=limit)
    return {"entries": entries, "total": len(entries)}


# ── Compartmentalized Secrets Routes ────────────────────────────────


class SecretProvisionRequest(BaseModel):
    secret_id: str
    secret_type: str
    scope: str
    description: str = ""
    fingerprint: str = ""


@router.get("/secrets/distribution")
async def get_secret_distribution(
    _user: dict = Depends(verify_session_token),
):
    """Get a summary of secret distribution across the mesh."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    mgr = get_secret_compartment_manager()
    return mgr.get_secret_distribution()


@router.get("/secrets/manifests")
async def list_secret_manifests(
    _user: dict = Depends(verify_session_token),
):
    """List all node secret manifests."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    mgr = get_secret_compartment_manager()
    return {"manifests": mgr.list_manifests()}


@router.post("/secrets/nodes/{node_id}")
async def register_secret_node(
    node_id: str,
    role: str = "agent",
    _user: dict = Depends(verify_session_token),
):
    """Register a node for secret compartmentalization."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    if role not in ("primary", "secondary", "agent"):
        raise HTTPException(status_code=400, detail="role must be primary, secondary, or agent")

    mgr = get_secret_compartment_manager()
    manifest = mgr.register_node(node_id, role)
    return manifest.to_dict()


@router.get("/secrets/nodes/{node_id}")
async def get_node_secrets(
    node_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Get secrets provisioned to a specific node."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    mgr = get_secret_compartment_manager()
    secrets = mgr.get_node_secrets(node_id)
    return {"node_id": node_id, "secrets": secrets, "total": len(secrets)}


@router.post("/secrets/nodes/{node_id}/provision")
async def provision_secret(
    node_id: str,
    req: SecretProvisionRequest,
    _user: dict = Depends(verify_session_token),
):
    """Provision a secret to a node (subject to access policy)."""
    from ..mesh.compartmentalized_secrets import (
        SecretEntry, get_secret_compartment_manager,
    )

    mgr = get_secret_compartment_manager()
    entry = SecretEntry(
        secret_id=req.secret_id,
        secret_type=req.secret_type,
        scope=req.scope,
        description=req.description,
        fingerprint=req.fingerprint,
    )
    allowed = mgr.provision_secret(node_id, entry)
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Secret provisioning denied for node {node_id}",
        )
    return {"status": "provisioned", "secret_id": req.secret_id, "node_id": node_id}


@router.delete("/secrets/nodes/{node_id}/{secret_id}")
async def revoke_secret(
    node_id: str,
    secret_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Revoke a specific secret from a node."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    mgr = get_secret_compartment_manager()
    revoked = mgr.revoke_secret(node_id, secret_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Secret or node not found")
    return {"status": "revoked", "node_id": node_id, "secret_id": secret_id}


@router.get("/secrets/nodes/{node_id}/compliance")
async def check_node_compliance(
    node_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Check if a node's secrets comply with the access policy."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    mgr = get_secret_compartment_manager()
    return mgr.check_compliance(node_id)


@router.get("/secrets/audit")
async def get_secrets_audit(
    limit: int = 50,
    _user: dict = Depends(verify_session_token),
):
    """Get secret management audit log."""
    from ..mesh.compartmentalized_secrets import get_secret_compartment_manager

    mgr = get_secret_compartment_manager()
    entries = mgr.get_audit_log(limit=limit)
    return {"entries": entries, "total": len(entries)}


# ── Recovery / Reconciliation Routes ────────────────────────────────


class RecoveryStartRequest(BaseModel):
    recovery_id: str
    outage_seconds: int = 0


class RecoverySyncRequest(BaseModel):
    events: List[dict] = Field(default_factory=list)


class RecoveryReviewRequest(BaseModel):
    decisions: List[dict] = Field(default_factory=list)
    auto_accept_actions: Optional[List[str]] = None
    auto_rollback_actions: Optional[List[str]] = None


class RecoveryMergeRequest(BaseModel):
    entries: List[dict] = Field(default_factory=list)


@router.get("/recovery/status")
async def get_recovery_status(
    _user: dict = Depends(verify_session_token),
):
    """Get current recovery process status."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    return mgr.get_status()


@router.post("/recovery/start")
async def start_recovery(
    req: RecoveryStartRequest,
    _user: dict = Depends(verify_session_token),
):
    """Start the recovery/reconciliation process."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    report = mgr.start_recovery(req.recovery_id, req.outage_seconds)
    return report.to_dict()


@router.post("/recovery/sync-events")
async def sync_events(
    req: RecoverySyncRequest,
    _user: dict = Depends(verify_session_token),
):
    """Step 1: Sync missed events from agents."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    count = mgr.sync_events(req.events)
    return {"status": "synced", "events_count": count}


@router.post("/recovery/review-decisions")
async def review_decisions(
    req: RecoveryReviewRequest,
    _user: dict = Depends(verify_session_token),
):
    """Step 2: Review secondary brain decisions."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    result = mgr.review_decisions(
        req.decisions,
        auto_accept_actions=req.auto_accept_actions,
        auto_rollback_actions=req.auto_rollback_actions,
    )
    return result


@router.post("/recovery/resolve-conflicts")
async def resolve_conflicts(
    _user: dict = Depends(verify_session_token),
):
    """Step 3: Resolve conflicts (desktop wins)."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    conflicts = mgr.resolve_conflicts()
    return {"conflicts": conflicts, "total": len(conflicts)}


@router.post("/recovery/restore-heartbeats")
async def restore_heartbeats(
    _user: dict = Depends(verify_session_token),
):
    """Step 4: Restore normal heartbeat operation."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    coord = get_mesh_coordinator()
    result = mgr.restore_heartbeats(coordinator=coord)
    return result


@router.post("/recovery/merge-audit")
async def merge_audit_log(
    req: RecoveryMergeRequest,
    _user: dict = Depends(verify_session_token),
):
    """Step 5: Merge secondary brain audit log into master."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    count = mgr.merge_audit_log(req.entries)
    return {"status": "merged", "entries_count": count}


@router.post("/recovery/complete")
async def complete_recovery(
    _user: dict = Depends(verify_session_token),
):
    """Finalize and archive the recovery report."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    report = mgr.complete_recovery()
    if report is None:
        raise HTTPException(status_code=400, detail="No recovery in progress")
    return report.to_dict()


@router.post("/recovery/run-full")
async def run_full_recovery(
    req: RecoveryStartRequest,
    _user: dict = Depends(verify_session_token),
):
    """Execute all 5 recovery steps in sequence (non-interactive).

    Performs coordination-only recovery: restores heartbeats and runs all
    protocol steps with no cached events/decisions. Use the step-by-step
    endpoints to replay specific events or decisions from the secondary brain.
    """
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    coord = get_mesh_coordinator()
    report = mgr.run_full_recovery(
        recovery_id=req.recovery_id,
        outage_seconds=req.outage_seconds,
        coordinator=coord,
    )
    return report.to_dict()


@router.get("/recovery/history")
async def get_recovery_history(
    limit: int = 10,
    _user: dict = Depends(verify_session_token),
):
    """Get recent recovery reports."""
    from ..mesh.recovery_protocol import get_recovery_manager

    mgr = get_recovery_manager()
    history = mgr.get_history(limit=limit)
    return {"history": history, "total": len(history)}


# ── Escalation Deduplication Routes ─────────────────────────────────


@router.get("/dedup/status")
async def get_dedup_status(
    _user: dict = Depends(verify_session_token),
):
    """Get escalation deduplicator status."""
    from ..mesh.escalation_dedup import get_escalation_deduplicator

    dedup = get_escalation_deduplicator()
    if not dedup:
        return {"running": False, "message": "Deduplicator not initialized"}
    return dedup.get_status()


@router.get("/dedup/pending")
async def get_dedup_pending(
    _user: dict = Depends(verify_session_token),
):
    """Get currently pending (not yet merged) escalation signatures."""
    from ..mesh.escalation_dedup import get_escalation_deduplicator

    dedup = get_escalation_deduplicator()
    if not dedup:
        return {"pending": [], "total": 0}
    pending = dedup.get_pending()
    return {"pending": pending, "total": len(pending)}


@router.get("/dedup/history")
async def get_dedup_history(
    limit: int = 50,
    _user: dict = Depends(verify_session_token),
):
    """Get recent merged escalations (newest first)."""
    from ..mesh.escalation_dedup import get_escalation_deduplicator

    dedup = get_escalation_deduplicator()
    if not dedup:
        return {"history": [], "total": 0}
    history = dedup.get_history(limit=limit)
    return {"history": history, "total": len(history)}
