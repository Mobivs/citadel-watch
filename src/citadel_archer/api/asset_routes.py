# PRD: Asset CRUD API
# Reference: ASSET_MANAGEMENT_ADDENDUM.md Section 2
#
# Provides REST endpoints for creating, reading, updating, and deleting
# managed assets. Assets are stored in SQLite via AssetInventory.

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..intel.assets import (
    Asset,
    AssetInventory,
    AssetPlatform,
    AssetStatus,
    AssetType,
)
from ..remote.ssh_manager import (
    SSHConnectionManager,
    SSHManagerError,
    AssetNotFoundError,
    NoCredentialError,
    VaultLockedError,
    ConnectionFailedError,
    CommandTimeoutError,
)
from ..vault import VaultManager
from .security import verify_session_token

router = APIRouter(prefix="/api/assets", tags=["assets"])

# Singleton inventory instance (with DB persistence)
_inventory: Optional[AssetInventory] = None


def get_inventory() -> AssetInventory:
    """Get or create the global AssetInventory singleton."""
    global _inventory
    if _inventory is None:
        _inventory = AssetInventory()
    return _inventory


def set_inventory(inv: AssetInventory):
    """Allow DI for testing."""
    global _inventory
    _inventory = inv


# SSH connection manager singleton
_ssh_manager: Optional[SSHConnectionManager] = None


def get_ssh_manager() -> SSHConnectionManager:
    """Get or create the SSHConnectionManager singleton."""
    global _ssh_manager
    if _ssh_manager is None:
        from .vault_routes import vault_manager
        _ssh_manager = SSHConnectionManager(vault_manager, get_inventory())
    return _ssh_manager


# ── Request/Response models ───────────────────────────────────────────

class AssetCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    hostname: str = ""
    ip_address: str = ""
    platform: str = "linux"
    asset_type: str = "vps"
    ssh_port: int = 22
    ssh_username: str = "root"
    tags: List[str] = []
    notes: str = ""


class AssetUpdateRequest(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    platform: Optional[str] = None
    asset_type: Optional[str] = None
    status: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_username: Optional[str] = None
    ssh_credential_id: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


class LinkAgentRequest(BaseModel):
    agent_id: str


class LinkCredentialRequest(BaseModel):
    credential_id: str


# ── Endpoints ─────────────────────────────────────────────────────────

@router.get("")
async def list_assets(
    status: Optional[str] = Query(None),
    asset_type: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    _token: str = Depends(verify_session_token),
):
    """List all managed assets with optional filters."""
    inv = get_inventory()
    assets = inv.all()

    if status:
        assets = [a for a in assets if a.status.value == status]
    if asset_type:
        assets = [a for a in assets if a.asset_type.value == asset_type]
    if platform:
        assets = [a for a in assets if a.platform.value == platform]

    return {
        "assets": [a.to_dict() for a in assets],
        "total": len(assets),
        "stats": inv.stats(),
    }


@router.post("")
async def create_asset(
    req: AssetCreateRequest,
    _token: str = Depends(verify_session_token),
):
    """Create a new managed asset."""
    inv = get_inventory()

    # Validate enums
    try:
        platform = AssetPlatform(req.platform)
    except ValueError:
        raise HTTPException(400, f"Invalid platform: {req.platform}")
    try:
        asset_type = AssetType(req.asset_type)
    except ValueError:
        raise HTTPException(400, f"Invalid asset_type: {req.asset_type}")

    asset = Asset(
        name=req.name,
        hostname=req.hostname,
        ip_address=req.ip_address,
        platform=platform,
        asset_type=asset_type,
        status=AssetStatus.UNKNOWN,
        ssh_port=req.ssh_port,
        ssh_username=req.ssh_username,
        tags=req.tags,
        notes=req.notes,
    )

    asset_id = inv.register(asset)

    return {
        "asset_id": asset_id,
        "name": asset.name,
        "status": asset.status.value,
        "ssh_credential_id": asset.ssh_credential_id or None,
        "remote_shield_agent_id": asset.remote_shield_agent_id or None,
        "created_at": asset.registered_at,
        "message": "Asset created. Link an SSH credential and test connection to enable remote operations.",
    }


@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Get detailed info for a single asset."""
    inv = get_inventory()
    asset = inv.get(asset_id)
    if asset is None:
        raise HTTPException(404, f"Asset not found: {asset_id}")
    return asset.to_dict()


@router.put("/{asset_id}")
async def update_asset(
    asset_id: str,
    req: AssetUpdateRequest,
    _token: str = Depends(verify_session_token),
):
    """Update an existing asset's metadata."""
    inv = get_inventory()

    # Build kwargs from non-None fields
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "No fields to update")

    updated = inv.update(asset_id, **updates)
    if updated is None:
        raise HTTPException(404, f"Asset not found: {asset_id}")

    return {
        "asset_id": asset_id,
        "updated": list(updates.keys()),
        "asset": updated.to_dict(),
    }


@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Delete a managed asset.

    If the asset_id is also an enrolled AI agent (same ID assigned at
    enrollment), the agent is also revoked so nothing is left orphaned.
    """
    inv = get_inventory()
    removed = inv.remove(asset_id)

    # Also revoke any enrolled AI agent with the same ID.
    # Enrollment auto-creates managed_assets with asset_id == agent_id,
    # so deleting the asset must clean up the agent entry too.
    agent_revoked = False
    try:
        from .agent_api_routes import get_agent_registry
        agent_revoked = get_agent_registry().revoke_agent(asset_id)
    except Exception:
        pass

    if not removed and not agent_revoked:
        raise HTTPException(404, f"Asset not found: {asset_id}")

    # Bust the assets cache so the UI reflects the deletion immediately.
    try:
        from .dashboard_ext import cache
        cache.clear()
    except Exception:
        pass

    return {"asset_id": asset_id, "deleted": True, "agent_revoked": agent_revoked}


@router.post("/{asset_id}/link-agent")
async def link_agent(
    asset_id: str,
    req: LinkAgentRequest,
    _token: str = Depends(verify_session_token),
):
    """Link a Remote Shield agent to this asset."""
    inv = get_inventory()
    if not inv.link_remote_shield_agent(asset_id, req.agent_id):
        raise HTTPException(404, f"Asset not found: {asset_id}")
    return {"asset_id": asset_id, "linked_agent_id": req.agent_id}


@router.post("/{asset_id}/link-credential")
async def link_credential(
    asset_id: str,
    req: LinkCredentialRequest,
    _token: str = Depends(verify_session_token),
):
    """Link a Vault SSH credential to this asset."""
    inv = get_inventory()
    if not inv.link_ssh_credential(asset_id, req.credential_id):
        raise HTTPException(404, f"Asset not found: {asset_id}")
    return {"asset_id": asset_id, "linked_credential_id": req.credential_id}


@router.post("/{asset_id}/test-connection")
async def test_connection(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Test SSH connectivity to a managed asset.

    Returns system info (OS, uptime, hostname) and whether
    a Remote Shield agent is detected on the remote host.
    """
    inv = get_inventory()
    if inv.get(asset_id) is None:
        raise HTTPException(404, f"Asset not found: {asset_id}")

    try:
        ssh = get_ssh_manager()
        result = await ssh.test_connection(asset_id)
    except AssetNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except NoCredentialError as exc:
        raise HTTPException(422, str(exc))
    except VaultLockedError as exc:
        raise HTTPException(503, str(exc))
    except CommandTimeoutError as exc:
        raise HTTPException(504, str(exc))
    except ConnectionFailedError as exc:
        raise HTTPException(502, str(exc))
    except SSHManagerError as exc:
        raise HTTPException(502, str(exc))

    if not result.success:
        return {
            "asset_id": asset_id,
            "connection_status": "failed",
            "error": result.error,
            "latency_ms": result.latency_ms,
        }

    return {
        "asset_id": asset_id,
        "connection_status": "success",
        "ssh_fingerprint": result.ssh_fingerprint,
        "remote_os": result.remote_os,
        "uptime": result.uptime,
        "hostname": result.hostname,
        "remote_shield_detected": result.remote_shield_detected,
        "agent_version": result.agent_version,
        "latency_ms": result.latency_ms,
    }
