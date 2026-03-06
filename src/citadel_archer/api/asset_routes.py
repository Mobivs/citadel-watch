# PRD: Asset CRUD API
# Reference: ASSET_MANAGEMENT_ADDENDUM.md Section 2
#
# Provides REST endpoints for creating, reading, updating, and deleting
# managed assets. Assets are stored in SQLite via AssetInventory.

import asyncio
import logging
import threading
import time as _time
import uuid as _uuid

logger = logging.getLogger(__name__)
from datetime import datetime
from typing import Dict, List, Optional

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


def get_vault_manager() -> VaultManager:
    """Access the VaultManager singleton from vault_routes."""
    from .vault_routes import vault_manager
    return vault_manager


# ── Pending SSH command store ─────────────────────────────────────────

_PENDING_SSH: Dict[str, Dict] = {}   # approval_uuid → {asset_id, command, timeout, expires}
_PENDING_SSH_LOCK = threading.Lock()
_PENDING_SSH_TTL  = 300              # 5 minutes


def register_pending_ssh(asset_id: str, command: str, timeout: int) -> str:
    """Store a write command pending user approval. Returns approval UUID."""
    approval_uuid = str(_uuid.uuid4())
    with _PENDING_SSH_LOCK:
        # Purge expired
        now = _time.time()
        expired = [k for k, v in _PENDING_SSH.items() if v["expires"] < now]
        for k in expired:
            del _PENDING_SSH[k]
        _PENDING_SSH[approval_uuid] = {
            "asset_id": asset_id,
            "command":  command,
            "timeout":  timeout,
            "expires":  now + _PENDING_SSH_TTL,
        }
    return approval_uuid


# ── Approval Futures (serial approval) ───────────────────────────────
# When ai_bridge awaits an approval, it creates a Future keyed by approval_uuid.
# The approve/deny endpoints resolve the Future so the tool loop unblocks
# and receives the actual result before processing the next command.

_APPROVAL_FUTURES: Dict[str, "asyncio.Future"] = {}
_APPROVAL_FUTURES_LOCK = threading.Lock()


def create_approval_future(approval_uuid: str) -> "asyncio.Future":
    """Create a Future that resolves when user approves or denies the command.

    Must be called from within the running asyncio event loop (i.e. from an
    async context).  Uses get_running_loop() which is the correct API for
    Python 3.10+ and avoids the DeprecationWarning from get_event_loop().
    """
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    with _APPROVAL_FUTURES_LOCK:
        _APPROVAL_FUTURES[approval_uuid] = fut
    return fut


def resolve_approval_future(approval_uuid: str, result: dict) -> bool:
    """Resolve the Future for an approval UUID. Returns True if a waiter was found.

    Returns False if no Future was waiting (legacy path — caller should use
    guardian_notifications instead) or if the Future could not be resolved
    (e.g. already cancelled due to user interrupt).
    """
    with _APPROVAL_FUTURES_LOCK:
        fut = _APPROVAL_FUTURES.pop(approval_uuid, None)
    if fut is not None and not fut.done():
        try:
            fut.set_result(result)
        except Exception:
            logger.warning(
                "Could not resolve approval future %s (likely cancelled by user interrupt)",
                approval_uuid, exc_info=True,
            )
            return False
        return True
    return False


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


class ExecuteSSHRequest(BaseModel):
    command:       str = ""   # direct execution (read-only, pre-validated)
    timeout:       int = 30
    approval_uuid: str = ""   # approved write command path
    justification: str = ""


class DenySSHRequest(BaseModel):
    approval_uuid: str


class RecoverSSHRequest(BaseModel):
    hostinger_vps_id: int


# ── SSH Key Rotation singleton ────────────────────────────────────────

_rotator = None


def get_rotator():
    """Get or create the SSHKeyRotator singleton."""
    global _rotator
    if _rotator is None:
        from ..remote.ssh_rotation import SSHKeyRotator, get_rotation_store
        from .vault_routes import vault_manager
        _rotator = SSHKeyRotator(
            vault=vault_manager,
            ssh=get_ssh_manager(),
            assets=get_inventory(),
            store=get_rotation_store(),
        )
    return _rotator


# ── Endpoints ─────────────────────────────────────────────────────────

@router.get("/pending-approvals")
async def get_pending_approvals(
    _token: str = Depends(verify_session_token),
):
    """Return all currently pending SSH approval requests.

    Used by the frontend to recover approval cards that were missed due to
    a WebSocket gap (page reload, brief disconnect, etc.). Polled on page load.
    """
    now = _time.time()
    with _PENDING_SSH_LOCK:
        pending = [
            {
                "approval_uuid": uuid,
                "asset_id": entry["asset_id"],
                "command": entry["command"],
                "expires_in": max(0, int(entry["expires"] - now)),
            }
            for uuid, entry in _PENDING_SSH.items()
            if entry["expires"] > now
        ]
    return {"pending": pending}


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
    asset = inv.get(asset_id)
    if asset is None:
        raise HTTPException(404, f"Asset not found: {asset_id}")

    # Pre-flight: verify the linked credential exists in vault before attempting SSH.
    if asset.ssh_credential_id:
        try:
            _vm = get_vault_manager()
            _cred = _vm.get_ssh_credential(asset.ssh_credential_id)
            if _cred is None:
                raise HTTPException(
                    422,
                    f"SSH credential linked to this asset no longer exists in the vault "
                    f"(ID: {asset.ssh_credential_id[:8]}…). "
                    "Go to Assets → link a valid credential, or add one in the Vault tab."
                )
            if _cred.get("auth_type") == "key" and not _cred.get("private_key"):
                raise HTTPException(
                    422,
                    f"SSH credential '{_cred.get('label', asset.ssh_credential_id[:8])}' "
                    "has no private key stored. Re-import the private key in the Vault tab."
                )
        except HTTPException:
            raise
        except Exception:
            pass  # Vault locked — let the SSH manager surface that error

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


@router.post("/{asset_id}/execute-ssh")
async def execute_ssh_command(
    asset_id: str,
    body: ExecuteSSHRequest,
    _token: str = Depends(verify_session_token),
):
    """Execute a shell command on a managed asset via SSH.

    Read-only commands may be called directly (command field).
    Write commands go through approval: pass approval_uuid from a
    previously registered pending command.
    """
    # Resolve command + timeout
    if body.approval_uuid:
        with _PENDING_SSH_LOCK:
            pending = _PENDING_SSH.pop(body.approval_uuid, None)
        if pending is None:
            raise HTTPException(404, "Approval UUID not found or expired")
        if pending["asset_id"] != asset_id:
            raise HTTPException(403, "Approval UUID does not match asset")
        command = pending["command"]
        timeout = pending["timeout"]
    else:
        command = body.command.strip()
        timeout = max(5, min(body.timeout, 120))

    if not command:
        raise HTTPException(400, "command is required")

    from ..core.audit_log import log_security_event, EventType, EventSeverity

    # ── Local-platform routing ────────────────────────────────────────
    # When the asset is the local host machine, use subprocess instead of SSH.
    inv = get_inventory()
    _asset = inv.get(asset_id)
    if _asset is not None and _asset.platform == AssetPlatform.LOCAL:
        from ..local.local_defender import LocalHostDefender
        try:
            result = await LocalHostDefender().execute_command_async(command, timeout)
        except TimeoutError as exc:
            raise HTTPException(504, str(exc))
        except RuntimeError as exc:
            raise HTTPException(502, str(exc))

        log_security_event(
            EventType.SSH_COMMAND_EXECUTED,
            EventSeverity.INFO,
            f"Local command on {asset_id}: {command!r}",
            details={
                "asset_id": asset_id,
                "command": command,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "justification": body.justification,
                "approval_uuid": body.approval_uuid or None,
                "mode": "local",
            },
        )

        local_result = {
            "asset_id": asset_id,
            "command": command,
            "success": result.exit_code == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "execution_time_ms": result.duration_ms,
        }
        if body.approval_uuid:
            # Unblock the tool loop. If a Future was waiting, Claude gets the result
            # directly via tool_result — no guardian notification needed (that would
            # create a duplicate [OK] message and potentially a redundant AI call).
            future_resolved = resolve_approval_future(body.approval_uuid, local_result)
            if not future_resolved:
                # Legacy path: no tool loop waiting — notify Guardian the old way
                try:
                    from ..agent.guardian_notifications import notify
                    notify("ssh_command_result", {
                        "asset_id":    asset_id,
                        "command":     command,
                        "success":     result.exit_code == 0,
                        "exit_code":   result.exit_code,
                        "stdout":      result.stdout,
                        "stderr":      result.stderr,
                        "duration_ms": result.duration_ms,
                        "approval_uuid": body.approval_uuid,
                        "mode": "local",
                    })
                except Exception:
                    logger.debug("Failed to send guardian notification for local result", exc_info=True)

        return local_result
    # ── End local-platform routing ────────────────────────────────────

    try:
        ssh = get_ssh_manager()
        result = await ssh.execute(asset_id, command, timeout=timeout)
    except (AssetNotFoundError, NoCredentialError, VaultLockedError,
            CommandTimeoutError, ConnectionFailedError, SSHManagerError) as exc:
        # If an approval Future is waiting, resolve it with the error immediately
        # so the AI tool loop unblocks with the real failure reason — not a 5-min timeout.
        if body.approval_uuid:
            _error_msg = str(exc)
            _ssh_error_result = {
                "asset_id": asset_id,
                "command": command,
                "success": False,
                "stdout": "",
                "stderr": _error_msg,
                "exit_code": -1,
                "execution_time_ms": 0,
                "connection_error": True,
                "error": _error_msg,
            }
            resolve_approval_future(body.approval_uuid, _ssh_error_result)
        # Map to appropriate HTTP status
        _status_map = {
            "AssetNotFoundError": 404, "NoCredentialError": 422,
            "VaultLockedError": 503, "CommandTimeoutError": 504,
        }
        _http_status = _status_map.get(type(exc).__name__, 502)
        raise HTTPException(_http_status, str(exc))

    log_security_event(
        EventType.SSH_COMMAND_EXECUTED,
        EventSeverity.INFO,
        f"SSH command on {asset_id}: {command!r}",
        details={
            "asset_id": asset_id,
            "command": command,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "justification": body.justification,
            "approval_uuid": body.approval_uuid or None,
        },
    )

    ssh_result = {
        "asset_id": asset_id,
        "command": command,
        "success": result.exit_code == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "execution_time_ms": result.duration_ms,
    }
    if body.approval_uuid:
        # Unblock the tool loop. Skip guardian notification when Future resolved —
        # Claude sees the result directly via tool_result (no duplicate [OK] message).
        future_resolved = resolve_approval_future(body.approval_uuid, ssh_result)
        if not future_resolved:
            # Legacy path: no tool loop waiting — notify Guardian the old way
            try:
                from ..agent.guardian_notifications import notify
                notify("ssh_command_result", {
                    "asset_id":    asset_id,
                    "command":     command,
                    "success":     result.exit_code == 0,
                    "exit_code":   result.exit_code,
                    "stdout":      result.stdout,
                    "stderr":      result.stderr,
                    "duration_ms": result.duration_ms,
                    "approval_uuid": body.approval_uuid,
                })
            except Exception:
                logger.debug("Failed to send guardian notification for SSH result", exc_info=True)

    return ssh_result


@router.post("/{asset_id}/execute-ssh/deny")
async def deny_ssh_command(
    asset_id: str,
    body: DenySSHRequest,
    _token: str = Depends(verify_session_token),
):
    """Discard a pending SSH write command without executing it."""
    with _PENDING_SSH_LOCK:
        removed = _PENDING_SSH.pop(body.approval_uuid, None)

    from ..core.audit_log import log_security_event, EventType, EventSeverity

    # Unblock any tool loop waiting on this approval (denied path).
    # Skip guardian notification when Future resolved — Claude handles denial inline.
    future_resolved = resolve_approval_future(body.approval_uuid, {"denied": True, "asset_id": asset_id})

    if removed:
        log_security_event(
            EventType.SSH_COMMAND_BLOCKED,
            EventSeverity.INFO,
            f"SSH command denied by user on {asset_id}: {removed['command']!r}",
            details={"asset_id": asset_id, "command": removed["command"],
                     "approval_uuid": body.approval_uuid},
        )
        if not future_resolved:
            try:
                from ..agent.guardian_notifications import notify
                notify("ssh_command_denied", {
                    "asset_id":      asset_id,
                    "command":       removed["command"],
                    "approval_uuid": body.approval_uuid,
                })
            except Exception:
                logger.debug("Failed to send guardian notification for SSH deny", exc_info=True)

    return {"asset_id": asset_id, "approval_uuid": body.approval_uuid, "status": "denied"}


# ── SSH Key Rotation endpoints ────────────────────────────────────────

@router.post("/{asset_id}/ssh/rotate")
async def start_ssh_rotation(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Begin a bumpless SSH key rotation for a managed asset.

    Returns immediately with a rotation_id. Poll GET .../ssh/rotate/status
    for progress. Rotation runs as a background task.
    """
    from ..core.audit_log import log_security_event, EventType, EventSeverity
    inv = get_inventory()
    if inv.get(asset_id) is None:
        raise HTTPException(404, f"Asset not found: {asset_id}")

    try:
        rotator = get_rotator()
        rotation_id = await rotator.start_rotation(asset_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Failed to start rotation: {exc}")

    log_security_event(
        EventType.SSH_KEY_ROTATION_STARTED,
        EventSeverity.INFO,
        f"SSH key rotation started for asset '{asset_id}'",
        details={"asset_id": asset_id, "rotation_id": rotation_id},
    )
    return {"rotation_id": rotation_id, "asset_id": asset_id, "status": "generating"}


@router.get("/{asset_id}/ssh/rotate/status")
async def get_ssh_rotation_status(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Poll the status of an in-progress or recent SSH key rotation."""
    from ..remote.ssh_rotation import get_rotation_store
    store = get_rotation_store()

    # First try active rotation, then latest completed
    rec = store.get_active(asset_id) or store.get_latest(asset_id)
    if rec is None:
        raise HTTPException(404, f"No rotation found for asset: {asset_id}")

    return {
        "rotation_id": rec["rotation_id"],
        "asset_id": rec["asset_id"],
        "status": rec["status"],
        "started_at": rec["started_at"],
        "updated_at": rec["updated_at"],
        "error": rec.get("error"),
        "new_pub_key": rec.get("new_pub_key"),
    }


@router.post("/{asset_id}/ssh/rotate/rollback")
async def rollback_ssh_rotation(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Reverse an in-progress rotation. Only possible before old key is removed."""
    from ..remote.ssh_rotation import get_rotation_store
    store = get_rotation_store()
    rec = store.get_active(asset_id)
    if rec is None:
        raise HTTPException(404, f"No active rotation found for asset: {asset_id}")

    from ..core.audit_log import log_security_event, EventType, EventSeverity
    try:
        rotator = get_rotator()
        result = await rotator.rollback(rec["rotation_id"])
    except Exception as exc:
        raise HTTPException(500, f"Rollback failed: {exc}")

    if "error" in result:
        raise HTTPException(400, result["error"])

    log_security_event(
        EventType.SSH_KEY_ROTATION_ROLLBACK,
        EventSeverity.ALERT,
        f"SSH key rotation rolled back for asset '{asset_id}'",
        details={"asset_id": asset_id, "rotation_id": rec["rotation_id"]},
    )
    return result


@router.post("/{asset_id}/ssh/recover")
async def start_ssh_recovery(
    asset_id: str,
    body: RecoverSSHRequest,
    _token: str = Depends(verify_session_token),
):
    """Begin emergency SSH recovery when the asset's SSH is broken.

    Uses the Hostinger API to set a temporary root password and
    generates a new key pair. Returns instructions for manual console access.
    """
    from ..core.audit_log import log_security_event, EventType, EventSeverity
    inv = get_inventory()
    if inv.get(asset_id) is None:
        raise HTTPException(404, f"Asset not found: {asset_id}")

    try:
        rotator = get_rotator()
        result = await rotator.start_recovery(asset_id, body.hostinger_vps_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Recovery failed to start: {exc}")

    log_security_event(
        EventType.SSH_KEY_RECOVERY_STARTED,
        EventSeverity.ALERT,
        f"Emergency SSH recovery started for asset '{asset_id}' (VPS {body.hostinger_vps_id})",
        details={"asset_id": asset_id, "hostinger_vps_id": body.hostinger_vps_id,
                 "rotation_id": result.get("rotation_id")},
    )
    return result


@router.post("/{asset_id}/ssh/recover/complete")
async def complete_ssh_recovery(
    asset_id: str,
    _token: str = Depends(verify_session_token),
):
    """Called after the user has manually added the new public key via VPS console.

    Tests the new key and marks the rotation completed on success.
    """
    from ..remote.ssh_rotation import get_rotation_store
    store = get_rotation_store()
    rec = store.get_active(asset_id)
    if rec is None:
        raise HTTPException(404, f"No active recovery found for asset: {asset_id}")

    from ..core.audit_log import log_security_event, EventType, EventSeverity
    try:
        rotator = get_rotator()
        result = await rotator.complete_recovery(rec["rotation_id"])
    except Exception as exc:
        raise HTTPException(500, f"Recovery completion failed: {exc}")

    if result.get("error") and not result.get("success"):
        raise HTTPException(400, result["error"])

    log_security_event(
        EventType.SSH_KEY_RECOVERY_COMPLETED,
        EventSeverity.INFO,
        f"Emergency SSH recovery completed for asset '{asset_id}'",
        details={"asset_id": asset_id, "rotation_id": rec["rotation_id"]},
    )
    return result
