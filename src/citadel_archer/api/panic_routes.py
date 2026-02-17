"""
Panic Room API Routes - Phase 3 Implementation
Emergency response endpoints for Citadel Commander
"""

import json
import hashlib
import hmac as hmac_mod
import logging
import re
import secrets
import time
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from ..panic import PanicManager, TriggerSource
from ..panic.panic_database import PanicDatabase, PanicSession
from ..panic.playbooks import PlaybookLibrary, PlaybookValidator, PlaybookScheduler
from ..panic.recovery_key import RecoveryKeyManager
from ..chat.message import MessageType
from ..core.auth import get_current_user
from ..core.audit_log import AuditLogger, EventType, EventSeverity

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/panic", tags=["panic"])
audit = AuditLogger()

# Singletons (initialized lazily, one per process)
_panic_manager: Optional[PanicManager] = None
_panic_db: Optional[PanicDatabase] = None
import threading
_init_lock = threading.RLock()  # RLock: get_panic_manager → _get_db re-enters


def _get_db() -> PanicDatabase:
    """Get or create the singleton PanicDatabase instance."""
    global _panic_db
    if _panic_db is None:
        with _init_lock:
            if _panic_db is None:
                _panic_db = PanicDatabase()
    return _panic_db


def get_panic_manager() -> PanicManager:
    """Dependency to get or create panic manager instance"""
    global _panic_manager
    if _panic_manager is None:
        with _init_lock:
            if _panic_manager is None:
                db = _get_db()
                config = {
                    "confirmation_timeout": 30,
                    "max_concurrent_sessions": 1,
                    "default_playbooks": [],
                    "recovery_dir": "/var/lib/citadel/panic/recovery",
                    "backup_dir": "/var/lib/citadel/panic/backups",
                }
                _panic_manager = PanicManager(db, config)
    return _panic_manager


# ── HMAC-based confirmation tokens ─────────────────────────────────
# Tokens use the server session secret as HMAC key and include a
# 5-minute time window for built-in expiry.

def _get_hmac_secret() -> str:
    """Get HMAC secret (session token generated at startup)."""
    from .security import get_session_token
    try:
        return get_session_token()
    except RuntimeError:
        return "dev-fallback-not-for-production"


def _make_confirmation_token(action: str, user_id: str, session_id: str = "") -> str:
    """Generate HMAC-based confirmation token with 5-minute window."""
    secret = _get_hmac_secret()
    window = int(time.time()) // 300
    msg = f"{action}:{user_id}:{session_id}:{window}"
    return hmac_mod.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()[:24]


def _verify_confirmation_token(
    action: str, user_id: str, token: str, session_id: str = ""
) -> bool:
    """Verify confirmation token (checks current and previous 5-min window)."""
    expected = _make_confirmation_token(action, user_id, session_id)
    if secrets.compare_digest(token, expected):
        return True
    # Check previous window in case user is at boundary
    secret = _get_hmac_secret()
    prev_window = int(time.time()) // 300 - 1
    msg = f"{action}:{user_id}:{session_id}:{prev_window}"
    prev_token = hmac_mod.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()[:24]
    return secrets.compare_digest(token, prev_token)


# Regex for valid session IDs (alphanumeric, underscores, hyphens)
_SESSION_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]+$')


# Request/Response Models

class PanicActivateRequest(BaseModel):
    """Request to activate panic mode"""
    confirmation_token: str = Field(..., description="User confirmation token")
    playbooks: List[str] = Field(..., description="List of playbook IDs to execute")
    reason: str = Field(..., description="Reason for triggering panic")
    metadata: Optional[dict] = Field(default={}, description="Additional context")


class PanicActivateResponse(BaseModel):
    """Response after activating panic mode"""
    session_id: str
    status: str
    playbooks_queued: int
    estimated_duration: int
    websocket_channel: str


class PanicStatusResponse(BaseModel):
    """Panic session status response"""
    session_id: str
    status: str
    triggered_at: str
    trigger_source: str
    reason: str
    progress: dict
    logs: List[dict]


class RollbackRequest(BaseModel):
    """Request to rollback panic actions"""
    components: Optional[List[str]] = Field(None, description="Components to rollback (None = all)")
    target_assets: Optional[List[str]] = Field(None, description="Asset IDs to rollback (None = all assets in session)")
    confirmation_token: str = Field(..., description="User confirmation token")


class WhitelistEntry(BaseModel):
    """Whitelist entry for panic mode"""
    resource_type: str = Field(..., pattern="^(ip|domain|port|process|file)$")
    resource_value: str
    description: Optional[str] = None
    is_permanent: bool = False


# Routes

@router.post("/activate", response_model=PanicActivateResponse)
async def activate_panic(
    request: PanicActivateRequest,
    current_user: dict = Depends(get_current_user)
) -> PanicActivateResponse:
    """
    Activate panic mode with specified playbooks
    Requires user confirmation via token
    """
    try:
        manager = get_panic_manager()

        # Validate HMAC-based confirmation token
        if not _verify_confirmation_token("panic", current_user['id'], request.confirmation_token):
            audit.log_event(
                event_type=EventType.USER_OVERRIDE,
                severity=EventSeverity.ALERT,
                message="Panic activation failed: invalid confirmation token",
                details={"user_id": current_user['id']}
            )
            raise HTTPException(status_code=403, detail="Invalid confirmation token")

        # Trigger panic mode
        session = await manager.trigger_panic(
            trigger_source=TriggerSource.MANUAL,
            playbook_ids=request.playbooks,
            reason=request.reason,
            user_id=current_user['id'],
            confirmation_token=hashlib.sha256(request.confirmation_token.encode()).hexdigest()[:16],
            metadata=request.metadata
        )

        # Escalate to AI via SecureChat (Trigger 2c)
        try:
            chat = manager._chat_manager
            if chat:
                summary = (
                    f"[Panic Room] ACTIVATED — {request.reason}\n"
                    f"Playbooks: {'; '.join(request.playbooks)}\n"
                    f"Session: {session.id}\n"
                    f"Critical/high-priority emergency response initiated."
                )
                await chat.send_system(summary, MessageType.EVENT)
        except Exception:
            pass  # Chat failure must never block panic activation

        # Calculate estimated duration based on playbooks
        estimated_duration = len(request.playbooks) * 30

        return PanicActivateResponse(
            session_id=str(session.id),
            status=session.status,
            playbooks_queued=len(request.playbooks),
            estimated_duration=estimated_duration,
            websocket_channel=f"/ws/panic/{session.id}"
        )

    except HTTPException:
        raise
    except Exception as e:
        _logger.error(f"Panic activation error: {e}", exc_info=True)
        audit.log_event(
            event_type=EventType.AI_ALERT,
            severity=EventSeverity.CRITICAL,
            message="Panic activation failed (internal error)",
            details={"user_id": current_user['id']}
        )
        raise HTTPException(status_code=500, detail="Panic activation failed")


@router.get("/status/{session_id}", response_model=PanicStatusResponse)
async def get_panic_status(
    session_id: str,
    current_user: dict = Depends(get_current_user)
) -> PanicStatusResponse:
    """
    Get current status of a panic session
    Includes progress and recent logs
    """
    try:
        manager = get_panic_manager()
        
        # Convert string to UUID
        session_uuid = UUID(session_id)
        
        # Get status
        status = await manager.get_status(session_uuid)
        
        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])
        
        return PanicStatusResponse(**status)
        
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except Exception:
        _logger.exception("Failed to get panic status")
        raise HTTPException(status_code=500, detail="Failed to retrieve session status")


@router.post("/rollback/{session_id}")
async def rollback_panic(
    session_id: str,
    request: RollbackRequest,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Rollback panic actions for specified components
    Requires user confirmation
    """
    try:
        manager = get_panic_manager()

        # Validate HMAC-based rollback token (distinct from panic token)
        if not _verify_confirmation_token("rollback", current_user['id'], request.confirmation_token, session_id):
            audit.log_event(
                event_type=EventType.USER_OVERRIDE,
                severity=EventSeverity.ALERT,
                message="Panic rollback denied: invalid confirmation token",
                details={"session_id": session_id, "user_id": current_user['id']}
            )
            raise HTTPException(status_code=403, detail="Invalid confirmation token")

        # Convert string to UUID
        session_uuid = UUID(session_id)

        # Perform rollback (optionally scoped to specific components and/or assets)
        results = await manager.rollback_panic(
            session_id=session_uuid,
            components=request.components,
            target_assets=request.target_assets,
            confirmation_token=hashlib.sha256(request.confirmation_token.encode()).hexdigest()[:16],
            user_id=current_user['id']
        )

        audit.log_event(
            event_type=EventType.USER_OVERRIDE,
            severity=EventSeverity.ALERT,
            message=f"Panic rollback executed for session {session_id}",
            details={
                "session_id": session_id,
                "user_id": current_user['id'],
                "components": request.components,
                "target_assets": request.target_assets,
            }
        )

        return results

    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except Exception:
        _logger.exception("Panic rollback failed")
        raise HTTPException(status_code=500, detail="Rollback operation failed")


# Draft /sessions route removed - superseded by /sessions/history and /sessions/active below


# Draft /playbooks route removed - superseded by Phase 3 PlaybookLibrary route below


# ── Confirmation token endpoint ────────────────────────────────────

class ConfirmationTokenRequest(BaseModel):
    action: str = Field(..., pattern="^(panic|cancel|rollback)$")
    session_id: Optional[str] = Field(None, description="Required for cancel/rollback")


@router.post("/confirmation-token")
async def get_confirmation_token(
    request: ConfirmationTokenRequest,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Get an HMAC-based confirmation token for the requested action.
    The frontend echoes this token back to confirm intent.
    Tokens expire after 5 minutes (time-window based).
    """
    user_id = current_user['id']

    if request.action == "cancel":
        if not request.session_id:
            raise HTTPException(400, "session_id required for cancel action")
        token = _make_confirmation_token("cancel", user_id, request.session_id)
    elif request.action in ("panic", "rollback"):
        session_id = request.session_id or ""
        token = _make_confirmation_token(request.action, user_id, session_id)
    else:
        raise HTTPException(400, "Unknown action")

    return {"token": token, "action": request.action, "expires_in": 300}


# ── Configuration endpoints ───────────────────────────────────────

class PanicConfigRequest(BaseModel):
    ipWhitelist: List[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])
    processWhitelist: List[str] = Field(default_factory=lambda: ["ssh", "nginx", "mysql"])
    isolationMode: str = "strict"


@router.get("/config")
async def get_panic_config(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Get panic room configuration."""
    db = _get_db()
    config = db.get_config()
    # Return defaults if nothing saved yet
    return {
        "ipWhitelist": config.get("ipWhitelist", ["127.0.0.1", "::1"]),
        "processWhitelist": config.get("processWhitelist", ["ssh", "nginx", "mysql"]),
        "isolationMode": config.get("isolationMode", "strict"),
    }


@router.post("/config")
async def save_panic_config(
    request: PanicConfigRequest,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Save panic room configuration."""
    db = _get_db()
    db.save_config({
        "ipWhitelist": request.ipWhitelist,
        "processWhitelist": request.processWhitelist,
        "isolationMode": request.isolationMode,
    })

    try:
        audit.log_event(
            event_type=EventType.USER_OVERRIDE,
            severity=EventSeverity.INFO,
            message="Panic room configuration updated",
            details={
                "user_id": current_user['id'],
                "config": request.model_dump(),
            }
        )
    except Exception:
        pass

    return {"status": "saved"}


# WebSocket endpoint for real-time updates

@router.websocket("/ws/{session_id}")
async def panic_websocket(
    websocket: WebSocket,
    session_id: str,
    token: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time panic session updates.
    Requires session token as query param for authentication.
    """
    # Validate session token before accepting
    from .security import get_session_token
    try:
        expected = get_session_token()
        if not token or not secrets.compare_digest(token, expected):
            await websocket.close(code=4401, reason="Unauthorized")
            return
    except RuntimeError:
        pass  # Token not initialized yet — allow in dev

    await websocket.accept()

    session_uuid = None
    try:
        manager = get_panic_manager()
        session_uuid = UUID(session_id)

        # Register websocket handler
        if session_uuid not in manager.websocket_handlers:
            manager.websocket_handlers[session_uuid] = []
        manager.websocket_handlers[session_uuid].append(websocket)

        # Send initial status
        status = await manager.get_status(session_uuid)
        await websocket.send_json({"event": "status", "data": status})

        # Keep connection alive
        try:
            while True:
                # Wait for client messages (ping/pong)
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            pass

    except Exception as e:
        _logger.error(f"Panic WebSocket error: {e}")
        try:
            await websocket.send_json({"event": "error", "message": "Internal server error"})
        except Exception:
            pass
    finally:
        # Unregister handler (only if session_uuid was successfully parsed)
        if session_uuid is not None and session_uuid in manager.websocket_handlers:
            manager.websocket_handlers[session_uuid].remove(websocket)


# Initialize panic manager on module load
def init_panic_manager(db_connection, config: dict):
    """Initialize the panic manager with database and config"""
    global _panic_manager
    _panic_manager = PanicManager(db_connection, config)


# Phase 3 Additional Routes

@router.get("/playbooks", response_model=List[dict])
async def list_playbooks(
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    List all available panic response playbooks
    """
    playbooks = PlaybookLibrary.list_playbooks()
    
    # Add validation status for each playbook
    for playbook in playbooks:
        valid, issues = PlaybookValidator.validate_prerequisites(playbook)
        playbook['can_execute'] = valid
        playbook['validation_issues'] = issues
    
    return playbooks


@router.get("/playbooks/categories", response_model=List[str])
async def get_playbook_categories(
    current_user: dict = Depends(get_current_user)
) -> List[str]:
    """
    Get available playbook categories
    """
    return PlaybookLibrary.get_playbook_categories()


@router.get("/playbooks/{playbook_id}", response_model=dict)
async def get_playbook(
    playbook_id: str,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Get detailed information about a specific playbook
    """
    playbook = PlaybookLibrary.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # Add validation status
    valid, issues = PlaybookValidator.validate_prerequisites(playbook)
    playbook['can_execute'] = valid
    playbook['validation_issues'] = issues
    
    return playbook


@router.post("/plan", response_model=List[dict])
async def create_execution_plan(
    playbook_ids: List[str],
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    Create an execution plan for multiple playbooks
    """
    plan = PlaybookScheduler.create_execution_plan(playbook_ids)
    return plan


@router.get("/sessions/history", response_model=List[dict])
async def get_session_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    Get panic session history
    """
    db = _get_db()
    history = db.get_session_history(limit=limit)
    return history


@router.get("/sessions/active", response_model=List[dict])
async def get_active_sessions(
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    Get all active panic sessions
    """
    db = _get_db()
    sessions = db.get_active_sessions()
    return sessions


@router.get("/sessions/{session_id}/logs", response_model=List[dict])
async def get_session_logs(
    session_id: str,
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    Get detailed action logs for a panic session
    """
    db = _get_db()
    logs = db.get_action_logs(session_id)
    if not logs:
        raise HTTPException(status_code=404, detail="Session not found")
    return logs


@router.get("/sessions/{session_id}/recovery", response_model=List[dict])
async def get_recovery_snapshots(
    session_id: str,
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    Get recovery snapshots for a panic session
    """
    db = _get_db()
    snapshots = db.get_recovery_snapshots(session_id)
    return snapshots


@router.get("/sessions/{session_id}/remote-status")
async def get_remote_panic_status(
    session_id: str,
    current_user: dict = Depends(get_current_user),
) -> list:
    """Return status of all panic commands queued for remote agents in this session."""
    try:
        pm = get_panic_manager()
        dispatcher = getattr(pm, "_panic_dispatcher", None)
        if dispatcher is None:
            # Fallback: create ephemeral dispatcher if not wired
            from .remote_shield_routes import get_shield_db
            from ..remote.panic_dispatcher import RemotePanicDispatcher
            shield_db = get_shield_db()
            dispatcher = RemotePanicDispatcher(shield_db)
        return dispatcher.get_remote_status(session_id)
    except Exception:
        _logger.debug("remote-status lookup failed for session %s", session_id, exc_info=True)
        return []


class CancelSessionRequest(BaseModel):
    """Request body for cancelling a panic session."""
    confirmation_token: str = Field(..., description="Cancel confirmation token")


@router.post("/sessions/{session_id}/cancel", response_model=dict)
async def cancel_panic_session(
    session_id: str,
    request: CancelSessionRequest,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Cancel an active panic session.
    Token is passed in request body (not query params) to avoid access log exposure.
    """
    if not _verify_confirmation_token("cancel", current_user['id'], request.confirmation_token, session_id):
        raise HTTPException(status_code=403, detail="Invalid confirmation token")

    db = _get_db()
    success = db.update_session(session_id, {
        "status": "cancelled",
        "completed_at": datetime.utcnow().isoformat(),
        "error": "User cancelled"
    })
    
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    
    try:
        audit.log_event(
            event_type=EventType.USER_OVERRIDE,
            severity=EventSeverity.ALERT,
            message=f"Panic session cancelled: {session_id}",
            details={
                "session_id": session_id,
                "user_id": current_user['id']
            }
        )
    except Exception:
        pass
    
    return {"status": "cancelled", "session_id": session_id}


class PanicActivateV2Request(BaseModel):
    """Request body for v2 panic activation"""
    playbooks: List[str]
    reason: str
    confirmation_token: str
    target_assets: List[str] = Field(
        default=["local"],
        description="Asset IDs to target. 'local' = this machine. Omit for backward compat."
    )
    config: Optional[Dict] = None


# Enhanced activation with Phase 3 features
@router.post("/activate/v2", response_model=dict)
async def activate_panic_v2(
    request: PanicActivateV2Request,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Enhanced panic activation with Phase 3 features
    """
    # Validate HMAC-based confirmation token
    if not _verify_confirmation_token("panic", current_user['id'], request.confirmation_token):
        raise HTTPException(status_code=403, detail="Invalid confirmation token")

    # Create execution plan
    plan = PlaybookScheduler.create_execution_plan(request.playbooks)

    # Check for issues
    blocked_playbooks = [p for p in plan if not p['can_execute']]
    if blocked_playbooks:
        return {
            "status": "validation_failed",
            "blocked_playbooks": blocked_playbooks
        }

    # Resolve target assets (default to local-only for backward compat)
    target_assets = request.target_assets or ["local"]

    # Create panic session
    session_id = f"panic_{int(time.time() * 1000)}"
    session = PanicSession(
        session_id=session_id,
        status="active",
        playbooks=request.playbooks,
        started_at=datetime.utcnow(),
        trigger_source="manual",
        user_id=current_user['id'],
        confirmation_token=hashlib.sha256(request.confirmation_token.encode()).hexdigest()[:16],
        reason=request.reason,
        metadata={**(request.config or {}), "target_assets": target_assets}
    )
    
    # Store in database
    db = _get_db()
    db.create_session(session)

    # Escalate to AI via SecureChat (Trigger 2c)
    try:
        pm = get_panic_manager()
        chat = pm._chat_manager
        if chat:
            summary = (
                f"[Panic Room] ACTIVATED — {request.reason}\n"
                f"Playbooks: {'; '.join(request.playbooks)}\n"
                f"Target assets: {'; '.join(target_assets)}\n"
                f"Session: {session_id}\n"
                f"Critical/high-priority emergency response initiated."
            )
            await chat.send_system(summary, MessageType.EVENT)
    except Exception:
        pass  # Chat failure must never block panic activation

    # Log activation
    try:
        audit.log_event(
            event_type=EventType.AI_ALERT,
            severity=EventSeverity.CRITICAL,
            message=f"Panic Room activated: {request.reason}",
            details={
                "session_id": session_id,
                "user_id": current_user['id'],
                "playbooks": request.playbooks,
                "target_assets": target_assets,
                "reason": request.reason
            }
        )
    except Exception:
        pass  # Audit logging should never block panic operations
    
    # Calculate estimated duration
    total_duration = sum(p['estimated_duration'] for p in plan)
    
    return {
        "status": "activated",
        "session_id": session_id,
        "target_assets": target_assets,
        "execution_plan": plan,
        "estimated_duration": total_duration,
        "websocket_channel": f"/api/panic/ws/{session_id}"
    }


# ── Recovery Key Endpoints ─────────────────────────────────────────

def _get_recovery_manager() -> RecoveryKeyManager:
    """Get or create a RecoveryKeyManager instance."""
    return RecoveryKeyManager(_get_db())


def _make_rotation_token(user_id: str) -> str:
    """Generate an HMAC-based rotation confirmation token."""
    return _make_confirmation_token("rotate_recovery", user_id)


@router.get("/recovery-key")
async def get_recovery_key_status(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Get recovery key status (exists, fingerprint, age).

    Includes a ``rotation_token`` when a key exists so the frontend
    can echo it back to the rotate endpoint.
    """
    mgr = _get_recovery_manager()
    status = await mgr.get_status()
    if status.get("exists"):
        status["rotation_token"] = _make_rotation_token(current_user["id"])
    return status


@router.post("/recovery-key/generate")
async def generate_recovery_key(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Generate a new recovery key. Returns the private key ONCE.

    The private key is the user's break-glass escape hatch —
    it must be saved immediately as it will never be shown again.
    """
    mgr = _get_recovery_manager()

    try:
        result = await mgr.generate_recovery_key()

        try:
            audit.log_event(
                event_type=EventType.AI_ALERT,
                severity=EventSeverity.ALERT,
                message="Recovery key generated",
                details={
                    "user_id": current_user['id'],
                    "key_id": result["key_id"],
                    "fingerprint": result["fingerprint"],
                }
            )
        except Exception:
            pass  # Audit should never block

        return result

    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception:
        _logger.exception("Recovery key generation failed")
        raise HTTPException(status_code=500, detail="Recovery key generation failed")


class RotateRecoveryKeyRequest(BaseModel):
    confirmation_token: str = Field(..., description="User confirmation token")


@router.post("/recovery-key/rotate")
async def rotate_recovery_key(
    request: RotateRecoveryKeyRequest,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Rotate the recovery key. Returns the new private key ONCE.

    Atomic: new key is added before old key is removed.
    Requires confirmation token.
    """
    # Validate confirmation token
    if not _verify_confirmation_token("rotate_recovery", current_user["id"], request.confirmation_token):
        raise HTTPException(status_code=403, detail="Invalid confirmation token")

    mgr = _get_recovery_manager()

    try:
        result = await mgr.rotate_recovery_key()

        try:
            audit.log_event(
                event_type=EventType.AI_ALERT,
                severity=EventSeverity.CRITICAL,
                message="Recovery key rotated",
                details={
                    "user_id": current_user['id'],
                    "new_key_id": result["key_id"],
                    "replaced_key_id": result["replaced_key_id"],
                    "fingerprint": result["fingerprint"],
                }
            )
        except Exception:
            pass

        return result

    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception:
        _logger.exception("Recovery key rotation failed")
        raise HTTPException(status_code=500, detail="Recovery key rotation failed")


@router.post("/recovery-key/verify")
async def verify_recovery_key(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """Verify the recovery key is valid and present in authorized_keys."""
    mgr = _get_recovery_manager()
    return await mgr.verify_recovery_key()