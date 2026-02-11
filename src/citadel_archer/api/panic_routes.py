"""
Panic Room API Routes - Phase 3 Implementation
Emergency response endpoints for Citadel Commander
"""

import json
import hashlib
import time
from datetime import datetime
from typing import Optional, List, Dict
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from ..panic import PanicManager, TriggerSource
from ..panic.panic_database import PanicDatabase, PanicSession
from ..panic.playbooks import PlaybookLibrary, PlaybookValidator, PlaybookScheduler
from ..core.auth import get_current_user
from ..core.audit_log import AuditLogger

router = APIRouter(prefix="/api/panic", tags=["panic"])
audit = AuditLogger()

# Initialize panic manager (lazy singleton)
_panic_manager: Optional[PanicManager] = None


def get_panic_manager() -> PanicManager:
    """Dependency to get or create panic manager instance"""
    global _panic_manager
    if _panic_manager is None:
        db = PanicDatabase()
        config = {
            "confirmation_timeout": 30,
            "max_concurrent_sessions": 1,
            "default_playbooks": [],
            "recovery_dir": "/var/lib/citadel/panic/recovery",
            "backup_dir": "/var/lib/citadel/panic/backups",
        }
        _panic_manager = PanicManager(db, config)
    return _panic_manager


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
        
        # Generate expected confirmation token
        expected_token = hashlib.sha256(
            f"panic_{current_user['id']}_{datetime.utcnow().date()}".encode()
        ).hexdigest()[:16]
        
        # Validate confirmation token
        if request.confirmation_token != expected_token:
            # Log failed attempt
            await audit.log_event(
                event_type="panic_activation_failed",
                severity="warning",
                details={
                    "user_id": current_user['id'],
                    "reason": "Invalid confirmation token"
                }
            )
            raise HTTPException(status_code=403, detail="Invalid confirmation token")
        
        # Trigger panic mode
        session = await manager.trigger_panic(
            trigger_source=TriggerSource.MANUAL,
            playbook_ids=request.playbooks,
            reason=request.reason,
            user_id=current_user['id'],
            confirmation_token=request.confirmation_token,
            metadata=request.metadata
        )
        
        # Calculate estimated duration based on playbooks
        estimated_duration = len(request.playbooks) * 30  # 30 seconds per playbook estimate
        
        return PanicActivateResponse(
            session_id=str(session.id),
            status=session.status,
            playbooks_queued=len(request.playbooks),
            estimated_duration=estimated_duration,
            websocket_channel=f"/ws/panic/{session.id}"
        )
        
    except Exception as e:
        await audit.log_event(
            event_type="panic_activation_error",
            severity="error",
            details={
                "user_id": current_user['id'],
                "error": str(e)
            }
        )
        raise HTTPException(status_code=500, detail=str(e))


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
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        
        # Generate expected confirmation token
        expected_token = hashlib.sha256(
            f"panic_{current_user['id']}_{datetime.utcnow().date()}".encode()
        ).hexdigest()[:16]
        
        # Validate confirmation
        if request.confirmation_token != expected_token:
            await audit.log_event(
                event_type="panic_rollback_denied",
                severity="warning",
                details={
                    "session_id": session_id,
                    "user_id": current_user['id'],
                    "reason": "Invalid confirmation token"
                }
            )
            raise HTTPException(status_code=403, detail="Invalid confirmation token")
        
        # Convert string to UUID
        session_uuid = UUID(session_id)
        
        # Perform rollback
        results = await manager.rollback_panic(
            session_id=session_uuid,
            components=request.components,
            confirmation_token=request.confirmation_token,
            user_id=current_user['id']
        )
        
        # Log rollback
        await audit.log_event(
            event_type="panic_rollback",
            severity="info",
            details={
                "session_id": session_id,
                "user_id": current_user['id'],
                "components": request.components,
                "results": results
            }
        )
        
        return results
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Draft /sessions route removed - superseded by /sessions/history and /sessions/active below


# Draft /playbooks route removed - superseded by Phase 3 PlaybookLibrary route below


# Draft whitelist/config routes removed - used asyncpg patterns incompatible with SQLite PanicDatabase
# TODO: Re-implement whitelist/config using PanicDatabase when needed


# WebSocket endpoint for real-time updates

@router.websocket("/ws/{session_id}")
async def panic_websocket(
    websocket: WebSocket,
    session_id: str
):
    """
    WebSocket endpoint for real-time panic session updates
    """
    await websocket.accept()
    
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
        await websocket.send_json({"event": "error", "message": str(e)})
    finally:
        # Unregister handler
        if session_uuid in manager.websocket_handlers:
            manager.websocket_handlers[session_uuid].remove(websocket)


# Initialize panic manager on module load
def init_panic_manager(db_connection, config: dict):
    """Initialize the panic manager with database and config"""
    global panic_manager
    panic_manager = PanicManager(db_connection, config)


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
    db = PanicDatabase()
    history = db.get_session_history(limit=limit)
    return history


@router.get("/sessions/active", response_model=List[dict])
async def get_active_sessions(
    current_user: dict = Depends(get_current_user)
) -> List[dict]:
    """
    Get all active panic sessions
    """
    db = PanicDatabase()
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
    db = PanicDatabase()
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
    db = PanicDatabase()
    snapshots = db.get_recovery_snapshots(session_id)
    return snapshots


@router.post("/sessions/{session_id}/cancel", response_model=dict)
async def cancel_panic_session(
    session_id: str,
    confirmation_token: str,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Cancel an active panic session
    """
    # Generate expected confirmation token
    expected_token = hashlib.sha256(
        f"cancel_{current_user['id']}_{session_id}".encode()
    ).hexdigest()[:16]
    
    if confirmation_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid confirmation token")
    
    db = PanicDatabase()
    success = db.update_session(session_id, {
        "status": "cancelled",
        "completed_at": datetime.utcnow().isoformat(),
        "error": "User cancelled"
    })
    
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    
    await audit.log_event(
        event_type="panic_session_cancelled",
        severity="warning",
        details={
            "session_id": session_id,
            "user_id": current_user['id']
        }
    )
    
    return {"status": "cancelled", "session_id": session_id}


# Enhanced activation with Phase 3 features
@router.post("/activate/v2", response_model=dict)
async def activate_panic_v2(
    playbooks: List[str],
    reason: str,
    confirmation_token: str,
    config: Optional[Dict] = None,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Enhanced panic activation with Phase 3 features
    """
    # Generate expected confirmation token
    expected_token = hashlib.sha256(
        f"panic_{current_user['id']}_{datetime.utcnow().date()}".encode()
    ).hexdigest()[:16]
    
    if confirmation_token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid confirmation token")
    
    # Create execution plan
    plan = PlaybookScheduler.create_execution_plan(playbooks)
    
    # Check for issues
    blocked_playbooks = [p for p in plan if not p['can_execute']]
    if blocked_playbooks:
        return {
            "status": "validation_failed",
            "blocked_playbooks": blocked_playbooks
        }
    
    # Create panic session
    session_id = f"panic_{int(time.time() * 1000)}"
    session = PanicSession(
        session_id=session_id,
        status="active",
        playbooks=playbooks,
        started_at=datetime.utcnow(),
        trigger_source="manual",
        user_id=current_user['id'],
        confirmation_token=confirmation_token,
        reason=reason,
        metadata=config or {}
    )
    
    # Store in database
    db = PanicDatabase()
    db.create_session(session)
    
    # Log activation
    await audit.log_event(
        event_type="panic_activated_v2",
        severity="critical",
        details={
            "session_id": session_id,
            "user_id": current_user['id'],
            "playbooks": playbooks,
            "reason": reason
        }
    )
    
    # Calculate estimated duration
    total_duration = sum(p['estimated_duration'] for p in plan)
    
    return {
        "status": "activated",
        "session_id": session_id,
        "execution_plan": plan,
        "estimated_duration": total_duration,
        "websocket_channel": f"/api/panic/ws/{session_id}"
    }