# PRD: Dashboard - FastAPI Backend
# Reference: docs/PRD.md v0.2.2, Section: Technical Architecture
#
# FastAPI REST API + WebSocket server for Dashboard communication.
# PRD: "FastAPI REST API setup, WebSocket endpoint for real-time updates"

from typing import List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
import uvicorn
import json
from datetime import datetime

from ..core import (
    SecurityLevel,
    get_security_manager,
    EventType,
    EventSeverity,
    get_audit_logger,
)
from ..guardian import FileMonitor, ProcessMonitor
from .vault_routes import router as vault_router
from .dashboard_ext import router as dashboard_ext_router
from .security import initialize_session_token, get_session_token

# FastAPI app
app = FastAPI(
    title="Citadel Archer API",
    description="AI-centric defensive security platform API",
    version="0.2.2"
)

# CORS configuration (local only for security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(vault_router)
app.include_router(dashboard_ext_router)

# Serve frontend static files for desktop app
FRONTEND_DIR = Path(__file__).parent.parent.parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")
    if (FRONTEND_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")

# Global instances
file_monitor: Optional[FileMonitor] = None
process_monitor: Optional[ProcessMonitor] = None
websocket_clients: List[WebSocket] = []


# Startup: Initialize security
@app.on_event("startup")
async def startup_event():
    """
    Initialize security on backend startup.

    Security: Generates a random session token that must be included
    in all sensitive API requests. This prevents unauthorized access.
    """
    session_token = initialize_session_token()
    logger = get_audit_logger()
    logger.log_event(
        event_type=EventType.SYSTEM_START,
        severity=EventSeverity.INFO,
        message="API session initialized with authentication token"
    )


# Pydantic models
class SystemStatus(BaseModel):
    """System status response."""
    guardian_active: bool
    security_level: str
    threat_level: str  # green, yellow, red
    monitored_paths: List[str]
    uptime: str


class SecurityLevelUpdate(BaseModel):
    """Request to update security level."""
    level: str  # observer, guardian, sentinel


class ProcessInfo(BaseModel):
    """Process information."""
    pid: int
    name: str
    username: Optional[str]
    cpu_percent: float
    memory_percent: float


class EventInfo(BaseModel):
    """Security event information."""
    event_id: str
    event_type: str
    severity: str
    message: str
    timestamp: str


# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        get_audit_logger().log_event(
            event_type=EventType.USER_LOGIN,
            severity=EventSeverity.INFO,
            message="Dashboard connected via WebSocket"
        )

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        self.active_connections.remove(websocket)
        get_audit_logger().log_event(
            event_type=EventType.USER_LOGOUT,
            severity=EventSeverity.INFO,
            message="Dashboard disconnected"
        )

    async def broadcast(self, message: dict):
        """
        Broadcast message to all connected clients.

        PRD: "Real-time event stream in UI, Live notifications for threats"
        """
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                dead_connections.append(connection)
            except Exception:
                dead_connections.append(connection)

        # Clean up dead connections
        for connection in dead_connections:
            self.active_connections.remove(connection)


manager = ConnectionManager()


# Startup/shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize Guardian agents on startup."""
    global file_monitor, process_monitor

    get_audit_logger().log_event(
        event_type=EventType.SYSTEM_START,
        severity=EventSeverity.INFO,
        message="Citadel Archer API server starting"
    )

    # Initialize monitors (don't start yet - wait for user)
    file_monitor = FileMonitor()
    process_monitor = ProcessMonitor()

    # Start monitors automatically (can be made optional)
    file_monitor.start()
    process_monitor.start()


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    get_audit_logger().log_event(
        event_type=EventType.SYSTEM_STOP,
        severity=EventSeverity.INFO,
        message="Citadel Archer API server shutting down"
    )

    if file_monitor:
        file_monitor.stop()
    if process_monitor:
        process_monitor.stop()


# REST API Endpoints
@app.get("/")
async def serve_frontend():
    """Serve frontend HTML for desktop app."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    else:
        # Fallback to API info if frontend not found
        return {
            "name": "Citadel Archer API",
            "version": "0.2.3",
            "status": "operational"
        }


@app.get("/index.html")
async def serve_frontend_html():
    """Serve frontend HTML via /index.html path."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    else:
        return {"name": "Citadel Archer API", "version": "0.2.3", "status": "operational"}


@app.get("/vault.html")
async def serve_vault():
    """Serve Vault page for desktop app."""
    vault_path = FRONTEND_DIR / "vault.html"
    if vault_path.exists():
        return FileResponse(vault_path)
    else:
        raise HTTPException(status_code=404, detail="Vault page not found")


@app.get("/vault")
async def serve_vault_redirect():
    """Redirect /vault to /vault.html"""
    vault_path = FRONTEND_DIR / "vault.html"
    if vault_path.exists():
        return FileResponse(vault_path)
    else:
        raise HTTPException(status_code=404, detail="Vault page not found")

@app.get("/api/session")
async def get_session():
    """
    Get session token for API authentication.

    Security: This endpoint provides the session token that was generated
    on backend startup. Frontend must call this once on load and include
    the token in X-Session-Token header for all protected API calls.

    Note: This endpoint is unprotected because the frontend needs the token
    to authenticate. The security comes from:
    1. Token is random and unpredictable (256 bits)
    2. Token changes every backend restart
    3. Only accessible on localhost
    4. Prevents unauthorized local processes from accessing vault
    """
    return {
        "session_token": get_session_token()
    }


@app.get("/api")
async def api_info():
    """API information endpoint."""
    return {
        "name": "Citadel Archer API",
        "version": "0.2.3",
        "status": "operational",
        "philosophy": "Proactive protection. Acts first, informs after."
    }


@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """
    Get current system status.

    PRD: "Shows Guardian status, real-time threat level, security level"
    """
    security_manager = get_security_manager()

    return SystemStatus(
        guardian_active=file_monitor.is_running if file_monitor else False,
        security_level=security_manager.current_level.value,
        threat_level="green",  # TODO: Implement threat level calculation
        monitored_paths=file_monitor.get_monitored_paths() if file_monitor else [],
        uptime="0h 0m"  # TODO: Track uptime
    )


@app.get("/api/security-level")
async def get_security_level():
    """Get current security level."""
    security_manager = get_security_manager()
    return {
        "level": security_manager.current_level.value,
        "description": security_manager.current_level.description,
        "can_block_processes": security_manager.current_level.can_block_processes,
        "can_quarantine_files": security_manager.current_level.can_quarantine_files,
    }


@app.post("/api/security-level")
async def update_security_level(update: SecurityLevelUpdate):
    """
    Update security level.

    PRD: "User control - users explicitly choose security level"
    """
    try:
        new_level = SecurityLevel.from_string(update.level)
        security_manager = get_security_manager()

        old_level = security_manager.current_level
        security_manager.set_level(new_level, reason="User changed via Dashboard")

        # Log change
        get_audit_logger().log_event(
            event_type=EventType.SECURITY_LEVEL_CHANGED,
            severity=EventSeverity.INFO,
            message=f"Security level changed: {old_level} → {new_level}",
            details={"old_level": old_level.value, "new_level": new_level.value}
        )

        # Broadcast to connected clients
        await manager.broadcast({
            "type": "security_level_changed",
            "old_level": old_level.value,
            "new_level": new_level.value,
            "timestamp": datetime.utcnow().isoformat()
        })

        return {"status": "success", "level": new_level.value}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid security level: {str(e)}"
        )


@app.get("/api/processes", response_model=List[ProcessInfo])
async def get_processes():
    """
    Get list of running processes.

    PRD: "Shows recent file/process events"
    """
    if not process_monitor:
        return []

    processes = process_monitor.get_running_processes()
    return [ProcessInfo(**p) for p in processes[:100]]  # Limit to 100


@app.post("/api/processes/{pid}/kill")
async def kill_process(pid: int, reason: Optional[str] = "User requested"):
    """
    Kill a specific process.

    PRD: "User control - users can override AI decisions"
    """
    if not process_monitor:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process monitor not initialized"
        )

    success = process_monitor.kill_process(pid, reason)

    if success:
        # Broadcast to connected clients
        await manager.broadcast({
            "type": "process_killed",
            "pid": pid,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        })
        return {"status": "success", "pid": pid}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Process {pid} not found or could not be killed"
        )


@app.get("/api/events", response_model=List[EventInfo])
async def get_recent_events(limit: int = 50):
    """
    Get recent security events.

    PRD: "Log viewer in Dashboard"
    TODO: Phase 1 - Implement event querying from audit log
    """
    # Placeholder - will implement with audit log querying
    return []


@app.get("/api/guardian/start")
async def start_guardian():
    """Start Guardian monitoring."""
    if file_monitor and not file_monitor.is_running:
        file_monitor.start()
    if process_monitor and not process_monitor.is_running:
        process_monitor.start()

    await manager.broadcast({
        "type": "guardian_started",
        "timestamp": datetime.utcnow().isoformat()
    })

    return {"status": "success", "message": "Guardian started"}


@app.get("/api/guardian/stop")
async def stop_guardian():
    """Stop Guardian monitoring."""
    if file_monitor and file_monitor.is_running:
        file_monitor.stop()
    if process_monitor and process_monitor.is_running:
        process_monitor.stop()

    await manager.broadcast({
        "type": "guardian_stopped",
        "timestamp": datetime.utcnow().isoformat()
    })

    return {"status": "success", "message": "Guardian stopped"}


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time Dashboard updates.

    PRD: "Real-time event stream in UI, No page refresh needed"
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for client messages
            data = await websocket.receive_text()
            # Echo back for ping/pong
            await websocket.send_text(f"Server received: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)


def start_api_server(host: str = "127.0.0.1", port: int = 8000):
    """
    Start FastAPI server.

    Args:
        host: Host to bind to (default: localhost only for security)
        port: Port to listen on
    """
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    start_api_server()
