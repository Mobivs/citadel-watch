# PRD: Dashboard - FastAPI Backend
# Reference: docs/PRD.md v0.2.2, Section: Technical Architecture
#
# FastAPI REST API + WebSocket server for Dashboard communication.
# PRD: "FastAPI REST API setup, WebSocket endpoint for real-time updates"

from typing import List, Optional, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
import uvicorn
import json
import uuid
import asyncio
from datetime import datetime, timezone

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
from .remote_shield_routes import router as remote_shield_router
from .panic_routes import router as panic_router
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
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://127.0.0.1:8000", "http://187.77.15.247:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(vault_router)
app.include_router(dashboard_ext_router)
app.include_router(remote_shield_router)
app.include_router(panic_router)

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


@app.get("/assets.html")
async def serve_assets_page():
    """Serve Assets page."""
    path = FRONTEND_DIR / "assets.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Assets page not found")


@app.get("/assets-page")
async def serve_assets_page_redirect():
    """Redirect /assets-page to /assets.html"""
    path = FRONTEND_DIR / "assets.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Assets page not found")


@app.get("/risk-metrics.html")
async def serve_risk_metrics():
    """Serve Risk Metrics page."""
    path = FRONTEND_DIR / "risk-metrics.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Risk Metrics page not found")


@app.get("/risk-metrics")
async def serve_risk_metrics_redirect():
    """Redirect /risk-metrics to /risk-metrics.html"""
    path = FRONTEND_DIR / "risk-metrics.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Risk Metrics page not found")


@app.get("/timeline.html")
async def serve_timeline():
    """Serve Alert Timeline page."""
    timeline_path = FRONTEND_DIR / "timeline.html"
    if timeline_path.exists():
        return FileResponse(timeline_path)
    else:
        raise HTTPException(status_code=404, detail="Timeline page not found")


@app.get("/timeline")
async def serve_timeline_redirect():
    """Redirect /timeline to /timeline.html"""
    timeline_path = FRONTEND_DIR / "timeline.html"
    if timeline_path.exists():
        return FileResponse(timeline_path)
    else:
        raise HTTPException(status_code=404, detail="Timeline page not found")


@app.get("/charts.html")
async def serve_charts():
    """Serve Charts & Visualization page."""
    charts_path = FRONTEND_DIR / "charts.html"
    if charts_path.exists():
        return FileResponse(charts_path)
    else:
        raise HTTPException(status_code=404, detail="Charts page not found")


@app.get("/charts")
async def serve_charts_redirect():
    """Redirect /charts to /charts.html"""
    charts_path = FRONTEND_DIR / "charts.html"
    if charts_path.exists():
        return FileResponse(charts_path)
    else:
        raise HTTPException(status_code=404, detail="Charts page not found")


@app.get("/remote-shield.html")
async def serve_remote_shield():
    """Serve Remote Shield page."""
    path = FRONTEND_DIR / "remote-shield.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Remote Shield page not found")


@app.get("/remote-shield")
async def serve_remote_shield_redirect():
    """Redirect /remote-shield to /remote-shield.html"""
    path = FRONTEND_DIR / "remote-shield.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Remote Shield page not found")


@app.get("/panic-room.html")
async def serve_panic_room():
    """Serve Panic Room page."""
    path = FRONTEND_DIR / "panic-room.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Panic Room page not found")


@app.get("/panic-room")
async def serve_panic_room_redirect():
    """Redirect /panic-room to /panic-room.html"""
    path = FRONTEND_DIR / "panic-room.html"
    if path.exists():
        return FileResponse(path)
    else:
        raise HTTPException(status_code=404, detail="Panic Room page not found")


@app.get("/favicon.ico")
async def serve_favicon():
    """Serve favicon."""
    favicon_path = FRONTEND_DIR / "favicon.ico"
    if favicon_path.exists():
        return FileResponse(favicon_path)
    # Return 204 No Content instead of 404 to silence browser errors
    from starlette.responses import Response
    return Response(status_code=204)


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


@app.get("/test-events.html")
async def serve_test_events():
    """Serve test-events.html for Developer Tools (no-cache for dev tool)."""
    test_events_path = FRONTEND_DIR / "test-events.html"
    if test_events_path.exists():
        return FileResponse(
            test_events_path,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate"}
        )
    else:
        raise HTTPException(status_code=404, detail="Test events page not found")


@app.get("/test-events")
async def serve_test_events_redirect():
    """Redirect /test-events to /test-events.html"""
    test_events_path = FRONTEND_DIR / "test-events.html"
    if test_events_path.exists():
        return FileResponse(
            test_events_path,
            headers={"Cache-Control": "no-store, no-cache, must-revalidate"}
        )
    else:
        raise HTTPException(status_code=404, detail="Test events page not found")

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
            "timestamp": datetime.now(timezone.utc).isoformat()
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
            "timestamp": datetime.now(timezone.utc).isoformat()
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
        "timestamp": datetime.now(timezone.utc).isoformat()
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
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    return {"status": "success", "message": "Guardian stopped"}


# ============================================================================
# PHASE 2: ALERT SYSTEM ENDPOINTS
# ============================================================================

# In-memory storage for alerts and threats (Phase 2 implementation)
# In production, this would be stored in a database
alerts_storage = []
threats_storage = []
alert_config = {
    "escalation_enabled": True,
    "stage_intervals": [0, 300, 600],  # seconds between escalation stages
    "deduplication": True,
    "deduplication_window": 300,  # seconds
    "max_alerts": 1000,
    "auto_acknowledge": False,
    "severity_thresholds": {
        "low": 3,
        "medium": 5,
        "high": 7,
        "critical": 9
    }
}

class ThreatSubmission(BaseModel):
    """Phase 2: Threat submission model"""
    threat_type: str
    severity: int  # 1-10 scale
    source: str
    target: Optional[str] = None
    description: str
    timestamp: Optional[str] = None
    metadata: Optional[dict] = None

class Alert(BaseModel):
    """Phase 2: Alert model"""
    id: str
    threat_id: Optional[str] = None
    threat_type: str
    severity: int
    severity_level: str  # low, medium, high, critical
    source: str
    target: Optional[str] = None
    description: str
    timestamp: str
    created_at: str
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None
    escalation_stage: int = 1  # 1, 2, or 3
    escalated_at: Optional[str] = None
    deduplicated: bool = False
    duplicate_count: int = 0

class AlertFilter(BaseModel):
    """Phase 2: Alert filter model"""
    severity_min: Optional[int] = None
    severity_max: Optional[int] = None
    threat_type: Optional[str] = None
    acknowledged: Optional[bool] = None
    limit: Optional[int] = 100

class AlertConfig(BaseModel):
    """Phase 2: Alert configuration model"""
    escalation_enabled: Optional[bool] = None
    stage_intervals: Optional[List[int]] = None
    deduplication: Optional[bool] = None
    deduplication_window: Optional[int] = None
    max_alerts: Optional[int] = None
    auto_acknowledge: Optional[bool] = None
    severity_thresholds: Optional[dict] = None

def get_severity_level(severity: int) -> str:
    """Convert numeric severity to level string"""
    thresholds = alert_config["severity_thresholds"]
    if severity < thresholds["low"]:
        return "info"
    elif severity < thresholds["medium"]:
        return "low"
    elif severity < thresholds["high"]:
        return "medium"
    elif severity < thresholds["critical"]:
        return "high"
    else:
        return "critical"

def check_deduplication(threat: ThreatSubmission) -> Optional[Alert]:
    """
    Phase 2: Check if threat is duplicate within deduplication window
    Returns existing alert if duplicate, None otherwise
    """
    if not alert_config["deduplication"]:
        return None
    
    window = alert_config["deduplication_window"]
    current_time = datetime.now(timezone.utc)
    
    for alert in alerts_storage:
        # Check if alert is within deduplication window
        # Parse the created_at timestamp properly
        alert_time_str = alert.created_at.replace('Z', '')
        if not alert_time_str.endswith('+00:00'):
            alert_time_str = alert_time_str.split('+')[0]  # Remove any existing offset
        alert_time = datetime.fromisoformat(alert_time_str)
        time_diff = (current_time - alert_time).total_seconds()
        
        if time_diff <= window:
            # Check if threat characteristics match
            if (alert.threat_type == threat.threat_type and 
                alert.source == threat.source and
                alert.severity == threat.severity):
                return alert
    
    return None

async def escalate_alert(alert: Alert):
    """
    Phase 2: Handle alert escalation through stages
    Stage 1: Initial alert
    Stage 2: Elevated priority
    Stage 3: Critical escalation
    """
    if not alert_config["escalation_enabled"]:
        return
    
    intervals = alert_config["stage_intervals"]
    
    # Schedule stage 2 escalation
    if alert.escalation_stage == 1 and len(intervals) > 1:
        import asyncio
        await asyncio.sleep(intervals[1])
        if not alert.acknowledged:
            alert.escalation_stage = 2
            alert.escalated_at = datetime.now(timezone.utc).isoformat() + "Z"
            # Broadcast escalation
            await manager.broadcast({
                "type": "alert_escalated",
                "alert_id": alert.id,
                "stage": 2,
                "timestamp": alert.escalated_at
            })
            
            # Schedule stage 3 escalation
            if len(intervals) > 2:
                await asyncio.sleep(intervals[2] - intervals[1])
                if not alert.acknowledged:
                    alert.escalation_stage = 3
                    alert.escalated_at = datetime.now(timezone.utc).isoformat() + "Z"
                    await manager.broadcast({
                        "type": "alert_escalated",
                        "alert_id": alert.id,
                        "stage": 3,
                        "timestamp": alert.escalated_at
                    })

@app.get("/api/health")
async def health_check():
    """
    Phase 2: Health check endpoint for monitoring
    """
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat() + "Z"}

@app.post("/api/threats/submit")
async def submit_threat(threat: ThreatSubmission):
    """
    Phase 2: Accept threat JSON, store in database, run deduplication, trigger alert engine
    """
    import uuid
    import asyncio
    
    # Store threat
    threat_id = str(uuid.uuid4())
    threat_data = threat.model_dump()
    threat_data["id"] = threat_id
    threat_data["received_at"] = datetime.now(timezone.utc).isoformat() + "Z"
    
    if not threat_data.get("timestamp"):
        threat_data["timestamp"] = threat_data["received_at"]
    
    threats_storage.append(threat_data)
    
    # Check for deduplication
    existing_alert = check_deduplication(threat)
    
    if existing_alert:
        # Update duplicate count
        existing_alert.duplicate_count += 1
        existing_alert.deduplicated = True
        
        # Log deduplication
        get_audit_logger().log_event(
            event_type=EventType.AI_ALERT,
            severity=EventSeverity.INFO,
            message=f"Duplicate threat detected: {threat.threat_type}",
            details={"alert_id": existing_alert.id, "duplicate_count": existing_alert.duplicate_count}
        )
        
        return {
            "status": "deduplicated",
            "alert_id": existing_alert.id,
            "duplicate_count": existing_alert.duplicate_count
        }
    
    # Create new alert
    alert = Alert(
        id=str(uuid.uuid4()),
        threat_id=threat_id,
        threat_type=threat.threat_type,
        severity=threat.severity,
        severity_level=get_severity_level(threat.severity),
        source=threat.source,
        target=threat.target,
        description=threat.description,
        timestamp=threat_data["timestamp"],
        created_at=datetime.now(timezone.utc).isoformat() + "Z",
        acknowledged=False,
        escalation_stage=1,
        deduplicated=False,
        duplicate_count=0
    )
    
    # Store alert
    alerts_storage.append(alert)
    
    # Enforce max alerts limit
    if len(alerts_storage) > alert_config["max_alerts"]:
        alerts_storage.pop(0)  # Remove oldest alert
    
    # Log alert creation
    # Map severity levels to EventSeverity
    severity_map = {
        "info": EventSeverity.INFO,
        "low": EventSeverity.INFO,
        "medium": EventSeverity.INVESTIGATE,
        "high": EventSeverity.ALERT,
        "critical": EventSeverity.CRITICAL
    }
    log_severity = severity_map.get(alert.severity_level, EventSeverity.INFO)
    
    get_audit_logger().log_event(
        event_type=EventType.AI_ALERT,
        severity=log_severity,
        message=f"Alert created: {threat.threat_type}",
        details={"alert_id": alert.id, "severity": threat.severity}
    )
    
    # Broadcast to WebSocket clients
    await manager.broadcast({
        "type": "alert_created",
        "alert": alert.model_dump(),
        "timestamp": alert.created_at
    })
    
    # Start escalation process in background
    if alert_config["escalation_enabled"] and threat.severity >= 7:
        asyncio.create_task(escalate_alert(alert))
    
    return {
        "status": "created",
        "alert_id": alert.id,
        "severity_level": alert.severity_level,
        "escalation_enabled": alert_config["escalation_enabled"]
    }

@app.get("/api/alerts")
async def get_alerts(
    severity_min: Optional[int] = None,
    severity_max: Optional[int] = None,
    threat_type: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 100
):
    """
    Phase 2: List alerts with filters
    """
    filtered_alerts = alerts_storage.copy()
    
    # Apply filters
    if severity_min is not None:
        filtered_alerts = [a for a in filtered_alerts if a.severity >= severity_min]
    
    if severity_max is not None:
        filtered_alerts = [a for a in filtered_alerts if a.severity <= severity_max]
    
    if threat_type is not None:
        filtered_alerts = [a for a in filtered_alerts if a.threat_type == threat_type]
    
    if acknowledged is not None:
        filtered_alerts = [a for a in filtered_alerts if a.acknowledged == acknowledged]
    
    # Sort by creation time (newest first) and apply limit
    filtered_alerts.sort(key=lambda x: x.created_at, reverse=True)
    filtered_alerts = filtered_alerts[:limit]
    
    return {
        "alerts": [a.model_dump() for a in filtered_alerts],
        "total": len(filtered_alerts),
        "filters_applied": {
            "severity_min": severity_min,
            "severity_max": severity_max,
            "threat_type": threat_type,
            "acknowledged": acknowledged
        }
    }

@app.post("/api/alerts/acknowledge-all")
async def acknowledge_all_alerts():
    """
    Phase 2: Mark all alerts as acknowledged
    """
    acknowledged_count = 0
    current_time = datetime.now(timezone.utc).isoformat() + "Z"
    
    for alert in alerts_storage:
        if not alert.acknowledged:
            alert.acknowledged = True
            alert.acknowledged_at = current_time
            acknowledged_count += 1
    
    # Log bulk acknowledgment
    if acknowledged_count > 0:
        get_audit_logger().log_event(
            event_type=EventType.USER_OVERRIDE,
            severity=EventSeverity.INFO,
            message=f"Bulk alert acknowledgment: {acknowledged_count} alerts",
            details={"count": acknowledged_count}
        )
        
        # Broadcast update
        await manager.broadcast({
            "type": "alerts_acknowledged",
            "count": acknowledged_count,
            "timestamp": current_time
        })
    
    return {
        "status": "success",
        "acknowledged_count": acknowledged_count,
        "timestamp": current_time
    }

@app.delete("/api/alerts/clear")
async def clear_alert_history():
    """
    Phase 2: Delete alert history
    """
    alert_count = len(alerts_storage)
    alerts_storage.clear()
    
    # Log clearing
    get_audit_logger().log_event(
        event_type=EventType.USER_OVERRIDE,
        severity=EventSeverity.ALERT,  # Using ALERT for important user actions
        message=f"Alert history cleared: {alert_count} alerts deleted",
        details={"deleted_count": alert_count}
    )
    
    # Broadcast update
    await manager.broadcast({
        "type": "alerts_cleared",
        "deleted_count": alert_count,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    })
    
    return {
        "status": "success",
        "deleted_count": alert_count
    }

@app.get("/api/alert-config")
async def get_alert_config():
    """
    Phase 2: Return current alert configuration
    """
    return alert_config

@app.post("/api/alert-config")
async def update_alert_config(config: AlertConfig):
    """
    Phase 2: Update alert configuration
    """
    global alert_config
    
    # Track changes for audit
    changes = {}
    
    # Update only provided fields
    if config.escalation_enabled is not None:
        changes["escalation_enabled"] = (alert_config["escalation_enabled"], config.escalation_enabled)
        alert_config["escalation_enabled"] = config.escalation_enabled
    
    if config.stage_intervals is not None:
        changes["stage_intervals"] = (alert_config["stage_intervals"], config.stage_intervals)
        alert_config["stage_intervals"] = config.stage_intervals
    
    if config.deduplication is not None:
        changes["deduplication"] = (alert_config["deduplication"], config.deduplication)
        alert_config["deduplication"] = config.deduplication
    
    if config.deduplication_window is not None:
        changes["deduplication_window"] = (alert_config["deduplication_window"], config.deduplication_window)
        alert_config["deduplication_window"] = config.deduplication_window
    
    if config.max_alerts is not None:
        changes["max_alerts"] = (alert_config["max_alerts"], config.max_alerts)
        alert_config["max_alerts"] = config.max_alerts
    
    if config.auto_acknowledge is not None:
        changes["auto_acknowledge"] = (alert_config["auto_acknowledge"], config.auto_acknowledge)
        alert_config["auto_acknowledge"] = config.auto_acknowledge
    
    if config.severity_thresholds is not None:
        changes["severity_thresholds"] = (alert_config["severity_thresholds"], config.severity_thresholds)
        alert_config["severity_thresholds"] = config.severity_thresholds
    
    # Log configuration change
    if changes:
        get_audit_logger().log_event(
            event_type=EventType.AI_DECISION,  # Using AI_DECISION for config changes
            severity=EventSeverity.INFO,
            message="Alert configuration updated",
            details={"changes": changes}
        )
        
        # Broadcast update
        await manager.broadcast({
            "type": "config_updated",
            "config": alert_config,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
        })
    
    return {
        "status": "success",
        "config": alert_config,
        "changes_applied": len(changes)
    }

# ============================================================================
# END PHASE 2 ALERT SYSTEM
# ============================================================================

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
