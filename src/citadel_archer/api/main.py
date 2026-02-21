# PRD: Dashboard - FastAPI Backend
# Reference: docs/PRD.md v0.2.2, Section: Technical Architecture
#
# FastAPI REST API + WebSocket server for Dashboard communication.
# PRD: "FastAPI REST API setup, WebSocket endpoint for real-time updates"

import logging
from typing import List, Optional, Dict
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
import uvicorn
import json
import uuid
import asyncio
from datetime import datetime, timedelta, timezone

from ..core import (
    SecurityLevel,
    get_security_manager,
    EventType,
    EventSeverity,
    get_audit_logger,
)
from ..guardian import FileMonitor, ProcessMonitor
from .vault_routes import router as vault_router
from .dashboard_ext import router as dashboard_ext_router, services as dashboard_services
from .remote_shield_routes import router as remote_shield_router
from .panic_routes import router as panic_router
from .asset_routes import router as asset_router
from .chat_routes import router as chat_router
from .agent_api_routes import router as agent_api_router
from .ai_audit_routes import router as ai_audit_router
from .scs_quota_routes import router as scs_quota_router
from .ssh_hardening_routes import router as hardening_router
from .firewall_routes import router as firewall_router
from .onboarding_routes import router as onboarding_router
from .contact_routes import router as contact_router
from .file_routes import router as file_router
from .group_policy_routes import router as group_policy_router
from .enrollment_routes import router as enrollment_router
from .backup_routes import router as backup_router
from .performance_routes import router as performance_router
from .mesh_routes import router as mesh_router
from .security import initialize_session_token, get_session_token

logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Citadel Archer API",
    description="AI-centric defensive security platform API",
    version="0.2.2"
)

# CORS configuration — local + Tailscale origins.
# Remote agents use Bearer token auth (no CORS), but the Tailscale origin
# is needed if the desktop UI is accessed from a Tailscale IP.
_allowed_origins = [
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:8000", "http://127.0.0.1:8000",
    "http://localhost:8080", "http://127.0.0.1:8080",
    "http://100.68.75.8:8000",   # Tailscale (this machine)
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# No-cache for ALL frontend assets (prevents Edge from serving stale HTML/JS/CSS).
# Uses pure ASGI middleware (NOT BaseHTTPMiddleware) to avoid interfering with
# WebSocket upgrade requests — BaseHTTPMiddleware has known issues with WS.
class NoCacheStaticMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            # Pass WebSocket and other non-HTTP connections straight through
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        needs_no_cache = (
            path.startswith(("/js/", "/css/", "/assets/"))
            or path.endswith(".html")
            or path == "/"
        )

        if not needs_no_cache:
            await self.app(scope, receive, send)
            return

        # Wrap send to inject no-cache headers on HTTP responses
        async def send_with_no_cache(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                for name, value in [
                    (b"cache-control", b"no-cache, no-store, must-revalidate"),
                    (b"pragma", b"no-cache"),
                    (b"expires", b"0"),
                ]:
                    headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_no_cache)


app.add_middleware(NoCacheStaticMiddleware)

# Register routers
app.include_router(vault_router)
app.include_router(dashboard_ext_router)
app.include_router(remote_shield_router)
app.include_router(panic_router)
app.include_router(asset_router)
app.include_router(chat_router)
app.include_router(agent_api_router)
app.include_router(ai_audit_router)
app.include_router(scs_quota_router)
app.include_router(hardening_router)
app.include_router(firewall_router)
app.include_router(onboarding_router)
app.include_router(contact_router)
app.include_router(file_router)
app.include_router(group_policy_router)
app.include_router(enrollment_router)
app.include_router(backup_router)
app.include_router(performance_router)
app.include_router(mesh_router)

# No-cache headers for HTML responses — prevents Edge --app from serving stale pages
_NO_CACHE = {"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache", "Expires": "0"}

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
_server_start_time: Optional[datetime] = None


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
    """Initialize security, session token, and Guardian agents on startup."""
    global file_monitor, process_monitor, _server_start_time

    # Initialize session token for API authentication
    _server_start_time = datetime.now(timezone.utc)
    initialize_session_token()

    # Wire up EventAggregator for charts/timeline data
    from ..intel.event_aggregator import EventAggregator
    aggregator = EventAggregator(max_history=10_000)
    dashboard_services.event_aggregator = aggregator

    # Share the AssetInventory singleton with DashboardServices so
    # /api/asset-view returns the same data as /api/assets (CRUD).
    from .asset_routes import get_inventory
    dashboard_services.asset_inventory = get_inventory()

    # Back-fill aggregator with recent audit log events so charts
    # aren't empty on first load.
    audit_logger = get_audit_logger()
    try:
        recent_events = audit_logger.query_events(limit=500)
        for evt in reversed(recent_events):  # oldest first
            aggregator.ingest(
                event_type=evt.get("event_type", "system.start"),
                severity=evt.get("severity", "info"),
                asset_id=evt.get("details", {}).get("asset_id"),
                message=evt.get("message", ""),
                details=evt.get("details", {}),
                timestamp=evt.get("timestamp"),
            )
    except Exception:
        pass  # best-effort back-fill

    # Forward all future audit events into the aggregator
    audit_logger.on_event(aggregator.ingest_bus_event)

    audit_logger.log_event(
        event_type=EventType.SYSTEM_START,
        severity=EventSeverity.INFO,
        message="Citadel Archer API server starting (session token initialized)"
    )

    # Initialize monitors (don't start yet - wait for user)
    file_monitor = FileMonitor()
    process_monitor = ProcessMonitor()

    # Start monitors automatically (can be made optional)
    file_monitor.start()
    process_monitor.start()

    # Initialize SecureChat manager and wire to WebSocket broadcast
    from ..chat import ChatManager, ChatStore
    from .chat_routes import set_chat_manager
    chat_mgr = ChatManager(ChatStore())
    chat_mgr.set_ws_broadcast(manager.broadcast)
    set_chat_manager(chat_mgr)
    dashboard_services.chat_manager = chat_mgr

    # Register chat commands (Milestone 2: Quick Add VPS)
    from ..chat.commands.add_vps import register_commands
    register_commands(chat_mgr)

    # Register deploy command
    from ..chat.commands.deploy_agent import register_commands as register_deploy
    register_deploy(chat_mgr)

    # Initialize AI Bridge (connects SecureChat to Claude API)
    # Gracefully degrades if no ANTHROPIC_API_KEY is set
    from ..chat.ai_bridge import AIBridge
    ai_bridge = AIBridge(chat_manager=chat_mgr)
    ai_bridge.register()
    app.state.ai_bridge = ai_bridge
    dashboard_services._ai_bridge = ai_bridge

    # Send a welcome message so the sidebar isn't empty on first run.
    # Purge any previous startup banners first so restarts don't accumulate copies.
    chat_mgr.store.delete_matching_payload("Citadel Archer online")
    if ai_bridge.enabled:
        backend = ai_bridge.active_backend
        backend_msg = f"AI assistant active (backend: {backend})."
        await chat_mgr.send_system(
            f"Citadel Archer online. {backend_msg} "
            "Type 'add vps <ip>' to protect a server, or ask me anything."
        )
    else:
        await chat_mgr.send_system(
            "Citadel Archer online. Type 'add vps <ip>' to protect a server. "
            "(Set ANTHROPIC_API_KEY or install Ollama to enable AI assistant.)"
        )

    # Start agent poller as background task (Milestone 4)
    try:
        from .asset_routes import get_ssh_manager
        from ..remote.agent_poller import AgentPoller
        _poller = AgentPoller(
            ssh_manager=get_ssh_manager(),
            event_aggregator=aggregator,
            chat_manager=chat_mgr,
        )
        await _poller.start()
        app.state.agent_poller = _poller
    except Exception:
        pass  # Poller is best-effort; SSH may not be configured yet

    # Wire local Guardian escalation to AI via SecureChat (Trigger 2b)
    from ..chat.guardian_escalation import GuardianEscalation
    _loop = asyncio.get_running_loop()
    guardian_esc = GuardianEscalation(
        aggregator=aggregator,
        chat_manager=chat_mgr,
        loop=_loop,
    )
    guardian_esc.start()
    app.state.guardian_escalation = guardian_esc

    # Wire Remote Shield VPS escalation to AI via SecureChat (Trigger 2d)
    from ..chat.remote_shield_escalation import RemoteShieldEscalation
    remote_esc = RemoteShieldEscalation(
        aggregator=aggregator,
        chat_manager=chat_mgr,
        loop=_loop,
    )
    remote_esc.start()
    app.state.remote_shield_escalation = remote_esc

    # Wire Panic Room → AI escalation (Trigger 2c)
    try:
        from .panic_routes import get_panic_manager
        pm = get_panic_manager()
        pm.set_chat_manager(chat_mgr)
    except Exception:
        pass  # Panic manager is lazy-init, best-effort wiring

    # Start scheduled security posture analysis (Trigger 3a)
    from ..chat.posture_analyzer import PostureAnalyzer
    try:
        from .asset_routes import get_inventory
        inv = get_inventory()
    except (ImportError, RuntimeError):
        inv = None
    try:
        from ..remote.shield_database import RemoteShieldDatabase
        shield_db = RemoteShieldDatabase()
    except (ImportError, RuntimeError):
        shield_db = None
    dashboard_services.shield_db = shield_db

    # Wire SSH manager and vault for service lookup
    try:
        from .asset_routes import get_ssh_manager
        dashboard_services.ssh_manager = get_ssh_manager()
    except Exception:
        pass  # SSH may not be configured yet
    try:
        from .vault_routes import vault_manager as _vm
        dashboard_services.vault = _vm
    except Exception:
        pass

    posture = PostureAnalyzer(
        chat_manager=chat_mgr,
        aggregator=aggregator,
        inventory=inv,
        shield_db=shield_db,
    )
    await posture.start()
    app.state.posture_analyzer = posture

    # Startup catch-up (Trigger 3b) — review events from offline period
    from ..chat.startup_catchup import StartupCatchup

    catchup = StartupCatchup(
        chat_manager=chat_mgr,
        audit_logger=audit_logger,
        inventory=inv,
        shield_db=shield_db,
    )
    await catchup.run()
    app.state.startup_catchup = catchup

    # Threshold breach detection (Trigger 3c) — aggregate pattern escalation
    from ..chat.threshold_engine import ThresholdEngine
    threshold_engine = ThresholdEngine(
        aggregator=aggregator,
        chat_manager=chat_mgr,
        loop=asyncio.get_running_loop(),
    )
    threshold_engine.start()
    app.state.threshold_engine = threshold_engine

    # Intel feed aggregator — schedules daily fetch from all threat feeds
    intel_store = None
    try:
        from ..intel.aggregator import IntelAggregator
        from ..intel.store import IntelStore
        from ..intel.otx_fetcher import OTXFetcher
        from ..intel.abusech_fetcher import AbuseChFetcher
        from ..intel.mitre_fetcher import MitreFetcher
        from ..intel.nvd_fetcher import NVDFetcher

        intel_store = IntelStore()
        intel_agg = IntelAggregator(store=intel_store)

        # Register all threat feed fetchers
        otx = OTXFetcher()
        otx.configure()
        intel_agg.register(otx)

        abusech = AbuseChFetcher()
        abusech.configure()
        intel_agg.register(abusech)

        mitre = MitreFetcher()
        mitre.configure()
        intel_agg.register(mitre)

        nvd = NVDFetcher()
        nvd.configure()
        intel_agg.register(nvd)

        intel_agg.start()
        app.state.intel_aggregator = intel_agg
    except Exception:
        logger.warning("Intel aggregator failed to start", exc_info=True)

    # Cross-asset threat correlation (Watchtower completion)
    try:
        from ..intel.cross_asset_correlation import CrossAssetCorrelator
        correlator = CrossAssetCorrelator(
            aggregator=aggregator,
            chat_manager=chat_mgr,
            intel_store=intel_store,
            loop=asyncio.get_running_loop(),
        )
        correlator.start()
        app.state.cross_asset_correlator = correlator
        dashboard_services._correlator = correlator
        correlator.set_ws_broadcast(manager.broadcast)

        # Wire cross-system alert propagation to remote agents
        if shield_db is not None:
            try:
                from ..remote.alert_propagator import AlertPropagator
                _propagator = AlertPropagator(shield_db=shield_db)
                correlator.set_alert_propagation(_propagator.propagate)
            except Exception:
                logger.warning("Alert propagator failed to wire", exc_info=True)

    except Exception:
        logger.warning("Cross-asset correlator failed to start", exc_info=True)

    # Wire Panic Room → Remote Shield agent dispatch
    if shield_db is not None:
        try:
            from ..remote.panic_dispatcher import RemotePanicDispatcher
            from .panic_routes import get_panic_manager as _get_pm
            _panic_dispatcher = RemotePanicDispatcher(shield_db=shield_db)
            _get_pm().set_panic_dispatcher(_panic_dispatcher)
        except Exception:
            logger.debug("Remote panic dispatcher failed to wire", exc_info=True)

    # Browser extension inventory scanner + watcher + threat intel
    try:
        from ..guardian.extension_scanner import ExtensionScanner
        from ..guardian.extension_intel import ExtensionIntelDatabase
        from ..guardian.extension_watcher import ExtensionWatcher

        ext_intel = ExtensionIntelDatabase()
        ext_scanner = ExtensionScanner(aggregator=aggregator)
        scan_result = ext_scanner.scan_all()  # Initial scan on startup
        dashboard_services._extension_scanner = ext_scanner
        dashboard_services._extension_intel = ext_intel
        app.state.extension_scanner = ext_scanner

        # Start real-time extension directory watcher
        ext_watcher = ExtensionWatcher(
            aggregator=aggregator,
            intel_db=ext_intel,
        )
        # Seed known IDs from initial scan so only NEW installs trigger alerts
        ext_watcher.set_known_extensions(
            {e.extension_id for e in scan_result.extensions}
        )
        ext_watcher.start()
        dashboard_services._extension_watcher = ext_watcher
        app.state.extension_watcher = ext_watcher
    except Exception:
        logger.warning("Extension scanner/watcher failed on startup", exc_info=True)

    # Defense Mesh heartbeat protocol (v0.3.36)
    # HMAC-signed heartbeats with pre-shared keys.
    # Pure automation at NORMAL phase (zero AI tokens).
    # AI only invoked on escalation transitions: Haiku → Sonnet → Opus.
    try:
        from ..mesh.mesh_state import MeshCoordinator, EscalationPhase
        from ..mesh.mesh_database import MeshDatabase, set_mesh_database
        from ..mesh.mesh_keys import load_or_create_psk, get_psk_fingerprint
        from .mesh_routes import set_mesh_coordinator
        from ..core.user_preferences import get_user_preferences

        mesh_db = MeshDatabase()
        set_mesh_database(mesh_db)

        prefs = get_user_preferences()
        mesh_interval = int(prefs.get("mesh_interval", "30"))
        mesh_port = int(prefs.get("mesh_port", "9378"))

        # Load or generate HMAC pre-shared key
        mesh_psk = load_or_create_psk()
        logger.info(
            "Mesh PSK loaded (fingerprint: %s)", get_psk_fingerprint(mesh_psk)
        )

        mesh_coord = MeshCoordinator(
            node_id="desktop",
            port=mesh_port,
            interval=mesh_interval,
            psk=mesh_psk,
        )

        # Wire escalation callback → audit log + WebSocket broadcast
        _ws_loop = asyncio.get_running_loop()

        def _mesh_phase_change(node_id, old_phase, new_phase, peer_state):
            if new_phase == EscalationPhase.NORMAL:
                evt = EventType.MESH_RECOVERY
                sev = EventSeverity.INFO
            else:
                evt = EventType.MESH_ESCALATION
                sev = EventSeverity.ALERT if new_phase in (
                    EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS
                ) else EventSeverity.INVESTIGATE
            get_audit_logger().log_event(
                event_type=evt,
                severity=sev,
                message=f"Mesh peer {node_id}: {old_phase.value} → {new_phase.value}",
                details={
                    "node_id": node_id,
                    "old_phase": old_phase.value,
                    "new_phase": new_phase.value,
                    "model_tier": new_phase.model_tier,
                    "missed_count": peer_state.missed_count,
                },
            )
            # Persist escalation phase to database
            try:
                from ..mesh.mesh_database import get_mesh_database
                get_mesh_database().update_peer_heartbeat(
                    node_id=node_id,
                    escalation_phase=new_phase.value,
                )
            except Exception:
                pass

            # Execute autonomous escalation actions (v0.3.37)
            try:
                from ..mesh.autonomous_escalation import get_escalation_handler
                handler = get_escalation_handler()
                handler.handle_phase_change(node_id, old_phase, new_phase, peer_state)
            except Exception:
                logger.debug("Autonomous escalation failed for %s", node_id, exc_info=True)

            # Broadcast peer alert to surviving nodes (v0.3.38)
            try:
                from ..mesh.peer_alerting import get_peer_alert_broadcaster
                broadcaster = get_peer_alert_broadcaster()
                if broadcaster:
                    all_peers = list(mesh_coord.state_manager.all_peers())
                    broadcaster.handle_phase_change(
                        node_id, old_phase, new_phase, peer_state,
                        all_peers=all_peers,
                    )
            except Exception:
                logger.debug("Peer alert broadcast failed for %s", node_id, exc_info=True)

            # Submit to escalation deduplicator (v0.3.43)
            try:
                from ..mesh.escalation_dedup import (
                    EscalationEvent, get_escalation_deduplicator,
                )
                dedup = get_escalation_deduplicator()
                if dedup and new_phase != EscalationPhase.NORMAL:
                    dedup.submit(EscalationEvent(
                        agent_id=node_id,
                        rule_id=f"mesh_escalation_{new_phase.value.lower()}",
                        event_type="mesh.escalation",
                        severity="high" if new_phase == EscalationPhase.AUTONOMOUS else "medium",
                        message=f"Peer {node_id}: {old_phase.value} → {new_phase.value}",
                        details={
                            "old_phase": old_phase.value,
                            "new_phase": new_phase.value,
                            "missed_count": peer_state.missed_count,
                        },
                    ))
            except Exception:
                logger.debug("Escalation dedup submit failed for %s", node_id, exc_info=True)

            # Secondary brain activation/deactivation (v0.3.39)
            try:
                from ..mesh.secondary_brain import get_secondary_brain_manager
                sb_mgr = get_secondary_brain_manager()
                sb_mgr.handle_phase_change(node_id, old_phase, new_phase, peer_state)
            except Exception:
                logger.debug("Secondary brain handler failed for %s", node_id, exc_info=True)

            # Broadcast to WebSocket clients
            try:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast({
                        "type": "mesh_phase_change",
                        "node_id": node_id,
                        "old_phase": old_phase.value,
                        "new_phase": new_phase.value,
                        "model_tier": new_phase.model_tier,
                        "missed_count": peer_state.missed_count,
                    }),
                    _ws_loop,
                )
            except Exception:
                pass

        mesh_coord.on_phase_change(_mesh_phase_change)

        # Load persisted peers
        for peer_row in mesh_db.list_peers():
            mesh_coord.add_peer(
                node_id=peer_row["node_id"],
                ip_address=peer_row["ip_address"],
                port=peer_row["port"],
                is_desktop=peer_row["is_desktop"],
                label=peer_row["label"],
            )

        mesh_coord.start()
        set_mesh_coordinator(mesh_coord)
        app.state.mesh_coordinator = mesh_coord

        # Initialize peer alert broadcaster (v0.3.38)
        try:
            from ..mesh.peer_alerting import PeerAlertBroadcaster, set_peer_alert_broadcaster
            broadcaster = PeerAlertBroadcaster(node_id="desktop", psk=mesh_psk)
            set_peer_alert_broadcaster(broadcaster)
        except Exception:
            logger.debug("Peer alert broadcaster failed to initialize", exc_info=True)

        # Initialize escalation deduplicator (v0.3.43)
        try:
            from ..mesh.escalation_dedup import (
                EscalationDeduplicator, set_escalation_deduplicator,
            )
            dedup = EscalationDeduplicator()
            dedup.start()
            set_escalation_deduplicator(dedup)
            app.state.escalation_dedup = dedup
        except Exception:
            logger.debug("Escalation deduplicator failed to initialize", exc_info=True)

    except Exception:
        logger.warning("Defense Mesh failed to start", exc_info=True)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    get_audit_logger().log_event(
        event_type=EventType.SYSTEM_STOP,
        severity=EventSeverity.INFO,
        message="Citadel Archer API server shutting down"
    )

    # Stop agent poller
    poller = getattr(app.state, "agent_poller", None)
    if poller:
        await poller.stop()

    # Stop Guardian escalation
    guardian_esc = getattr(app.state, "guardian_escalation", None)
    if guardian_esc:
        guardian_esc.stop()

    # Stop Remote Shield escalation
    remote_esc = getattr(app.state, "remote_shield_escalation", None)
    if remote_esc:
        remote_esc.stop()

    # Stop threshold engine
    threshold_engine = getattr(app.state, "threshold_engine", None)
    if threshold_engine:
        threshold_engine.stop()

    # Stop posture analyzer
    posture = getattr(app.state, "posture_analyzer", None)
    if posture:
        try:
            await posture.stop()
        except Exception:
            pass

    # Stop cross-asset correlator
    correlator = getattr(app.state, "cross_asset_correlator", None)
    if correlator:
        correlator.stop()

    # Stop intel aggregator
    intel_agg = getattr(app.state, "intel_aggregator", None)
    if intel_agg:
        intel_agg.stop()

    # Stop escalation deduplicator
    dedup = getattr(app.state, "escalation_dedup", None)
    if dedup:
        dedup.stop()

    # Stop Defense Mesh coordinator
    mesh_coord = getattr(app.state, "mesh_coordinator", None)
    if mesh_coord:
        mesh_coord.stop()

    # Stop extension watcher
    ext_watcher = getattr(app.state, "extension_watcher", None)
    if ext_watcher:
        ext_watcher.stop()

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
        return FileResponse(index_path, headers=_NO_CACHE)
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
        return FileResponse(index_path, headers=_NO_CACHE)
    else:
        return {"name": "Citadel Archer API", "version": "0.2.3", "status": "operational"}


@app.get("/assets.html")
async def serve_assets_page():
    """Serve Assets page."""
    path = FRONTEND_DIR / "assets.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Assets page not found")


@app.get("/assets-page")
async def serve_assets_page_redirect():
    """Redirect /assets-page to /assets.html"""
    path = FRONTEND_DIR / "assets.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Assets page not found")


@app.get("/risk-metrics.html")
async def serve_risk_metrics():
    """Serve Risk Metrics page."""
    path = FRONTEND_DIR / "risk-metrics.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Risk Metrics page not found")


@app.get("/risk-metrics")
async def serve_risk_metrics_redirect():
    """Redirect /risk-metrics to /risk-metrics.html"""
    path = FRONTEND_DIR / "risk-metrics.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Risk Metrics page not found")


@app.get("/timeline.html")
async def serve_timeline():
    """Serve Alert Timeline page."""
    timeline_path = FRONTEND_DIR / "timeline.html"
    if timeline_path.exists():
        return FileResponse(timeline_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Timeline page not found")


@app.get("/timeline")
async def serve_timeline_redirect():
    """Redirect /timeline to /timeline.html"""
    timeline_path = FRONTEND_DIR / "timeline.html"
    if timeline_path.exists():
        return FileResponse(timeline_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Timeline page not found")


@app.get("/charts.html")
async def serve_charts():
    """Serve Charts & Visualization page."""
    charts_path = FRONTEND_DIR / "charts.html"
    if charts_path.exists():
        return FileResponse(charts_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Charts page not found")


@app.get("/charts")
async def serve_charts_redirect():
    """Redirect /charts to /charts.html"""
    charts_path = FRONTEND_DIR / "charts.html"
    if charts_path.exists():
        return FileResponse(charts_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Charts page not found")


@app.get("/remote-shield.html")
async def serve_remote_shield():
    """Serve Remote Shield page."""
    path = FRONTEND_DIR / "remote-shield.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Remote Shield page not found")


@app.get("/remote-shield")
async def serve_remote_shield_redirect():
    """Redirect /remote-shield to /remote-shield.html"""
    path = FRONTEND_DIR / "remote-shield.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Remote Shield page not found")


@app.get("/panic-room.html")
async def serve_panic_room():
    """Serve Panic Room page."""
    path = FRONTEND_DIR / "panic-room.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Panic Room page not found")


@app.get("/panic-room")
async def serve_panic_room_redirect():
    """Redirect /panic-room to /panic-room.html"""
    path = FRONTEND_DIR / "panic-room.html"
    if path.exists():
        return FileResponse(path, headers=_NO_CACHE)
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
        return FileResponse(vault_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Vault page not found")


@app.get("/vault")
async def serve_vault_redirect():
    """Redirect /vault to /vault.html"""
    vault_path = FRONTEND_DIR / "vault.html"
    if vault_path.exists():
        return FileResponse(vault_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Vault page not found")


@app.get("/test-events.html")
async def serve_test_events():
    """Serve test-events.html for Developer Tools."""
    test_events_path = FRONTEND_DIR / "test-events.html"
    if test_events_path.exists():
        return FileResponse(test_events_path, headers=_NO_CACHE)
    else:
        raise HTTPException(status_code=404, detail="Test events page not found")


@app.get("/test-events")
async def serve_test_events_redirect():
    """Redirect /test-events to /test-events.html"""
    test_events_path = FRONTEND_DIR / "test-events.html"
    if test_events_path.exists():
        return FileResponse(test_events_path, headers=_NO_CACHE)
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


def _calculate_threat_level() -> str:
    """Calculate current threat level from recent audit events and VPS agent threats.

    Returns 'green', 'yellow', or 'red'.
    """
    critical_count = 0
    alert_count = 0

    # Local Guardian events (last hour from audit log)
    try:
        audit = get_audit_logger()
        one_hour_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
        recent = audit.query_events(start_time=one_hour_ago, limit=200)
        critical_count += sum(1 for e in recent if e.get("severity") == "critical")
        alert_count += sum(1 for e in recent if e.get("severity") == "alert")
    except Exception:
        pass

    # Open threats from VPS Shield agents (reported to RemoteShieldDatabase,
    # not to the local audit log — without this check, VPS critical threats
    # are invisible to the dashboard threat level).
    try:
        from ..remote.shield_database import RemoteShieldDatabase
        sdb = RemoteShieldDatabase()
        open_threats = sdb.list_threats(status="open", limit=100)
        for t in open_threats:
            sev = t.get("severity", 0)
            if sev >= 9:
                critical_count += 1
            elif sev >= 7:
                alert_count += 1
    except Exception:
        pass

    if critical_count >= 1:
        return "red"
    if alert_count >= 3:
        return "red"
    if alert_count >= 1:
        return "yellow"
    return "green"


def _format_uptime() -> str:
    """Format server uptime as a human-readable string."""
    if _server_start_time is None:
        return "0h 0m"
    delta = datetime.now(timezone.utc) - _server_start_time
    total_seconds = int(delta.total_seconds())
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"


@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """
    Get current system status.

    PRD: "Shows Guardian status, real-time threat level, security level"
    """
    security_manager = get_security_manager()

    # Calculate threat level from recent events
    threat_level = _calculate_threat_level()

    # Calculate uptime
    uptime = _format_uptime()

    return SystemStatus(
        guardian_active=file_monitor.is_running if file_monitor else False,
        security_level=security_manager.current_level.value,
        threat_level=threat_level,
        monitored_paths=file_monitor.get_monitored_paths() if file_monitor else [],
        uptime=uptime,
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
async def get_recent_events(
    limit: int = 50,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
):
    """
    Get recent security events.

    PRD: "Log viewer in Dashboard"
    """
    from ..core.audit_log import get_audit_logger, EventType, EventSeverity

    logger = get_audit_logger()

    # Build filter params
    event_types = None
    if event_type:
        try:
            event_types = [EventType(event_type)]
        except ValueError:
            pass

    sev = None
    if severity:
        try:
            sev = EventSeverity(severity)
        except ValueError:
            pass

    raw_events = logger.query_events(
        event_types=event_types,
        severity=sev,
        limit=limit,
    )

    return [
        EventInfo(
            event_id=e.get("event_id", ""),
            event_type=e.get("event_type", ""),
            severity=e.get("severity", "info"),
            message=e.get("message", ""),
            timestamp=e.get("timestamp", ""),
        )
        for e in raw_events
    ]


@app.post("/api/guardian/start")
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


@app.post("/api/guardian/stop")
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


# Desktop heartbeat — frontend pings this to signal the window is open
_last_heartbeat = None

@app.post("/api/heartbeat")
async def heartbeat():
    global _last_heartbeat
    _last_heartbeat = datetime.now(timezone.utc)
    return {"ok": True}

def get_last_heartbeat():
    return _last_heartbeat

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

    # Evict alerts older than 24 hours to bound memory
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_str = cutoff.isoformat()
    alerts_storage[:] = [
        a for a in alerts_storage
        if a.created_at.replace('Z', '+00:00') >= cutoff_str
    ]
    
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
