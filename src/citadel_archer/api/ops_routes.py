# Citadel Archer — Ops Center API
#
# Three endpoints that back the Ops Center HMI tab (frontend/js/ops-center.js):
#
#   WebSocket  /ws/ops               — real-time event + metrics push stream
#   GET        /api/ops/metrics      — current metrics snapshot (pre-populate bars)
#   GET        /api/ops/events       — recent event history (pre-populate log)
#
# Data sources:
#   - REMOTE_THREAT events in the audit log (citadel_daemon: auth, proc, cron, file)
#   - REMOTE_PATCH  events in the audit log (citadel_daemon: pending package updates)
#
# Wire-up in main.py:
#   from .ops_routes import router as ops_router, audit_ops_callback
#   app.include_router(ops_router)
#   # in startup_event:
#   audit_logger.on_event(audit_ops_callback)

import asyncio
import logging
import re
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Module-level state ─────────────────────────────────────────────────────

# Latest known resource metrics per node (agent_id → metrics).
# Auto-creates entries for any agent that sends metrics — no hardcoded list.
_node_metrics: dict = defaultdict(lambda: {"cpu": 0.0, "mem": 0.0, "dsk": 0.0, "patches": 0})

# Per-WS-client fan-out queues.  Each connected client has its own queue;
# audit_ops_callback puts messages into all of them (put_nowait — non-blocking).
_client_queues: set = set()

# ── Node resolution ────────────────────────────────────────────────────────

def _resolve_node(hostname: str, ip: str = "") -> Optional[str]:
    """Map a daemon hostname or Tailscale IP to the corresponding agent_id.

    Queries the live agent registry — no hardcoded IP or hostname maps.
    Tries hostname substring-match first, IP exact-match as fallback.
    Returns None if the machine isn't a registered agent.
    """
    try:
        from .agent_api_routes import get_agent_registry
        agents = get_agent_registry().list_agents()
        h = (hostname or "").lower()
        for agent in agents:
            ah = (agent.get("hostname") or "").lower()
            if ah and h and (ah in h or h in ah):
                return agent["agent_id"]
        if ip:
            for agent in agents:
                if agent.get("ip_address") == ip:
                    return agent["agent_id"]
    except Exception:
        pass
    return None


def _node_for_agent(agent_id: str) -> Optional[str]:
    """Return agent_id if it's a registered agent, else None.

    Called when _resolve_node() fails (e.g., audit entry has agent_id but
    no hostname). Because the agent_id IS the node_id, we just verify it exists.
    """
    try:
        from .agent_api_routes import get_agent_registry
        if get_agent_registry().get_agent(agent_id):
            return agent_id
    except Exception:
        pass
    return None

# ── Event / alarm / severity mappings ─────────────────────────────────────

# daemon threat_type → ops-center alarm tile ID
# Note: config_change is used by both cron-tamper and disk-usage events.
# Disk events are re-mapped to al-res inside _audit_to_ops_event() by
# inspecting the message text.
_THREAT_ALARM: dict = {
    "brute_force_attempt": "al-ssh",
    "unauthorized_access":  "al-ssh",   # sudo abuse — auth-related
    "file_integrity":       "al-file",
    "config_change":        "al-proc",  # cron tamper (disk gets re-mapped below)
    "suspicious_process":   "al-proc",
    "process_anomaly":      "al-res",   # high CPU / mem
    "port_scan_anomaly":    "al-proc",  # suspicious listener on backdoor port
}

# audit EventSeverity → ops-center severity label
_SEV_MAP: dict = {
    "critical":    "CRIT",
    "alert":       "HIGH",
    "investigate": "WARN",
    "info":        "INFO",
}

# ── Audit-entry translators ────────────────────────────────────────────────

def _audit_to_ops_event(entry: dict, node_id: str) -> Optional[dict]:
    """Translate an audit-log entry to an ops-center event payload.

    node_id must already be resolved by the caller (audit_ops_callback
    resolves once and shares it to avoid double DB lookups).
    Returns None if the entry isn't relevant to the Ops Center.
    """
    event_type = entry.get("event_type", "")
    if event_type not in ("remote.threat", "remote.patch"):
        return None

    details  = entry.get("details", {})
    hostname = details.get("hostname", "")
    ui_sev   = _SEV_MAP.get(entry.get("severity", "info"), "INFO")

    # Strip the "[daemon:hostname] " prefix that log_security_event prepends
    msg = entry.get("message", "")
    if hostname:
        msg = msg.replace(f"[daemon:{hostname}] ", "")

    if event_type == "remote.patch":
        alarm     = "al-patch"
        is_attack = False
    else:
        threat_type = details.get("threat_type", "")
        alarm       = _THREAT_ALARM.get(threat_type, "al-proc")
        is_attack   = threat_type in ("brute_force_attempt", "unauthorized_access")

        # Daemon uses config_change for both cron tamper and disk events.
        # Disk events belong on the resource alarm tile, not process.
        if threat_type == "config_change" and "disk" in msg.lower():
            alarm = "al-res"

    event: dict = {
        "sev":      ui_sev,
        "nodeId":   node_id,
        "msg":      msg[:120],
        "alarm":    alarm,
        "isAttack": is_attack,
        "isCrit":   ui_sev == "CRIT",
    }

    # Extract attacker IP from raw detail for SSH brute-force events
    if is_attack:
        raw = details.get("raw_detail", "")
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", raw)
        if m:
            event["ip"] = m.group(1)
        event["country"] = "???"  # GeoIP not implemented

    ts = entry.get("timestamp", "")
    if len(ts) >= 19:
        event["time"] = ts[11:19]

    return event


def _try_update_metrics(entry: dict, node_id: str) -> Optional[dict]:
    """If this audit entry carries resource data, update _node_metrics and
    return a 'metrics' WS message.  Otherwise return None.

    node_id must already be resolved by the caller.

    Handles:
    - REMOTE_PATCH  events  → updates patches count
    - REMOTE_THREAT with threat_type 'process_anomaly' OR 'config_change'
      (daemon uses config_change for disk-usage alerts) → updates cpu/mem/dsk
    """
    event_type  = entry.get("event_type", "")
    details     = entry.get("details", {})

    # ── Patch count ──
    if event_type == "remote.patch":
        _node_metrics[node_id]["patches"] = int(details.get("pending_count", 0))
        return {"type": "metrics", "nodeId": node_id, **_node_metrics[node_id]}

    # ── Resource sensor: process_anomaly (CPU/mem) or config_change (disk) ──
    threat_type = details.get("threat_type", "")
    if threat_type not in ("process_anomaly", "config_change"):
        return None

    # Parse raw detail string from citadel_daemon.py resource sensor:
    #   "High load average: 4.5 (4 CPUs, threshold 8)"
    #   "High memory usage: 87% (250MB available of 2000MB)"
    #   "Disk usage critical: 91% on /"       ← config_change threat_type
    raw = (details.get("raw_detail") or entry.get("message", "")).lower()

    key = ""
    pct = 0.0

    if "high load" in raw or "load average" in raw:
        # Convert load/cpus to a 0-100 CPU-equivalent percentage
        m = re.search(r":\s*([\d.]+)\s*\((\d+)\s*cpu", raw)
        if m:
            pct = min(100.0, float(m.group(1)) / int(m.group(2)) * 100.0)
        key = "cpu"
    elif "memory" in raw:
        m = re.search(r":\s*([\d.]+)\s*%", raw)
        if m:
            pct = float(m.group(1))
        key = "mem"
    elif "disk" in raw:
        m = re.search(r":\s*([\d.]+)\s*%", raw)
        if m:
            pct = float(m.group(1))
        key = "dsk"

    if key:
        _node_metrics[node_id][key] = round(pct, 1)
        return {"type": "metrics", "nodeId": node_id, **_node_metrics[node_id]}

    return None

# ── Audit callback (synchronous — runs in event-loop thread) ──────────────

def audit_ops_callback(entry: dict) -> None:
    """Registered with AuditLogger.on_event() at startup.

    Called synchronously every time log_security_event() fires.  Because
    log_security_event is called from async FastAPI route handlers, this
    callback runs in the asyncio event-loop thread — making
    asyncio.Queue.put_nowait() safe to call without await.

    Node resolution is performed once here and shared between the metrics
    and event translators to avoid double SQLite lookups per event.

    Fanout strategy: one asyncio.Queue per connected WS client.
    """
    event_type = entry.get("event_type", "")
    if event_type not in ("remote.threat", "remote.patch"):
        return

    details  = entry.get("details", {})
    if details.get("source") != "citadel_daemon":
        return

    # Resolve node once — shared by both translators below
    hostname = details.get("hostname", "")
    agent_id = details.get("agent_id", "")
    node_id  = _resolve_node(hostname) or (agent_id and _node_for_agent(agent_id))
    if not node_id:
        return

    msgs: list = []

    metrics_msg = _try_update_metrics(entry, node_id)
    if metrics_msg:
        msgs.append(metrics_msg)

    ops_event = _audit_to_ops_event(entry, node_id)
    if ops_event:
        msgs.append({"type": "event", **ops_event})

    if msgs:
        for msg in msgs:
            for q in list(_client_queues):
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    pass  # Slow client — drop rather than block

# ── REST: GET /api/ops/topology ───────────────────────────────────────────

_SHIELD_AGENT_TYPES = {"vps", "workstation", "cloud"}

@router.get("/api/ops/topology")
async def get_ops_topology(_token: str = Depends(verify_session_token)) -> list:
    """Return enrolled Shield agents as topology nodes for the Ops Center canvas.

    Fetched by the frontend on every tab activation so newly-enrolled agents
    appear without a page reload.  Only active Shield-type agents (vps,
    workstation, cloud) are included — AI agents (claude_code, forge) are
    excluded.

    Positions are evenly spaced across the canvas width (col 0.20–0.80).
    Colors: green for VPS/cloud, blue for workstation.
    """
    try:
        from .agent_api_routes import get_agent_registry
        all_agents = get_agent_registry().list_agents()
    except Exception:
        all_agents = []

    active = [
        a for a in all_agents
        if a.get("status") == "active"
        and a.get("agent_type") in _SHIELD_AGENT_TYPES
    ]

    n = len(active)
    nodes = []
    for i, agent in enumerate(active):
        agent_type = agent.get("agent_type", "vps")
        color = "#00D9FF" if agent_type == "workstation" else "#00CC66"
        col = (0.20 + (0.60 / max(n - 1, 1)) * i) if n > 1 else 0.50
        nodes.append({
            "id":    agent["agent_id"],
            "label": (agent.get("name") or "AGENT").upper(),
            "sub":   agent.get("hostname") or "",
            "os":    "",
            "col":   round(col, 3),
            "row":   0.40,
            "color": color,
            "ts":    agent.get("ip_address") or "",
        })

    return nodes


# ── REST: GET /api/ops/metrics ─────────────────────────────────────────────

@router.get("/api/ops/metrics")
async def get_ops_metrics(_token: str = Depends(verify_session_token)) -> dict:
    """Return current resource metrics for all three nodes.

    Called once on Ops Center tab activation to pre-populate the canvas
    bar graphs before the WebSocket stream delivers live updates.
    Values are 0 until the first daemon report arrives.
    """
    return {nid: dict(m) for nid, m in _node_metrics.items()}

# ── REST: GET /api/ops/events ──────────────────────────────────────────────

@router.get("/api/ops/events")
async def get_ops_events(limit: int = 40, _token: str = Depends(verify_session_token)) -> list:
    """Return recent security events, newest-first.

    Populates the CRIT event log and alarm annunciator with history before
    the WebSocket stream catches up on tab activation.
    """
    from ..core.audit_log import get_audit_logger, EventType

    audit = get_audit_logger()
    raw   = audit.query_events(
        event_types=[EventType.REMOTE_THREAT, EventType.REMOTE_PATCH],
        limit=limit * 4,   # over-read to compensate for filter losses
    )

    events: list = []
    for entry in raw:
        details  = entry.get("details", {})
        if details.get("source") != "citadel_daemon":
            continue
        hostname = details.get("hostname", "")
        agent_id = details.get("agent_id", "")
        node_id  = _resolve_node(hostname) or (agent_id and _node_for_agent(agent_id))
        if not node_id:
            continue
        evt = _audit_to_ops_event(entry, node_id)
        if evt:
            events.append(evt)
            if len(events) >= limit:
                break

    return events

# ── WebSocket: /ws/ops ─────────────────────────────────────────────────────

@router.websocket("/ws/ops")
async def ops_websocket(ws: WebSocket) -> None:
    """Real-time Ops Center push stream.

    Message types pushed to the client:
      {"type": "event",       "sev":..., "nodeId":..., "msg":..., ...}
      {"type": "metrics",     "nodeId":..., "cpu":..., "mem":..., ...}
      {"type": "node_status", "nodeId":..., "status": "ok"|"warn"|...}

    Client → server: "ping" → server replies "pong" (keepalive).

    Connection lifecycle:
    - On connect: immediately pushes current _node_metrics for all nodes
    - On each audit event: audit_ops_callback puts messages in this client's queue
    - On disconnect: client queue is removed from _client_queues

    WS loop design:
    - Two tasks race per iteration: ws.receive_text() vs queue.get()
    - asyncio.wait(FIRST_COMPLETED) handles whichever arrives first
    - Both tasks are checked and handled if both completed in the same tick
    - A send failure breaks the loop immediately (client is gone)
    - Pending tasks are cancelled only after both done tasks are handled
    """
    await ws.accept()

    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    _client_queues.add(queue)

    try:
        # Seed with current metrics so bars appear immediately, not after first event
        for nid, m in _node_metrics.items():
            await ws.send_json({"type": "metrics", "nodeId": nid, **m})

        while True:
            recv_task  = asyncio.create_task(ws.receive_text())
            queue_task = asyncio.create_task(queue.get())

            done, pending = await asyncio.wait(
                {recv_task, queue_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Handle ALL tasks that completed this tick (both can finish together).
            # Process recv first so a disconnect breaks the loop before any send.
            if recv_task in done:
                try:
                    text = recv_task.result()
                    if text == "ping":
                        await ws.send_text("pong")
                except Exception:
                    # WebSocketDisconnect or client gone — cancel sibling and exit
                    for t in pending:
                        t.cancel()
                    break

            if queue_task in done:
                try:
                    msg = queue_task.result()
                    await ws.send_json(msg)
                except Exception:
                    # Send failed — client is gone
                    for t in pending:
                        t.cancel()
                    break

            # Cancel tasks that didn't win the race this iteration
            for t in pending:
                t.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ops WS error: %s", exc)
    finally:
        _client_queues.discard(queue)
