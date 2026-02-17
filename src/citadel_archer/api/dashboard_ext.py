# PRD: Dashboard Backend Extensions - Phase 2 Endpoints
# Reference: PHASE_2_SPEC.md
#
# Extends the Phase 1 FastAPI dashboard with:
#   /api/charts            - Threat trend data for charting
#   /api/timeline          - Alert history timeline (local only)
#   /api/timeline/unified  - Unified timeline (local + remote-shield + correlations)
#   /api/threat-score      - Risk metric summary from ThreatScorer
#   /api/asset-view        - Multi-asset inventory view (enriched with event counts)
#
# Also provides a dedicated /ws/events WebSocket for real-time
# event streaming and a 5-minute TTL cache for expensive queries.

import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from .security import verify_session_token

# ---------------------------------------------------------------------------
# Caching layer (5-minute TTL)
# ---------------------------------------------------------------------------

class _CacheEntry:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.expires_at = time.monotonic() + ttl


class TTLCache:
    """Thread-safe in-memory cache with per-key TTL (seconds)."""

    def __init__(self, default_ttl: float = 300.0):
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
        self._store: Dict[str, _CacheEntry] = {}

    def get(self, key: str) -> Any:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if time.monotonic() > entry.expires_at:
                del self._store[key]
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            self._store[key] = _CacheEntry(value, ttl or self._default_ttl)

    def invalidate(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    @property
    def size(self) -> int:
        with self._lock:
            # Purge expired while counting
            now = time.monotonic()
            expired = [k for k, v in self._store.items() if now > v.expires_at]
            for k in expired:
                del self._store[k]
            return len(self._store)


# Module-level cache instance (shared across requests)
cache = TTLCache(default_ttl=300.0)

# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------

class ThreatTrendPoint(BaseModel):
    timestamp: str
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0
    total: int = 0


class ChartResponse(BaseModel):
    period: str
    points: List[ThreatTrendPoint]
    generated_at: str


class TimelineEntry(BaseModel):
    event_id: str
    event_type: str
    severity: str
    message: str
    asset_id: str
    timestamp: str
    category: str


class TimelineResponse(BaseModel):
    entries: List[TimelineEntry]
    total: int
    generated_at: str


class UnifiedTimelineEntry(BaseModel):
    event_id: str
    event_type: str
    severity: str  # normalized: info|investigate|alert|critical
    message: str
    asset_id: str
    timestamp: str
    category: str
    source: str  # local | remote-shield | correlation
    source_detail: Optional[dict] = None


class UnifiedTimelineResponse(BaseModel):
    entries: List[UnifiedTimelineEntry]
    total: int
    stats: dict
    generated_at: str


# ---------------------------------------------------------------------------
# Severity normalization helpers
# ---------------------------------------------------------------------------

def _normalize_remote_severity(score: int) -> str:
    """Map remote shield 1-10 integer severity to 4-level string."""
    if score >= 8:
        return "critical"
    if score >= 6:
        return "alert"
    if score >= 4:
        return "investigate"
    return "info"


_CORRELATION_SEV_MAP = {"low": "info", "medium": "investigate", "high": "alert", "critical": "critical"}


def _normalize_correlation_severity(level: str) -> str:
    """Map correlation severity string to 4-level string."""
    return _CORRELATION_SEV_MAP.get(level.lower(), "investigate")


class ThreatScoreResponse(BaseModel):
    total_scored: int
    by_risk_level: Dict[str, int]
    recent_critical: int
    recent_high: int
    top_threats: List[Dict[str, Any]]
    generated_at: str


class AssetView(BaseModel):
    asset_id: str
    name: str
    platform: str
    status: str
    hostname: str
    ip_address: str
    guardian_active: bool
    event_count: int
    last_seen: str


class AssetsResponse(BaseModel):
    assets: List[AssetView]
    total: int
    by_status: Dict[str, int]
    generated_at: str


# ---------------------------------------------------------------------------
# Service layer — bridges API to Intel module singletons
# ---------------------------------------------------------------------------

class DashboardServices:
    """Holds references to Intel module components.

    The API layer calls methods on this object rather than importing
    Intel singletons directly, making testing and dependency injection
    straightforward.
    """

    def __init__(self):
        self.event_aggregator = None   # EventAggregator
        self.threat_scorer = None      # ThreatScorer
        self.asset_inventory = None    # AssetInventory
        self.anomaly_detector = None   # AnomalyDetector
        self.guardian_updater = None   # GuardianUpdater
        self.ssh_manager = None        # SSHConnectionManager
        self.shield_db = None          # RemoteShieldDatabase
        self.vault = None              # VaultManager
        self.chat_manager = None       # ChatManager
        self._correlator = None        # CrossAssetCorrelator
        self._extension_scanner = None # ExtensionScanner
        self._extension_watcher = None # ExtensionWatcher
        self._extension_intel = None   # ExtensionIntelDatabase
        self._ai_bridge = None         # AIBridge

    def get(self, key: str, default=None):
        """Dict-like access for service lookup by route modules."""
        return getattr(self, key, default)

    # -- Charts (threat trends) -------------------------------------------

    def get_chart_data(
        self, hours: int = 24, bucket_hours: int = 1
    ) -> ChartResponse:
        cache_key = f"charts:{hours}:{bucket_hours}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        now = datetime.utcnow()
        points: List[ThreatTrendPoint] = []

        if self.event_aggregator is not None:
            cutoff = (now - timedelta(hours=hours)).isoformat()
            events = self.event_aggregator.since(cutoff)
        else:
            events = []

        # Bucket events by hour (include current hour)
        buckets: Dict[str, Dict[str, int]] = {}
        for i in range(0, hours + bucket_hours, bucket_hours):
            bucket_start = now - timedelta(hours=hours - i)
            key = bucket_start.strftime("%Y-%m-%dT%H:00:00")
            buckets[key] = {"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}

        for evt in events:
            try:
                ts = datetime.fromisoformat(evt.timestamp)
            except (ValueError, TypeError):
                continue
            key = ts.strftime("%Y-%m-%dT%H:00:00")
            if key in buckets:
                sev = evt.severity.lower()
                if sev in ("info", "investigate"):
                    buckets[key]["low"] += 1
                elif sev == "alert":
                    buckets[key]["medium"] += 1
                elif sev == "critical":
                    buckets[key]["critical"] += 1
                else:
                    buckets[key]["low"] += 1
                buckets[key]["total"] += 1

        for ts_key in sorted(buckets.keys()):
            b = buckets[ts_key]
            points.append(ThreatTrendPoint(timestamp=ts_key, **b))

        result = ChartResponse(
            period=f"{hours}h",
            points=points,
            generated_at=now.isoformat(),
        )
        cache.set(cache_key, result)
        return result

    # -- Timeline (alert history) -----------------------------------------

    def get_timeline(
        self, limit: int = 100, severity: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> TimelineResponse:
        cache_key = f"timeline:{limit}:{severity}:{asset_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        entries: List[TimelineEntry] = []
        if self.event_aggregator is None:
            result = TimelineResponse(
                entries=[], total=0,
                generated_at=datetime.utcnow().isoformat(),
            )
            cache.set(cache_key, result)
            return result

        events = self.event_aggregator.recent(limit=limit * 2)

        if severity:
            events = [e for e in events if e.severity.lower() == severity.lower()]
        if asset_id:
            events = [e for e in events if e.asset_id == asset_id]

        for evt in events[-limit:]:
            entries.append(TimelineEntry(
                event_id=evt.event_id,
                event_type=evt.event_type,
                severity=evt.severity,
                message=evt.message,
                asset_id=evt.asset_id or "",
                timestamp=evt.timestamp,
                category=evt.category.value,
            ))

        result = TimelineResponse(
            entries=entries,
            total=len(entries),
            generated_at=datetime.utcnow().isoformat(),
        )
        cache.set(cache_key, result)
        return result

    # -- Unified timeline (all sources) -----------------------------------

    def get_unified_timeline(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        asset_id: Optional[str] = None,
        source: Optional[str] = None,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
    ) -> UnifiedTimelineResponse:
        # Normalize empty strings to None for consistent cache keys
        severity = severity or None
        asset_id = asset_id or None
        source = source or None
        time_from = time_from or None
        time_to = time_to or None

        cache_key = f"unified:{limit}:{severity}:{asset_id}:{source}:{time_from}:{time_to}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        merged: List[UnifiedTimelineEntry] = []

        # 1. Local events from EventAggregator
        if self.event_aggregator is not None and source in (None, "", "local"):
            for evt in self.event_aggregator.recent(limit=limit * 2):
                merged.append(UnifiedTimelineEntry(
                    event_id=evt.event_id,
                    event_type=evt.event_type,
                    severity=evt.severity,
                    message=evt.message,
                    asset_id=evt.asset_id or "",
                    timestamp=evt.timestamp,
                    category=evt.category.value,
                    source="local",
                ))

        # 2. Remote Shield threats
        if self.shield_db is not None and source in (None, "", "remote-shield"):
            threats = self.shield_db.list_threats(limit=limit)
            for t in threats:
                norm_sev = _normalize_remote_severity(t.get("severity", 5))
                merged.append(UnifiedTimelineEntry(
                    event_id=t["id"],
                    event_type=t.get("type", "unknown"),
                    severity=norm_sev,
                    message=t.get("title", ""),
                    asset_id=t.get("agent_id", ""),
                    timestamp=t.get("detected_at") or t.get("reported_at") or t.get("created_at", ""),
                    category="remote",
                    source="remote-shield",
                    source_detail={
                        "original_severity": t.get("severity"),
                        "agent_id": t.get("agent_id"),
                        "hostname": t.get("hostname"),
                        "status": t.get("status"),
                    },
                ))

        # 3. Cross-asset correlations
        if self._correlator is not None and source in (None, "", "correlation"):
            try:
                corrs = self._correlator.recent_correlations(limit=limit)
            except Exception:
                corrs = []
            for c in corrs:
                norm_sev = _normalize_correlation_severity(c.get("severity", "medium"))
                merged.append(UnifiedTimelineEntry(
                    event_id=c.get("correlation_id", ""),
                    event_type=c.get("correlation_type", "correlation"),
                    severity=norm_sev,
                    message=c.get("description", "Cross-system correlation detected"),
                    asset_id=",".join(c.get("affected_assets", [])),
                    timestamp=c.get("last_seen") or c.get("first_seen", ""),
                    category="correlation",
                    source="correlation",
                    source_detail={
                        "original_severity": c.get("severity"),
                        "correlation_type": c.get("correlation_type"),
                        "affected_assets": c.get("affected_assets", []),
                        "indicator": c.get("indicator", ""),
                        "event_count": c.get("event_count", 0),
                    },
                ))

        # Apply filters
        if severity:
            merged = [e for e in merged if e.severity.lower() == severity.lower()]
        if asset_id:
            # Substring match supports correlation entries with comma-joined asset IDs
            merged = [e for e in merged if asset_id in e.asset_id.split(",")]

        def _norm_ts(ts: str) -> str:
            """Strip timezone suffixes for safe string comparison."""
            return ts.replace("Z", "").split("+")[0]

        if time_from:
            nf = _norm_ts(time_from)
            merged = [e for e in merged if _norm_ts(e.timestamp) >= nf]
        if time_to:
            nt = _norm_ts(time_to)
            merged = [e for e in merged if _norm_ts(e.timestamp) <= nt]

        # Sort by timestamp descending (normalise for consistent ordering)
        merged.sort(key=lambda e: _norm_ts(e.timestamp), reverse=True)

        # Compute stats before slicing
        sev_counts = {"info": 0, "investigate": 0, "alert": 0, "critical": 0}
        source_counts = {"local": 0, "remote-shield": 0, "correlation": 0}
        for e in merged:
            sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1
            source_counts[e.source] = source_counts.get(e.source, 0) + 1

        # Slice to limit
        entries = merged[:limit]

        result = UnifiedTimelineResponse(
            entries=entries,
            total=len(merged),
            stats={
                "local_count": source_counts.get("local", 0),
                "remote_count": source_counts.get("remote-shield", 0),
                "correlation_count": source_counts.get("correlation", 0),
                "by_severity": sev_counts,
            },
            generated_at=datetime.utcnow().isoformat(),
        )
        cache.set(cache_key, result, ttl=30.0)  # shorter TTL for real-time feel
        return result

    # -- Threat score (risk metrics) --------------------------------------

    def get_threat_score(self) -> ThreatScoreResponse:
        cached = cache.get("threat_score")
        if cached is not None:
            return cached

        if self.threat_scorer is None:
            result = ThreatScoreResponse(
                total_scored=0, by_risk_level={},
                recent_critical=0, recent_high=0,
                top_threats=[],
                generated_at=datetime.utcnow().isoformat(),
            )
            cache.set("threat_score", result)
            return result

        stats = self.threat_scorer.stats()

        # Gather recent high-severity events for top threats
        top_threats: List[Dict[str, Any]] = []
        if self.event_aggregator is not None:
            recent = self.event_aggregator.by_severity("critical")[-5:]
            recent += self.event_aggregator.by_severity("alert")[-5:]
            scored = self.threat_scorer.score_batch(recent)
            for t in scored[:10]:
                top_threats.append({
                    "event_type": t.event_type,
                    "risk_level": t.risk_level.value,
                    "risk_score": t.risk_score,
                    "asset_id": t.asset_id,
                    "timestamp": t.timestamp,
                })

        by_risk = stats.get("by_risk_level", {})
        result = ThreatScoreResponse(
            total_scored=stats.get("total_scored", 0),
            by_risk_level=by_risk,
            recent_critical=by_risk.get("critical", 0),
            recent_high=by_risk.get("high", 0),
            top_threats=top_threats,
            generated_at=datetime.utcnow().isoformat(),
        )
        cache.set("threat_score", result)
        return result

    # -- Assets (multi-asset view) ----------------------------------------

    def get_assets(
        self, status_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
    ) -> AssetsResponse:
        cache_key = f"assets:{status_filter}:{platform_filter}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        if self.asset_inventory is None:
            result = AssetsResponse(
                assets=[], total=0, by_status={},
                generated_at=datetime.utcnow().isoformat(),
            )
            cache.set(cache_key, result)
            return result

        all_assets = self.asset_inventory.all()

        if status_filter:
            all_assets = [a for a in all_assets if a.status.value == status_filter]
        if platform_filter:
            all_assets = [a for a in all_assets if a.platform.value == platform_filter]

        views: List[AssetView] = []
        for a in all_assets:
            event_count = 0
            if self.event_aggregator is not None:
                event_count = len(self.event_aggregator.by_asset(a.asset_id))
            views.append(AssetView(
                asset_id=a.asset_id,
                name=a.name,
                platform=a.platform.value,
                status=a.status.value,
                hostname=a.hostname,
                ip_address=a.ip_address,
                guardian_active=a.guardian_active,
                event_count=event_count,
                last_seen=a.last_seen,
            ))

        inv_stats = self.asset_inventory.stats()
        result = AssetsResponse(
            assets=views,
            total=len(views),
            by_status=inv_stats.get("by_status", {}),
            generated_at=datetime.utcnow().isoformat(),
        )
        cache.set(cache_key, result)
        return result


# Module-level services instance
services = DashboardServices()


# ---------------------------------------------------------------------------
# WebSocket event broadcaster
# ---------------------------------------------------------------------------

class EventBroadcaster:
    """Manages WebSocket connections for real-time event streaming.

    Separate from the main ``ConnectionManager`` in ``main.py`` so
    Phase 2 event streams don't interfere with Phase 1 broadcast.
    """

    def __init__(self):
        self._connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        with self._lock:
            self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    @property
    def connection_count(self) -> int:
        with self._lock:
            return len(self._connections)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        dead: List[WebSocket] = []
        with self._lock:
            connections = list(self._connections)
        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            with self._lock:
                for ws in dead:
                    if ws in self._connections:
                        self._connections.remove(ws)


broadcaster = EventBroadcaster()


# ---------------------------------------------------------------------------
# Router definition
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api", tags=["dashboard-ext"])


@router.get("/charts", response_model=ChartResponse)
async def get_charts(
    hours: int = Query(24, ge=1, le=168),
    bucket_hours: int = Query(1, ge=1, le=24),
    _token: str = Depends(verify_session_token),
):
    """Threat trend data bucketed by hour for charting."""
    return services.get_chart_data(hours=hours, bucket_hours=bucket_hours)


@router.get("/timeline", response_model=TimelineResponse)
async def get_timeline(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    _token: str = Depends(verify_session_token),
):
    """Alert history timeline with optional severity/asset filtering."""
    return services.get_timeline(limit=limit, severity=severity, asset_id=asset_id)


@router.get("/timeline/unified", response_model=UnifiedTimelineResponse)
async def get_unified_timeline(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    _token: str = Depends(verify_session_token),
):
    """Unified threat timeline merging local, remote-shield, and correlation events."""
    return services.get_unified_timeline(
        limit=limit,
        severity=severity,
        asset_id=asset_id,
        source=source,
        time_from=time_from,
        time_to=time_to,
    )


@router.get("/threat-score", response_model=ThreatScoreResponse)
async def get_threat_score(
    _token: str = Depends(verify_session_token),
):
    """Risk metric summary from the ThreatScorer."""
    return services.get_threat_score()


@router.get("/asset-view", response_model=AssetsResponse)
async def get_asset_view(
    status: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    _token: str = Depends(verify_session_token),
):
    """Multi-asset inventory view enriched with event counts.

    Note: For CRUD operations, use /api/assets (asset_routes).
    """
    return services.get_assets(status_filter=status, platform_filter=platform)


@router.get("/cache/stats")
async def get_cache_stats(
    _token: str = Depends(verify_session_token),
):
    """Cache statistics for monitoring."""
    return {"size": cache.size, "default_ttl": cache._default_ttl}


@router.post("/cache/clear")
async def clear_cache(
    _token: str = Depends(verify_session_token),
):
    """Invalidate all cached responses."""
    n = cache.clear()
    return {"cleared": n}


@router.get("/correlations")
async def get_correlations(
    limit: int = Query(20, ge=1, le=100),
    _token: str = Depends(verify_session_token),
):
    """Return recent cross-asset threat correlations."""
    try:
        correlator = services._correlator
        if correlator is None:
            return {"correlations": [], "stats": {}, "total": 0}
        correlations = correlator.recent_correlations(limit=limit)
        return {
            "correlations": correlations,
            "stats": correlator.stats(),
            "total": len(correlations),
        }
    except Exception:
        return {"correlations": [], "stats": {}, "total": 0}


@router.get("/correlation-stats")
async def get_correlation_stats(
    _token: str = Depends(verify_session_token),
):
    """Return cross-asset correlation engine statistics."""
    correlator = getattr(services, "_correlator", None)
    if correlator is None:
        return {"running": False, "indicator_count": 0, "tracked_assets": 0}
    return correlator.stats()


@router.get("/extensions")
async def get_extensions(
    _token: str = Depends(verify_session_token),
):
    """Return the most recent browser extension scan results."""
    scanner = services._extension_scanner
    if scanner is None:
        return {"extensions": [], "total": 0, "flagged": 0, "by_risk": {}, "by_browser": {}}
    result = scanner.last_scan
    if result is None:
        return {"extensions": [], "total": 0, "flagged": 0, "by_risk": {}, "by_browser": {}}
    return result.to_dict()


@router.post("/extensions/scan")
async def trigger_extension_scan(
    _token: str = Depends(verify_session_token),
):
    """Trigger a fresh browser extension scan."""
    import asyncio
    scanner = services._extension_scanner
    if scanner is None:
        return {"error": "Extension scanner not initialized", "total": 0}
    result = await asyncio.to_thread(scanner.scan_all)

    # Update watcher's known set after rescan
    watcher = services._extension_watcher
    if watcher:
        watcher.set_known_extensions(
            {e.extension_id for e in result.extensions}
        )

    return result.to_dict()


@router.get("/extensions/intel")
async def get_extension_intel_stats(
    _token: str = Depends(verify_session_token),
):
    """Return extension threat intelligence database stats."""
    intel = services._extension_intel
    if intel is None:
        return {"known_malicious_count": 0, "custom_blocklist_count": 0}
    return intel.stats()


@router.get("/extensions/watcher")
async def get_extension_watcher_status(
    _token: str = Depends(verify_session_token),
):
    """Return extension watcher status."""
    watcher = services._extension_watcher
    if watcher is None:
        return {"running": False, "detected_count": 0}
    return {
        "running": watcher.running,
        "detected_count": watcher.detected_count,
    }


# ---------------------------------------------------------------------------
# User Preferences endpoints
# ---------------------------------------------------------------------------


@router.get("/preferences")
async def get_all_preferences(
    _token: str = Depends(verify_session_token),
):
    """Return all user preferences as a dict."""
    from ..core.user_preferences import get_user_preferences

    prefs = get_user_preferences()
    return prefs.get_all()


@router.get("/preferences/{key}")
async def get_preference(
    key: str,
    _token: str = Depends(verify_session_token),
):
    """Return a single preference value."""
    from ..core.user_preferences import get_user_preferences

    prefs = get_user_preferences()
    value = prefs.get(key)
    return {"key": key, "value": value}


class PreferenceUpdate(BaseModel):
    value: str


@router.put("/preferences/{key}")
async def set_preference(
    key: str,
    body: PreferenceUpdate,
    _token: str = Depends(verify_session_token),
):
    """Set a user preference (upsert)."""
    from ..core.user_preferences import get_user_preferences

    prefs = get_user_preferences()
    prefs.set(key, body.value)
    return {"key": key, "value": body.value}


# ---------------------------------------------------------------------------
# AI / Ollama endpoints
# ---------------------------------------------------------------------------


@router.get("/ai/status")
async def get_ai_status(
    _token: str = Depends(verify_session_token),
):
    """Return AI backend status: active backend, Ollama availability, models."""
    bridge = services._ai_bridge
    if bridge is None:
        return {
            "enabled": False,
            "active_backend": "none",
            "ollama": {"available": False},
        }
    ollama = await bridge.ollama_status()
    return {
        "enabled": bridge.enabled,
        "active_backend": bridge.active_backend,
        "ollama": ollama,
    }


@router.get("/ai/ollama/models")
async def get_ollama_models(
    _token: str = Depends(verify_session_token),
):
    """List locally available Ollama models."""
    bridge = services._ai_bridge
    if bridge is None:
        return {"models": [], "current": None}
    return await bridge.list_ollama_models()


@router.post("/ai/ollama/model")
async def set_ollama_model(
    _token: str = Depends(verify_session_token),
    model: str = Query(..., min_length=1, description="Ollama model name"),
):
    """Switch the active Ollama model."""
    bridge = services._ai_bridge
    if bridge is None:
        return {"error": "AI Bridge not initialized"}
    return await bridge.set_ollama_model(model)
