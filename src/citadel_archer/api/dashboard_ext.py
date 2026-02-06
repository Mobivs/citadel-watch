# PRD: Dashboard Backend Extensions - Phase 2 Endpoints
# Reference: PHASE_2_SPEC.md
#
# Extends the Phase 1 FastAPI dashboard with:
#   /api/charts       - Threat trend data for charting
#   /api/timeline     - Alert history timeline
#   /api/threat-score - Risk metric summary from ThreatScorer
#   /api/assets       - Multi-asset inventory view
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

        # Bucket events by hour
        buckets: Dict[str, Dict[str, int]] = {}
        for i in range(0, hours, bucket_hours):
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


@router.get("/threat-score", response_model=ThreatScoreResponse)
async def get_threat_score(
    _token: str = Depends(verify_session_token),
):
    """Risk metric summary from the ThreatScorer."""
    return services.get_threat_score()


@router.get("/assets", response_model=AssetsResponse)
async def get_assets(
    status: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    _token: str = Depends(verify_session_token),
):
    """Multi-asset inventory view with event counts."""
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
