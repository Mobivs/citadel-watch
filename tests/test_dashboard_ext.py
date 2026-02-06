# Tests for T12: Dashboard Backend Extensions
# Covers: TTLCache, DashboardServices, endpoint responses,
#          caching behaviour, WebSocket EventBroadcaster,
#          filtering, and integration with Intel modules.

import time
import threading
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.api.dashboard_ext import (
    TTLCache,
    DashboardServices,
    EventBroadcaster,
    ChartResponse,
    TimelineResponse,
    ThreatScoreResponse,
    AssetsResponse,
    cache as module_cache,
    services as module_services,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventAggregator,
    EventCategory,
)
from citadel_archer.intel.assets import (
    Asset,
    AssetInventory,
    AssetPlatform,
    AssetStatus,
)
from citadel_archer.intel.threat_scorer import ThreatScorer, RiskLevel


# ── TTLCache ─────────────────────────────────────────────────────────

class TestTTLCache:
    def test_set_and_get(self):
        c = TTLCache(default_ttl=60)
        c.set("k1", "v1")
        assert c.get("k1") == "v1"

    def test_miss_returns_none(self):
        c = TTLCache()
        assert c.get("nope") is None

    def test_expiry(self):
        c = TTLCache(default_ttl=0.05)
        c.set("k", "val")
        assert c.get("k") == "val"
        time.sleep(0.06)
        assert c.get("k") is None

    def test_custom_ttl_per_key(self):
        c = TTLCache(default_ttl=60)
        c.set("short", "x", ttl=0.05)
        c.set("long", "y", ttl=60)
        time.sleep(0.06)
        assert c.get("short") is None
        assert c.get("long") == "y"

    def test_invalidate(self):
        c = TTLCache()
        c.set("k", "v")
        assert c.invalidate("k") is True
        assert c.get("k") is None
        assert c.invalidate("k") is False

    def test_clear(self):
        c = TTLCache()
        c.set("a", 1)
        c.set("b", 2)
        n = c.clear()
        assert n == 2
        assert c.size == 0

    def test_size_purges_expired(self):
        c = TTLCache(default_ttl=0.05)
        c.set("x", 1)
        time.sleep(0.06)
        assert c.size == 0

    def test_thread_safety(self):
        c = TTLCache(default_ttl=10)
        errors = []

        def writer(tid):
            try:
                for i in range(50):
                    c.set(f"{tid}:{i}", i)
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(50):
                    c.get("0:0")
                    _ = c.size
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(3)]
        threads.append(threading.Thread(target=reader))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ── DashboardServices — chart data ──────────────────────────────────

class TestChartData:
    def test_empty_when_no_aggregator(self):
        svc = DashboardServices()
        result = svc.get_chart_data(hours=4)
        assert isinstance(result, ChartResponse)
        assert result.period == "4h"
        assert len(result.points) >= 1

    def test_with_events(self):
        svc = DashboardServices()
        agg = EventAggregator()
        svc.event_aggregator = agg

        now = datetime.utcnow()
        for i in range(5):
            agg.ingest(
                event_type="file.modified",
                severity="info",
                timestamp=(now - timedelta(minutes=i * 10)).isoformat(),
            )
        agg.ingest(
            event_type="process.suspicious",
            severity="critical",
            timestamp=now.isoformat(),
        )

        # Clear cache so fresh data flows through
        module_cache.clear()
        result = svc.get_chart_data(hours=2)
        assert result.period == "2h"
        total = sum(p.total for p in result.points)
        assert total >= 1

    def test_cached_result(self):
        svc = DashboardServices()
        module_cache.clear()
        r1 = svc.get_chart_data(hours=6)
        r2 = svc.get_chart_data(hours=6)
        # Same object returned from cache
        assert r1.generated_at == r2.generated_at


# ── DashboardServices — timeline ────────────────────────────────────

class TestTimeline:
    def test_empty_when_no_aggregator(self):
        svc = DashboardServices()
        module_cache.clear()
        result = svc.get_timeline()
        assert isinstance(result, TimelineResponse)
        assert result.total == 0

    def test_with_events(self):
        svc = DashboardServices()
        agg = EventAggregator()
        svc.event_aggregator = agg

        agg.ingest(event_type="file.created", severity="info", message="test1")
        agg.ingest(event_type="process.suspicious", severity="alert", message="test2")

        module_cache.clear()
        result = svc.get_timeline(limit=10)
        assert result.total == 2
        assert result.entries[0].event_type == "file.created"

    def test_severity_filter(self):
        svc = DashboardServices()
        agg = EventAggregator()
        svc.event_aggregator = agg

        agg.ingest(event_type="file.created", severity="info")
        agg.ingest(event_type="process.suspicious", severity="alert")

        module_cache.clear()
        result = svc.get_timeline(severity="alert")
        assert all(e.severity == "alert" for e in result.entries)

    def test_asset_filter(self):
        svc = DashboardServices()
        agg = EventAggregator()
        svc.event_aggregator = agg

        agg.ingest(event_type="file.created", severity="info", asset_id="a1")
        agg.ingest(event_type="file.modified", severity="info", asset_id="a2")

        module_cache.clear()
        result = svc.get_timeline(asset_id="a1")
        assert all(e.asset_id == "a1" for e in result.entries)


# ── DashboardServices — threat score ────────────────────────────────

class TestThreatScore:
    def test_empty_when_no_scorer(self):
        svc = DashboardServices()
        module_cache.clear()
        result = svc.get_threat_score()
        assert isinstance(result, ThreatScoreResponse)
        assert result.total_scored == 0

    def test_with_scorer(self):
        svc = DashboardServices()
        scorer = ThreatScorer()
        svc.threat_scorer = scorer
        agg = EventAggregator()
        svc.event_aggregator = agg

        # Score some events through the scorer
        evt = AggregatedEvent(
            event_type="process.suspicious",
            category=EventCategory.PROCESS,
            severity="critical",
        )
        scorer.score_event(evt)
        agg.ingest(event_type="process.suspicious", severity="critical")

        module_cache.clear()
        result = svc.get_threat_score()
        assert result.total_scored == 1

    def test_cached_threat_score(self):
        svc = DashboardServices()
        svc.threat_scorer = ThreatScorer()
        module_cache.clear()
        r1 = svc.get_threat_score()
        r2 = svc.get_threat_score()
        assert r1.generated_at == r2.generated_at


# ── DashboardServices — assets ──────────────────────────────────────

class TestAssets:
    def test_empty_when_no_inventory(self):
        svc = DashboardServices()
        module_cache.clear()
        result = svc.get_assets()
        assert isinstance(result, AssetsResponse)
        assert result.total == 0

    def test_with_inventory(self):
        svc = DashboardServices()
        inv = AssetInventory()
        svc.asset_inventory = inv

        inv.register(Asset(name="srv1", platform=AssetPlatform.LINUX,
                           status=AssetStatus.ONLINE, hostname="srv1.local"))
        inv.register(Asset(name="srv2", platform=AssetPlatform.VPS,
                           status=AssetStatus.PROTECTED, hostname="srv2.cloud"))

        module_cache.clear()
        result = svc.get_assets()
        assert result.total == 2
        assert len(result.assets) == 2

    def test_status_filter(self):
        svc = DashboardServices()
        inv = AssetInventory()
        svc.asset_inventory = inv

        inv.register(Asset(name="a", status=AssetStatus.ONLINE))
        inv.register(Asset(name="b", status=AssetStatus.OFFLINE))

        module_cache.clear()
        result = svc.get_assets(status_filter="online")
        assert all(a.status == "online" for a in result.assets)

    def test_platform_filter(self):
        svc = DashboardServices()
        inv = AssetInventory()
        svc.asset_inventory = inv

        inv.register(Asset(name="a", platform=AssetPlatform.LINUX))
        inv.register(Asset(name="b", platform=AssetPlatform.MAC))

        module_cache.clear()
        result = svc.get_assets(platform_filter="linux")
        assert all(a.platform == "linux" for a in result.assets)

    def test_event_count_per_asset(self):
        svc = DashboardServices()
        inv = AssetInventory()
        agg = EventAggregator()
        svc.asset_inventory = inv
        svc.event_aggregator = agg

        asset = Asset(name="srv1")
        inv.register(asset)

        agg.ingest(event_type="file.modified", asset_id=asset.asset_id)
        agg.ingest(event_type="file.created", asset_id=asset.asset_id)

        module_cache.clear()
        result = svc.get_assets()
        assert result.assets[0].event_count == 2


# ── EventBroadcaster ────────────────────────────────────────────────

class TestEventBroadcaster:
    def test_initial_state(self):
        eb = EventBroadcaster()
        assert eb.connection_count == 0

    def test_disconnect_unknown_is_safe(self):
        eb = EventBroadcaster()
        mock_ws = MagicMock()
        eb.disconnect(mock_ws)  # Should not raise


# ── FastAPI endpoint integration (using TestClient) ─────────────────

class TestEndpointsWithTestClient:
    """Integration tests using FastAPI TestClient.

    These tests verify that routes are wired correctly, return
    expected status codes, and enforce authentication.
    """

    @pytest.fixture(autouse=True)
    def _setup(self):
        """Ensure cache is clean before each test."""
        module_cache.clear()

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from citadel_archer.api.dashboard_ext import router, services
        from citadel_archer.api.security import initialize_session_token
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        token = initialize_session_token()

        # Wire up minimal services
        services.event_aggregator = EventAggregator()
        services.asset_inventory = AssetInventory()
        services.threat_scorer = ThreatScorer()

        tc = TestClient(app)
        tc.headers["X-Session-Token"] = token
        yield tc

    def test_charts_200(self, client):
        resp = client.get("/api/charts")
        assert resp.status_code == 200
        data = resp.json()
        assert "points" in data
        assert "period" in data

    def test_charts_custom_hours(self, client):
        resp = client.get("/api/charts?hours=12&bucket_hours=4")
        assert resp.status_code == 200

    def test_timeline_200(self, client):
        resp = client.get("/api/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert "entries" in data

    def test_timeline_with_filters(self, client):
        resp = client.get("/api/timeline?severity=alert&limit=10")
        assert resp.status_code == 200

    def test_threat_score_200(self, client):
        resp = client.get("/api/threat-score")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scored" in data
        assert "by_risk_level" in data

    def test_assets_200(self, client):
        resp = client.get("/api/assets")
        assert resp.status_code == 200
        data = resp.json()
        assert "assets" in data
        assert "total" in data

    def test_assets_with_filters(self, client):
        resp = client.get("/api/assets?status=online&platform=linux")
        assert resp.status_code == 200

    def test_cache_stats_200(self, client):
        resp = client.get("/api/cache/stats")
        assert resp.status_code == 200
        assert "size" in resp.json()

    def test_cache_clear_200(self, client):
        resp = client.post("/api/cache/clear")
        assert resp.status_code == 200
        assert "cleared" in resp.json()

    def test_auth_required(self):
        """Endpoints must reject requests without session token."""
        from fastapi.testclient import TestClient
        from citadel_archer.api.dashboard_ext import router
        from citadel_archer.api.security import initialize_session_token
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        initialize_session_token()

        tc = TestClient(app)
        # No token header
        resp = tc.get("/api/charts")
        assert resp.status_code in (401, 403)


# ── Cache integration across endpoints ──────────────────────────────

class TestCacheIntegration:
    def test_repeated_chart_calls_use_cache(self):
        svc = DashboardServices()
        module_cache.clear()
        r1 = svc.get_chart_data(hours=24)
        r2 = svc.get_chart_data(hours=24)
        assert r1.generated_at == r2.generated_at

    def test_cache_clear_forces_fresh(self):
        svc = DashboardServices()
        module_cache.clear()
        r1 = svc.get_chart_data(hours=24)
        module_cache.clear()
        import time; time.sleep(0.01)
        r2 = svc.get_chart_data(hours=24)
        assert r2.generated_at != r1.generated_at
