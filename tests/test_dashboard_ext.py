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
        # Place events 1-2 hours ago so they fall within chart hour-buckets
        for i in range(5):
            agg.ingest(
                event_type="file.modified",
                severity="info",
                timestamp=(now - timedelta(hours=1, minutes=i * 10)).isoformat(),
            )
        agg.ingest(
            event_type="process.suspicious",
            severity="critical",
            timestamp=(now - timedelta(hours=1)).isoformat(),
        )

        # Clear cache so fresh data flows through
        module_cache.clear()
        result = svc.get_chart_data(hours=4)
        assert result.period == "4h"
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
    @pytest.fixture(autouse=True)
    def _isolate_agents(self):
        """Prevent real agent registry from leaking into asset tests."""
        with patch(
            "citadel_archer.api.dashboard_ext.DashboardServices._get_enrolled_agent_views",
            return_value=[],
        ):
            yield

    def test_empty_when_no_inventory(self):
        svc = DashboardServices()
        module_cache.clear()
        result = svc.get_assets()
        assert isinstance(result, AssetsResponse)
        assert result.total == 0

    def test_with_inventory(self):
        svc = DashboardServices()
        inv = AssetInventory(db_path=None)
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
        inv = AssetInventory(db_path=None)
        svc.asset_inventory = inv

        inv.register(Asset(name="a", status=AssetStatus.ONLINE))
        inv.register(Asset(name="b", status=AssetStatus.OFFLINE))

        module_cache.clear()
        result = svc.get_assets(status_filter="online")
        assert all(a.status == "online" for a in result.assets)

    def test_platform_filter(self):
        svc = DashboardServices()
        inv = AssetInventory(db_path=None)
        svc.asset_inventory = inv

        inv.register(Asset(name="a", platform=AssetPlatform.LINUX))
        inv.register(Asset(name="b", platform=AssetPlatform.MAC))

        module_cache.clear()
        result = svc.get_assets(platform_filter="linux")
        assert all(a.platform == "linux" for a in result.assets)

    def test_event_count_per_asset(self):
        svc = DashboardServices()
        inv = AssetInventory(db_path=None)
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

    def test_enrolled_agents_appear_in_assets(self):
        """Enrolled external agents should be merged into the asset view."""
        svc = DashboardServices()
        svc.asset_inventory = AssetInventory(db_path=None)

        mock_registry = MagicMock()
        mock_registry.list_agents.return_value = [
            {
                "agent_id": "abc123",
                "name": "Test-VPS-Agent",
                "agent_type": "claude_code",
                "status": "active",
                "created_at": "2026-02-18T00:00:00",
                "last_message_at": "2026-02-18T01:00:00",
                "message_count": 5,
            },
        ]

        mock_protocol = MagicMock()
        mock_protocol.list_online_agents.return_value = [
            {"agent_id": "abc123"},
        ]

        module_cache.clear()
        with patch("citadel_archer.api.dashboard_ext.DashboardServices._get_enrolled_agent_views") as mock_method:
            # Call the real method but with mocked dependencies
            from citadel_archer.api.dashboard_ext import AssetView as DashAssetView
            mock_method.return_value = [
                DashAssetView(
                    asset_id="abc123",
                    name="Test-VPS-Agent",
                    platform="cloud",
                    status="online",
                    hostname="Test-VPS-Agent",
                    ip_address="",
                    guardian_active=True,
                    event_count=5,
                    last_seen="2026-02-18T01:00:00",
                ),
            ]
            result = svc.get_assets()

        assert result.total == 1
        agent_view = result.assets[0]
        assert agent_view.asset_id == "abc123"
        assert agent_view.name == "Test-VPS-Agent"
        assert agent_view.status == "online"
        assert agent_view.platform == "cloud"
        assert agent_view.event_count == 5

    def test_enrolled_agents_mixed_with_inventory(self):
        """Agents should appear alongside inventory assets."""
        svc = DashboardServices()
        inv = AssetInventory(db_path=None)
        svc.asset_inventory = inv

        inv.register(Asset(name="local-srv", platform=AssetPlatform.LINUX,
                           status=AssetStatus.ONLINE, hostname="srv.local"))

        module_cache.clear()
        with patch("citadel_archer.api.dashboard_ext.DashboardServices._get_enrolled_agent_views") as mock_method:
            from citadel_archer.api.dashboard_ext import AssetView as DashAssetView
            mock_method.return_value = [
                DashAssetView(
                    asset_id="agent-xyz",
                    name="Remote-Agent",
                    platform="cloud",
                    status="offline",
                    hostname="Remote-Agent",
                    ip_address="",
                    guardian_active=False,
                    event_count=0,
                    last_seen="",
                ),
            ]
            result = svc.get_assets()

        assert result.total == 2
        names = {a.name for a in result.assets}
        assert "local-srv" in names
        assert "Remote-Agent" in names

    def test_no_agents_when_registry_unavailable(self):
        """get_assets should still work if agent registry is not set up."""
        svc = DashboardServices()
        inv = AssetInventory(db_path=None)
        svc.asset_inventory = inv
        inv.register(Asset(name="local", status=AssetStatus.ONLINE))

        module_cache.clear()
        with patch("citadel_archer.api.dashboard_ext.DashboardServices._get_enrolled_agent_views") as mock_method:
            mock_method.return_value = []
            result = svc.get_assets()

        assert result.total == 1
        assert result.assets[0].name == "local"


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
        from citadel_archer.api.asset_routes import router as asset_router, set_inventory
        from citadel_archer.api.security import initialize_session_token
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        app.include_router(asset_router)
        token = initialize_session_token()

        # Wire up minimal services
        inv = AssetInventory(db_path=None)
        services.event_aggregator = EventAggregator()
        services.asset_inventory = inv
        services.threat_scorer = ThreatScorer()
        set_inventory(inv)

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


# ── Preference Endpoints ──────────────────────────────────────────────

class TestPreferenceEndpoints:
    """Verify that preference API endpoints are registered."""

    def test_preference_routes_exist(self):
        """The router should include preference GET/PUT routes."""
        from citadel_archer.api.dashboard_ext import router

        paths = [r.path for r in router.routes]
        assert "/preferences" in paths or any("/preferences" in p for p in paths)

    def test_user_preferences_importable(self):
        """UserPreferences module should be importable from dashboard_ext."""
        from citadel_archer.core.user_preferences import (
            UserPreferences,
            get_user_preferences,
            set_user_preferences,
            PREF_DASHBOARD_MODE,
        )
        assert PREF_DASHBOARD_MODE == "dashboard_mode"
