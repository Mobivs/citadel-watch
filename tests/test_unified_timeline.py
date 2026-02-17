"""Tests for Unified Cross-System Threat Timeline (v0.3.28).

Covers:
  Backend:
  - Severity normalization helpers (_normalize_remote_severity, _normalize_correlation_severity)
  - UnifiedTimelineEntry / UnifiedTimelineResponse models
  - DashboardServices.get_unified_timeline() — empty, local-only, remote-only, merged
  - Filters: severity, asset, source, time range
  - Pagination/limit
  - Stats computation
  - Source detail fields for remote-shield and correlation entries
  - WS broadcast wiring (remote_shield_routes, cross_asset_correlation)

  Frontend:
  - timeline.html structure (source filter, source column, badge CSS)
  - timeline.js structure (unified API, SOURCE_COLOURS, WS subscriptions)
  - websocket-handler.js MESSAGE_TYPES updated
"""

import json
import re
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, AsyncMock

import pytest


# ── Paths ────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
TIMELINE_HTML = FRONTEND / "timeline.html"
TIMELINE_JS = FRONTEND / "js" / "timeline.js"
WS_HANDLER_JS = FRONTEND / "js" / "websocket-handler.js"
DASHBOARD_EXT = ROOT / "src" / "citadel_archer" / "api" / "dashboard_ext.py"
REMOTE_SHIELD_ROUTES = ROOT / "src" / "citadel_archer" / "api" / "remote_shield_routes.py"
CROSS_ASSET_CORR = ROOT / "src" / "citadel_archer" / "intel" / "cross_asset_correlation.py"
MAIN_PY = ROOT / "src" / "citadel_archer" / "api" / "main.py"


# ── Backend: Severity Normalisation ──────────────────────────────────


class TestNormalizeRemoteSeverity:
    """_normalize_remote_severity maps 1-10 integers to 4-level strings."""

    def setup_method(self):
        from citadel_archer.api.dashboard_ext import _normalize_remote_severity
        self.fn = _normalize_remote_severity

    def test_1_to_3_maps_to_info(self):
        for score in (1, 2, 3):
            assert self.fn(score) == "info", f"score {score}"

    def test_4_to_5_maps_to_investigate(self):
        for score in (4, 5):
            assert self.fn(score) == "investigate", f"score {score}"

    def test_6_to_7_maps_to_alert(self):
        for score in (6, 7):
            assert self.fn(score) == "alert", f"score {score}"

    def test_8_to_10_maps_to_critical(self):
        for score in (8, 9, 10):
            assert self.fn(score) == "critical", f"score {score}"


class TestNormalizeCorrelationSeverity:
    """_normalize_correlation_severity maps string levels."""

    def setup_method(self):
        from citadel_archer.api.dashboard_ext import _normalize_correlation_severity
        self.fn = _normalize_correlation_severity

    def test_low_maps_to_info(self):
        assert self.fn("low") == "info"

    def test_medium_maps_to_investigate(self):
        assert self.fn("medium") == "investigate"

    def test_high_maps_to_alert(self):
        assert self.fn("high") == "alert"

    def test_critical_maps_to_critical(self):
        assert self.fn("critical") == "critical"

    def test_case_insensitive(self):
        assert self.fn("HIGH") == "alert"
        assert self.fn("Low") == "info"

    def test_unknown_defaults_to_investigate(self):
        assert self.fn("unknown") == "investigate"


# ── Backend: Pydantic Models ────────────────────────────────────────


class TestUnifiedTimelineModels:
    """UnifiedTimelineEntry and UnifiedTimelineResponse validation."""

    def test_entry_has_source_field(self):
        from citadel_archer.api.dashboard_ext import UnifiedTimelineEntry
        entry = UnifiedTimelineEntry(
            event_id="e1", event_type="file_access", severity="info",
            message="test", asset_id="a1", timestamp="2026-02-16T00:00:00",
            category="file", source="local",
        )
        assert entry.source == "local"
        assert entry.source_detail is None

    def test_entry_with_source_detail(self):
        from citadel_archer.api.dashboard_ext import UnifiedTimelineEntry
        entry = UnifiedTimelineEntry(
            event_id="e2", event_type="malware", severity="critical",
            message="threat", asset_id="a1", timestamp="2026-02-16T01:00:00",
            category="remote", source="remote-shield",
            source_detail={"agent_id": "agent-1", "hostname": "pc-1", "original_severity": 9},
        )
        assert entry.source == "remote-shield"
        assert entry.source_detail["agent_id"] == "agent-1"

    def test_response_model(self):
        from citadel_archer.api.dashboard_ext import UnifiedTimelineResponse, UnifiedTimelineEntry
        entries = [
            UnifiedTimelineEntry(
                event_id="e1", event_type="test", severity="info",
                message="m", asset_id="a", timestamp="2026-02-16T00:00:00",
                category="system", source="local",
            ),
        ]
        resp = UnifiedTimelineResponse(
            entries=entries, total=1,
            stats={"local_count": 1, "remote_count": 0, "correlation_count": 0, "by_severity": {"info": 1}},
            generated_at="2026-02-16T00:00:00",
        )
        assert resp.total == 1
        assert resp.stats["local_count"] == 1


# ── Backend: DashboardServices.get_unified_timeline() ────────────────


@dataclass
class _FakeEvent:
    """Mimics AggregatedEvent for testing."""
    event_id: str = "local-1"
    event_type: str = "file_access"
    severity: str = "info"
    message: str = "file accessed"
    asset_id: Optional[str] = "host-main"
    timestamp: str = "2026-02-16T10:00:00"
    category: "Any" = None  # will be set in __post_init__

    def __post_init__(self):
        if self.category is None:
            self.category = MagicMock(value="file")


@pytest.fixture
def dashboard_services():
    """Create DashboardServices with mocked sub-services."""
    from citadel_archer.api.dashboard_ext import DashboardServices, cache

    # Clear cache to avoid stale results between tests
    cache.clear()

    svc = DashboardServices()

    # Mock event aggregator
    svc.event_aggregator = MagicMock()
    svc.event_aggregator.recent.return_value = []

    # Mock shield DB
    svc.shield_db = MagicMock()
    svc.shield_db.list_threats.return_value = []

    # Mock correlator
    svc._correlator = MagicMock()
    svc._correlator.recent_correlations.return_value = []

    return svc


class TestGetUnifiedTimeline:
    """DashboardServices.get_unified_timeline() integration tests."""

    def test_empty_services(self, dashboard_services):
        result = dashboard_services.get_unified_timeline()
        assert result.total == 0
        assert result.entries == []
        assert result.stats["local_count"] == 0
        assert result.stats["remote_count"] == 0
        assert result.stats["correlation_count"] == 0

    def test_local_only(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1", severity="info", timestamp="2026-02-16T10:00:00"),
            _FakeEvent(event_id="l2", severity="alert", timestamp="2026-02-16T10:01:00"),
        ]
        result = dashboard_services.get_unified_timeline()
        assert result.total == 2
        assert all(e.source == "local" for e in result.entries)
        assert result.stats["local_count"] == 2

    def test_remote_only(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = []
        dashboard_services.shield_db.list_threats.return_value = [
            {"id": "t1", "type": "malware", "severity": 8, "title": "trojan found",
             "agent_id": "agent-1", "detected_at": "2026-02-16T09:00:00",
             "hostname": "family-pc", "status": "active"},
        ]
        result = dashboard_services.get_unified_timeline()
        assert result.total == 1
        assert result.entries[0].source == "remote-shield"
        assert result.entries[0].severity == "critical"  # 8 → critical
        assert result.entries[0].source_detail["hostname"] == "family-pc"
        assert result.stats["remote_count"] == 1

    def test_correlation_only(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = []
        dashboard_services._correlator.recent_correlations.return_value = [
            {
                "correlation_id": "c1",
                "correlation_type": "shared_ioc",
                "severity": "high",
                "affected_assets": ["host-main", "family-pc"],
                "indicator": "192.168.1.100",
                "event_count": 5,
                "first_seen": "2026-02-16T08:00:00",
                "last_seen": "2026-02-16T09:00:00",
                "description": "Same IP on two hosts",
            },
        ]
        result = dashboard_services.get_unified_timeline()
        assert result.total == 1
        assert result.entries[0].source == "correlation"
        assert result.entries[0].severity == "alert"  # high → alert
        assert result.entries[0].source_detail["indicator"] == "192.168.1.100"
        assert result.stats["correlation_count"] == 1

    def test_merged_sort_order(self, dashboard_services):
        """Entries from all sources should be sorted by timestamp descending."""
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1", timestamp="2026-02-16T10:00:00"),
        ]
        dashboard_services.shield_db.list_threats.return_value = [
            {"id": "t1", "type": "malware", "severity": 5, "title": "threat",
             "agent_id": "a1", "detected_at": "2026-02-16T11:00:00",
             "hostname": "pc1", "status": "active"},
        ]
        dashboard_services._correlator.recent_correlations.return_value = [
            {"correlation_id": "c1", "correlation_type": "shared_ioc",
             "severity": "medium", "affected_assets": [],
             "indicator": "x", "event_count": 1,
             "first_seen": "2026-02-16T09:00:00",
             "last_seen": "2026-02-16T09:30:00",
             "description": "corr"},
        ]
        result = dashboard_services.get_unified_timeline()
        assert result.total == 3
        # 11:00 > 10:00 > 09:30 (last_seen used for correlations)
        assert result.entries[0].source == "remote-shield"
        assert result.entries[1].source == "local"
        assert result.entries[2].source == "correlation"

    def test_source_filter_local(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1"),
        ]
        dashboard_services.shield_db.list_threats.return_value = [
            {"id": "t1", "type": "malware", "severity": 5, "title": "x",
             "agent_id": "a1", "detected_at": "2026-02-16T09:00:00",
             "hostname": "pc1", "status": "active"},
        ]
        result = dashboard_services.get_unified_timeline(source="local")
        assert result.total == 1
        assert all(e.source == "local" for e in result.entries)

    def test_source_filter_remote(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1"),
        ]
        dashboard_services.shield_db.list_threats.return_value = [
            {"id": "t1", "type": "malware", "severity": 5, "title": "x",
             "agent_id": "a1", "detected_at": "2026-02-16T09:00:00",
             "hostname": "pc1", "status": "active"},
        ]
        result = dashboard_services.get_unified_timeline(source="remote-shield")
        assert result.total == 1
        assert result.entries[0].source == "remote-shield"

    def test_severity_filter(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1", severity="info"),
            _FakeEvent(event_id="l2", severity="critical"),
        ]
        result = dashboard_services.get_unified_timeline(severity="critical")
        assert result.total == 1
        assert result.entries[0].severity == "critical"

    def test_asset_filter(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1", asset_id="host-main"),
            _FakeEvent(event_id="l2", asset_id="vps-1"),
        ]
        result = dashboard_services.get_unified_timeline(asset_id="vps-1")
        assert result.total == 1
        assert result.entries[0].asset_id == "vps-1"

    def test_time_range_filter(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1", timestamp="2026-02-16T08:00:00"),
            _FakeEvent(event_id="l2", timestamp="2026-02-16T12:00:00"),
            _FakeEvent(event_id="l3", timestamp="2026-02-16T16:00:00"),
        ]
        result = dashboard_services.get_unified_timeline(
            time_from="2026-02-16T10:00:00", time_to="2026-02-16T14:00:00",
        )
        assert result.total == 1
        assert result.entries[0].event_id == "l2"

    def test_pagination_limit(self, dashboard_services):
        events = [
            _FakeEvent(event_id=f"l{i}", timestamp=f"2026-02-16T{10+i:02d}:00:00")
            for i in range(10)
        ]
        dashboard_services.event_aggregator.recent.return_value = events
        result = dashboard_services.get_unified_timeline(limit=3)
        assert len(result.entries) == 3
        assert result.total == 10  # total before slicing

    def test_stats_counts_correct(self, dashboard_services):
        dashboard_services.event_aggregator.recent.return_value = [
            _FakeEvent(event_id="l1", severity="info"),
            _FakeEvent(event_id="l2", severity="critical"),
        ]
        dashboard_services.shield_db.list_threats.return_value = [
            {"id": "t1", "type": "malware", "severity": 6, "title": "x",
             "agent_id": "a1", "detected_at": "2026-02-16T09:00:00",
             "hostname": "pc1", "status": "active"},
        ]
        result = dashboard_services.get_unified_timeline()
        assert result.stats["local_count"] == 2
        assert result.stats["remote_count"] == 1
        assert result.stats["correlation_count"] == 0
        assert result.stats["by_severity"]["info"] == 1
        assert result.stats["by_severity"]["critical"] == 1
        assert result.stats["by_severity"]["alert"] == 1  # severity 6 → alert

    def test_source_detail_remote(self, dashboard_services):
        dashboard_services.shield_db.list_threats.return_value = [
            {"id": "t1", "type": "malware", "severity": 9, "title": "ransomware",
             "agent_id": "agent-win-1", "detected_at": "2026-02-16T09:00:00",
             "hostname": "family-pc", "status": "active"},
        ]
        result = dashboard_services.get_unified_timeline()
        detail = result.entries[0].source_detail
        assert detail["agent_id"] == "agent-win-1"
        assert detail["hostname"] == "family-pc"
        assert detail["original_severity"] == 9
        assert detail["status"] == "active"

    def test_source_detail_correlation(self, dashboard_services):
        dashboard_services._correlator.recent_correlations.return_value = [
            {
                "correlation_id": "c1",
                "correlation_type": "ip_multi_asset",
                "severity": "critical",
                "affected_assets": ["host-1", "host-2"],
                "indicator": "10.0.0.1",
                "event_count": 12,
                "first_seen": "2026-02-16T08:00:00",
                "last_seen": "2026-02-16T09:00:00",
                "description": "IP seen on 2 hosts",
            },
        ]
        result = dashboard_services.get_unified_timeline()
        detail = result.entries[0].source_detail
        assert detail["correlation_type"] == "ip_multi_asset"
        assert detail["affected_assets"] == ["host-1", "host-2"]
        assert detail["indicator"] == "10.0.0.1"
        assert detail["event_count"] == 12


# ── Backend: WS Broadcast Wiring ────────────────────────────────────


class TestWSBroadcastWiring:
    """Verify WS broadcast code is wired in remote_shield_routes and correlator."""

    def test_remote_shield_routes_broadcasts_threat(self):
        source = REMOTE_SHIELD_ROUTES.read_text(encoding="utf-8")
        assert "manager.broadcast" in source
        assert '"threat:remote-shield"' in source or "'threat:remote-shield'" in source

    def test_cross_asset_correlator_has_set_ws_broadcast(self):
        source = CROSS_ASSET_CORR.read_text(encoding="utf-8")
        assert "def set_ws_broadcast" in source
        assert "threat:correlation" in source

    def test_main_py_wires_correlator_broadcast(self):
        source = MAIN_PY.read_text(encoding="utf-8")
        assert "correlator.set_ws_broadcast(manager.broadcast)" in source


# ── Frontend: timeline.html Structure ────────────────────────────────


class TestTimelineHTMLStructure:
    """Verify timeline.html has source filter, column, and badge styles."""

    @pytest.fixture(autouse=True)
    def _load_html(self):
        self.html = TIMELINE_HTML.read_text(encoding="utf-8")

    def test_has_source_filter_dropdown(self):
        assert 'id="filter-source"' in self.html

    def test_source_filter_has_options(self):
        assert '<option value="local">Local</option>' in self.html
        assert '<option value="remote-shield">Remote Shield</option>' in self.html
        assert '<option value="correlation">Correlations</option>' in self.html

    def test_has_source_column_header(self):
        assert 'data-sort="source"' in self.html

    def test_source_badge_css_local(self):
        assert ".source-local" in self.html

    def test_source_badge_css_remote(self):
        assert ".source-remote" in self.html

    def test_source_badge_css_correlation(self):
        assert ".source-correlation" in self.html

    def test_source_badge_class(self):
        assert ".source-badge" in self.html

    def test_source_stats_pills(self):
        assert 'id="stat-local-count"' in self.html
        assert 'id="stat-remote-count"' in self.html
        assert 'id="stat-correlation-count"' in self.html


# ── Frontend: timeline.js Structure ──────────────────────────────────


class TestTimelineJSStructure:
    """Verify timeline.js calls unified API and has source rendering."""

    @pytest.fixture(autouse=True)
    def _load_js(self):
        self.js = TIMELINE_JS.read_text(encoding="utf-8")

    def test_calls_unified_api(self):
        assert "/api/timeline/unified" in self.js

    def test_source_colours_defined(self):
        assert "SOURCE_COLOURS" in self.js
        assert "'remote-shield'" in self.js or '"remote-shield"' in self.js
        assert "correlation" in self.js

    def test_subscribes_remote_ws(self):
        assert "threat:remote-shield" in self.js

    def test_subscribes_correlation_ws(self):
        assert "threat:correlation" in self.js

    def test_source_filter_in_get_filters(self):
        assert "filter-source" in self.js

    def test_source_in_apply_filters(self):
        assert "e.source === source" in self.js or "e.source ===" in self.js

    def test_source_badge_rendering(self):
        assert "source-badge" in self.js

    def test_render_source_detail_function(self):
        assert "renderSourceDetail" in self.js

    def test_exports_source_colours(self):
        assert "SOURCE_COLOURS" in self.js
        # Check it's in the export block
        export_match = re.search(r'export\s*\{[^}]+\}', self.js, re.DOTALL)
        assert export_match is not None
        assert "SOURCE_COLOURS" in export_match.group()


# ── Frontend: websocket-handler.js ───────────────────────────────────


class TestWebSocketHandlerUpdated:
    """Verify MESSAGE_TYPES includes new threat types."""

    @pytest.fixture(autouse=True)
    def _load_js(self):
        self.js = WS_HANDLER_JS.read_text(encoding="utf-8")

    def test_has_remote_shield_type(self):
        assert "'threat:remote-shield'" in self.js

    def test_has_correlation_type(self):
        assert "'threat:correlation'" in self.js


# ── Backend: Route Endpoint ──────────────────────────────────────────


class TestUnifiedTimelineRoute:
    """Verify the GET /api/timeline/unified route exists."""

    def test_route_defined(self):
        source = DASHBOARD_EXT.read_text(encoding="utf-8")
        assert '"/timeline/unified"' in source
        assert "get_unified_timeline" in source

    def test_route_has_auth(self):
        source = DASHBOARD_EXT.read_text(encoding="utf-8")
        # Find the route function and check it has verify_session_token
        idx = source.index('"/timeline/unified"')
        route_block = source[idx:idx + 500]
        assert "verify_session_token" in route_block

    def test_route_has_source_param(self):
        source = DASHBOARD_EXT.read_text(encoding="utf-8")
        idx = source.index('"/timeline/unified"')
        route_block = source[idx:idx + 500]
        assert "source" in route_block
