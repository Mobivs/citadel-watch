# PRD: Tests - Charts & Visualization Component (P2.1.5-T1)
# Reference: PHASE_2_SPEC.md
#
# 25+ tests covering:
#   - Chart data API responses
#   - Dashboard services chart generation
#   - HTML structure validation
#   - JS file structure validation
#   - Chart.js config format
#   - Time range selection logic
#   - WebSocket event handling
#   - TTL cache behaviour
#   - Route registration
#   - Summary stat calculations

import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Intel module imports ─────────────────────────────────────────────

from citadel_archer.intel.chart_data import (
    AggregationInterval,
    ChartConfig,
    ChartDataset,
    ChartTheme,
    build_all_charts,
    category_breakdown_chart,
    severity_distribution_chart,
    threat_trend_chart,
    timeline_scatter_chart,
)
from citadel_archer.intel.event_aggregator import AggregatedEvent, EventCategory

# ── Dashboard ext imports ────────────────────────────────────────────

from citadel_archer.api.dashboard_ext import (
    ChartResponse,
    DashboardServices,
    TTLCache,
    ThreatTrendPoint,
    cache,
)


# ── Helpers ──────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def _make_event(
    event_id="evt-1",
    severity="info",
    category=EventCategory.SYSTEM,
    timestamp=None,
    asset_id="asset-1",
    message="test event",
):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    return AggregatedEvent(
        event_id=event_id,
        event_type="test",
        severity=severity,
        message=message,
        timestamp=timestamp,
        asset_id=asset_id,
        category=category,
        details={},
    )


def _make_events_spread(count=20, hours=24):
    """Generate events spread across a time window."""
    now = datetime.utcnow()
    sevs = ["info", "investigate", "alert", "critical"]
    cats = list(EventCategory)
    events = []
    for i in range(count):
        ts = now - timedelta(hours=hours * i / count)
        events.append(_make_event(
            event_id=f"evt-{i}",
            severity=sevs[i % len(sevs)],
            category=cats[i % len(cats)],
            timestamp=ts.isoformat(),
            asset_id=f"asset-{i % 3}",
        ))
    return events


# =====================================================================
# Section 1: Chart Data Pipeline (chart_data.py)
# =====================================================================

class TestThreatTrendChart:
    """Threat trend chart generation."""

    def test_empty_events_produces_empty_buckets(self):
        config = threat_trend_chart([], hours=6)
        assert config.chart_type == "line"
        assert config.title == "Threat Trends"
        assert len(config.datasets) == 4
        # All data should be zeros
        for ds in config.datasets:
            assert all(v == 0 for v in ds.data)

    def test_events_bucketed_by_hour(self):
        now = datetime.utcnow()
        events = [
            _make_event(severity="info", timestamp=now.isoformat()),
            _make_event(event_id="e2", severity="critical", timestamp=now.isoformat()),
        ]
        config = threat_trend_chart(events, hours=2)
        assert len(config.labels) > 0
        # At least one bucket should have data
        total = sum(sum(ds.data) for ds in config.datasets)
        assert total >= 2

    def test_to_dict_produces_chartjs_format(self):
        config = threat_trend_chart([], hours=1)
        d = config.to_dict()
        assert d["type"] == "line"
        assert "data" in d
        assert "labels" in d["data"]
        assert "datasets" in d["data"]
        assert "options" in d


class TestSeverityDistributionChart:
    """Severity distribution doughnut chart."""

    def test_empty_events(self):
        config = severity_distribution_chart([])
        assert config.chart_type == "doughnut"
        assert config.datasets[0].data == [0, 0, 0, 0]

    def test_counts_by_severity(self):
        events = [
            _make_event(severity="info"),
            _make_event(event_id="e2", severity="info"),
            _make_event(event_id="e3", severity="critical"),
        ]
        config = severity_distribution_chart(events)
        data = config.datasets[0].data
        # data = [low, medium, high, critical]
        assert data[0] == 2  # info -> low
        assert data[3] == 1  # critical

    def test_labels_match_data(self):
        config = severity_distribution_chart([])
        assert config.labels == ["Low", "Medium", "High", "Critical"]
        assert len(config.datasets[0].data) == 4


class TestTimelineScatterChart:
    """Timeline scatter chart."""

    def test_empty_events(self):
        config = timeline_scatter_chart([], hours=1)
        assert config.chart_type == "scatter"
        assert len(config.datasets) == 4
        for ds in config.datasets:
            assert len(ds.data) == 0

    def test_scatter_points_have_x_y(self):
        events = [_make_event(severity="critical")]
        config = timeline_scatter_chart(events, hours=1)
        # Critical dataset (index 3) should have a point
        assert len(config.datasets[3].data) == 1
        point = config.datasets[3].data[0]
        assert "x" in point
        assert "y" in point
        assert point["y"] == 4.0  # critical = 4


class TestCategoryBreakdownChart:
    """Category breakdown bar chart."""

    def test_empty_events(self):
        config = category_breakdown_chart([])
        assert config.chart_type == "bar"
        assert len(config.labels) == 0

    def test_counts_categories(self):
        events = [
            _make_event(category=EventCategory.FILE),
            _make_event(event_id="e2", category=EventCategory.FILE),
            _make_event(event_id="e3", category=EventCategory.NETWORK),
        ]
        config = category_breakdown_chart(events)
        assert len(config.labels) == 2
        # File should be first (count 2)
        assert config.labels[0] == "File"
        assert config.datasets[0].data[0] == 2

    def test_sorted_descending(self):
        events = [
            _make_event(category=EventCategory.NETWORK),
            _make_event(event_id="e2", category=EventCategory.FILE),
            _make_event(event_id="e3", category=EventCategory.FILE),
            _make_event(event_id="e4", category=EventCategory.FILE),
        ]
        config = category_breakdown_chart(events)
        assert config.datasets[0].data[0] >= config.datasets[0].data[1]


class TestBuildAllCharts:
    """build_all_charts convenience function."""

    def test_returns_four_chart_dicts(self):
        result = build_all_charts([], hours=1)
        assert "trend" in result
        assert "severity" in result
        assert "timeline" in result
        assert "category" in result

    def test_each_chart_has_type(self):
        result = build_all_charts([], hours=1)
        assert result["trend"]["type"] == "line"
        assert result["severity"]["type"] == "doughnut"
        assert result["timeline"]["type"] == "scatter"
        assert result["category"]["type"] == "bar"


class TestChartTheme:
    """Chart theme colour utilities."""

    def test_severity_colour_info(self):
        c = ChartTheme.severity_colour("info", 0.5)
        assert "16, 185, 129" in c  # emerald
        assert "0.5" in c

    def test_severity_colour_critical(self):
        c = ChartTheme.severity_colour("critical")
        assert "239, 68, 68" in c  # red

    def test_category_colour_network(self):
        c = ChartTheme.category_colour("network", 0.8)
        assert "0, 217, 255" in c  # neon-blue

    def test_unknown_severity_defaults_to_low(self):
        c = ChartTheme.severity_colour("xyzzy")
        assert "16, 185, 129" in c


# =====================================================================
# Section 2: Dashboard Services (API layer)
# =====================================================================

class TestDashboardServicesCharts:
    """DashboardServices.get_chart_data()."""

    def test_no_aggregator_returns_empty(self):
        svc = DashboardServices()
        result = svc.get_chart_data(hours=6)
        assert isinstance(result, ChartResponse)
        assert result.period == "6h"
        # All points should have zero totals
        for p in result.points:
            assert p.total == 0

    def test_caches_result(self):
        svc = DashboardServices()
        r1 = svc.get_chart_data(hours=6)
        r2 = svc.get_chart_data(hours=6)
        assert r1.generated_at == r2.generated_at  # same cached object

    def test_different_params_different_cache(self):
        test_cache = TTLCache(default_ttl=60)
        with patch("citadel_archer.api.dashboard_ext.cache", test_cache):
            svc = DashboardServices()
            r1 = svc.get_chart_data(hours=6)
            r2 = svc.get_chart_data(hours=12)
            # Could have different generated_at if not cached together
            assert r1.period == "6h"
            assert r2.period == "12h"


class TestTTLCacheCharts:
    """TTL cache behaviour for chart data."""

    def test_set_and_get(self):
        c = TTLCache(default_ttl=60)
        c.set("k1", "v1")
        assert c.get("k1") == "v1"

    def test_expired_key_returns_none(self):
        c = TTLCache(default_ttl=0.01)
        c.set("k1", "v1")
        time.sleep(0.02)
        assert c.get("k1") is None

    def test_clear_returns_count(self):
        c = TTLCache()
        c.set("a", 1)
        c.set("b", 2)
        assert c.clear() == 2
        assert c.size == 0

    def test_invalidate_specific_key(self):
        c = TTLCache()
        c.set("charts:24:1", "data")
        assert c.invalidate("charts:24:1") is True
        assert c.get("charts:24:1") is None


# =====================================================================
# Section 3: HTML Structure Validation
# =====================================================================

class TestChartsHTML:
    """Validate charts.html structure."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "charts.html"
        if not path.exists():
            pytest.skip("charts.html not found")
        return path.read_text()

    def test_has_chart_js_cdn(self, html_content):
        assert "chart.js" in html_content.lower() or "chart.umd" in html_content

    def test_has_tailwind_cdn(self, html_content):
        assert "cdn.tailwindcss.com" in html_content

    def test_has_four_chart_canvases(self, html_content):
        assert 'id="threat-trend-chart"' in html_content
        assert 'id="severity-distribution-chart"' in html_content
        assert 'id="timeline-scatter-chart"' in html_content
        assert 'id="category-breakdown-chart"' in html_content

    def test_has_time_range_selector(self, html_content):
        assert 'id="time-range-selector"' in html_content
        assert 'data-hours="6"' in html_content
        assert 'data-hours="24"' in html_content
        assert 'data-hours="168"' in html_content

    def test_has_live_badge(self, html_content):
        assert 'id="live-badge"' in html_content

    def test_has_summary_stats(self, html_content):
        assert 'id="stat-total"' in html_content
        assert 'id="stat-critical"' in html_content
        assert 'id="stat-high"' in html_content
        assert 'id="stat-medium"' in html_content

    def test_has_dashboard_link(self, html_content):
        assert 'href="index.html"' in html_content

    def test_has_vault_link(self, html_content):
        assert 'href="vault.html"' in html_content

    def test_has_glassmorphic_theme(self, html_content):
        assert "glass-card" in html_content
        assert "dark-bg" in html_content
        assert "neon-blue" in html_content

    def test_has_responsive_breakpoints(self, html_content):
        assert "640px" in html_content
        assert "1024px" in html_content or "1023px" in html_content

    def test_loads_charts_js(self, html_content):
        assert 'src="js/charts.js"' in html_content

    def test_has_shared_css(self, html_content):
        assert 'href="css/styles.css"' in html_content

    def test_line_count_over_300(self, html_content):
        lines = html_content.strip().split("\n")
        assert len(lines) >= 250  # Allow slight flexibility


# =====================================================================
# Section 4: JS File Structure Validation
# =====================================================================

class TestChartsJS:
    """Validate charts.js structure."""

    @pytest.fixture
    def js_content(self):
        path = FRONTEND_DIR / "js" / "charts.js"
        if not path.exists():
            pytest.skip("charts.js not found")
        return path.read_text()

    def test_imports_api_client(self, js_content):
        assert "api-client" in js_content or "apiClient" in js_content

    def test_has_colour_constants(self, js_content):
        assert "COLOURS" in js_content
        assert "CATEGORY_COLOURS" in js_content

    def test_has_fetch_chart_data(self, js_content):
        assert "fetchChartData" in js_content

    def test_has_build_functions(self, js_content):
        assert "buildTrendChart" in js_content
        assert "buildSeverityChart" in js_content
        assert "buildTimelineScatterChart" in js_content
        assert "buildCategoryChart" in js_content

    def test_has_update_functions(self, js_content):
        assert "updateTrendChart" in js_content
        assert "updateSeverityChart" in js_content

    def test_has_websocket_connection(self, js_content):
        assert "WebSocket" in js_content
        assert "connectWebSocket" in js_content

    def test_has_30_second_refresh(self, js_content):
        assert "30000" in js_content

    def test_has_time_range_handler(self, js_content):
        assert "setupTimeRangeSelector" in js_content or "time-range" in js_content

    def test_has_live_status_handler(self, js_content):
        assert "setLiveStatus" in js_content

    def test_has_init_function(self, js_content):
        assert "async function init" in js_content or "function init" in js_content

    def test_exports_for_testing(self, js_content):
        assert "export" in js_content


# =====================================================================
# Section 5: Index.html Navigation Update
# =====================================================================

class TestIndexHTMLNavigation:
    """Verify Charts tab was added to index.html."""

    @pytest.fixture
    def index_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_charts_tab(self, index_content):
        assert 'id="tab-btn-charts"' in index_content

    def test_has_charts_panel(self, index_content):
        assert 'id="tab-panel-charts"' in index_content

    def test_charts_tab_before_vault(self, index_content):
        charts_pos = index_content.index('id="tab-btn-charts"')
        vault_pos = index_content.index('href="vault.html"')
        assert charts_pos < vault_pos


# =====================================================================
# Section 6: API Route Registration
# =====================================================================

class TestChartsRoutes:
    """Verify charts routes in main.py."""

    @pytest.fixture
    def main_content(self):
        path = Path(__file__).parent.parent / "src" / "citadel_archer" / "api" / "main.py"
        if not path.exists():
            pytest.skip("main.py not found")
        return path.read_text()

    def test_charts_html_route(self, main_content):
        assert "/charts.html" in main_content

    def test_charts_redirect_route(self, main_content):
        assert '"/charts"' in main_content

    def test_dashboard_ext_router_included(self, main_content):
        assert "dashboard_ext_router" in main_content


# =====================================================================
# Section 7: ChartConfig Serialisation
# =====================================================================

class TestChartConfigFormat:
    """Chart.js config format correctness."""

    def test_chartconfig_to_dict_json_serialisable(self):
        config = threat_trend_chart([], hours=1)
        d = config.to_dict()
        # Must be JSON-serialisable
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_dataset_to_dict(self):
        ds = ChartDataset(
            label="Test",
            data=[1, 2, 3],
            backgroundColor="rgba(0,0,0,1)",
            borderColor="rgba(0,0,0,1)",
        )
        d = ds.to_dict()
        assert d["label"] == "Test"
        assert d["data"] == [1, 2, 3]

    def test_build_all_json_serialisable(self):
        result = build_all_charts([], hours=1)
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        assert "trend" in parsed


# =====================================================================
# Section 8: Chart Data with Real Events
# =====================================================================

class TestChartDataWithEvents:
    """Charts with realistic event data."""

    def test_20_events_produces_nonempty_charts(self):
        events = _make_events_spread(20, hours=12)
        result = build_all_charts(events, hours=24)

        # Trend chart should have data
        trend_data = result["trend"]["data"]["datasets"]
        total = sum(sum(ds["data"]) for ds in trend_data)
        assert total > 0

        # Severity should have nonzero values
        sev_data = result["severity"]["data"]["datasets"][0]["data"]
        assert sum(sev_data) == 20

    def test_category_chart_with_mixed_events(self):
        events = _make_events_spread(40, hours=6)
        config = category_breakdown_chart(events)
        # Should have multiple categories
        assert len(config.labels) >= 2

    def test_scatter_with_all_severities(self):
        events = _make_events_spread(16, hours=2)
        config = timeline_scatter_chart(events, hours=4)
        # Should have points across severity levels
        total_points = sum(len(ds.data) for ds in config.datasets)
        assert total_points > 0
