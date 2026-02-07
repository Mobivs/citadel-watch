# PRD: Tests - Alert Timeline UI (P2.1.5-T2)
# Reference: PHASE_2_SPEC.md
#
# 30+ tests covering:
#   - Backend alert_timeline module (filtering, sorting, pagination, drill-down)
#   - Dashboard services timeline API
#   - HTML structure validation
#   - JS file structure validation
#   - Route registration
#   - D3.js integration
#   - 1000+ event performance
#   - Search filtering
#   - Drill-down detail

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# ── Intel module imports ─────────────────────────────────────────────

from citadel_archer.intel.alert_timeline import (
    AlertTimeline,
    DrillDownView,
    SortField,
    SortOrder,
    TimelineEntry,
    TimelineView,
    drill_down,
    filter_entries,
    paginate,
    sort_entries,
)
from citadel_archer.intel.event_aggregator import AggregatedEvent, EventCategory

# ── Dashboard ext imports ────────────────────────────────────────────

from citadel_archer.api.dashboard_ext import (
    DashboardServices,
    TTLCache,
    TimelineResponse,
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
    event_type="test",
):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    return AggregatedEvent(
        event_id=event_id,
        event_type=event_type,
        severity=severity,
        message=message,
        timestamp=timestamp,
        asset_id=asset_id,
        category=category,
        details={},
    )


def _make_events(count=100, hours=24):
    """Generate spread events for testing."""
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
            asset_id=f"asset-{i % 5}",
            event_type=f"type-{i % 8}",
            message=f"Event {i} description for testing search",
        ))
    return events


def _make_entries(count=100, hours=24):
    """Generate TimelineEntry list."""
    events = _make_events(count, hours)
    return [TimelineEntry.from_event(e) for e in events]


# =====================================================================
# Section 1: Filtering (3 dimensions + search)
# =====================================================================

class TestFilterEntries:
    """filter_entries() with severity, asset, event_type, search."""

    def test_no_filters_returns_all(self):
        entries = _make_entries(20)
        result = filter_entries(entries)
        assert len(result) == 20

    def test_filter_by_severity(self):
        entries = _make_entries(40)
        result = filter_entries(entries, severity="critical")
        assert all(e.severity == "critical" for e in result)
        assert len(result) == 10  # 40 / 4 severities

    def test_filter_by_asset(self):
        entries = _make_entries(50)
        result = filter_entries(entries, asset_id="asset-0")
        assert all(e.asset_id == "asset-0" for e in result)
        assert len(result) == 10  # 50 / 5 assets

    def test_filter_by_event_type(self):
        entries = _make_entries(40)
        result = filter_entries(entries, event_type="type-0")
        assert all(e.event_type == "type-0" for e in result)

    def test_filter_by_search_description(self):
        entries = _make_entries(20)
        result = filter_entries(entries, search="Event 5")
        assert any("Event 5" in e.description for e in result)

    def test_filter_by_search_asset(self):
        entries = _make_entries(20)
        result = filter_entries(entries, search="asset-2")
        assert all("asset-2" in e.asset_id for e in result)

    def test_filter_combined_severity_and_asset(self):
        entries = _make_entries(100)
        result = filter_entries(entries, severity="info", asset_id="asset-0")
        assert all(e.severity == "info" and e.asset_id == "asset-0" for e in result)

    def test_filter_by_category(self):
        entries = _make_entries(40)
        result = filter_entries(entries, category="system")
        assert all(e.category.lower() == "system" for e in result)

    def test_empty_entries_returns_empty(self):
        result = filter_entries([], severity="critical")
        assert result == []


# =====================================================================
# Section 2: Sorting (3 columns)
# =====================================================================

class TestSortEntries:
    """sort_entries() with time, severity, asset."""

    def test_sort_by_time_desc(self):
        entries = _make_entries(20)
        result = sort_entries(entries, SortField.TIME, SortOrder.DESC)
        for i in range(len(result) - 1):
            assert result[i].timestamp >= result[i + 1].timestamp

    def test_sort_by_time_asc(self):
        entries = _make_entries(20)
        result = sort_entries(entries, SortField.TIME, SortOrder.ASC)
        for i in range(len(result) - 1):
            assert result[i].timestamp <= result[i + 1].timestamp

    def test_sort_by_severity_desc(self):
        entries = _make_entries(20)
        result = sort_entries(entries, SortField.SEVERITY, SortOrder.DESC)
        # First entries should be critical (rank 4)
        assert result[0].severity == "critical"

    def test_sort_by_severity_asc(self):
        entries = _make_entries(20)
        result = sort_entries(entries, SortField.SEVERITY, SortOrder.ASC)
        # First entries should be info (rank 0)
        assert result[0].severity == "info"

    def test_sort_by_asset(self):
        entries = _make_entries(20)
        result = sort_entries(entries, SortField.ASSET, SortOrder.ASC)
        for i in range(len(result) - 1):
            assert result[i].asset_id <= result[i + 1].asset_id

    def test_sort_by_event_type(self):
        entries = _make_entries(20)
        result = sort_entries(entries, SortField.EVENT_TYPE, SortOrder.ASC)
        for i in range(len(result) - 1):
            assert result[i].event_type <= result[i + 1].event_type

    def test_sort_preserves_count(self):
        entries = _make_entries(30)
        result = sort_entries(entries, SortField.TIME, SortOrder.DESC)
        assert len(result) == 30


# =====================================================================
# Section 3: Pagination
# =====================================================================

class TestPagination:
    """paginate() with 50 per page."""

    def test_first_page(self):
        entries = _make_entries(120)
        page_entries, total_pages = paginate(entries, page=1, page_size=50)
        assert len(page_entries) == 50
        assert total_pages == 3

    def test_second_page(self):
        entries = _make_entries(120)
        page_entries, total_pages = paginate(entries, page=2, page_size=50)
        assert len(page_entries) == 50

    def test_last_page_partial(self):
        entries = _make_entries(120)
        page_entries, total_pages = paginate(entries, page=3, page_size=50)
        assert len(page_entries) == 20

    def test_page_out_of_range_clamped(self):
        entries = _make_entries(30)
        page_entries, total_pages = paginate(entries, page=999, page_size=50)
        assert total_pages == 1
        assert len(page_entries) == 30

    def test_empty_entries(self):
        page_entries, total_pages = paginate([], page=1, page_size=50)
        assert len(page_entries) == 0
        assert total_pages == 1


# =====================================================================
# Section 4: Drill-down
# =====================================================================

class TestDrillDown:
    """drill_down() detail panel."""

    def test_finds_target_event(self):
        entries = _make_entries(20)
        result = drill_down("evt-5", entries)
        assert result is not None
        assert result.entry.event_id == "evt-5"

    def test_unknown_event_returns_none(self):
        entries = _make_entries(10)
        result = drill_down("nonexistent", entries)
        assert result is None

    def test_related_events_same_asset(self):
        now = datetime.utcnow()
        entries = [
            TimelineEntry(event_id="a", timestamp=now.isoformat(), asset_id="x", event_type="t1", severity="info", description="d", category="system"),
            TimelineEntry(event_id="b", timestamp=(now - timedelta(minutes=5)).isoformat(), asset_id="x", event_type="t2", severity="alert", description="d2", category="network"),
        ]
        result = drill_down("a", entries)
        assert len(result.related_events) == 1
        assert result.related_events[0].event_id == "b"

    def test_related_events_same_type(self):
        now = datetime.utcnow()
        entries = [
            TimelineEntry(event_id="a", timestamp=now.isoformat(), asset_id="x", event_type="t1", severity="info", description="d", category="system"),
            TimelineEntry(event_id="b", timestamp=(now - timedelta(minutes=10)).isoformat(), asset_id="y", event_type="t1", severity="alert", description="d2", category="network"),
        ]
        result = drill_down("a", entries)
        assert len(result.related_events) == 1

    def test_context_includes_severity_rank(self):
        entries = _make_entries(10)
        result = drill_down("evt-3", entries)
        assert "severity_rank" in result.context

    def test_drill_down_respects_max_related(self):
        now = datetime.utcnow()
        entries = [TimelineEntry(event_id="target", timestamp=now.isoformat(), asset_id="x", event_type="t", severity="info", description="d", category="system")]
        for i in range(50):
            entries.append(TimelineEntry(
                event_id=f"r-{i}", timestamp=(now - timedelta(minutes=i)).isoformat(),
                asset_id="x", event_type="other", severity="info", description="d", category="system",
            ))
        result = drill_down("target", entries, max_related=5)
        assert len(result.related_events) <= 5


# =====================================================================
# Section 5: AlertTimeline class (query API)
# =====================================================================

class TestAlertTimeline:
    """AlertTimeline.query() full pipeline."""

    def test_load_events(self):
        events = _make_events(50)
        tl = AlertTimeline(events)
        assert tl.size == 50

    def test_query_returns_timeline_view(self):
        tl = AlertTimeline(_make_events(100))
        view = tl.query()
        assert isinstance(view, TimelineView)
        assert view.total_unfiltered == 100
        assert view.page_size == 50
        assert len(view.entries) == 50  # first page

    def test_query_with_severity_filter(self):
        tl = AlertTimeline(_make_events(100))
        view = tl.query(severity="critical")
        assert view.total_filtered == 25  # 100 / 4 severities
        assert all(e.severity == "critical" for e in view.entries)

    def test_query_with_search(self):
        tl = AlertTimeline(_make_events(50))
        view = tl.query(search="Event 1")
        assert view.total_filtered > 0

    def test_query_page_2(self):
        tl = AlertTimeline(_make_events(120))
        view = tl.query(page=2)
        assert view.page == 2
        assert len(view.entries) == 50

    def test_unique_assets(self):
        tl = AlertTimeline(_make_events(50))
        assets = tl.unique_assets()
        assert len(assets) == 5  # asset-0..asset-4

    def test_unique_event_types(self):
        tl = AlertTimeline(_make_events(50))
        types = tl.unique_event_types()
        assert len(types) == 8  # type-0..type-7

    def test_unique_severities(self):
        tl = AlertTimeline(_make_events(50))
        sevs = tl.unique_severities()
        assert len(sevs) == 4

    def test_summary(self):
        tl = AlertTimeline(_make_events(100))
        s = tl.summary()
        assert s["total"] == 100
        assert s["unique_assets"] == 5

    def test_drill_down_via_class(self):
        tl = AlertTimeline(_make_events(20))
        result = tl.drill_down("evt-5")
        assert result is not None
        assert result.entry.event_id == "evt-5"

    def test_to_dict_serialisable(self):
        tl = AlertTimeline(_make_events(10))
        view = tl.query()
        d = view.to_dict()
        json_str = json.dumps(d)
        assert len(json_str) > 0


# =====================================================================
# Section 6: Performance (1000+ events)
# =====================================================================

class TestTimelinePerformance:
    """1000+ event rendering performance."""

    def test_1000_events_filter_under_1_second(self):
        entries = _make_entries(1000)
        start = time.time()
        result = filter_entries(entries, severity="critical", search="Event")
        elapsed = time.time() - start
        assert elapsed < 1.0
        assert len(result) > 0

    def test_1000_events_sort_under_1_second(self):
        entries = _make_entries(1000)
        start = time.time()
        result = sort_entries(entries, SortField.SEVERITY, SortOrder.DESC)
        elapsed = time.time() - start
        assert elapsed < 1.0
        assert len(result) == 1000

    def test_1000_events_paginate(self):
        entries = _make_entries(1000)
        page_entries, total_pages = paginate(entries, page=5, page_size=50)
        assert total_pages == 20
        assert len(page_entries) == 50

    def test_1000_events_full_query(self):
        tl = AlertTimeline(_make_events(1000))
        start = time.time()
        view = tl.query(severity="critical", sort_field=SortField.TIME, page=3)
        elapsed = time.time() - start
        assert elapsed < 2.0
        assert view.page == 3


# =====================================================================
# Section 7: Dashboard Services Timeline API
# =====================================================================

class TestDashboardServicesTimeline:
    """DashboardServices.get_timeline()."""

    def test_no_aggregator_returns_empty(self):
        svc = DashboardServices()
        result = svc.get_timeline(limit=50)
        assert isinstance(result, TimelineResponse)
        assert result.total == 0

    def test_caches_timeline(self):
        svc = DashboardServices()
        r1 = svc.get_timeline(limit=50)
        r2 = svc.get_timeline(limit=50)
        assert r1.generated_at == r2.generated_at


# =====================================================================
# Section 8: HTML Structure Validation
# =====================================================================

class TestTimelineHTML:
    """Validate timeline.html structure."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "timeline.html"
        if not path.exists():
            pytest.skip("timeline.html not found")
        return path.read_text()

    def test_has_d3_cdn(self, html_content):
        assert "d3" in html_content.lower()
        assert "cdn" in html_content.lower()

    def test_has_tailwind_cdn(self, html_content):
        assert "cdn.tailwindcss.com" in html_content

    def test_has_timeline_table(self, html_content):
        assert 'id="timeline-table"' in html_content

    def test_has_filter_controls(self, html_content):
        assert 'id="filter-severity"' in html_content
        assert 'id="filter-asset"' in html_content
        assert 'id="filter-event-type"' in html_content

    def test_has_search_input(self, html_content):
        assert 'id="search-input"' in html_content

    def test_has_pagination_controls(self, html_content):
        assert 'id="page-prev"' in html_content
        assert 'id="page-next"' in html_content
        assert 'id="pagination-info"' in html_content

    def test_has_detail_panel(self, html_content):
        assert 'id="detail-panel"' in html_content
        assert 'id="detail-content"' in html_content

    def test_has_d3_timeline_viz(self, html_content):
        assert 'id="d3-timeline-viz"' in html_content

    def test_has_sort_headers(self, html_content):
        assert 'data-sort="time"' in html_content
        assert 'data-sort="severity"' in html_content
        assert 'data-sort="asset"' in html_content

    def test_has_dashboard_link(self, html_content):
        assert 'href="index.html"' in html_content

    def test_has_charts_link(self, html_content):
        assert 'href="charts.html"' in html_content

    def test_has_vault_link(self, html_content):
        assert 'href="vault.html"' in html_content

    def test_has_glassmorphic_theme(self, html_content):
        assert "glass-card" in html_content
        assert "dark-bg" in html_content
        assert "neon-blue" in html_content

    def test_has_responsive_styles(self, html_content):
        assert "640px" in html_content

    def test_loads_timeline_js(self, html_content):
        assert 'src="js/timeline.js"' in html_content

    def test_has_severity_badge_styles(self, html_content):
        assert "sev-info" in html_content or ".sev-info" in html_content
        assert "sev-critical" in html_content or ".sev-critical" in html_content

    def test_has_live_badge(self, html_content):
        assert 'id="live-badge"' in html_content


# =====================================================================
# Section 9: JS File Structure Validation
# =====================================================================

class TestTimelineJS:
    """Validate timeline.js structure."""

    @pytest.fixture
    def js_content(self):
        path = FRONTEND_DIR / "js" / "timeline.js"
        if not path.exists():
            pytest.skip("timeline.js not found")
        return path.read_text()

    def test_imports_api_client(self, js_content):
        assert "api-client" in js_content

    def test_has_sev_colours(self, js_content):
        assert "SEV_COLOURS" in js_content

    def test_has_filter_functions(self, js_content):
        assert "applyFilters" in js_content
        assert "getFilters" in js_content

    def test_has_sort_function(self, js_content):
        assert "sortEntries" in js_content

    def test_has_pagination(self, js_content):
        assert "getPage" in js_content
        assert "PAGE_SIZE" in js_content

    def test_has_drill_down(self, js_content):
        assert "openDetail" in js_content
        assert "closeDetail" in js_content

    def test_has_websocket(self, js_content):
        assert "WebSocket" in js_content
        assert "connectWebSocket" in js_content

    def test_has_d3_rendering(self, js_content):
        assert "d3.select" in js_content or "renderD3Timeline" in js_content

    def test_has_search_debounce(self, js_content):
        assert "setTimeout" in js_content or "debounce" in js_content

    def test_has_escape_html(self, js_content):
        assert "escapeHtml" in js_content

    def test_has_30_second_refresh(self, js_content):
        assert "30000" in js_content

    def test_exports_for_testing(self, js_content):
        assert "export" in js_content


# =====================================================================
# Section 10: Index.html & Route Registration
# =====================================================================

class TestTimelineNavigation:
    """Verify Timeline tab in index.html."""

    @pytest.fixture
    def index_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_timeline_tab(self, index_content):
        assert 'id="tab-btn-timeline"' in index_content

    def test_has_timeline_panel(self, index_content):
        assert 'id="tab-panel-timeline"' in index_content

    def test_timeline_tab_after_charts(self, index_content):
        charts_pos = index_content.index('id="tab-btn-charts"')
        timeline_pos = index_content.index('id="tab-btn-timeline"')
        assert timeline_pos > charts_pos


class TestTimelineRoutes:
    """Verify timeline routes in main.py."""

    @pytest.fixture
    def main_content(self):
        path = Path(__file__).parent.parent / "src" / "citadel_archer" / "api" / "main.py"
        if not path.exists():
            pytest.skip("main.py not found")
        return path.read_text()

    def test_timeline_html_route(self, main_content):
        assert "/timeline.html" in main_content

    def test_timeline_redirect_route(self, main_content):
        assert '"/timeline"' in main_content
