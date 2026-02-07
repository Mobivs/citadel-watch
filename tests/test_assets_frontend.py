# PRD: Tests - Multi-Asset View Table (P2.1.5-T4)
# Reference: PHASE_2_SPEC.md
#
# 30+ tests covering:
#   - Backend asset_view module (filtering, sorting, colour coding, drill-down)
#   - Dashboard services assets API
#   - HTML structure validation
#   - JS file structure validation
#   - Route registration
#   - Pagination logic
#   - Search filtering

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# ── Intel module imports ─────────────────────────────────────────────

from citadel_archer.intel.asset_view import (
    AssetDetail,
    AssetRow,
    AssetSortField,
    AssetSortOrder,
    AssetTableView,
    AssetView,
    _ROW_COLOURS,
    _STATUS_COLOURS,
    build_asset_row,
    filter_asset_rows,
    sort_asset_rows,
)
from citadel_archer.intel.assets import Asset, AssetInventory, AssetPlatform, AssetStatus
from citadel_archer.intel.event_aggregator import AggregatedEvent, EventCategory
from citadel_archer.intel.threat_scorer import RiskLevel, ScoredThreat

# ── Dashboard ext imports ────────────────────────────────────────────

from citadel_archer.api.dashboard_ext import (
    AssetsResponse,
    DashboardServices,
)


# ── Helpers ──────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def _make_asset(asset_id="a-1", name="TestBox", status=AssetStatus.ONLINE, platform=AssetPlatform.LOCAL):
    return Asset(asset_id=asset_id, name=name, status=status, platform=platform,
                 hostname=f"{name}.local", ip_address="10.0.0.1")


def _make_event(event_id="e-1", asset_id="a-1", timestamp=None, severity="info"):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    return AggregatedEvent(
        event_id=event_id, event_type="test", severity=severity,
        message="test event", timestamp=timestamp, asset_id=asset_id,
        category=EventCategory.SYSTEM, details={},
    )


def _make_scored(asset_id="a-1", risk_level=RiskLevel.LOW, timestamp=None):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    return ScoredThreat(
        event_id="e-1", event_type="test", severity="info", message="test",
        timestamp=timestamp, asset_id=asset_id,
        risk_level=risk_level, risk_score=25.0,
    )


def _make_rows(count=10):
    """Generate asset rows for testing."""
    statuses = ["online", "protected", "offline", "compromised"]
    threats = ["low", "medium", "high", "critical"]
    rows = []
    for i in range(count):
        rows.append(AssetRow(
            asset_id=f"a-{i}",
            asset_name=f"Asset-{i}",
            status=statuses[i % len(statuses)],
            threat_level=threats[i % len(threats)],
            last_event=(datetime.utcnow() - timedelta(hours=i)).isoformat(),
            event_count_24h=i * 5,
            row_colour=_ROW_COLOURS.get(threats[i % len(threats)], ""),
            status_colour=_STATUS_COLOURS.get(statuses[i % len(statuses)], ""),
        ))
    return rows


# =====================================================================
# Section 1: Filtering (status + threat level)
# =====================================================================

class TestFilterAssetRows:
    """filter_asset_rows() with status and threat level."""

    def test_no_filters_returns_all(self):
        rows = _make_rows(10)
        result = filter_asset_rows(rows)
        assert len(result) == 10

    def test_filter_by_status(self):
        rows = _make_rows(12)
        result = filter_asset_rows(rows, status="online")
        assert all(r.status == "online" for r in result)
        assert len(result) == 3  # 12 / 4 statuses

    def test_filter_by_threat_level(self):
        rows = _make_rows(12)
        result = filter_asset_rows(rows, threat_level="critical")
        assert all(r.threat_level == "critical" for r in result)
        assert len(result) == 3

    def test_filter_combined(self):
        rows = _make_rows(20)
        result = filter_asset_rows(rows, status="online", threat_level="low")
        assert all(r.status == "online" and r.threat_level == "low" for r in result)

    def test_filter_case_insensitive(self):
        rows = _make_rows(10)
        result = filter_asset_rows(rows, status="ONLINE")
        assert len(result) > 0

    def test_empty_rows(self):
        result = filter_asset_rows([], status="online")
        assert result == []


# =====================================================================
# Section 2: Sorting (all columns)
# =====================================================================

class TestSortAssetRows:
    """sort_asset_rows() on all 5 columns."""

    def test_sort_by_name_asc(self):
        rows = _make_rows(10)
        result = sort_asset_rows(rows, AssetSortField.NAME, AssetSortOrder.ASC)
        for i in range(len(result) - 1):
            assert result[i].asset_name.lower() <= result[i + 1].asset_name.lower()

    def test_sort_by_name_desc(self):
        rows = _make_rows(10)
        result = sort_asset_rows(rows, AssetSortField.NAME, AssetSortOrder.DESC)
        for i in range(len(result) - 1):
            assert result[i].asset_name.lower() >= result[i + 1].asset_name.lower()

    def test_sort_by_threat_level_desc(self):
        rows = _make_rows(10)
        result = sort_asset_rows(rows, AssetSortField.THREAT_LEVEL, AssetSortOrder.DESC)
        assert result[0].threat_level == "critical"

    def test_sort_by_threat_level_asc(self):
        rows = _make_rows(10)
        result = sort_asset_rows(rows, AssetSortField.THREAT_LEVEL, AssetSortOrder.ASC)
        assert result[0].threat_level == "low"

    def test_sort_by_status(self):
        rows = _make_rows(10)
        result = sort_asset_rows(rows, AssetSortField.STATUS, AssetSortOrder.DESC)
        assert result[0].status == "compromised"

    def test_sort_by_event_count(self):
        rows = _make_rows(10)
        result = sort_asset_rows(rows, AssetSortField.EVENT_COUNT, AssetSortOrder.DESC)
        assert result[0].event_count_24h >= result[-1].event_count_24h

    def test_sort_preserves_count(self):
        rows = _make_rows(15)
        result = sort_asset_rows(rows, AssetSortField.NAME, AssetSortOrder.ASC)
        assert len(result) == 15


# =====================================================================
# Section 3: Colour Coding
# =====================================================================

class TestColourCoding:
    """Row colour coding by threat level."""

    def test_critical_row_colour(self):
        assert "239, 68, 68" in _ROW_COLOURS["critical"]

    def test_high_row_colour(self):
        assert "249, 115, 22" in _ROW_COLOURS["high"]

    def test_medium_row_colour(self):
        assert "245, 158, 11" in _ROW_COLOURS["medium"]

    def test_low_row_colour(self):
        assert "16, 185, 129" in _ROW_COLOURS["low"]

    def test_status_online_colour(self):
        assert "16, 185, 129" in _STATUS_COLOURS["online"]

    def test_status_compromised_colour(self):
        assert "239, 68, 68" in _STATUS_COLOURS["compromised"]

    def test_build_row_assigns_colours(self):
        asset = _make_asset()
        threats = [_make_scored(risk_level=RiskLevel.CRITICAL)]
        row = build_asset_row(asset, [], threats)
        assert row.row_colour == _ROW_COLOURS["critical"]
        assert row.threat_level == "critical"


# =====================================================================
# Section 4: build_asset_row
# =====================================================================

class TestBuildAssetRow:
    """build_asset_row() from asset + events + threats."""

    def test_empty_events_and_threats(self):
        asset = _make_asset()
        row = build_asset_row(asset, [], [])
        assert row.threat_level == "low"
        assert row.event_count_24h == 0
        assert row.last_event == ""

    def test_with_events(self):
        asset = _make_asset()
        events = [_make_event(), _make_event(event_id="e-2")]
        row = build_asset_row(asset, events, [])
        assert row.event_count_24h == 2
        assert row.last_event != ""

    def test_threat_level_from_scored(self):
        asset = _make_asset()
        threats = [
            _make_scored(risk_level=RiskLevel.HIGH),
            _make_scored(risk_level=RiskLevel.LOW),
        ]
        row = build_asset_row(asset, [], threats)
        assert row.threat_level == "high"
        assert row.high_count == 1
        assert row.low_count == 1


# =====================================================================
# Section 5: AssetView engine (query + drill-down)
# =====================================================================

class TestAssetViewEngine:
    """AssetView.query() and asset_detail()."""

    def test_query_empty(self):
        view = AssetView()
        result = view.query()
        assert isinstance(result, AssetTableView)
        assert result.total_assets == 0

    def test_query_with_inventory(self):
        inv = AssetInventory()
        inv.register(_make_asset("a-1", "Box1"))
        inv.register(_make_asset("a-2", "Box2"))
        view = AssetView(inventory=inv)
        result = view.query()
        assert result.total_assets == 2

    def test_query_with_filter(self):
        inv = AssetInventory()
        inv.register(_make_asset("a-1", "Box1", AssetStatus.ONLINE))
        inv.register(_make_asset("a-2", "Box2", AssetStatus.OFFLINE))
        view = AssetView(inventory=inv)
        result = view.query(status="online")
        assert result.total_filtered == 1

    def test_drill_down_found(self):
        inv = AssetInventory()
        inv.register(_make_asset("a-1", "Box1"))
        view = AssetView(inventory=inv)
        view.ingest_events([_make_event(asset_id="a-1")])
        detail = view.asset_detail("a-1")
        assert detail is not None
        assert detail.asset_id == "a-1"

    def test_drill_down_not_found(self):
        view = AssetView()
        detail = view.asset_detail("nonexistent")
        assert detail is None

    def test_to_dict_serialisable(self):
        inv = AssetInventory()
        inv.register(_make_asset("a-1", "Box1"))
        view = AssetView(inventory=inv)
        result = view.query()
        d = result.to_dict()
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_summary(self):
        inv = AssetInventory()
        inv.register(_make_asset("a-1", "Box1", AssetStatus.ONLINE))
        inv.register(_make_asset("a-2", "Box2", AssetStatus.OFFLINE))
        view = AssetView(inventory=inv)
        s = view.summary()
        assert s["total_assets"] == 2
        assert "online" in s["by_status"]


# =====================================================================
# Section 6: Dashboard Services Assets API
# =====================================================================

class TestDashboardServicesAssets:
    """DashboardServices.get_assets()."""

    def test_no_inventory_returns_empty(self):
        svc = DashboardServices()
        result = svc.get_assets()
        assert isinstance(result, AssetsResponse)
        assert result.total == 0

    def test_caches_result(self):
        svc = DashboardServices()
        r1 = svc.get_assets()
        r2 = svc.get_assets()
        assert r1.generated_at == r2.generated_at


# =====================================================================
# Section 7: HTML Structure
# =====================================================================

class TestAssetsHTML:
    """Validate assets.html structure."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "assets.html"
        if not path.exists():
            pytest.skip("assets.html not found")
        return path.read_text()

    def test_has_tailwind_cdn(self, html_content):
        assert "cdn.tailwindcss.com" in html_content

    def test_has_asset_table(self, html_content):
        assert 'id="asset-table"' in html_content

    def test_has_sort_headers(self, html_content):
        assert 'data-sort="name"' in html_content
        assert 'data-sort="status"' in html_content
        assert 'data-sort="threat_level"' in html_content
        assert 'data-sort="last_event"' in html_content
        assert 'data-sort="event_count"' in html_content

    def test_has_filter_controls(self, html_content):
        assert 'id="filter-status"' in html_content
        assert 'id="filter-threat"' in html_content

    def test_has_search_input(self, html_content):
        assert 'id="search-input"' in html_content

    def test_has_pagination(self, html_content):
        assert 'id="page-prev"' in html_content
        assert 'id="page-next"' in html_content
        assert 'id="page-size-select"' in html_content

    def test_has_detail_panel(self, html_content):
        assert 'id="detail-panel"' in html_content
        assert 'id="detail-content"' in html_content

    def test_has_stats_pills(self, html_content):
        assert 'id="stat-online"' in html_content
        assert 'id="stat-total"' in html_content

    def test_has_navigation_links(self, html_content):
        assert 'href="index.html"' in html_content
        assert 'href="charts.html"' in html_content
        assert 'href="timeline.html"' in html_content
        assert 'href="vault.html"' in html_content

    def test_has_glassmorphic_theme(self, html_content):
        assert "glass-card" in html_content
        assert "dark-bg" in html_content

    def test_has_responsive_styles(self, html_content):
        assert "640px" in html_content

    def test_loads_assets_js(self, html_content):
        assert 'src="js/assets.js"' in html_content

    def test_has_live_badge(self, html_content):
        assert 'id="live-badge"' in html_content

    def test_has_status_badge_styles(self, html_content):
        assert "status-online" in html_content
        assert "status-compromised" in html_content

    def test_has_threat_badge_styles(self, html_content):
        assert "threat-critical" in html_content
        assert "threat-low" in html_content


# =====================================================================
# Section 8: JS File Structure
# =====================================================================

class TestAssetsJS:
    """Validate assets.js structure."""

    @pytest.fixture
    def js_content(self):
        path = FRONTEND_DIR / "js" / "assets.js"
        if not path.exists():
            pytest.skip("assets.js not found")
        return path.read_text()

    def test_imports_api_client(self, js_content):
        assert "api-client" in js_content

    def test_has_threat_rank(self, js_content):
        assert "THREAT_RANK" in js_content

    def test_has_status_rank(self, js_content):
        assert "STATUS_RANK" in js_content

    def test_has_fetch_assets(self, js_content):
        assert "fetchAssets" in js_content

    def test_has_filter_functions(self, js_content):
        assert "applyFilters" in js_content

    def test_has_sort_function(self, js_content):
        assert "sortAssets" in js_content

    def test_has_pagination(self, js_content):
        assert "getPage" in js_content

    def test_has_drill_down(self, js_content):
        assert "openDetail" in js_content
        assert "closeDetail" in js_content

    def test_has_websocket(self, js_content):
        assert "WebSocket" in js_content

    def test_has_threat_level_derivation(self, js_content):
        assert "assetThreatLevel" in js_content

    def test_has_30_second_refresh(self, js_content):
        assert "30000" in js_content

    def test_has_exports(self, js_content):
        assert "export" in js_content

    def test_has_escape_html(self, js_content):
        assert "escapeHtml" in js_content


# =====================================================================
# Section 9: Navigation & Routes
# =====================================================================

class TestAssetsNavigation:
    """Verify Assets tab in index.html."""

    @pytest.fixture
    def index_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_assets_link(self, index_content):
        assert 'href="assets.html"' in index_content

    def test_assets_link_after_risk(self, index_content):
        risk_pos = index_content.index('href="risk-metrics.html"')
        assets_pos = index_content.index('href="assets.html"')
        assert assets_pos > risk_pos


class TestAssetsRoutes:
    """Verify routes in main.py."""

    @pytest.fixture
    def main_content(self):
        path = Path(__file__).parent.parent / "src" / "citadel_archer" / "api" / "main.py"
        if not path.exists():
            pytest.skip("main.py not found")
        return path.read_text()

    def test_assets_html_route(self, main_content):
        assert "/assets.html" in main_content

    def test_assets_page_route(self, main_content):
        assert "assets-page" in main_content or "assets.html" in main_content
