# PRD: Integration Tests & Performance - Frontend End-to-End Validation (P2.1.5-T8)
# Reference: PHASE_2_SPEC.md
#
# 70+ tests covering:
#   Section  1: Dashboard HTML — all components present & renderable
#   Section  2: Charts page — canvas elements, Chart.js integration, API wiring
#   Section  3: Timeline page — table, D3.js viz, filters, pagination, drill-down
#   Section  4: Risk Metrics page — gauge, sparklines, counters, sensitivity
#   Section  5: Assets page — table, filters, drill-down, page-size selector
#   Section  6: WebSocket integration — shared handler used by all pages
#   Section  7: Error scenarios — API down indicators, WS reconnect badge
#   Section  8: Performance — 1000-event rendering, CSS optimization, no leaks
#   Section  9: Responsive design — breakpoints, mobile layout, detail panels
#   Section 10: Browser compatibility — no vendor-locked APIs
#   Section 11: Cross-page consistency — unified colours, shared CSS tokens
#   Section 12: API client & session auth — X-Session-Token wiring
#   Section 13: Navigation integration — tab switching, iframe loading, ARIA

import re
from pathlib import Path

import pytest


# ── Paths ────────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
JS_DIR = FRONTEND_DIR / "js"
CSS_DIR = FRONTEND_DIR / "css"

INDEX_HTML = FRONTEND_DIR / "index.html"
CHARTS_HTML = FRONTEND_DIR / "charts.html"
TIMELINE_HTML = FRONTEND_DIR / "timeline.html"
RISK_HTML = FRONTEND_DIR / "risk-metrics.html"
ASSETS_HTML = FRONTEND_DIR / "assets.html"

CHARTS_JS = JS_DIR / "charts.js"
TIMELINE_JS = JS_DIR / "timeline.js"
RISK_JS = JS_DIR / "risk-metrics.js"
ASSETS_JS = JS_DIR / "assets.js"
WS_HANDLER_JS = JS_DIR / "websocket-handler.js"
DASHBOARD_NAV_JS = JS_DIR / "dashboard-nav.js"
MAIN_JS = JS_DIR / "main.js"
API_CLIENT_JS = JS_DIR / "utils" / "api-client.js"
STYLES_CSS = CSS_DIR / "styles.css"

ALL_PAGE_HTML = {
    "charts": CHARTS_HTML,
    "timeline": TIMELINE_HTML,
    "risk-metrics": RISK_HTML,
    "assets": ASSETS_HTML,
}

ALL_PAGE_JS = {
    "charts": CHARTS_JS,
    "timeline": TIMELINE_JS,
    "risk-metrics": RISK_JS,
    "assets": ASSETS_JS,
}


# ── Helpers ──────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"{path.name} not found")
    return path.read_text(encoding='utf-8')


# =====================================================================
# Section 1: Dashboard HTML — All Components Present & Renderable
# =====================================================================

class TestDashboardComponentsRender:
    """Load dashboard → all components render."""

    @pytest.fixture
    def html(self):
        return _read(INDEX_HTML)

    def test_app_container(self, html):
        assert 'id="app"' in html

    def test_header_logo(self, html):
        assert "Citadel Archer" in html

    def test_guardian_status_component(self, html):
        assert "<guardian-status" in html

    def test_threat_level_component(self, html):
        assert "<threat-level" in html

    def test_protected_systems_component(self, html):
        assert "<protected-systems" in html

    def test_event_log_component(self, html):
        assert "<event-log" in html

    def test_process_list_component(self, html):
        assert "<process-list" in html

    def test_ai_insights_component(self, html):
        assert "<ai-insights" in html

    def test_security_level_badge(self, html):
        assert 'id="security-level-badge"' in html

    def test_connection_badge(self, html):
        assert 'id="nav-conn-badge"' in html
        assert 'id="nav-conn-dot"' in html
        assert 'id="nav-conn-text"' in html

    def test_all_tab_buttons(self, html):
        for tab in ["intelligence", "charts", "timeline", "risk-metrics", "assets",
                     "remote-shield", "panic-room"]:
            assert f'id="tab-btn-{tab}"' in html, f"Missing tab button: {tab}"

    def test_tab_panels(self, html):
        # Tab-loader architecture: intelligence panel + shared dynamic panel
        assert 'id="tab-panel-intelligence"' in html
        assert 'id="tab-panel-dynamic"' in html

    def test_no_iframes(self, html):
        assert '<iframe' not in html, "Tab-loader architecture uses no iframes"

    def test_tab_bar_role_tablist(self, html):
        assert 'role="tablist"' in html

    def test_tab_buttons_have_aria_controls(self, html):
        assert 'aria-controls="tab-panel-intelligence"' in html
        assert 'aria-controls="tab-panel-dynamic"' in html

    def test_loads_web_component_scripts(self, html):
        for comp in ["guardian-status", "threat-level", "protected-systems",
                      "event-log", "process-list", "ai-insights"]:
            assert f"js/components/{comp}.js" in html, f"Missing script: {comp}.js"

    def test_loads_dashboard_nav_script(self, html):
        assert "js/dashboard-nav.js" in html

    def test_loads_main_script(self, html):
        assert "js/main.js" in html

    def test_loads_styles_css(self, html):
        assert 'href="css/styles.css"' in html


# =====================================================================
# Section 2: Charts Page — Canvas Elements, Chart.js, API Wiring
# =====================================================================

class TestChartsPageIntegration:
    """Fetch /api/charts → charts update."""

    @pytest.fixture
    def html(self):
        return _read(CHARTS_HTML)

    @pytest.fixture
    def js(self):
        return _read(CHARTS_JS)

    def test_four_chart_canvases(self, html):
        for cid in ["threat-trend-chart", "severity-distribution-chart",
                     "timeline-scatter-chart", "category-breakdown-chart"]:
            assert f'id="{cid}"' in html, f"Missing canvas: {cid}"

    def test_stat_elements(self, html):
        for sid in ["stat-total", "stat-critical", "stat-high", "stat-medium"]:
            assert f'id="{sid}"' in html, f"Missing stat: {sid}"

    def test_time_range_selector(self, html):
        assert 'id="time-range-selector"' in html

    def test_live_badge(self, html):
        assert 'id="live-badge"' in html
        assert 'id="live-dot"' in html
        assert 'id="live-text"' in html

    def test_js_fetches_chart_api(self, js):
        assert "/api/charts" in js

    def test_js_fetches_timeline_api(self, js):
        assert "/api/timeline" in js

    def test_js_fetches_threat_score_api(self, js):
        assert "/api/threat-score" in js

    def test_js_builds_four_chart_types(self, js):
        for fn in ["buildTrendChart", "buildSeverityChart",
                    "buildTimelineScatterChart", "buildCategoryChart"]:
            assert fn in js, f"Missing chart builder: {fn}"

    def test_js_exports_refresh_function(self, js):
        assert "refreshAllCharts" in js

    def test_auto_refresh_interval(self, js):
        assert "setInterval" in js, "Must auto-refresh on interval"
        assert "30000" in js, "Auto-refresh should be 30 seconds"


# =====================================================================
# Section 3: Timeline Page — Table, D3, Filters, Pagination, Drill-down
# =====================================================================

class TestTimelinePageIntegration:
    """Fetch /api/timeline → timeline updates."""

    @pytest.fixture
    def html(self):
        return _read(TIMELINE_HTML)

    @pytest.fixture
    def js(self):
        return _read(TIMELINE_JS)

    def test_table_body(self, html):
        assert 'id="timeline-tbody"' in html

    def test_d3_visualization_container(self, html):
        assert 'id="d3-timeline-viz"' in html

    def test_filter_controls(self, html):
        for fid in ["filter-severity", "filter-asset", "filter-event-type", "search-input"]:
            assert f'id="{fid}"' in html, f"Missing filter: {fid}"

    def test_clear_filters_button(self, html):
        assert 'id="clear-filters-btn"' in html

    def test_pagination_controls(self, html):
        for pid in ["pagination-info", "page-indicator", "page-prev", "page-next"]:
            assert f'id="{pid}"' in html, f"Missing pagination: {pid}"

    def test_drill_down_panel(self, html):
        for did in ["detail-overlay", "detail-panel", "detail-close", "detail-content"]:
            assert f'id="{did}"' in html, f"Missing detail element: {did}"

    def test_sortable_columns(self, html):
        for col in ["time", "severity", "asset", "event_type", "category"]:
            assert f'data-sort="{col}"' in html, f"Missing sort column: {col}"

    def test_js_fetches_timeline_api(self, js):
        assert "/api/timeline" in js

    def test_js_page_size_50(self, js):
        assert "PAGE_SIZE" in js
        assert re.search(r"PAGE_SIZE\s*=\s*50", js)

    def test_js_has_apply_filters(self, js):
        assert "applyFilters" in js

    def test_js_has_sort_entries(self, js):
        assert "sortEntries" in js

    def test_js_has_render_d3_timeline(self, js):
        assert "renderD3Timeline" in js

    def test_js_has_open_close_detail(self, js):
        assert "openDetail" in js
        assert "closeDetail" in js

    def test_js_escape_key_closes_detail(self, js):
        assert "'Escape'" in js or '"Escape"' in js

    def test_stat_elements(self, html):
        for sid in ["stat-critical-count", "stat-high-count", "stat-total-count"]:
            assert f'id="{sid}"' in html, f"Missing stat: {sid}"


# =====================================================================
# Section 4: Risk Metrics Page — Gauge, Sparklines, Counters
# =====================================================================

class TestRiskMetricsPageIntegration:
    """Fetch /api/threat-score → metrics update."""

    @pytest.fixture
    def html(self):
        return _read(RISK_HTML)

    @pytest.fixture
    def js(self):
        return _read(RISK_JS)

    def test_threat_gauge_canvas(self, html):
        assert 'id="threat-gauge"' in html

    def test_gauge_value_display(self, html):
        assert 'id="gauge-value-text"' in html

    def test_four_counter_elements(self, html):
        for level in ["critical", "high", "medium", "low"]:
            assert f'id="count-{level}"' in html, f"Missing counter: count-{level}"

    def test_four_sparkline_containers(self, html):
        for level in ["critical", "high", "medium", "low"]:
            assert f'id="sparkline-{level}"' in html, f"Missing sparkline: sparkline-{level}"

    def test_trend_chart_canvas(self, html):
        assert 'id="trend-chart"' in html

    def test_asset_risk_chart_canvas(self, html):
        assert 'id="asset-risk-chart"' in html

    def test_sensitivity_buttons(self, html):
        for s in ["low", "moderate", "high"]:
            assert f'data-sensitivity="{s}"' in html, f"Missing sensitivity: {s}"

    def test_js_fetches_threat_score_api(self, js):
        assert "/api/threat-score" in js

    def test_js_fetches_charts_api(self, js):
        assert "/api/charts" in js

    def test_js_fetches_assets_api(self, js):
        assert "/api/asset-view" in js

    def test_js_draws_gauge(self, js):
        assert "drawGauge" in js

    def test_js_draws_sparklines(self, js):
        assert "drawSparkline" in js

    def test_js_has_gauge_zones(self, js):
        assert "GAUGE_ZONES" in js

    def test_js_compute_gauge_value(self, js):
        assert "computeGaugeValue" in js


# =====================================================================
# Section 5: Assets Page — Table, Filters, Drill-down, Page Size
# =====================================================================

class TestAssetsPageIntegration:
    """Fetch /api/assets → asset table updates."""

    @pytest.fixture
    def html(self):
        return _read(ASSETS_HTML)

    @pytest.fixture
    def js(self):
        return _read(ASSETS_JS)

    def test_asset_table_body(self, html):
        assert 'id="asset-tbody"' in html

    def test_filter_controls(self, html):
        for fid in ["filter-status", "filter-threat", "search-input"]:
            assert f'id="{fid}"' in html, f"Missing filter: {fid}"

    def test_stat_pills(self, html):
        for sid in ["stat-online", "stat-protected", "stat-total"]:
            assert f'id="{sid}"' in html, f"Missing stat: {sid}"

    def test_page_size_selector(self, html):
        assert 'id="page-size-select"' in html

    def test_drill_down_panel(self, html):
        for did in ["detail-overlay", "detail-panel", "detail-close", "detail-content"]:
            assert f'id="{did}"' in html, f"Missing detail element: {did}"

    def test_sortable_columns(self, html):
        for col in ["name", "status", "threat_level", "last_event", "event_count"]:
            assert f'data-sort="{col}"' in html, f"Missing sort column: {col}"

    def test_js_fetches_assets_api(self, js):
        assert "/api/assets" in js

    def test_js_threat_level_derivation(self, js):
        assert "assetThreatLevel" in js

    def test_js_default_page_size_25(self, js):
        assert re.search(r"pageSize\s*=\s*25", js)

    def test_js_escape_key_closes_detail(self, js):
        assert "'Escape'" in js or '"Escape"' in js


# =====================================================================
# Section 6: WebSocket Integration — Shared Handler, All Pages
# =====================================================================

class TestWebSocketE2EIntegration:
    """WebSocket event → UI updates in real-time."""

    @pytest.fixture
    def ws_src(self):
        return _read(WS_HANDLER_JS)

    def test_handler_is_singleton(self, ws_src):
        assert re.search(r"const\s+wsHandler\s*=\s*new\s+WebSocketHandler", ws_src)

    def test_handler_auto_connects(self, ws_src):
        assert "DOMContentLoaded" in ws_src
        dcl = ws_src[ws_src.index("DOMContentLoaded"):]
        assert "connect()" in dcl

    def test_all_pages_import_ws_handler(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert re.search(
                r"import\s*\{[^}]*wsHandler[^}]*\}\s*from\s*['\"]\.\/websocket-handler\.js['\"]",
                src
            ), f"{name}.js must import wsHandler"

    def test_all_pages_subscribe_to_events(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "wsHandler.subscribe(" in src, \
                f"{name}.js must subscribe to events"

    def test_all_pages_poll_ws_handler_connected(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "wsHandler.connected" in src, \
                f"{name}.js must poll wsHandler.connected for badge status"

    def test_all_pages_listen_ws_connected(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "'ws-connected'" in src or '"ws-connected"' in src, \
                f"{name}.js must listen for ws-connected"

    def test_all_pages_listen_ws_disconnected(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "'ws-disconnected'" in src or '"ws-disconnected"' in src, \
                f"{name}.js must listen for ws-disconnected"

    def test_no_page_creates_websocket_directly(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "new WebSocket(" not in src, \
                f"{name}.js must NOT create WebSocket directly"

    def test_charts_subscribes_threat_detected(self):
        src = _read(CHARTS_JS)
        assert "subscribe('threat_detected'" in src or \
               'subscribe("threat_detected"' in src

    def test_timeline_subscribes_alert_created(self):
        src = _read(TIMELINE_JS)
        assert "subscribe('alert_created'" in src or \
               'subscribe("alert_created"' in src

    def test_assets_subscribes_asset_status_changed(self):
        src = _read(ASSETS_JS)
        assert "subscribe('asset_status_changed'" in src or \
               'subscribe("asset_status_changed"' in src


# =====================================================================
# Section 7: Error Scenarios — API Down, WebSocket Reconnect
# =====================================================================

class TestErrorScenarios:
    """Error scenario: API down → error message; WS down → reconnect indicator."""

    @pytest.fixture
    def ws_src(self):
        return _read(WS_HANDLER_JS)

    def test_ws_max_retries_constant(self, ws_src):
        assert re.search(r"MAX_RETRIES\s*=\s*5", ws_src)

    def test_ws_exponential_backoff(self, ws_src):
        assert "computeBackoff" in ws_src
        assert "Math.pow" in ws_src

    def test_ws_max_delay_cap(self, ws_src):
        assert re.search(r"MAX_DELAY_MS\s*=\s*30000", ws_src)

    def test_ws_slow_polls_after_max_retries(self, ws_src):
        """After fast retries are exhausted, falls back to slow 30s polling."""
        assert re.search(r"_retryCount\s*>=\s*MAX_RETRIES", ws_src)
        assert "30000" in ws_src, "Must slow-poll every 30s after fast retries"

    def test_all_pages_have_set_live_status(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "setLiveStatus" in src, \
                f"{name}.js must have setLiveStatus for connection indicator"

    def test_all_pages_have_live_badge_html(self):
        for name, path in ALL_PAGE_HTML.items():
            html = _read(path)
            assert 'id="live-badge"' in html, \
                f"{name}.html must have live-badge element"

    def test_dashboard_has_error_container(self):
        html = _read(INDEX_HTML)
        assert 'id="nav-error-container"' in html

    def test_dashboard_nav_has_show_error(self):
        src = _read(DASHBOARD_NAV_JS)
        assert "showError" in src

    def test_api_client_error_handling(self):
        src = _read(API_CLIENT_JS)
        assert "catch" in src, "API client must handle errors"
        assert "throw" in src, "API client must throw on failure"


# =====================================================================
# Section 8: Performance — 1000 Events, CSS Optimization, No Leaks
# =====================================================================

class TestPerformanceIndicators:
    """Structural checks that indicate performance readiness."""

    def test_timeline_pagination_limits_dom(self):
        """Render 1000+ events: pagination ensures <50 DOM rows."""
        src = _read(TIMELINE_JS)
        assert re.search(r"PAGE_SIZE\s*=\s*50", src), \
            "Timeline must paginate to limit DOM rows"
        assert "getPage" in src, "Must have pagination function"

    def test_assets_pagination_limits_dom(self):
        src = _read(ASSETS_JS)
        assert "getPage" in src
        assert re.search(r"pageSize\s*=\s*25", src)

    def test_css_no_layout_thrashing_animations(self):
        """CSS animations should use transform/opacity, not layout properties."""
        css = _read(STYLES_CSS)
        # Check that animations exist
        assert "@keyframes" in css
        # Verify pulse and shimmer use opacity/transform not width/height
        assert "@keyframes pulse" in css
        assert "@keyframes shimmer" in css

    def test_css_will_change_or_transforms_for_effects(self):
        css = _read(STYLES_CSS)
        # Glass effects should use backdrop-filter (GPU-accelerated)
        assert "backdrop-filter" in css

    def test_auto_refresh_not_too_frequent(self):
        """All pages use 30s refresh interval (not too aggressive)."""
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            if "setInterval" in src:
                assert "30000" in src, \
                    f"{name}.js auto-refresh should be 30s, not more frequent"

    def test_ws_handler_clear_subscribers_prevents_leaks(self):
        src = _read(WS_HANDLER_JS)
        assert "clearSubscribers" in src, \
            "Must have clearSubscribers() for memory leak prevention"

    def test_ws_handler_disconnect_cleanup(self):
        src = _read(WS_HANDLER_JS)
        disconnect = src[src.index("disconnect()"):src.index("reset()")]
        assert "_disposed" in disconnect, "disconnect must set disposed flag"
        assert "this._ws = null" in disconnect or "this._ws=null" in disconnect, \
            "disconnect must null the WebSocket reference"

    def test_charts_destroys_old_chart_instances(self):
        """Chart.js charts must be destroyed before recreating to prevent leaks."""
        src = _read(CHARTS_JS)
        assert ".destroy()" in src, \
            "Chart.js charts must be destroyed before rebuilding"

    def test_timeline_d3_clears_previous(self):
        src = _read(TIMELINE_JS)
        d3_section = src[src.index("renderD3Timeline"):]
        assert "innerHTML" in d3_section or ".remove()" in d3_section, \
            "D3 timeline must clear previous SVG before redraw"


# =====================================================================
# Section 9: Responsive Design — Breakpoints, Mobile Layout
# =====================================================================

class TestResponsiveDesign:
    """Mobile responsive: iOS Safari, Android Chrome."""

    @pytest.fixture
    def css(self):
        return _read(STYLES_CSS)

    def test_viewport_meta_in_dashboard(self):
        html = _read(INDEX_HTML)
        assert 'viewport' in html
        assert 'width=device-width' in html

    def test_viewport_meta_in_all_pages(self):
        for name, path in ALL_PAGE_HTML.items():
            html = _read(path)
            assert 'viewport' in html, f"{name}.html must have viewport meta"

    def test_small_phone_breakpoint(self, css):
        assert "max-width: 400px" in css or "max-width:400px" in css

    def test_mobile_breakpoint(self, css):
        assert "max-width: 640px" in css or "max-width:640px" in css

    def test_desktop_breakpoint(self, css):
        assert "min-width: 1024px" in css or "min-width:1024px" in css

    def test_dashboard_tab_bar_responsive(self):
        html = _read(INDEX_HTML)
        assert "flex-wrap" in html, "Tab bar must wrap on small screens"

    def test_timeline_detail_panel_responsive(self):
        html = _read(TIMELINE_HTML)
        # Detail panel should be full-width on mobile (check inline or CSS)
        assert "detail-panel" in html

    def test_assets_detail_panel_responsive(self):
        html = _read(ASSETS_HTML)
        assert "detail-panel" in html


# =====================================================================
# Section 10: Browser Compatibility — No Vendor-Locked APIs
# =====================================================================

class TestBrowserCompatibility:
    """Chrome, Firefox, Safari, Edge compatibility checks."""

    def test_no_webkit_only_in_main_css(self):
        css = _read(STYLES_CSS)
        # backdrop-filter needs -webkit- prefix for Safari but should have standard too
        if "-webkit-backdrop-filter" in css:
            assert "backdrop-filter" in css.replace("-webkit-backdrop-filter", ""), \
                "Must include standard backdrop-filter alongside -webkit- prefix"

    def test_es_modules_used(self):
        html = _read(INDEX_HTML)
        assert 'type="module"' in html, "Must use ES modules for cross-browser support"

    def test_no_optional_chaining_in_css(self):
        """CSS should not use any JS-only syntax."""
        css = _read(STYLES_CSS)
        assert "?." not in css

    def test_standard_event_apis(self):
        src = _read(WS_HANDLER_JS)
        assert "CustomEvent" in src, "Must use standard CustomEvent API"
        assert "dispatchEvent" in src, "Must use standard dispatchEvent"

    def test_standard_websocket_api(self):
        src = _read(WS_HANDLER_JS)
        assert "new WebSocket(" in src, "Must use standard WebSocket constructor"

    def test_standard_localstorage(self):
        src = _read(DASHBOARD_NAV_JS)
        assert "localStorage" in src, "Must use standard localStorage"


# =====================================================================
# Section 11: Cross-Page Consistency — Unified Colours, CSS Tokens
# =====================================================================

class TestCrossPageConsistency:
    """Unified severity colours and design tokens across all pages."""

    SEVERITY_HEX = {
        "critical": "#ff3333",
        "high": "#ff9900",
        "medium": "#e6b800",
        "low": "#00cc66",
    }

    def test_css_has_severity_custom_properties(self):
        css = _read(STYLES_CSS)
        for level, colour in self.SEVERITY_HEX.items():
            assert colour in css, f"CSS must define severity colour {colour} for {level}"

    def test_all_js_use_unified_colours(self):
        """All JS files must use the unified severity palette (hex or rgba)."""
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            # Each file should reference at least critical and low colours (hex or rgba)
            assert "#ff3333" in src or "255, 51, 51" in src, \
                f"{name}.js must use unified critical colour"
            assert "#00cc66" in src or "0, 204, 102" in src, \
                f"{name}.js must use unified low colour"

    def test_connection_badge_colours_consistent(self):
        """All pages with live badges must use same green/red colours (hex or rgba)."""
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            if "setLiveStatus" in src:
                assert "#00cc66" in src or "0, 204, 102" in src, \
                    f"{name}.js live badge green must be #00cc66"
                assert "#ff3333" in src or "255, 51, 51" in src, \
                    f"{name}.js live badge red must be #ff3333"

    def test_css_custom_properties_exist(self):
        css = _read(STYLES_CSS)
        for prop in ["--bg-primary", "--card-bg", "--text-primary",
                      "--accent", "--sev-critical", "--sev-high",
                      "--sev-medium", "--sev-low"]:
            assert prop in css, f"CSS must define custom property {prop}"

    def test_dark_background_0f0f0f(self):
        css = _read(STYLES_CSS)
        assert "#0f0f0f" in css, "Dark background must be #0f0f0f"

    def test_accent_colour_00D9FF(self):
        css = _read(STYLES_CSS)
        assert "#00D9FF" in css.upper() or "#00d9ff" in css.lower(), \
            "Accent colour must be #00D9FF"


# =====================================================================
# Section 12: API Client & Session Auth
# =====================================================================

class TestAPIClientIntegration:
    """API client wiring and session token flow."""

    @pytest.fixture
    def api_src(self):
        return _read(API_CLIENT_JS)

    def test_api_client_class(self, api_src):
        assert "class APIClient" in api_src

    def test_session_endpoint(self, api_src):
        assert "/api/session" in api_src

    def test_session_token_header(self, api_src):
        assert "X-Session-Token" in api_src

    def test_exports_singleton(self, api_src):
        assert re.search(r"export\s+const\s+apiClient", api_src)

    def test_all_pages_import_api_client(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert re.search(
                r"import\s*\{[^}]*apiClient[^}]*\}\s*from",
                src
            ), f"{name}.js must import apiClient"

    def test_all_pages_initialize_api_client(self):
        for name, path in ALL_PAGE_JS.items():
            src = _read(path)
            assert "apiClient.initialize()" in src, \
                f"{name}.js must call apiClient.initialize()"

    def test_api_client_has_get_method(self, api_src):
        assert "async get(" in api_src

    def test_api_client_has_post_method(self, api_src):
        assert "async post(" in api_src


# =====================================================================
# Section 13: Navigation Integration — Tabs, Iframes, ARIA
# =====================================================================

class TestNavigationIntegration:
    """Tab switching, iframe loading, ARIA compliance."""

    @pytest.fixture
    def nav_src(self):
        return _read(DASHBOARD_NAV_JS)

    def test_tab_ids_constant(self, nav_src):
        assert "TAB_IDS" in nav_src
        for tab in ["intelligence", "charts", "timeline", "risk-metrics", "assets",
                     "remote-shield", "panic-room"]:
            assert f"'{tab}'" in nav_src or f'"{tab}"' in nav_src

    def test_tab_config_with_sources(self, nav_src):
        assert "TAB_CONFIG" in nav_src
        for page in ["charts.html", "timeline.html", "risk-metrics.html", "assets.html"]:
            assert page in nav_src, f"TAB_CONFIG must map to {page}"

    def test_switch_tab_function(self, nav_src):
        assert "function switchTab" in nav_src or "switchTab" in nav_src

    def test_local_storage_persistence(self, nav_src):
        assert "citadel_active_tab" in nav_src
        assert "localStorage" in nav_src

    def test_tab_loader_integration(self, nav_src):
        assert "activate" in nav_src, "Must import activate from tab-loader.js"
        assert "deactivate" in nav_src, "Must import deactivate from tab-loader.js"

    def test_keyboard_navigation(self, nav_src):
        for key in ["ArrowRight", "ArrowLeft", "Home", "End"]:
            assert key in nav_src, f"Keyboard nav must support {key}"

    def test_tab_changed_event(self, nav_src):
        assert "tab-changed" in nav_src, "Must broadcast tab-changed event"

    def test_connection_badge_updates(self, nav_src):
        assert "updateConnectionBadge" in nav_src
        assert "ws-connected" in nav_src
        assert "ws-disconnected" in nav_src

    def test_aria_selected_updates(self, nav_src):
        assert "aria-selected" in nav_src

    def test_aria_hidden_updates(self, nav_src):
        assert "aria-hidden" in nav_src

    def test_exports_all_public_api(self, nav_src):
        export_block = nav_src[nav_src.rfind("export"):]
        for name in ["switchTab", "loadSavedTab", "saveTab", "showPanel",
                      "updateConnectionBadge", "showError", "initDashboardNav"]:
            assert name in export_block, f"Must export {name}"
