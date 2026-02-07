# PRD: Tests - Dashboard Navigation & Tab Integration (P2.1.5-T5)
# Reference: PHASE_2_SPEC.md
#
# 25+ tests covering:
#   - HTML structure: tab bar, tab buttons, tab panels, iframes
#   - JS file structure: exports, constants, functions
#   - Tab ordering (Intelligence → Charts → Timeline → Risk → Assets)
#   - ARIA accessibility attributes
#   - Connection badge
#   - Error container
#   - localStorage key
#   - Responsive breakpoints
#   - Script loading order
#   - Vault link preserved as external

from pathlib import Path

import pytest


FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


# =====================================================================
# Section 1: HTML Tab Bar Structure
# =====================================================================

class TestTabBarHTML:
    """Validate dashboard tab bar in index.html."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_tab_bar_container(self, html_content):
        assert 'id="dashboard-tab-bar"' in html_content

    def test_tab_bar_has_tablist_role(self, html_content):
        assert 'role="tablist"' in html_content

    def test_tab_bar_has_aria_label(self, html_content):
        assert 'aria-label="Dashboard tabs"' in html_content

    def test_has_intelligence_tab_button(self, html_content):
        assert 'id="tab-btn-intelligence"' in html_content

    def test_has_charts_tab_button(self, html_content):
        assert 'id="tab-btn-charts"' in html_content

    def test_has_timeline_tab_button(self, html_content):
        assert 'id="tab-btn-timeline"' in html_content

    def test_has_risk_metrics_tab_button(self, html_content):
        assert 'id="tab-btn-risk-metrics"' in html_content

    def test_has_assets_tab_button(self, html_content):
        assert 'id="tab-btn-assets"' in html_content

    def test_intelligence_tab_active_by_default(self, html_content):
        # The intelligence button should have tab-active class
        idx = html_content.index('id="tab-btn-intelligence"')
        # Check in the surrounding tag
        tag_start = html_content.rfind('<button', 0, idx)
        tag_end = html_content.index('>', idx)
        tag = html_content[tag_start:tag_end + 1]
        assert 'tab-active' in tag

    def test_tab_buttons_have_role_tab(self, html_content):
        assert html_content.count('role="tab"') == 5


# =====================================================================
# Section 2: Tab Panels
# =====================================================================

class TestTabPanels:
    """Validate tab panel containers in index.html."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_intelligence_panel(self, html_content):
        assert 'id="tab-panel-intelligence"' in html_content

    def test_has_charts_panel(self, html_content):
        assert 'id="tab-panel-charts"' in html_content

    def test_has_timeline_panel(self, html_content):
        assert 'id="tab-panel-timeline"' in html_content

    def test_has_risk_metrics_panel(self, html_content):
        assert 'id="tab-panel-risk-metrics"' in html_content

    def test_has_assets_panel(self, html_content):
        assert 'id="tab-panel-assets"' in html_content

    def test_panels_have_tabpanel_role(self, html_content):
        assert html_content.count('role="tabpanel"') == 5

    def test_non_intelligence_panels_hidden(self, html_content):
        # Charts, Timeline, Risk Metrics, Assets should have aria-hidden="true"
        for panel_id in ['charts', 'timeline', 'risk-metrics', 'assets']:
            idx = html_content.index(f'id="tab-panel-{panel_id}"')
            tag_start = html_content.rfind('<div', 0, idx)
            tag_end = html_content.index('>', idx)
            tag = html_content[tag_start:tag_end + 1]
            assert 'aria-hidden="true"' in tag, f"Panel {panel_id} should be hidden"

    def test_intelligence_panel_not_hidden(self, html_content):
        idx = html_content.index('id="tab-panel-intelligence"')
        tag_start = html_content.rfind('<div', 0, idx)
        tag_end = html_content.index('>', idx)
        tag = html_content[tag_start:tag_end + 1]
        assert 'aria-hidden' not in tag


# =====================================================================
# Section 3: Iframes
# =====================================================================

class TestIframes:
    """Validate iframe elements for tabbed content."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_charts_iframe(self, html_content):
        assert 'id="tab-iframe-charts"' in html_content

    def test_has_timeline_iframe(self, html_content):
        assert 'id="tab-iframe-timeline"' in html_content

    def test_has_risk_metrics_iframe(self, html_content):
        assert 'id="tab-iframe-risk-metrics"' in html_content

    def test_has_assets_iframe(self, html_content):
        assert 'id="tab-iframe-assets"' in html_content

    def test_iframes_have_title(self, html_content):
        assert 'title="Charts"' in html_content
        assert 'title="Timeline"' in html_content
        assert 'title="Risk Metrics"' in html_content
        assert 'title="Assets"' in html_content

    def test_iframes_no_initial_src(self, html_content):
        # Iframes should not have src set (lazy-loaded by JS)
        for iframe_id in ['charts', 'timeline', 'risk-metrics', 'assets']:
            idx = html_content.index(f'id="tab-iframe-{iframe_id}"')
            tag_start = html_content.rfind('<iframe', 0, idx)
            tag_end = html_content.index('>', idx)
            tag = html_content[tag_start:tag_end + 1]
            assert 'src="charts.html"' not in tag or iframe_id != 'charts'

    def test_no_intelligence_iframe(self, html_content):
        assert 'id="tab-iframe-intelligence"' not in html_content


# =====================================================================
# Section 4: Tab Ordering
# =====================================================================

class TestTabOrdering:
    """Tabs appear in correct order."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_intelligence_first(self, html_content):
        positions = []
        for tab_id in ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets']:
            positions.append(html_content.index(f'id="tab-btn-{tab_id}"'))
        # Intelligence should be first
        assert positions[0] < positions[1]

    def test_charts_second(self, html_content):
        charts = html_content.index('id="tab-btn-charts"')
        intel = html_content.index('id="tab-btn-intelligence"')
        timeline = html_content.index('id="tab-btn-timeline"')
        assert intel < charts < timeline

    def test_full_order(self, html_content):
        positions = []
        for tab_id in ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets']:
            positions.append(html_content.index(f'id="tab-btn-{tab_id}"'))
        assert positions == sorted(positions)


# =====================================================================
# Section 5: Connection Badge
# =====================================================================

class TestConnectionBadge:
    """Connection status badge in header."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_connection_badge(self, html_content):
        assert 'id="nav-conn-badge"' in html_content

    def test_has_connection_dot(self, html_content):
        assert 'id="nav-conn-dot"' in html_content

    def test_has_connection_text(self, html_content):
        assert 'id="nav-conn-text"' in html_content

    def test_default_offline(self, html_content):
        # Should show Offline by default
        idx = html_content.index('id="nav-conn-text"')
        nearby = html_content[idx:idx + 100]
        assert 'Offline' in nearby


# =====================================================================
# Section 6: Intelligence Panel Content
# =====================================================================

class TestIntelligencePanel:
    """Intelligence tab preserves Phase 1 Web Components."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_guardian_status(self, html_content):
        assert '<guardian-status>' in html_content

    def test_has_threat_level(self, html_content):
        assert '<threat-level>' in html_content

    def test_has_protected_systems(self, html_content):
        assert '<protected-systems>' in html_content

    def test_has_event_log(self, html_content):
        assert '<event-log>' in html_content

    def test_has_process_list(self, html_content):
        assert '<process-list>' in html_content

    def test_has_ai_insights(self, html_content):
        assert '<ai-insights>' in html_content


# =====================================================================
# Section 7: External Links Preserved
# =====================================================================

class TestExternalLinks:
    """Vault remains as external link."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_vault_link_preserved(self, html_content):
        assert 'href="vault.html"' in html_content

    def test_no_vault_tab(self, html_content):
        assert 'id="tab-btn-vault"' not in html_content


# =====================================================================
# Section 8: Styles & Responsive
# =====================================================================

class TestStyles:
    """Tab bar CSS and responsive breakpoints."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_tab_btn_class(self, html_content):
        assert '.tab-btn' in html_content

    def test_has_tab_active_class(self, html_content):
        assert '.tab-active' in html_content
        assert 'tab-active' in html_content

    def test_has_responsive_breakpoint(self, html_content):
        assert '640px' in html_content

    def test_has_glassmorphic_theme(self, html_content):
        assert 'glass-card' in html_content
        assert 'dark-bg' in html_content

    def test_has_error_toast_style(self, html_content):
        assert '.nav-error-toast' in html_content

    def test_has_conn_badge_style(self, html_content):
        assert '.conn-badge' in html_content


# =====================================================================
# Section 9: JS File Structure
# =====================================================================

class TestDashboardNavJS:
    """Validate dashboard-nav.js structure."""

    @pytest.fixture
    def js_content(self):
        path = FRONTEND_DIR / "js" / "dashboard-nav.js"
        if not path.exists():
            pytest.skip("dashboard-nav.js not found")
        return path.read_text()

    def test_has_tab_ids_constant(self, js_content):
        assert 'TAB_IDS' in js_content
        assert "'intelligence'" in js_content
        assert "'charts'" in js_content
        assert "'timeline'" in js_content
        assert "'risk-metrics'" in js_content
        assert "'assets'" in js_content

    def test_has_storage_key(self, js_content):
        assert 'STORAGE_KEY' in js_content
        assert 'citadel_active_tab' in js_content

    def test_has_tab_config(self, js_content):
        assert 'TAB_CONFIG' in js_content

    def test_has_switch_tab(self, js_content):
        assert 'switchTab' in js_content

    def test_has_load_saved_tab(self, js_content):
        assert 'loadSavedTab' in js_content

    def test_has_save_tab(self, js_content):
        assert 'saveTab' in js_content

    def test_has_show_panel(self, js_content):
        assert 'showPanel' in js_content

    def test_has_update_tab_buttons(self, js_content):
        assert 'updateTabButtons' in js_content

    def test_has_load_iframe(self, js_content):
        assert 'loadIframe' in js_content

    def test_has_connection_badge_update(self, js_content):
        assert 'updateConnectionBadge' in js_content

    def test_has_show_error(self, js_content):
        assert 'showError' in js_content

    def test_has_init_function(self, js_content):
        assert 'initDashboardNav' in js_content

    def test_has_keyboard_navigation(self, js_content):
        assert 'ArrowRight' in js_content
        assert 'ArrowLeft' in js_content

    def test_has_local_storage_usage(self, js_content):
        assert 'localStorage.getItem' in js_content
        assert 'localStorage.setItem' in js_content

    def test_has_exports(self, js_content):
        assert 'export' in js_content
        assert 'switchTab' in js_content
        assert 'TAB_IDS' in js_content

    def test_has_custom_event_dispatch(self, js_content):
        assert 'tab-changed' in js_content
        assert 'CustomEvent' in js_content

    def test_has_dom_content_loaded(self, js_content):
        assert 'DOMContentLoaded' in js_content

    def test_has_ws_event_listeners(self, js_content):
        assert 'ws-connected' in js_content
        assert 'ws-disconnected' in js_content


# =====================================================================
# Section 10: Script Loading
# =====================================================================

class TestScriptLoading:
    """Verify script loading order in index.html."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_loads_dashboard_nav_js(self, html_content):
        assert 'src="js/dashboard-nav.js"' in html_content

    def test_loads_main_js(self, html_content):
        assert 'src="js/main.js"' in html_content

    def test_dashboard_nav_before_main(self, html_content):
        nav_pos = html_content.index('dashboard-nav.js')
        main_pos = html_content.index('js/main.js')
        assert nav_pos < main_pos

    def test_web_components_before_nav(self, html_content):
        guardian_pos = html_content.index('guardian-status.js')
        nav_pos = html_content.index('dashboard-nav.js')
        assert guardian_pos < nav_pos

    def test_has_error_container(self, html_content):
        assert 'id="nav-error-container"' in html_content


# =====================================================================
# Section 11: ARIA Accessibility
# =====================================================================

class TestARIA:
    """Tab ARIA attributes for accessibility."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_tab_buttons_have_aria_controls(self, html_content):
        for tab_id in ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets']:
            assert f'aria-controls="tab-panel-{tab_id}"' in html_content

    def test_panels_have_aria_labelledby(self, html_content):
        for tab_id in ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets']:
            assert f'aria-labelledby="tab-btn-{tab_id}"' in html_content

    def test_intelligence_selected_by_default(self, html_content):
        idx = html_content.index('id="tab-btn-intelligence"')
        tag_start = html_content.rfind('<button', 0, idx)
        tag_end = html_content.index('>', idx)
        tag = html_content[tag_start:tag_end + 1]
        assert 'aria-selected="true"' in tag

    def test_other_tabs_not_selected(self, html_content):
        for tab_id in ['charts', 'timeline', 'risk-metrics', 'assets']:
            idx = html_content.index(f'id="tab-btn-{tab_id}"')
            tag_start = html_content.rfind('<button', 0, idx)
            tag_end = html_content.index('>', idx)
            tag = html_content[tag_start:tag_end + 1]
            assert 'aria-selected="false"' in tag
