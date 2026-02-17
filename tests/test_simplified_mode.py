"""Tests for Simplified Protected Mode (v0.3.25).

Covers:
  - Settings panel HTML elements exist in index.html
  - Mode toggle buttons present
  - Remote shield simplified view elements in remote-shield.html
  - Dashboard nav exports SIMPLIFIED_TABS
  - CSS simplified-mode rules exist in styles.css
  - THREAT_GUIDANCE dictionary in remote-shield.js
  - dashboard-nav.js mode-switching functions
  - assets.js simplified rendering function exists
  - settings.js mode save/load functions exist
"""

from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


class TestIndexHtmlSettingsPanel:
    """Verify settings panel markup exists in index.html."""

    @pytest.fixture(scope="class")
    def html(self):
        return (FRONTEND / "index.html").read_text(encoding="utf-8")

    def test_settings_menu_list_id(self, html):
        assert 'id="settings-menu-list"' in html

    def test_settings_general_panel(self, html):
        assert 'id="settings-general-panel"' in html

    def test_mode_btn_technical(self, html):
        assert 'id="mode-btn-technical"' in html

    def test_mode_btn_simplified(self, html):
        assert 'id="mode-btn-simplified"' in html

    def test_mode_toggle_group(self, html):
        assert 'id="mode-toggle-group"' in html

    def test_settings_general_back_button(self, html):
        assert 'id="settings-general-back"' in html


class TestRemoteShieldSimplifiedView:
    """Verify simplified view markup in remote-shield.html."""

    @pytest.fixture(scope="class")
    def html(self):
        return (FRONTEND / "remote-shield.html").read_text(encoding="utf-8")

    def test_simplified_view_container(self, html):
        assert 'id="rs-simplified-view"' in html

    def test_technical_view_container(self, html):
        assert 'id="rs-technical-view"' in html

    def test_hero_icon_element(self, html):
        assert 'id="rs-hero-icon"' in html

    def test_hero_title_element(self, html):
        assert 'id="rs-hero-title"' in html

    def test_device_list_container(self, html):
        assert 'id="rs-device-list"' in html

    def test_alert_cards_container(self, html):
        assert 'id="rs-alert-cards"' in html

    def test_alert_cards_section(self, html):
        assert 'id="rs-alert-cards-section"' in html


class TestDashboardNavSimplifiedTabs:
    """Verify dashboard-nav.js has SIMPLIFIED_TABS and mode functions."""

    @pytest.fixture(scope="class")
    def js(self):
        return (FRONTEND / "js" / "dashboard-nav.js").read_text(encoding="utf-8")

    def test_simplified_tabs_constant(self, js):
        assert "SIMPLIFIED_TABS" in js

    def test_simplified_tabs_includes_intelligence(self, js):
        assert "'intelligence'" in js or '"intelligence"' in js

    def test_apply_dashboard_mode_function(self, js):
        assert "function applyDashboardMode" in js

    def test_get_visible_tabs_function(self, js):
        assert "function getVisibleTabs" in js

    def test_mode_storage_key(self, js):
        assert "citadel_dashboard_mode" in js

    def test_exports_simplified_tabs(self, js):
        assert "SIMPLIFIED_TABS" in js
        # Check it's in the export block
        export_start = js.index("export {")
        export_end = js.index("}", export_start)
        export_block = js[export_start:export_end]
        assert "SIMPLIFIED_TABS" in export_block


class TestRemoteShieldJSThreatGuidance:
    """Verify THREAT_GUIDANCE dictionary in remote-shield.js."""

    @pytest.fixture(scope="class")
    def js(self):
        return (FRONTEND / "js" / "remote-shield.js").read_text(encoding="utf-8")

    def test_threat_guidance_exists(self, js):
        assert "THREAT_GUIDANCE" in js

    def test_defender_disabled_guidance(self, js):
        assert "defender_disabled" in js

    def test_firewall_disabled_guidance(self, js):
        assert "firewall_disabled" in js

    def test_logon_failure_guidance(self, js):
        assert "logon_failure" in js

    def test_audit_log_cleared_guidance(self, js):
        assert "audit_log_cleared" in js

    def test_what_to_do_text(self, js):
        assert "What to do" in js

    def test_exports_threat_guidance(self, js):
        assert "THREAT_GUIDANCE" in js


class TestCSSSimplifiedMode:
    """Verify CSS simplified-mode overrides in styles.css."""

    @pytest.fixture(scope="class")
    def css(self):
        return (FRONTEND / "css" / "styles.css").read_text(encoding="utf-8")

    def test_simplified_mode_class(self, css):
        assert "body.simplified-mode" in css

    def test_hides_add_asset_btn(self, css):
        assert "add-asset-btn" in css

    def test_hides_filter_threat(self, css):
        assert "filter-threat" in css

    def test_hides_filter_status(self, css):
        assert "filter-status" in css


class TestSettingsJSModeFunctions:
    """Verify settings.js mode toggle functions exist."""

    @pytest.fixture(scope="class")
    def js(self):
        return (FRONTEND / "js" / "settings.js").read_text(encoding="utf-8")

    def test_open_general_settings(self, js):
        assert "openGeneralSettings()" in js

    def test_close_general_settings(self, js):
        assert "closeGeneralSettings()" in js

    def test_load_current_mode(self, js):
        assert "loadCurrentMode()" in js

    def test_save_mode(self, js):
        assert "saveMode(mode)" in js or "saveMode(" in js

    def test_highlight_mode_button(self, js):
        assert "highlightModeButton(" in js

    def test_dispatches_mode_changed_event(self, js):
        assert "dashboard-mode-changed" in js


class TestAssetsJSSimplifiedMode:
    """Verify assets.js has simplified rendering support."""

    @pytest.fixture(scope="class")
    def js(self):
        return (FRONTEND / "js" / "assets.js").read_text(encoding="utf-8")

    def test_render_simplified_assets_function(self, js):
        assert "renderSimplifiedAssets" in js

    def test_open_simplified_detail_function(self, js):
        assert "openSimplifiedDetail" in js

    def test_mode_listener_cleanup(self, js):
        assert "_modeListener" in js

    def test_listens_for_mode_change(self, js):
        assert "dashboard-mode-changed" in js
