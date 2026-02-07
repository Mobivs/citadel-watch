# PRD: Tests - Styling & Dark Theme (P2.1.5-T6)
# Reference: PHASE_2_SPEC.md
#
# 60+ tests covering:
#   - CSS custom properties (design tokens)
#   - Unified severity colours (#ff3333, #ff9900, #ffcc00, #00cc66)
#   - Responsive breakpoints (400px, 640px, 1024px)
#   - Dark theme background/card/text
#   - Glassmorphic effects
#   - Hover effects
#   - Smooth transitions
#   - Chart.js theme styling
#   - Font sizing
#   - Severity colour consistency across all pages & JS files

import re
from pathlib import Path

import pytest


FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
CSS_PATH = FRONTEND_DIR / "css" / "styles.css"

# Unified severity hex values (lowercase)
SEV_CRITICAL = '#ff3333'
SEV_HIGH     = '#ff9900'
SEV_MEDIUM   = '#ffcc00'
SEV_LOW      = '#00cc66'

# Old Phase 1 severity hex values (should NOT appear)
OLD_CRITICAL = '#EF4444'
OLD_HIGH     = '#F97316'
OLD_MEDIUM   = '#F59E0B'
OLD_LOW      = '#10B981'


# =====================================================================
# Section 1: CSS Custom Properties (Design Tokens)
# =====================================================================

class TestCSSCustomProperties:
    """Verify CSS custom properties in :root."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_has_root_block(self, css):
        assert ':root' in css

    def test_bg_primary(self, css):
        assert '--bg-primary' in css
        assert '#0f0f0f' in css

    def test_bg_secondary(self, css):
        assert '--bg-secondary' in css
        assert '#1a1a1a' in css

    def test_card_bg_glassmorphic(self, css):
        assert '--card-bg' in css
        assert 'rgba(255, 255, 255, 0.1)' in css

    def test_text_primary(self, css):
        assert '--text-primary' in css
        assert '#e0e0e0' in css

    def test_accent_colour(self, css):
        assert '--accent' in css
        assert '#00d4ff' in css

    def test_accent_rgb(self, css):
        assert '--accent-rgb' in css

    def test_sev_critical_var(self, css):
        assert '--sev-critical' in css
        assert SEV_CRITICAL in css

    def test_sev_high_var(self, css):
        assert '--sev-high' in css
        assert SEV_HIGH in css

    def test_sev_medium_var(self, css):
        assert '--sev-medium' in css
        assert SEV_MEDIUM in css

    def test_sev_low_var(self, css):
        assert '--sev-low' in css
        assert SEV_LOW in css

    def test_sev_rgb_vars(self, css):
        assert '--sev-critical-rgb' in css
        assert '--sev-high-rgb' in css
        assert '--sev-medium-rgb' in css
        assert '--sev-low-rgb' in css

    def test_spacing_vars(self, css):
        assert '--space-4: 16px' in css
        assert '--space-8: 32px' in css

    def test_transition_vars(self, css):
        assert '--transition-fast' in css
        assert '--transition-normal' in css

    def test_radius_vars(self, css):
        assert '--radius-md' in css
        assert '--radius-xl' in css
        assert '--radius-full' in css


# =====================================================================
# Section 2: Dark Theme
# =====================================================================

class TestDarkTheme:
    """Verify dark theme values."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_body_gradient_background(self, css):
        assert 'background: linear-gradient' in css
        assert '--bg-gradient-start' in css or '#0A0E27' in css

    def test_body_text_colour(self, css):
        assert 'color: var(--text-primary)' in css

    def test_body_font_size(self, css):
        assert 'font-size: 16px' in css

    def test_antialiasing(self, css):
        assert '-webkit-font-smoothing: antialiased' in css


# =====================================================================
# Section 3: Glassmorphic Effects
# =====================================================================

class TestGlassmorphic:
    """Verify glassmorphic card styles."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_glass_card_backdrop_filter(self, css):
        assert 'backdrop-filter: blur(20px)' in css

    def test_glass_card_webkit_backdrop(self, css):
        assert '-webkit-backdrop-filter: blur(20px)' in css

    def test_glass_card_border(self, css):
        assert 'var(--card-border)' in css

    def test_glass_card_shadow(self, css):
        assert 'var(--card-shadow)' in css

    def test_glass_hover_overlay(self, css):
        assert '.glass-hover' in css
        assert '.glass-hover::after' in css
        assert '.glass-hover:hover::after' in css


# =====================================================================
# Section 4: Hover Effects & Transitions
# =====================================================================

class TestHoverEffects:
    """Verify smooth hover effects."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_glass_card_hover_lift(self, css):
        assert 'translateY(-2px)' in css

    def test_glass_card_hover_border_colour(self, css):
        assert 'var(--card-hover)' in css

    def test_btn_primary_hover(self, css):
        assert '.btn-primary:hover' in css

    def test_btn_secondary_hover(self, css):
        assert '.btn-secondary:hover' in css

    def test_transitions_use_vars(self, css):
        assert 'var(--transition-normal)' in css


# =====================================================================
# Section 5: Responsive Breakpoints
# =====================================================================

class TestResponsiveBreakpoints:
    """Verify 3 responsive breakpoints (400px, 640px, 1024px)."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_has_400px_breakpoint(self, css):
        assert '400px' in css

    def test_has_640px_breakpoint(self, css):
        assert '640px' in css

    def test_has_1024px_breakpoint(self, css):
        assert '1024px' in css

    def test_small_phone_font_size(self, css):
        # Within the 400px media query
        assert 'font-size: 14px' in css

    def test_mobile_font_size(self, css):
        # Within the 640px media query
        assert 'font-size: 15px' in css

    def test_mobile_filter_bar_stack(self, css):
        assert 'flex-direction: column' in css

    def test_mobile_detail_panel_full_width(self, css):
        assert 'right: -100%' in css

    def test_tablet_detail_panel_width(self, css):
        assert 'width: 400px' in css


# =====================================================================
# Section 6: Severity Badge Classes in CSS
# =====================================================================

class TestSeverityBadgeCSS:
    """Verify severity badge classes use unified colours."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_sev_critical_class(self, css):
        assert '.sev-critical' in css

    def test_sev_high_class(self, css):
        assert '.sev-high' in css or '.sev-alert' in css

    def test_sev_medium_class(self, css):
        assert '.sev-medium' in css or '.sev-investigate' in css

    def test_sev_low_class(self, css):
        assert '.sev-low' in css or '.sev-info' in css

    def test_threat_badge_classes(self, css):
        assert '.threat-critical' in css
        assert '.threat-high' in css
        assert '.threat-medium' in css
        assert '.threat-low' in css

    def test_sev_badge_base_class(self, css):
        assert '.sev-badge' in css


# =====================================================================
# Section 7: Chart.js Theme
# =====================================================================

class TestChartTheme:
    """Verify chart container and theme styles."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_chart_container_class(self, css):
        assert '.chart-container' in css

    def test_chart_container_min_height(self, css):
        assert 'min-height: 280px' in css

    def test_chart_canvas_full_width(self, css):
        assert '.chart-container canvas' in css
        assert 'width: 100%' in css


# =====================================================================
# Section 8: JS Severity Colour Consistency (charts.js)
# =====================================================================

class TestChartsJSColours:
    """Verify charts.js uses unified severity colours."""

    @pytest.fixture
    def js(self):
        path = FRONTEND_DIR / "js" / "charts.js"
        if not path.exists():
            pytest.skip("charts.js not found")
        return path.read_text()

    def test_no_old_critical(self, js):
        assert OLD_CRITICAL not in js

    def test_no_old_high(self, js):
        assert OLD_HIGH not in js

    def test_no_old_medium(self, js):
        assert OLD_MEDIUM not in js

    def test_has_new_critical_rgb(self, js):
        assert '255, 51, 51' in js

    def test_has_new_high_rgb(self, js):
        assert '255, 153, 0' in js

    def test_has_new_medium_rgb(self, js):
        assert '255, 204, 0' in js

    def test_has_new_low_rgb(self, js):
        assert '0, 204, 102' in js


# =====================================================================
# Section 9: JS Severity Colour Consistency (risk-metrics.js)
# =====================================================================

class TestRiskMetricsJSColours:
    """Verify risk-metrics.js uses unified severity colours."""

    @pytest.fixture
    def js(self):
        path = FRONTEND_DIR / "js" / "risk-metrics.js"
        if not path.exists():
            pytest.skip("risk-metrics.js not found")
        return path.read_text()

    def test_no_old_critical(self, js):
        assert OLD_CRITICAL not in js

    def test_no_old_high(self, js):
        assert OLD_HIGH not in js

    def test_no_old_medium(self, js):
        assert OLD_MEDIUM not in js

    def test_colours_has_new_critical(self, js):
        assert SEV_CRITICAL in js

    def test_colours_has_new_high(self, js):
        assert SEV_HIGH in js

    def test_colours_has_new_low(self, js):
        assert SEV_LOW in js

    def test_gauge_zones_new_colours(self, js):
        assert "GAUGE_ZONES" in js
        assert SEV_LOW in js      # Safe zone
        assert SEV_CRITICAL in js  # Critical zone


# =====================================================================
# Section 10: JS Severity Colour Consistency (timeline.js)
# =====================================================================

class TestTimelineJSColours:
    """Verify timeline.js uses unified severity colours."""

    @pytest.fixture
    def js(self):
        path = FRONTEND_DIR / "js" / "timeline.js"
        if not path.exists():
            pytest.skip("timeline.js not found")
        return path.read_text()

    def test_no_old_critical(self, js):
        assert OLD_CRITICAL not in js

    def test_no_old_high(self, js):
        assert OLD_HIGH not in js

    def test_no_old_medium(self, js):
        assert OLD_MEDIUM not in js

    def test_sev_colours_has_new_critical(self, js):
        assert SEV_CRITICAL in js

    def test_sev_colours_has_new_high(self, js):
        assert SEV_HIGH in js

    def test_sev_colours_has_new_low(self, js):
        assert SEV_LOW in js


# =====================================================================
# Section 11: JS Severity Colour Consistency (assets.js)
# =====================================================================

class TestAssetsJSColours:
    """Verify assets.js uses unified severity colours."""

    @pytest.fixture
    def js(self):
        path = FRONTEND_DIR / "js" / "assets.js"
        if not path.exists():
            pytest.skip("assets.js not found")
        return path.read_text()

    def test_no_old_critical(self, js):
        assert OLD_CRITICAL not in js

    def test_no_old_high(self, js):
        assert OLD_HIGH not in js

    def test_no_old_medium(self, js):
        assert OLD_MEDIUM not in js

    def test_row_colours_new_critical(self, js):
        assert '255, 51, 51' in js

    def test_row_colours_new_high(self, js):
        assert '255, 153, 0' in js


# =====================================================================
# Section 12: HTML Inline Colour Consistency
# =====================================================================

class TestHTMLInlineColours:
    """Verify HTML files use unified severity colours in inline styles."""

    @pytest.fixture
    def charts_html(self):
        path = FRONTEND_DIR / "charts.html"
        if not path.exists():
            pytest.skip("charts.html not found")
        return path.read_text()

    @pytest.fixture
    def timeline_html(self):
        path = FRONTEND_DIR / "timeline.html"
        if not path.exists():
            pytest.skip("timeline.html not found")
        return path.read_text()

    @pytest.fixture
    def risk_html(self):
        path = FRONTEND_DIR / "risk-metrics.html"
        if not path.exists():
            pytest.skip("risk-metrics.html not found")
        return path.read_text()

    @pytest.fixture
    def assets_html(self):
        path = FRONTEND_DIR / "assets.html"
        if not path.exists():
            pytest.skip("assets.html not found")
        return path.read_text()

    def test_charts_no_old_critical(self, charts_html):
        assert OLD_CRITICAL not in charts_html

    def test_charts_no_old_high(self, charts_html):
        assert OLD_HIGH not in charts_html

    def test_charts_no_old_medium(self, charts_html):
        assert OLD_MEDIUM not in charts_html

    def test_charts_has_new_critical(self, charts_html):
        assert SEV_CRITICAL in charts_html

    def test_timeline_no_old_critical(self, timeline_html):
        assert OLD_CRITICAL not in timeline_html

    def test_timeline_has_new_critical(self, timeline_html):
        assert SEV_CRITICAL in timeline_html

    def test_risk_no_old_critical(self, risk_html):
        assert OLD_CRITICAL not in risk_html

    def test_risk_has_new_critical(self, risk_html):
        assert SEV_CRITICAL in risk_html

    def test_risk_has_new_low(self, risk_html):
        assert SEV_LOW in risk_html

    def test_assets_no_old_critical(self, assets_html):
        assert OLD_CRITICAL not in assets_html

    def test_assets_has_new_low(self, assets_html):
        assert SEV_LOW in assets_html


# =====================================================================
# Section 13: Animations & Loading
# =====================================================================

class TestAnimations:
    """Verify animation keyframes and loading styles."""

    @pytest.fixture
    def css(self):
        if not CSS_PATH.exists():
            pytest.skip("styles.css not found")
        return CSS_PATH.read_text()

    def test_has_pulse_keyframe(self, css):
        assert '@keyframes pulse' in css

    def test_has_spin_keyframe(self, css):
        assert '@keyframes spin' in css

    def test_has_fadein_keyframe(self, css):
        assert '@keyframes fadeIn' in css

    def test_has_shimmer_keyframe(self, css):
        assert '@keyframes shimmer' in css

    def test_loading_class(self, css):
        assert '.loading' in css

    def test_fade_in_class(self, css):
        assert '.fade-in' in css

    def test_skeleton_row_class(self, css):
        assert '.skeleton-row' in css


# =====================================================================
# Section 14: All Pages Link styles.css
# =====================================================================

class TestPagesLinkCSS:
    """Every HTML page should link to css/styles.css."""

    @pytest.fixture(params=['index.html', 'charts.html', 'timeline.html',
                            'risk-metrics.html', 'assets.html'])
    def page(self, request):
        path = FRONTEND_DIR / request.param
        if not path.exists():
            pytest.skip(f"{request.param} not found")
        return path.read_text()

    def test_links_styles_css(self, page):
        assert 'href="css/styles.css"' in page
