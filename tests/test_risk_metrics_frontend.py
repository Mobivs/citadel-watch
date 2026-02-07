# PRD: Tests - Risk Metrics & Threat Gauge (P2.1.5-T3)
# Reference: PHASE_2_SPEC.md
#
# 25+ tests covering:
#   - Backend RiskMetrics engine (counts, gauge, assets, trend, sensitivity)
#   - Dashboard services threat-score API
#   - HTML structure validation
#   - JS file structure validation
#   - Route registration
#   - Gauge zone classification
#   - Sparkline data formatting

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# ── Intel module imports ─────────────────────────────────────────────

from citadel_archer.intel.risk_metrics import (
    AssetRisk,
    GaugeData,
    GaugeZone,
    RiskMetrics,
    RiskMetricsSnapshot,
    ThreatCounts,
    TrendPoint,
    _gauge_zone,
    _build_gauge_zones,
    asset_risk_bar_chart,
    gauge_chart,
    trend_line_chart,
)
from citadel_archer.intel.anomaly_detector import Sensitivity
from citadel_archer.intel.threat_scorer import RiskLevel, ScoredThreat

# ── Dashboard ext imports ────────────────────────────────────────────

from citadel_archer.api.dashboard_ext import (
    DashboardServices,
    ThreatScoreResponse,
)


# ── Helpers ──────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def _make_scored(
    risk_level=RiskLevel.LOW,
    risk_score=25.0,
    asset_id="asset-1",
    timestamp=None,
    event_type="test",
):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()
    return ScoredThreat(
        event_id="evt-1",
        event_type=event_type,
        severity="info",
        message="test",
        timestamp=timestamp,
        asset_id=asset_id,
        risk_level=risk_level,
        risk_score=risk_score,
    )


def _make_scored_spread(count=50, hours=24):
    """Generate spread scored threats."""
    now = datetime.utcnow()
    levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    threats = []
    for i in range(count):
        ts = now - timedelta(hours=hours * i / count)
        threats.append(_make_scored(
            risk_level=levels[i % len(levels)],
            risk_score=25.0 + i * 2,
            asset_id=f"asset-{i % 4}",
            timestamp=ts.isoformat(),
            event_type=f"type-{i % 5}",
        ))
    return threats


# =====================================================================
# Section 1: ThreatCounts
# =====================================================================

class TestThreatCounts:
    """Threat count calculation."""

    def test_empty_returns_zeros(self):
        rm = RiskMetrics()
        counts = rm.threat_counts([])
        assert counts.critical == 0
        assert counts.high == 0
        assert counts.medium == 0
        assert counts.low == 0
        assert counts.total == 0

    def test_counts_by_level(self):
        threats = _make_scored_spread(20)
        rm = RiskMetrics()
        counts = rm.threat_counts(threats)
        assert counts.critical == 5  # 20 / 4 levels
        assert counts.high == 5
        assert counts.medium == 5
        assert counts.low == 5
        assert counts.total == 20

    def test_to_dict_includes_total(self):
        counts = ThreatCounts(critical=3, high=2, medium=1, low=4)
        d = counts.to_dict()
        assert d["total"] == 10
        assert d["critical"] == 3


# =====================================================================
# Section 2: Gauge
# =====================================================================

class TestGauge:
    """Gauge value and zone classification."""

    def test_gauge_zone_safe(self):
        zone, label = _gauge_zone(0.1)
        assert zone == GaugeZone.SAFE
        assert label == "Safe"

    def test_gauge_zone_elevated(self):
        zone, label = _gauge_zone(0.3)
        assert zone == GaugeZone.ELEVATED
        assert label == "Elevated"

    def test_gauge_zone_high(self):
        zone, label = _gauge_zone(0.6)
        assert zone == GaugeZone.HIGH
        assert label == "High"

    def test_gauge_zone_critical(self):
        zone, label = _gauge_zone(0.8)
        assert zone == GaugeZone.CRITICAL
        assert label == "Critical"

    def test_overall_risk_empty(self):
        rm = RiskMetrics()
        assert rm.overall_risk([]) == 0.0

    def test_overall_risk_all_critical(self):
        threats = [_make_scored(RiskLevel.CRITICAL) for _ in range(5)]
        rm = RiskMetrics()
        assert rm.overall_risk(threats) == 1.0

    def test_overall_risk_all_low(self):
        threats = [_make_scored(RiskLevel.LOW) for _ in range(5)]
        rm = RiskMetrics()
        assert rm.overall_risk(threats) == 0.25

    def test_build_gauge_returns_zones(self):
        rm = RiskMetrics()
        gauge = rm.build_gauge([])
        assert len(gauge.zones) == 4
        assert gauge.zone == GaugeZone.SAFE

    def test_gauge_chart_config(self):
        rm = RiskMetrics()
        config = rm.gauge_chart_config([])
        assert config["type"] == "doughnut"

    def test_build_gauge_zones_static(self):
        zones = _build_gauge_zones()
        assert len(zones) == 4
        assert zones[0]["label"] == "Safe"
        assert zones[3]["label"] == "Critical"


# =====================================================================
# Section 3: Asset Risk Breakdown
# =====================================================================

class TestAssetRisk:
    """Per-asset risk breakdown."""

    def test_empty_threats(self):
        rm = RiskMetrics()
        result = rm.asset_risk_breakdown([])
        assert result == []

    def test_groups_by_asset(self):
        threats = _make_scored_spread(20)
        rm = RiskMetrics()
        result = rm.asset_risk_breakdown(threats)
        assert len(result) == 4  # asset-0..asset-3

    def test_sorted_by_highest_risk(self):
        threats = [
            _make_scored(RiskLevel.LOW, asset_id="safe-box"),
            _make_scored(RiskLevel.CRITICAL, asset_id="hot-zone"),
        ]
        rm = RiskMetrics()
        result = rm.asset_risk_breakdown(threats)
        assert result[0].asset_id == "hot-zone"

    def test_asset_bar_chart_config(self):
        threats = _make_scored_spread(10)
        rm = RiskMetrics()
        config = rm.asset_chart_config(threats)
        assert config["type"] == "bar"


# =====================================================================
# Section 4: Trending (threats/hour)
# =====================================================================

class TestTrending:
    """Threats per hour trend data."""

    def test_empty_threats_produces_buckets(self):
        rm = RiskMetrics()
        trend = rm.trending([], hours=6)
        assert len(trend) >= 6  # at least 6 hourly buckets
        assert all(t.count == 0 for t in trend)

    def test_threats_placed_in_buckets(self):
        threats = _make_scored_spread(24, hours=12)
        rm = RiskMetrics()
        trend = rm.trending(threats, hours=24)
        total = sum(t.count for t in trend)
        assert total > 0

    def test_trend_chart_config(self):
        rm = RiskMetrics()
        config = rm.trend_chart_config([], hours=6)
        assert config["type"] == "line"


# =====================================================================
# Section 5: Sensitivity Control
# =====================================================================

class TestSensitivity:
    """Sensitivity control."""

    def test_default_sensitivity(self):
        rm = RiskMetrics()
        assert rm.sensitivity == Sensitivity.MODERATE

    def test_set_sensitivity(self):
        rm = RiskMetrics()
        rm.set_sensitivity(Sensitivity.HIGH)
        assert rm.sensitivity == Sensitivity.HIGH

    def test_snapshot_includes_sensitivity(self):
        rm = RiskMetrics(sensitivity=Sensitivity.LOW)
        snap = rm.snapshot([])
        assert snap.sensitivity == "low"


# =====================================================================
# Section 6: RiskMetricsSnapshot
# =====================================================================

class TestSnapshot:
    """Full snapshot generation."""

    def test_snapshot_to_dict_json_serialisable(self):
        rm = RiskMetrics()
        snap = rm.snapshot(_make_scored_spread(10))
        d = snap.to_dict()
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_snapshot_contains_all_sections(self):
        rm = RiskMetrics()
        snap = rm.snapshot(_make_scored_spread(20))
        assert snap.counts.total == 20
        assert snap.gauge is not None
        assert len(snap.asset_risks) > 0
        assert len(snap.trend) > 0


# =====================================================================
# Section 7: Dashboard Services
# =====================================================================

class TestDashboardServicesThreatScore:
    """DashboardServices.get_threat_score()."""

    def test_no_scorer_returns_empty(self):
        svc = DashboardServices()
        result = svc.get_threat_score()
        assert isinstance(result, ThreatScoreResponse)
        assert result.total_scored == 0

    def test_caches_result(self):
        svc = DashboardServices()
        r1 = svc.get_threat_score()
        r2 = svc.get_threat_score()
        assert r1.generated_at == r2.generated_at


# =====================================================================
# Section 8: HTML Structure
# =====================================================================

class TestRiskMetricsHTML:
    """Validate risk-metrics.html structure."""

    @pytest.fixture
    def html_content(self):
        path = FRONTEND_DIR / "risk-metrics.html"
        if not path.exists():
            pytest.skip("risk-metrics.html not found")
        return path.read_text()

    def test_has_tailwind_cdn(self, html_content):
        assert "cdn.tailwindcss.com" in html_content

    def test_has_chart_js_cdn(self, html_content):
        assert "chart.js" in html_content.lower() or "chart.umd" in html_content

    def test_has_counter_cards(self, html_content):
        assert 'id="count-critical"' in html_content
        assert 'id="count-high"' in html_content
        assert 'id="count-medium"' in html_content
        assert 'id="count-low"' in html_content

    def test_has_sparkline_containers(self, html_content):
        assert 'id="sparkline-critical"' in html_content
        assert 'id="sparkline-low"' in html_content

    def test_has_threat_gauge(self, html_content):
        assert 'id="threat-gauge"' in html_content

    def test_has_trend_chart(self, html_content):
        assert 'id="trend-chart"' in html_content

    def test_has_asset_risk_chart(self, html_content):
        assert 'id="asset-risk-chart"' in html_content

    def test_has_sensitivity_selector(self, html_content):
        assert 'id="sensitivity-selector"' in html_content
        assert 'data-sensitivity="low"' in html_content
        assert 'data-sensitivity="moderate"' in html_content
        assert 'data-sensitivity="high"' in html_content

    def test_has_live_badge(self, html_content):
        assert 'id="live-badge"' in html_content

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

    def test_loads_risk_metrics_js(self, html_content):
        assert 'src="js/risk-metrics.js"' in html_content


# =====================================================================
# Section 9: JS File Structure
# =====================================================================

class TestRiskMetricsJS:
    """Validate risk-metrics.js structure."""

    @pytest.fixture
    def js_content(self):
        path = FRONTEND_DIR / "js" / "risk-metrics.js"
        if not path.exists():
            pytest.skip("risk-metrics.js not found")
        return path.read_text()

    def test_imports_api_client(self, js_content):
        assert "api-client" in js_content

    def test_has_colour_constants(self, js_content):
        assert "COLOURS" in js_content
        assert "GAUGE_ZONES" in js_content

    def test_has_fetch_functions(self, js_content):
        assert "fetchThreatScore" in js_content
        assert "fetchChartData" in js_content
        assert "fetchAssets" in js_content

    def test_has_counter_update(self, js_content):
        assert "updateCounters" in js_content

    def test_has_sparkline_drawing(self, js_content):
        assert "drawSparkline" in js_content

    def test_has_gauge_drawing(self, js_content):
        assert "drawGauge" in js_content

    def test_has_gauge_value_computation(self, js_content):
        assert "computeGaugeValue" in js_content

    def test_has_sensitivity_setup(self, js_content):
        assert "setupSensitivity" in js_content

    def test_has_websocket(self, js_content):
        assert "WebSocket" in js_content
        assert "connectWebSocket" in js_content

    def test_has_30_second_refresh(self, js_content):
        assert "30000" in js_content

    def test_has_exports(self, js_content):
        assert "export" in js_content


# =====================================================================
# Section 10: Navigation & Routes
# =====================================================================

class TestRiskMetricsNavigation:
    """Verify Risk Metrics tab in index.html."""

    @pytest.fixture
    def index_content(self):
        path = FRONTEND_DIR / "index.html"
        if not path.exists():
            pytest.skip("index.html not found")
        return path.read_text()

    def test_has_risk_metrics_tab(self, index_content):
        assert 'id="tab-btn-risk-metrics"' in index_content

    def test_has_risk_metrics_panel(self, index_content):
        assert 'id="tab-panel-risk-metrics"' in index_content

    def test_risk_tab_after_timeline(self, index_content):
        timeline_pos = index_content.index('id="tab-btn-timeline"')
        risk_pos = index_content.index('id="tab-btn-risk-metrics"')
        assert risk_pos > timeline_pos


class TestRiskMetricsRoutes:
    """Verify routes in main.py."""

    @pytest.fixture
    def main_content(self):
        path = Path(__file__).parent.parent / "src" / "citadel_archer" / "api" / "main.py"
        if not path.exists():
            pytest.skip("main.py not found")
        return path.read_text()

    def test_risk_metrics_html_route(self, main_content):
        assert "/risk-metrics.html" in main_content

    def test_risk_metrics_redirect_route(self, main_content):
        assert '"/risk-metrics"' in main_content
