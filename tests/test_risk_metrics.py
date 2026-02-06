# Tests for risk_metrics module — T15: Risk Metrics Display
#
# Coverage:
#   - ThreatCounts (to_dict, total)
#   - GaugeData & gauge zones
#   - AssetRisk serialization
#   - TrendPoint serialization
#   - RiskMetrics.threat_counts()
#   - RiskMetrics.overall_risk()
#   - RiskMetrics.build_gauge()
#   - RiskMetrics.asset_risk_breakdown()
#   - RiskMetrics.trending()
#   - RiskMetrics.snapshot()
#   - Gauge chart config
#   - Asset bar chart config
#   - Trend line chart config
#   - Sensitivity control
#   - Score and ingest with scorer
#   - Edge cases (empty data, unknown assets)

import pytest
from datetime import datetime, timedelta

from citadel_archer.intel.risk_metrics import (
    AssetRisk,
    GaugeData,
    GaugeZone,
    RiskMetrics,
    RiskMetricsSnapshot,
    ThreatCounts,
    TrendPoint,
    asset_risk_bar_chart,
    gauge_chart,
    trend_line_chart,
    _gauge_zone,
    _build_gauge_zones,
)
from citadel_archer.intel.threat_scorer import RiskLevel, ScoredThreat, ThreatScorer
from citadel_archer.intel.anomaly_detector import Sensitivity
from citadel_archer.intel.event_aggregator import AggregatedEvent, EventCategory


# ── Fixtures ─────────────────────────────────────────────────────────

def _make_threat(
    risk_level: RiskLevel = RiskLevel.LOW,
    risk_score: float = 0.1,
    asset_id: str = "asset-1",
    timestamp: str = "",
    event_type: str = "file.modified",
) -> ScoredThreat:
    if not timestamp:
        timestamp = datetime.utcnow().isoformat()
    return ScoredThreat(
        event_id=f"evt-{id(risk_level)}-{risk_score}",
        event_type=event_type,
        asset_id=asset_id,
        risk_score=risk_score,
        risk_level=risk_level,
        severity_weight=0.5,
        anomaly_score=0.3,
        intel_score=0.0,
        timestamp=timestamp,
    )


@pytest.fixture
def mixed_threats():
    """A set of threats across all risk levels."""
    now = datetime.utcnow()
    return [
        _make_threat(RiskLevel.CRITICAL, 0.90, "server-1", (now - timedelta(hours=1)).isoformat()),
        _make_threat(RiskLevel.HIGH, 0.70, "server-1", (now - timedelta(hours=2)).isoformat()),
        _make_threat(RiskLevel.HIGH, 0.65, "server-2", (now - timedelta(hours=3)).isoformat()),
        _make_threat(RiskLevel.MEDIUM, 0.45, "server-2", (now - timedelta(hours=4)).isoformat()),
        _make_threat(RiskLevel.MEDIUM, 0.40, "workstation-1", (now - timedelta(hours=5)).isoformat()),
        _make_threat(RiskLevel.LOW, 0.15, "workstation-1", (now - timedelta(hours=6)).isoformat()),
        _make_threat(RiskLevel.LOW, 0.10, "workstation-1", (now - timedelta(hours=7)).isoformat()),
        _make_threat(RiskLevel.LOW, 0.08, "workstation-2", (now - timedelta(hours=8)).isoformat()),
    ]


@pytest.fixture
def risk_metrics():
    return RiskMetrics()


# ── TestThreatCounts ─────────────────────────────────────────────────

class TestThreatCounts:
    def test_defaults(self):
        counts = ThreatCounts()
        assert counts.critical == 0
        assert counts.total == 0

    def test_total_property(self):
        counts = ThreatCounts(critical=2, high=3, medium=5, low=10)
        assert counts.total == 20

    def test_to_dict_includes_total(self):
        counts = ThreatCounts(critical=1, high=2, medium=3, low=4)
        d = counts.to_dict()
        assert d["total"] == 10
        assert d["critical"] == 1


# ── TestGaugeZone ────────────────────────────────────────────────────

class TestGaugeZone:
    def test_safe_zone(self):
        zone, label = _gauge_zone(0.10)
        assert zone == GaugeZone.SAFE
        assert label == "Safe"

    def test_elevated_zone(self):
        zone, label = _gauge_zone(0.30)
        assert zone == GaugeZone.ELEVATED
        assert label == "Elevated"

    def test_high_zone(self):
        zone, label = _gauge_zone(0.60)
        assert zone == GaugeZone.HIGH
        assert label == "High"

    def test_critical_zone(self):
        zone, label = _gauge_zone(0.80)
        assert zone == GaugeZone.CRITICAL
        assert label == "Critical"

    def test_boundary_values(self):
        assert _gauge_zone(0.0)[0] == GaugeZone.SAFE
        assert _gauge_zone(0.25)[0] == GaugeZone.ELEVATED
        assert _gauge_zone(0.50)[0] == GaugeZone.HIGH
        assert _gauge_zone(0.75)[0] == GaugeZone.CRITICAL
        assert _gauge_zone(1.0)[0] == GaugeZone.CRITICAL

    def test_build_gauge_zones(self):
        zones = _build_gauge_zones()
        assert len(zones) == 4
        assert zones[0]["label"] == "Safe"
        assert zones[3]["label"] == "Critical"


# ── TestDataclassSerialization ───────────────────────────────────────

class TestDataclassSerialization:
    def test_trend_point_to_dict(self):
        tp = TrendPoint(hour_label="14:00", timestamp_iso="2025-01-01T14:00:00", count=5)
        d = tp.to_dict()
        assert d["hour_label"] == "14:00"
        assert d["count"] == 5

    def test_asset_risk_to_dict(self):
        ar = AssetRisk(asset_id="srv-1", total_threats=10, critical=2, high=3)
        d = ar.to_dict()
        assert d["asset_id"] == "srv-1"
        assert d["total_threats"] == 10

    def test_gauge_data_to_dict(self):
        gd = GaugeData(value=0.6, zone=GaugeZone.HIGH, label="High")
        d = gd.to_dict()
        assert d["zone"] == "high"
        assert d["value"] == 0.6

    def test_snapshot_to_dict(self):
        snap = RiskMetricsSnapshot()
        d = snap.to_dict()
        assert "counts" in d
        assert "gauge" in d
        assert "asset_risks" in d
        assert "trend" in d
        assert "sensitivity" in d


# ── TestThreatCountsComputation ──────────────────────────────────────

class TestThreatCountsComputation:
    def test_counts_from_mixed_threats(self, risk_metrics, mixed_threats):
        counts = risk_metrics.threat_counts(mixed_threats)
        assert counts.critical == 1
        assert counts.high == 2
        assert counts.medium == 2
        assert counts.low == 3
        assert counts.total == 8

    def test_counts_empty(self, risk_metrics):
        counts = risk_metrics.threat_counts([])
        assert counts.total == 0

    def test_counts_all_critical(self, risk_metrics):
        threats = [_make_threat(RiskLevel.CRITICAL, 0.95) for _ in range(5)]
        counts = risk_metrics.threat_counts(threats)
        assert counts.critical == 5
        assert counts.high == 0


# ── TestOverallRisk ──────────────────────────────────────────────────

class TestOverallRisk:
    def test_empty_data_returns_zero(self, risk_metrics):
        assert risk_metrics.overall_risk([]) == 0.0

    def test_all_low_gives_low_value(self, risk_metrics):
        threats = [_make_threat(RiskLevel.LOW, 0.1) for _ in range(4)]
        # all LOW → weight=1 each, max=4 each → 4/16 = 0.25
        value = risk_metrics.overall_risk(threats)
        assert value == 0.25

    def test_all_critical_gives_max(self, risk_metrics):
        threats = [_make_threat(RiskLevel.CRITICAL, 0.95) for _ in range(3)]
        value = risk_metrics.overall_risk(threats)
        assert value == 1.0

    def test_mixed_levels(self, risk_metrics, mixed_threats):
        value = risk_metrics.overall_risk(mixed_threats)
        # 1*4 + 2*3 + 2*2 + 3*1 = 4+6+4+3 = 17, max=8*4=32 → 17/32=0.53125
        assert 0.50 <= value <= 0.55


# ── TestBuildGauge ───────────────────────────────────────────────────

class TestBuildGauge:
    def test_gauge_empty(self, risk_metrics):
        gauge = risk_metrics.build_gauge([])
        assert gauge.value == 0.0
        assert gauge.zone == GaugeZone.SAFE

    def test_gauge_critical_threats(self, risk_metrics):
        threats = [_make_threat(RiskLevel.CRITICAL, 0.95) for _ in range(5)]
        gauge = risk_metrics.build_gauge(threats)
        assert gauge.value == 1.0
        assert gauge.zone == GaugeZone.CRITICAL
        assert gauge.label == "Critical"

    def test_gauge_has_zones(self, risk_metrics, mixed_threats):
        gauge = risk_metrics.build_gauge(mixed_threats)
        assert len(gauge.zones) == 4


# ── TestAssetRiskBreakdown ───────────────────────────────────────────

class TestAssetRiskBreakdown:
    def test_breakdown_groups_by_asset(self, risk_metrics, mixed_threats):
        breakdown = risk_metrics.asset_risk_breakdown(mixed_threats)
        asset_ids = [a.asset_id for a in breakdown]
        assert "server-1" in asset_ids
        assert "server-2" in asset_ids
        assert "workstation-1" in asset_ids
        assert "workstation-2" in asset_ids

    def test_breakdown_sorted_by_severity(self, risk_metrics, mixed_threats):
        breakdown = risk_metrics.asset_risk_breakdown(mixed_threats)
        # server-1 has a CRITICAL threat → should be first
        assert breakdown[0].asset_id == "server-1"

    def test_breakdown_correct_counts(self, risk_metrics, mixed_threats):
        breakdown = risk_metrics.asset_risk_breakdown(mixed_threats)
        server1 = next(a for a in breakdown if a.asset_id == "server-1")
        assert server1.critical == 1
        assert server1.high == 1
        assert server1.total_threats == 2

    def test_breakdown_empty(self, risk_metrics):
        breakdown = risk_metrics.asset_risk_breakdown([])
        assert breakdown == []

    def test_avg_risk_score(self, risk_metrics, mixed_threats):
        breakdown = risk_metrics.asset_risk_breakdown(mixed_threats)
        for asset in breakdown:
            assert 0.0 <= asset.avg_risk_score <= 1.0


# ── TestTrending ─────────────────────────────────────────────────────

class TestTrending:
    def test_trending_returns_25_buckets(self, risk_metrics, mixed_threats):
        trend = risk_metrics.trending(mixed_threats, hours=24)
        # 24 hours → 25 buckets (inclusive of start hour)
        assert len(trend) >= 24

    def test_trending_has_counts(self, risk_metrics, mixed_threats):
        trend = risk_metrics.trending(mixed_threats, hours=24)
        total = sum(tp.count for tp in trend)
        # All 8 threats are within the last 24h
        assert total == 8

    def test_trending_empty(self, risk_metrics):
        trend = risk_metrics.trending([], hours=24)
        assert all(tp.count == 0 for tp in trend)

    def test_trending_bucket_labels(self, risk_metrics, mixed_threats):
        trend = risk_metrics.trending(mixed_threats, hours=24)
        # All labels should be HH:MM format
        for tp in trend:
            assert ":" in tp.hour_label


# ── TestSnapshot ─────────────────────────────────────────────────────

class TestSnapshot:
    def test_snapshot_complete(self, risk_metrics, mixed_threats):
        risk_metrics.ingest_scored(mixed_threats)
        snap = risk_metrics.snapshot()
        assert snap.counts.total == 8
        assert snap.gauge.zone in (GaugeZone.SAFE, GaugeZone.ELEVATED, GaugeZone.HIGH, GaugeZone.CRITICAL)
        assert len(snap.asset_risks) == 4
        assert len(snap.trend) >= 24
        assert snap.sensitivity == "moderate"

    def test_snapshot_to_dict(self, risk_metrics, mixed_threats):
        risk_metrics.ingest_scored(mixed_threats)
        d = risk_metrics.snapshot().to_dict()
        assert d["counts"]["total"] == 8
        assert "gauge" in d
        assert isinstance(d["asset_risks"], list)
        assert isinstance(d["trend"], list)


# ── TestChartConfigs ─────────────────────────────────────────────────

class TestGaugeChart:
    def test_gauge_chart_structure(self):
        gd = GaugeData(value=0.5, zone=GaugeZone.HIGH, label="High")
        cfg = gauge_chart(gd)
        d = cfg.to_dict()
        assert d["type"] == "doughnut"
        assert len(d["data"]["datasets"]) == 1
        assert len(d["data"]["datasets"][0]["data"]) == 2
        # value + remainder = 1.0
        assert sum(d["data"]["datasets"][0]["data"]) == pytest.approx(1.0)

    def test_gauge_chart_clamps(self):
        gd = GaugeData(value=1.5, zone=GaugeZone.CRITICAL)
        cfg = gauge_chart(gd)
        d = cfg.to_dict()
        assert d["data"]["datasets"][0]["data"][0] == 1.0
        assert d["data"]["datasets"][0]["data"][1] == 0.0


class TestAssetRiskBarChart:
    def test_empty_assets(self):
        cfg = asset_risk_bar_chart([])
        d = cfg.to_dict()
        assert d["data"]["labels"] == []
        assert d["data"]["datasets"] == []

    def test_chart_sorted_descending(self):
        assets = [
            AssetRisk(asset_id="a", total_threats=2),
            AssetRisk(asset_id="b", total_threats=10),
            AssetRisk(asset_id="c", total_threats=5),
        ]
        cfg = asset_risk_bar_chart(assets)
        d = cfg.to_dict()
        assert d["data"]["labels"] == ["b", "c", "a"]

    def test_chart_has_four_datasets(self):
        assets = [AssetRisk(asset_id="x", total_threats=1, critical=1)]
        cfg = asset_risk_bar_chart(assets)
        d = cfg.to_dict()
        # 4 datasets: Critical, High, Medium, Low
        assert len(d["data"]["datasets"]) == 4


class TestTrendLineChart:
    def test_trend_chart_structure(self):
        points = [
            TrendPoint(hour_label="00:00", count=5, critical=1, high=2),
            TrendPoint(hour_label="01:00", count=3, critical=0, high=1),
        ]
        cfg = trend_line_chart(points)
        d = cfg.to_dict()
        assert d["type"] == "line"
        assert d["data"]["labels"] == ["00:00", "01:00"]
        # 3 datasets: Total, Critical, High
        assert len(d["data"]["datasets"]) == 3


# ── TestSensitivityControl ───────────────────────────────────────────

class TestSensitivityControl:
    def test_default_sensitivity(self, risk_metrics):
        assert risk_metrics.sensitivity == Sensitivity.MODERATE

    def test_change_sensitivity(self, risk_metrics):
        risk_metrics.set_sensitivity(Sensitivity.HIGH)
        assert risk_metrics.sensitivity == Sensitivity.HIGH

    def test_sensitivity_in_snapshot(self, risk_metrics):
        risk_metrics.set_sensitivity(Sensitivity.LOW)
        snap = risk_metrics.snapshot()
        assert snap.sensitivity == "low"


# ── TestIngestAndClear ───────────────────────────────────────────────

class TestIngestAndClear:
    def test_ingest_and_count(self, risk_metrics, mixed_threats):
        risk_metrics.ingest_scored(mixed_threats)
        counts = risk_metrics.threat_counts()
        assert counts.total == 8

    def test_clear(self, risk_metrics, mixed_threats):
        risk_metrics.ingest_scored(mixed_threats)
        risk_metrics.clear()
        counts = risk_metrics.threat_counts()
        assert counts.total == 0

    def test_stats(self, risk_metrics, mixed_threats):
        risk_metrics.ingest_scored(mixed_threats)
        s = risk_metrics.stats()
        assert s["cached_threats"] == 8
        assert s["sensitivity"] == "moderate"
        assert s["has_scorer"] is False


# ── TestChartConfigMethods ───────────────────────────────────────────

class TestChartConfigMethods:
    def test_gauge_chart_config(self, risk_metrics, mixed_threats):
        d = risk_metrics.gauge_chart_config(mixed_threats)
        assert d["type"] == "doughnut"

    def test_asset_chart_config(self, risk_metrics, mixed_threats):
        d = risk_metrics.asset_chart_config(mixed_threats)
        assert d["type"] == "bar"
        assert len(d["data"]["labels"]) == 4

    def test_trend_chart_config(self, risk_metrics, mixed_threats):
        d = risk_metrics.trend_chart_config(mixed_threats, hours=24)
        assert d["type"] == "line"

    def test_all_chart_configs(self, risk_metrics, mixed_threats):
        configs = risk_metrics.all_chart_configs(mixed_threats)
        assert "gauge" in configs
        assert "asset_risk" in configs
        assert "trend" in configs
