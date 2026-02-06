# Tests for T13: Charts & Trend Visualization Data Layer
# Covers: ChartTheme, ChartDataset, ChartConfig, AggregationInterval,
#          threat_trend_chart, severity_distribution_chart,
#          timeline_scatter_chart, category_breakdown_chart,
#          build_all_charts, bucket generation, responsive config.

from datetime import datetime, timedelta

import pytest

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
    _bucket_key,
    _generate_bucket_keys,
    _label_format,
    _SEVERITY_Y,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_events(count: int = 10, hours_back: int = 12,
                 severity: str = "info", category: EventCategory = EventCategory.FILE,
                 asset_id: str = "a1") -> list:
    now = datetime.utcnow()
    return [
        AggregatedEvent(
            event_type="file.modified",
            category=category,
            severity=severity,
            asset_id=asset_id,
            message=f"evt-{i}",
            timestamp=(now - timedelta(hours=hours_back - i)).isoformat(),
        )
        for i in range(count)
    ]


def _mixed_events() -> list:
    """Create events with mixed severities and categories."""
    now = datetime.utcnow()
    events = []
    specs = [
        ("info", EventCategory.FILE),
        ("info", EventCategory.FILE),
        ("investigate", EventCategory.PROCESS),
        ("alert", EventCategory.NETWORK),
        ("alert", EventCategory.PROCESS),
        ("critical", EventCategory.NETWORK),
        ("critical", EventCategory.SYSTEM),
        ("info", EventCategory.VAULT),
    ]
    for i, (sev, cat) in enumerate(specs):
        events.append(AggregatedEvent(
            event_type=f"{cat.value}.test",
            category=cat,
            severity=sev,
            message=f"mixed-{i}",
            timestamp=(now - timedelta(hours=i)).isoformat(),
        ))
    return events


# ── ChartTheme ───────────────────────────────────────────────────────

class TestChartTheme:
    def test_severity_colour_info(self):
        c = ChartTheme.severity_colour("info", 0.5)
        assert "0.5" in c
        assert "16, 185, 129" in c  # emerald

    def test_severity_colour_critical(self):
        c = ChartTheme.severity_colour("critical")
        assert "239, 68, 68" in c  # red

    def test_severity_colour_unknown_falls_back(self):
        c = ChartTheme.severity_colour("unknown")
        # Falls back to LOW colour
        assert "16, 185, 129" in c

    def test_category_colour(self):
        c = ChartTheme.category_colour("network", 0.7)
        assert "0, 217, 255" in c  # neon-blue

    def test_category_colour_unknown(self):
        c = ChartTheme.category_colour("nonexistent")
        assert "107, 114, 128" in c  # gray fallback


# ── ChartDataset ─────────────────────────────────────────────────────

class TestChartDataset:
    def test_to_dict(self):
        ds = ChartDataset(label="Test", data=[1, 2, 3],
                          backgroundColor="red", borderColor="blue")
        d = ds.to_dict()
        assert d["label"] == "Test"
        assert d["data"] == [1, 2, 3]
        assert d["tension"] == 0.4

    def test_defaults(self):
        ds = ChartDataset()
        assert ds.fill is False
        assert ds.borderWidth == 2
        assert ds.pointRadius == 3


# ── ChartConfig ──────────────────────────────────────────────────────

class TestChartConfig:
    def test_to_dict_structure(self):
        cfg = ChartConfig(
            chart_type="bar",
            labels=["A", "B"],
            datasets=[ChartDataset(label="D1", data=[10, 20])],
            title="Test Chart",
        )
        d = cfg.to_dict()
        assert d["type"] == "bar"
        assert d["data"]["labels"] == ["A", "B"]
        assert len(d["data"]["datasets"]) == 1
        assert d["options"]["responsive"] is True
        assert d["options"]["plugins"]["title"]["display"] is True
        assert d["options"]["plugins"]["title"]["text"] == "Test Chart"

    def test_no_title(self):
        cfg = ChartConfig(chart_type="line", title="")
        d = cfg.to_dict()
        assert d["options"]["plugins"]["title"]["display"] is False


# ── Bucket helpers ───────────────────────────────────────────────────

class TestBucketHelpers:
    def test_bucket_key_hourly(self):
        dt = datetime(2025, 6, 15, 14, 37, 22)
        assert _bucket_key(dt, AggregationInterval.HOURLY) == "2025-06-15T14:00"

    def test_bucket_key_daily(self):
        dt = datetime(2025, 6, 15, 14, 37, 22)
        assert _bucket_key(dt, AggregationInterval.DAILY) == "2025-06-15"

    def test_generate_bucket_keys_hourly(self):
        start = datetime(2025, 1, 1, 0, 0)
        end = datetime(2025, 1, 1, 3, 0)
        keys = _generate_bucket_keys(start, end, AggregationInterval.HOURLY)
        assert len(keys) == 4  # 00, 01, 02, 03
        assert keys[0] == "2025-01-01T00:00"
        assert keys[-1] == "2025-01-01T03:00"

    def test_generate_bucket_keys_daily(self):
        start = datetime(2025, 1, 1)
        end = datetime(2025, 1, 3)
        keys = _generate_bucket_keys(start, end, AggregationInterval.DAILY)
        assert len(keys) == 3  # Jan 1, 2, 3

    def test_label_format_hourly(self):
        assert _label_format("2025-06-15T14:00", AggregationInterval.HOURLY) == "14:00"

    def test_label_format_daily(self):
        assert _label_format("2025-06-15", AggregationInterval.DAILY) == "2025-06-15"


# ── threat_trend_chart ───────────────────────────────────────────────

class TestThreatTrendChart:
    def test_empty_events(self):
        cfg = threat_trend_chart([], hours=4)
        assert cfg.chart_type == "line"
        assert cfg.title == "Threat Trends"
        assert len(cfg.datasets) == 4
        assert all(sum(ds.data) == 0 for ds in cfg.datasets)

    def test_events_bucketed(self):
        events = _make_events(5, hours_back=3, severity="info")
        cfg = threat_trend_chart(events, hours=4)
        low_ds = cfg.datasets[0]  # "Low"
        assert sum(low_ds.data) >= 1

    def test_critical_events_in_correct_dataset(self):
        events = _make_events(3, hours_back=2, severity="critical")
        cfg = threat_trend_chart(events, hours=4)
        crit_ds = cfg.datasets[3]  # "Critical"
        assert sum(crit_ds.data) >= 1
        low_ds = cfg.datasets[0]
        assert sum(low_ds.data) == 0

    def test_daily_interval(self):
        events = _make_events(10, hours_back=48, severity="info")
        cfg = threat_trend_chart(events, interval=AggregationInterval.DAILY, hours=72)
        assert len(cfg.labels) >= 2

    def test_fill_enabled(self):
        cfg = threat_trend_chart([], hours=2)
        assert all(ds.fill is True for ds in cfg.datasets)

    def test_to_dict_chartjs_compatible(self):
        cfg = threat_trend_chart([], hours=2)
        d = cfg.to_dict()
        assert d["type"] == "line"
        assert "labels" in d["data"]
        assert len(d["data"]["datasets"]) == 4


# ── severity_distribution_chart ──────────────────────────────────────

class TestSeverityDistribution:
    def test_empty_events(self):
        cfg = severity_distribution_chart([])
        assert cfg.chart_type == "doughnut"
        assert len(cfg.datasets) == 1
        assert cfg.datasets[0].data == [0, 0, 0, 0]

    def test_counts_correct(self):
        events = _mixed_events()
        cfg = severity_distribution_chart(events)
        data = cfg.datasets[0].data
        # labels: [Low, Medium, High, Critical]
        assert data[0] >= 1   # info + investigate → low
        assert data[2] >= 1   # alert → high
        assert data[3] >= 1   # critical

    def test_labels(self):
        cfg = severity_distribution_chart([])
        assert cfg.labels == ["Low", "Medium", "High", "Critical"]

    def test_background_colours_list(self):
        cfg = severity_distribution_chart([])
        bg = cfg.datasets[0].backgroundColor
        assert isinstance(bg, list)
        assert len(bg) == 4


# ── timeline_scatter_chart ───────────────────────────────────────────

class TestTimelineScatter:
    def test_empty_events(self):
        cfg = timeline_scatter_chart([], hours=4)
        assert cfg.chart_type == "scatter"
        assert len(cfg.datasets) == 4
        assert all(len(ds.data) == 0 for ds in cfg.datasets)

    def test_points_have_xy(self):
        events = _make_events(3, hours_back=2, severity="critical")
        cfg = timeline_scatter_chart(events, hours=4)
        crit_ds = cfg.datasets[3]  # Critical
        assert len(crit_ds.data) >= 1
        point = crit_ds.data[0]
        assert "x" in point
        assert "y" in point
        assert point["y"] == _SEVERITY_Y["critical"]

    def test_severity_y_mapping(self):
        assert _SEVERITY_Y["info"] == 1.0
        assert _SEVERITY_Y["critical"] == 4.0
        assert _SEVERITY_Y["alert"] == 3.0

    def test_old_events_filtered_out(self):
        old_events = _make_events(3, hours_back=100, severity="info")
        cfg = timeline_scatter_chart(old_events, hours=4)
        total = sum(len(ds.data) for ds in cfg.datasets)
        assert total == 0

    def test_point_radius(self):
        cfg = timeline_scatter_chart([], hours=2)
        assert all(ds.pointRadius == 5 for ds in cfg.datasets)


# ── category_breakdown_chart ─────────────────────────────────────────

class TestCategoryBreakdown:
    def test_empty(self):
        cfg = category_breakdown_chart([])
        assert cfg.chart_type == "bar"
        assert len(cfg.labels) == 0

    def test_counts_by_category(self):
        events = _mixed_events()
        cfg = category_breakdown_chart(events)
        assert len(cfg.labels) >= 2
        # Sorted descending by count
        data = cfg.datasets[0].data
        assert data == sorted(data, reverse=True)

    def test_colours_match_categories(self):
        events = _mixed_events()
        cfg = category_breakdown_chart(events)
        bg = cfg.datasets[0].backgroundColor
        assert isinstance(bg, list)
        assert len(bg) == len(cfg.labels)


# ── build_all_charts ─────────────────────────────────────────────────

class TestBuildAllCharts:
    def test_keys(self):
        result = build_all_charts([])
        assert set(result.keys()) == {"trend", "severity", "timeline", "category"}

    def test_each_is_chartjs_dict(self):
        events = _mixed_events()
        result = build_all_charts(events, hours=24)
        for key in ("trend", "severity", "timeline", "category"):
            chart = result[key]
            assert "type" in chart
            assert "data" in chart
            assert "options" in chart
            assert "datasets" in chart["data"]

    def test_custom_interval(self):
        result = build_all_charts([], interval=AggregationInterval.DAILY, hours=72)
        assert result["trend"]["type"] == "line"


# ── Responsive / dark theme ──────────────────────────────────────────

class TestResponsiveAndTheme:
    def test_responsive_default_true(self):
        cfg = threat_trend_chart([], hours=2)
        d = cfg.to_dict()
        assert d["options"]["responsive"] is True

    def test_all_charts_responsive(self):
        result = build_all_charts([])
        for chart in result.values():
            assert chart["options"]["responsive"] is True

    def test_theme_colours_are_rgba(self):
        c = ChartTheme.severity_colour("critical", 0.5)
        assert c.startswith("rgba(")
        assert "0.5" in c
