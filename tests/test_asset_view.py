# Tests for asset_view module — T16: Multi-Asset View
#
# Coverage:
#   - AssetRow serialization & colour coding
#   - AssetTableView serialization
#   - AssetDetail serialization
#   - build_asset_row (row construction from asset + events + threats)
#   - filter_asset_rows (by status, by threat level, combined)
#   - sort_asset_rows (all 5 columns, ASC/DESC)
#   - AssetView.query (full pipeline)
#   - AssetView.asset_detail (drill-down)
#   - AssetView ingestion & clear
#   - Summary stats
#   - Edge cases (no events, no threats, unknown assets)

import pytest
from datetime import datetime, timedelta

from citadel_archer.intel.asset_view import (
    AssetDetail,
    AssetRow,
    AssetSortField,
    AssetSortOrder,
    AssetTableView,
    AssetView,
    build_asset_row,
    filter_asset_rows,
    sort_asset_rows,
)
from citadel_archer.intel.assets import Asset, AssetInventory, AssetPlatform, AssetStatus
from citadel_archer.intel.event_aggregator import AggregatedEvent, EventCategory
from citadel_archer.intel.threat_scorer import RiskLevel, ScoredThreat


# ── Fixtures ─────────────────────────────────────────────────────────

def _make_event(
    asset_id: str = "srv-1",
    severity: str = "info",
    event_type: str = "file.modified",
    hours_ago: float = 1.0,
) -> AggregatedEvent:
    ts = (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat()
    return AggregatedEvent(
        event_type=event_type,
        category=EventCategory.FILE,
        severity=severity,
        asset_id=asset_id,
        message=f"Test event on {asset_id}",
        timestamp=ts,
    )


def _make_threat(
    asset_id: str = "srv-1",
    risk_level: RiskLevel = RiskLevel.LOW,
    risk_score: float = 0.1,
    hours_ago: float = 1.0,
) -> ScoredThreat:
    ts = (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat()
    return ScoredThreat(
        event_id=f"evt-{asset_id}-{risk_score}",
        event_type="file.modified",
        asset_id=asset_id,
        risk_score=risk_score,
        risk_level=risk_level,
        severity_weight=0.5,
        anomaly_score=0.3,
        intel_score=0.0,
        timestamp=ts,
    )


def _make_asset(
    asset_id: str = "srv-1",
    name: str = "Server 1",
    status: AssetStatus = AssetStatus.ONLINE,
) -> Asset:
    return Asset(
        asset_id=asset_id,
        name=name,
        platform=AssetPlatform.LINUX,
        status=status,
        hostname=f"{asset_id}.local",
        ip_address="10.0.0.1",
    )


@pytest.fixture
def inventory():
    inv = AssetInventory()
    inv.register(_make_asset("srv-1", "Server 1", AssetStatus.ONLINE))
    inv.register(_make_asset("srv-2", "Server 2", AssetStatus.PROTECTED))
    inv.register(_make_asset("ws-1", "Workstation 1", AssetStatus.OFFLINE))
    inv.register(_make_asset("ws-2", "Workstation 2", AssetStatus.COMPROMISED))
    return inv


@pytest.fixture
def sample_events():
    return [
        _make_event("srv-1", "critical", hours_ago=1),
        _make_event("srv-1", "alert", hours_ago=2),
        _make_event("srv-1", "info", hours_ago=3),
        _make_event("srv-2", "alert", hours_ago=1),
        _make_event("srv-2", "info", hours_ago=4),
        _make_event("ws-1", "info", hours_ago=2),
        _make_event("ws-2", "investigate", hours_ago=5),
    ]


@pytest.fixture
def sample_threats():
    return [
        _make_threat("srv-1", RiskLevel.CRITICAL, 0.90, hours_ago=1),
        _make_threat("srv-1", RiskLevel.HIGH, 0.70, hours_ago=2),
        _make_threat("srv-2", RiskLevel.HIGH, 0.65, hours_ago=1),
        _make_threat("srv-2", RiskLevel.MEDIUM, 0.45, hours_ago=4),
        _make_threat("ws-1", RiskLevel.LOW, 0.10, hours_ago=2),
        _make_threat("ws-2", RiskLevel.MEDIUM, 0.40, hours_ago=5),
    ]


@pytest.fixture
def asset_view(inventory, sample_events, sample_threats):
    av = AssetView(inventory=inventory)
    av.ingest_events(sample_events)
    av.ingest_threats(sample_threats)
    return av


# ── TestAssetRowSerialization ────────────────────────────────────────

class TestAssetRowSerialization:
    def test_to_dict(self):
        row = AssetRow(asset_id="a1", asset_name="Alpha", status="online", threat_level="high")
        d = row.to_dict()
        assert d["asset_id"] == "a1"
        assert d["asset_name"] == "Alpha"
        assert d["threat_level"] == "high"

    def test_colour_fields_present(self):
        row = AssetRow(row_colour="rgba(1,2,3,0.1)", status_colour="rgba(4,5,6,0.9)")
        d = row.to_dict()
        assert "row_colour" in d
        assert "status_colour" in d


class TestAssetTableViewSerialization:
    def test_to_dict(self):
        view = AssetTableView(total_assets=5, total_filtered=3, sort_field="name")
        d = view.to_dict()
        assert d["total_assets"] == 5
        assert d["sort_field"] == "name"
        assert isinstance(d["rows"], list)


class TestAssetDetailSerialization:
    def test_to_dict(self):
        detail = AssetDetail(asset_id="a1", asset_name="Alpha", event_count_24h=10)
        d = detail.to_dict()
        assert d["asset_id"] == "a1"
        assert d["event_count_24h"] == 10
        assert isinstance(d["recent_events"], list)


# ── TestBuildAssetRow ────────────────────────────────────────────────

class TestBuildAssetRow:
    def test_basic_row(self):
        asset = _make_asset("srv-1", "Server 1")
        events = [_make_event("srv-1", hours_ago=1), _make_event("srv-1", hours_ago=2)]
        threats = [_make_threat("srv-1", RiskLevel.HIGH, 0.7)]
        row = build_asset_row(asset, events, threats)
        assert row.asset_id == "srv-1"
        assert row.asset_name == "Server 1"
        assert row.event_count_24h == 2
        assert row.threat_level == "high"
        assert row.high_count == 1

    def test_row_no_threats(self):
        asset = _make_asset("srv-1")
        events = [_make_event("srv-1")]
        row = build_asset_row(asset, events, scored_threats=None)
        assert row.threat_level == "low"
        assert row.event_count_24h == 1

    def test_row_no_events(self):
        asset = _make_asset("srv-1")
        row = build_asset_row(asset, [], [])
        assert row.event_count_24h == 0
        assert row.last_event == ""

    def test_row_critical_takes_priority(self):
        asset = _make_asset("srv-1")
        threats = [
            _make_threat("srv-1", RiskLevel.LOW, 0.1),
            _make_threat("srv-1", RiskLevel.CRITICAL, 0.95),
            _make_threat("srv-1", RiskLevel.MEDIUM, 0.4),
        ]
        row = build_asset_row(asset, [], threats)
        assert row.threat_level == "critical"

    def test_row_colour_matches_threat_level(self):
        asset = _make_asset("srv-1")
        threats = [_make_threat("srv-1", RiskLevel.CRITICAL, 0.95)]
        row = build_asset_row(asset, [], threats)
        assert "239, 68, 68" in row.row_colour  # red

    def test_status_colour_set(self):
        asset = _make_asset("srv-1", status=AssetStatus.COMPROMISED)
        row = build_asset_row(asset, [], [])
        assert "239, 68, 68" in row.status_colour  # red


# ── TestFilterAssetRows ──────────────────────────────────────────────

class TestFilterAssetRows:
    def _sample_rows(self):
        return [
            AssetRow(asset_id="a1", status="online", threat_level="critical"),
            AssetRow(asset_id="a2", status="offline", threat_level="high"),
            AssetRow(asset_id="a3", status="online", threat_level="low"),
            AssetRow(asset_id="a4", status="compromised", threat_level="medium"),
        ]

    def test_filter_by_status(self):
        rows = self._sample_rows()
        result = filter_asset_rows(rows, status="online")
        assert len(result) == 2
        assert all(r.status == "online" for r in result)

    def test_filter_by_threat_level(self):
        rows = self._sample_rows()
        result = filter_asset_rows(rows, threat_level="critical")
        assert len(result) == 1
        assert result[0].asset_id == "a1"

    def test_filter_combined(self):
        rows = self._sample_rows()
        result = filter_asset_rows(rows, status="online", threat_level="low")
        assert len(result) == 1
        assert result[0].asset_id == "a3"

    def test_filter_no_match(self):
        rows = self._sample_rows()
        result = filter_asset_rows(rows, status="protected")
        assert len(result) == 0

    def test_no_filter_returns_all(self):
        rows = self._sample_rows()
        result = filter_asset_rows(rows)
        assert len(result) == 4

    def test_filter_case_insensitive(self):
        rows = self._sample_rows()
        result = filter_asset_rows(rows, status="ONLINE")
        assert len(result) == 2


# ── TestSortAssetRows ───────────────────────────────────────────────

class TestSortAssetRows:
    def _sample_rows(self):
        return [
            AssetRow(asset_id="a1", asset_name="Charlie", status="online",
                     threat_level="low", event_count_24h=5, last_event="2025-01-01T10:00:00"),
            AssetRow(asset_id="a2", asset_name="Alpha", status="offline",
                     threat_level="critical", event_count_24h=20, last_event="2025-01-01T15:00:00"),
            AssetRow(asset_id="a3", asset_name="Bravo", status="compromised",
                     threat_level="high", event_count_24h=10, last_event="2025-01-01T12:00:00"),
        ]

    def test_sort_by_name_asc(self):
        rows = self._sample_rows()
        result = sort_asset_rows(rows, AssetSortField.NAME, AssetSortOrder.ASC)
        assert [r.asset_name for r in result] == ["Alpha", "Bravo", "Charlie"]

    def test_sort_by_name_desc(self):
        rows = self._sample_rows()
        result = sort_asset_rows(rows, AssetSortField.NAME, AssetSortOrder.DESC)
        assert [r.asset_name for r in result] == ["Charlie", "Bravo", "Alpha"]

    def test_sort_by_threat_level_desc(self):
        rows = self._sample_rows()
        result = sort_asset_rows(rows, AssetSortField.THREAT_LEVEL, AssetSortOrder.DESC)
        assert result[0].threat_level == "critical"
        assert result[-1].threat_level == "low"

    def test_sort_by_status_desc(self):
        rows = self._sample_rows()
        result = sort_asset_rows(rows, AssetSortField.STATUS, AssetSortOrder.DESC)
        assert result[0].status == "compromised"

    def test_sort_by_event_count_desc(self):
        rows = self._sample_rows()
        result = sort_asset_rows(rows, AssetSortField.EVENT_COUNT, AssetSortOrder.DESC)
        assert result[0].event_count_24h == 20

    def test_sort_by_last_event_asc(self):
        rows = self._sample_rows()
        result = sort_asset_rows(rows, AssetSortField.LAST_EVENT, AssetSortOrder.ASC)
        assert result[0].last_event == "2025-01-01T10:00:00"


# ── TestAssetViewQuery ──────────────────────────────────────────────

class TestAssetViewQuery:
    def test_query_all(self, asset_view):
        view = asset_view.query()
        assert view.total_assets == 4
        assert view.total_filtered == 4
        assert len(view.rows) == 4

    def test_query_filter_status(self, asset_view):
        view = asset_view.query(status="online")
        assert view.total_filtered <= view.total_assets
        assert all(r.status == "online" for r in view.rows)

    def test_query_filter_threat_level(self, asset_view):
        view = asset_view.query(threat_level="critical")
        assert all(r.threat_level == "critical" for r in view.rows)

    def test_query_sorted_by_threat(self, asset_view):
        view = asset_view.query(sort_field=AssetSortField.THREAT_LEVEL, sort_order=AssetSortOrder.DESC)
        if len(view.rows) >= 2:
            from citadel_archer.intel.threat_scorer import _RISK_RANK, RiskLevel
            first_rank = _RISK_RANK.get(RiskLevel(view.rows[0].threat_level), 0)
            last_rank = _RISK_RANK.get(RiskLevel(view.rows[-1].threat_level), 0)
            assert first_rank >= last_rank

    def test_query_to_dict(self, asset_view):
        d = asset_view.query().to_dict()
        assert "rows" in d
        assert "total_assets" in d
        assert "filters_applied" in d

    def test_query_records_filters(self, asset_view):
        view = asset_view.query(status="online", threat_level="low")
        assert view.filters_applied["status"] == "online"
        assert view.filters_applied["threat_level"] == "low"


# ── TestAssetViewDrillDown ──────────────────────────────────────────

class TestAssetViewDrillDown:
    def test_detail_existing_asset(self, asset_view):
        detail = asset_view.asset_detail("srv-1")
        assert detail is not None
        assert detail.asset_id == "srv-1"
        assert detail.asset_name == "Server 1"
        assert detail.event_count_24h >= 1
        assert detail.threat_level == "critical"

    def test_detail_includes_recent_events(self, asset_view):
        detail = asset_view.asset_detail("srv-1")
        assert isinstance(detail.recent_events, list)

    def test_detail_includes_threat_timeline(self, asset_view):
        detail = asset_view.asset_detail("srv-1")
        assert isinstance(detail.threat_timeline, list)

    def test_detail_unknown_asset(self, asset_view):
        detail = asset_view.asset_detail("nonexistent-asset")
        assert detail is None

    def test_detail_to_dict(self, asset_view):
        detail = asset_view.asset_detail("srv-1")
        d = detail.to_dict()
        assert d["asset_id"] == "srv-1"
        assert "platform" in d
        assert "hostname" in d


# ── TestIngestAndClear ──────────────────────────────────────────────

class TestIngestAndClear:
    def test_ingest_events(self):
        av = AssetView()
        events = [_make_event("srv-1"), _make_event("srv-2")]
        count = av.ingest_events(events)
        assert count == 2

    def test_ingest_threats(self):
        av = AssetView()
        threats = [_make_threat("srv-1"), _make_threat("srv-2")]
        count = av.ingest_threats(threats)
        assert count == 2

    def test_clear(self, asset_view):
        asset_view.clear()
        # After clear, all rows should have zero events/threats
        view = asset_view.query()
        for row in view.rows:
            assert row.event_count_24h == 0


# ── TestSummary ─────────────────────────────────────────────────────

class TestSummary:
    def test_summary_structure(self, asset_view):
        s = asset_view.summary()
        assert "total_assets" in s
        assert "by_status" in s
        assert "by_threat_level" in s
        assert s["total_assets"] == 4

    def test_summary_empty(self):
        av = AssetView()
        s = av.summary()
        assert s["total_assets"] == 0
