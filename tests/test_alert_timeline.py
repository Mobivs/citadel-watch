# Tests for T14: Alert Timeline UI Data Layer
# Covers: TimelineEntry, DrillDownView, TimelineView, SortField,
#          SortOrder, filtering, sorting, pagination, drill-down,
#          AlertTimeline query API, unique value helpers, and summary.

from datetime import datetime, timedelta

import pytest

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
    _SEVERITY_RANK,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_events(count: int = 10) -> list:
    now = datetime.utcnow()
    sevs = ["info", "investigate", "alert", "critical"]
    cats = [EventCategory.FILE, EventCategory.PROCESS,
            EventCategory.NETWORK, EventCategory.SYSTEM]
    events = []
    for i in range(count):
        events.append(AggregatedEvent(
            event_id=f"evt-{i:04d}",
            event_type=f"{cats[i % 4].value}.test",
            category=cats[i % 4],
            severity=sevs[i % 4],
            asset_id=f"asset-{i % 3}",
            message=f"Test event {i}",
            details={"index": i},
            timestamp=(now - timedelta(minutes=count - i)).isoformat(),
        ))
    return events


def _entries_from_events(events: list) -> list:
    return [TimelineEntry.from_event(e) for e in events]


# ── TimelineEntry ────────────────────────────────────────────────────

class TestTimelineEntry:
    def test_from_event(self):
        evt = AggregatedEvent(
            event_id="e1", event_type="file.created",
            category=EventCategory.FILE, severity="alert",
            asset_id="a1", message="File created",
            details={"path": "/tmp/x"},
            timestamp="2025-06-15T10:00:00",
        )
        entry = TimelineEntry.from_event(evt)
        assert entry.event_id == "e1"
        assert entry.event_type == "file.created"
        assert entry.category == "file"
        assert entry.severity == "alert"
        assert entry.asset_id == "a1"
        assert entry.description == "File created"
        assert entry.details["path"] == "/tmp/x"

    def test_to_dict(self):
        entry = TimelineEntry(event_id="e1", severity="info")
        d = entry.to_dict()
        assert d["event_id"] == "e1"
        assert "details" in d

    def test_no_asset_id_defaults_empty(self):
        evt = AggregatedEvent(event_type="sys.start", category=EventCategory.SYSTEM)
        entry = TimelineEntry.from_event(evt)
        assert entry.asset_id == ""


# ── DrillDownView ────────────────────────────────────────────────────

class TestDrillDownView:
    def test_to_dict(self):
        entry = TimelineEntry(event_id="e1", severity="critical")
        dd = DrillDownView(
            entry=entry,
            related_events=[TimelineEntry(event_id="e2")],
            context={"severity_rank": 4},
        )
        d = dd.to_dict()
        assert d["entry"]["event_id"] == "e1"
        assert len(d["related_events"]) == 1
        assert d["context"]["severity_rank"] == 4


# ── TimelineView ─────────────────────────────────────────────────────

class TestTimelineView:
    def test_to_dict(self):
        tv = TimelineView(
            entries=[TimelineEntry(event_id="e1")],
            total_unfiltered=100, total_filtered=50,
            page=2, page_size=25, total_pages=2,
            sort_field="time", sort_order="desc",
            filters_applied={"severity": "critical"},
        )
        d = tv.to_dict()
        assert d["total_unfiltered"] == 100
        assert d["total_filtered"] == 50
        assert d["page"] == 2
        assert d["total_pages"] == 2
        assert d["filters_applied"]["severity"] == "critical"


# ── Filtering ────────────────────────────────────────────────────────

class TestFiltering:
    def test_filter_by_asset(self):
        entries = _entries_from_events(_make_events(12))
        filtered = filter_entries(entries, asset_id="asset-0")
        assert all(e.asset_id == "asset-0" for e in filtered)
        assert len(filtered) < len(entries)

    def test_filter_by_severity(self):
        entries = _entries_from_events(_make_events(12))
        filtered = filter_entries(entries, severity="critical")
        assert all(e.severity == "critical" for e in filtered)

    def test_filter_by_event_type(self):
        entries = _entries_from_events(_make_events(12))
        filtered = filter_entries(entries, event_type="file.test")
        assert all(e.event_type == "file.test" for e in filtered)

    def test_filter_by_category(self):
        entries = _entries_from_events(_make_events(12))
        filtered = filter_entries(entries, category="network")
        assert all(e.category == "network" for e in filtered)

    def test_filter_by_since(self):
        events = _make_events(10)
        entries = _entries_from_events(events)
        cutoff = events[5].timestamp
        filtered = filter_entries(entries, since=cutoff)
        assert all(e.timestamp >= cutoff for e in filtered)

    def test_filter_by_until(self):
        events = _make_events(10)
        entries = _entries_from_events(events)
        cutoff = events[5].timestamp
        filtered = filter_entries(entries, until=cutoff)
        assert all(e.timestamp <= cutoff for e in filtered)

    def test_filter_by_search(self):
        entries = _entries_from_events(_make_events(10))
        filtered = filter_entries(entries, search="event 3")
        assert any("event 3" in e.description.lower() for e in filtered)

    def test_combined_filters(self):
        entries = _entries_from_events(_make_events(20))
        filtered = filter_entries(entries, asset_id="asset-0", severity="info")
        assert all(e.asset_id == "asset-0" and e.severity == "info" for e in filtered)

    def test_no_filter_returns_all(self):
        entries = _entries_from_events(_make_events(10))
        filtered = filter_entries(entries)
        assert len(filtered) == 10


# ── Sorting ──────────────────────────────────────────────────────────

class TestSorting:
    def test_sort_by_time_desc(self):
        entries = _entries_from_events(_make_events(10))
        sorted_e = sort_entries(entries, SortField.TIME, SortOrder.DESC)
        timestamps = [e.timestamp for e in sorted_e]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_sort_by_time_asc(self):
        entries = _entries_from_events(_make_events(10))
        sorted_e = sort_entries(entries, SortField.TIME, SortOrder.ASC)
        timestamps = [e.timestamp for e in sorted_e]
        assert timestamps == sorted(timestamps)

    def test_sort_by_severity_desc(self):
        entries = _entries_from_events(_make_events(12))
        sorted_e = sort_entries(entries, SortField.SEVERITY, SortOrder.DESC)
        ranks = [_SEVERITY_RANK.get(e.severity.lower(), 0) for e in sorted_e]
        assert ranks == sorted(ranks, reverse=True)

    def test_sort_by_asset(self):
        entries = _entries_from_events(_make_events(10))
        sorted_e = sort_entries(entries, SortField.ASSET, SortOrder.ASC)
        ids = [e.asset_id for e in sorted_e]
        assert ids == sorted(ids)

    def test_sort_by_event_type(self):
        entries = _entries_from_events(_make_events(10))
        sorted_e = sort_entries(entries, SortField.EVENT_TYPE, SortOrder.ASC)
        types = [e.event_type for e in sorted_e]
        assert types == sorted(types)

    def test_sort_by_category(self):
        entries = _entries_from_events(_make_events(10))
        sorted_e = sort_entries(entries, SortField.CATEGORY, SortOrder.ASC)
        cats = [e.category for e in sorted_e]
        assert cats == sorted(cats)


# ── Pagination ───────────────────────────────────────────────────────

class TestPagination:
    def test_first_page(self):
        entries = _entries_from_events(_make_events(25))
        page, total_pages = paginate(entries, page=1, page_size=10)
        assert len(page) == 10
        assert total_pages == 3

    def test_last_page(self):
        entries = _entries_from_events(_make_events(25))
        page, total_pages = paginate(entries, page=3, page_size=10)
        assert len(page) == 5

    def test_page_beyond_range_clamps(self):
        entries = _entries_from_events(_make_events(10))
        page, total_pages = paginate(entries, page=999, page_size=10)
        assert len(page) == 10  # clamped to last page

    def test_page_zero_clamps_to_one(self):
        entries = _entries_from_events(_make_events(10))
        page, _ = paginate(entries, page=0, page_size=10)
        assert len(page) == 10

    def test_empty_entries(self):
        page, total_pages = paginate([], page=1, page_size=10)
        assert page == []
        assert total_pages == 1


# ── Drill-down ───────────────────────────────────────────────────────

class TestDrillDown:
    def test_find_target(self):
        entries = _entries_from_events(_make_events(10))
        dd = drill_down("evt-0005", entries)
        assert dd is not None
        assert dd.entry.event_id == "evt-0005"

    def test_not_found_returns_none(self):
        entries = _entries_from_events(_make_events(5))
        assert drill_down("nonexistent", entries) is None

    def test_related_events_same_asset(self):
        now = datetime.utcnow()
        events = [
            AggregatedEvent(
                event_id="target", event_type="file.created",
                category=EventCategory.FILE, severity="alert",
                asset_id="a1", message="target",
                timestamp=now.isoformat(),
            ),
            AggregatedEvent(
                event_id="related1", event_type="file.modified",
                category=EventCategory.FILE, severity="info",
                asset_id="a1", message="related same asset",
                timestamp=(now - timedelta(minutes=5)).isoformat(),
            ),
            AggregatedEvent(
                event_id="unrelated", event_type="process.started",
                category=EventCategory.PROCESS, severity="info",
                asset_id="a2", message="different asset",
                timestamp=(now - timedelta(minutes=5)).isoformat(),
            ),
        ]
        entries = _entries_from_events(events)
        dd = drill_down("target", entries, related_window_minutes=30)
        related_ids = {e.event_id for e in dd.related_events}
        assert "related1" in related_ids
        assert "unrelated" not in related_ids

    def test_related_events_same_event_type(self):
        now = datetime.utcnow()
        events = [
            AggregatedEvent(
                event_id="target", event_type="network.blocked",
                category=EventCategory.NETWORK, severity="alert",
                asset_id="a1", timestamp=now.isoformat(),
            ),
            AggregatedEvent(
                event_id="same_type", event_type="network.blocked",
                category=EventCategory.NETWORK, severity="info",
                asset_id="a2",
                timestamp=(now - timedelta(minutes=10)).isoformat(),
            ),
        ]
        entries = _entries_from_events(events)
        dd = drill_down("target", entries, related_window_minutes=30)
        assert any(e.event_id == "same_type" for e in dd.related_events)

    def test_related_outside_window_excluded(self):
        now = datetime.utcnow()
        events = [
            AggregatedEvent(
                event_id="target", event_type="file.created",
                category=EventCategory.FILE, severity="alert",
                asset_id="a1", timestamp=now.isoformat(),
            ),
            AggregatedEvent(
                event_id="old", event_type="file.created",
                category=EventCategory.FILE, severity="info",
                asset_id="a1",
                timestamp=(now - timedelta(hours=2)).isoformat(),
            ),
        ]
        entries = _entries_from_events(events)
        dd = drill_down("target", entries, related_window_minutes=30)
        assert len(dd.related_events) == 0

    def test_context_data(self):
        entries = _entries_from_events(_make_events(5))
        dd = drill_down("evt-0003", entries, related_window_minutes=60)
        assert "severity_rank" in dd.context
        assert "related_count" in dd.context
        assert dd.context["window_minutes"] == 60

    def test_max_related_cap(self):
        now = datetime.utcnow()
        events = [
            AggregatedEvent(
                event_id="target", event_type="file.created",
                category=EventCategory.FILE, severity="alert",
                asset_id="a1", timestamp=now.isoformat(),
            )
        ]
        for i in range(50):
            events.append(AggregatedEvent(
                event_id=f"r-{i}", event_type="file.created",
                category=EventCategory.FILE, severity="info",
                asset_id="a1",
                timestamp=(now - timedelta(minutes=i % 20 + 1)).isoformat(),
            ))
        entries = _entries_from_events(events)
        dd = drill_down("target", entries, max_related=5)
        assert len(dd.related_events) <= 5


# ── AlertTimeline class ─────────────────────────────────────────────

class TestAlertTimeline:
    def test_load(self):
        tl = AlertTimeline()
        count = tl.load(_make_events(10))
        assert count == 10
        assert tl.size == 10

    def test_init_with_events(self):
        tl = AlertTimeline(events=_make_events(5))
        assert tl.size == 5

    def test_append(self):
        tl = AlertTimeline()
        evt = AggregatedEvent(event_type="file.created",
                              category=EventCategory.FILE, severity="info")
        entry = tl.append(evt)
        assert tl.size == 1
        assert entry.event_type == "file.created"

    def test_query_default(self):
        tl = AlertTimeline(events=_make_events(20))
        view = tl.query()
        assert isinstance(view, TimelineView)
        assert view.total_unfiltered == 20
        assert view.total_filtered == 20
        assert view.sort_field == "time"
        assert view.sort_order == "desc"

    def test_query_with_filter(self):
        tl = AlertTimeline(events=_make_events(20))
        view = tl.query(severity="critical")
        assert view.total_filtered < view.total_unfiltered
        assert all(e.severity == "critical" for e in view.entries)
        assert view.filters_applied["severity"] == "critical"

    def test_query_with_sorting(self):
        tl = AlertTimeline(events=_make_events(12))
        view = tl.query(sort_field=SortField.SEVERITY, sort_order=SortOrder.DESC)
        ranks = [_SEVERITY_RANK.get(e.severity.lower(), 0) for e in view.entries]
        assert ranks == sorted(ranks, reverse=True)

    def test_query_with_pagination(self):
        tl = AlertTimeline(events=_make_events(30))
        view = tl.query(page=2, page_size=10)
        assert view.page == 2
        assert view.page_size == 10
        assert len(view.entries) == 10
        assert view.total_pages == 3

    def test_drill_down_via_class(self):
        tl = AlertTimeline(events=_make_events(10))
        dd = tl.drill_down("evt-0005")
        assert dd is not None
        assert dd.entry.event_id == "evt-0005"

    def test_drill_down_not_found(self):
        tl = AlertTimeline(events=_make_events(5))
        assert tl.drill_down("nope") is None


# ── Unique value helpers ─────────────────────────────────────────────

class TestUniqueHelpers:
    def test_unique_assets(self):
        tl = AlertTimeline(events=_make_events(12))
        assets = tl.unique_assets()
        assert len(assets) == 3
        assert assets == sorted(assets)

    def test_unique_event_types(self):
        tl = AlertTimeline(events=_make_events(12))
        types = tl.unique_event_types()
        assert len(types) >= 2

    def test_unique_severities(self):
        tl = AlertTimeline(events=_make_events(12))
        sevs = tl.unique_severities()
        assert len(sevs) >= 2
        # Sorted by rank
        ranks = [_SEVERITY_RANK.get(s.lower(), 0) for s in sevs]
        assert ranks == sorted(ranks)

    def test_unique_categories(self):
        tl = AlertTimeline(events=_make_events(12))
        cats = tl.unique_categories()
        assert len(cats) >= 2


# ── Summary ──────────────────────────────────────────────────────────

class TestSummary:
    def test_summary_structure(self):
        tl = AlertTimeline(events=_make_events(20))
        s = tl.summary()
        assert s["total"] == 20
        assert "by_severity" in s
        assert "by_category" in s
        assert "by_asset" in s
        assert "unique_assets" in s
        assert "unique_event_types" in s

    def test_summary_empty(self):
        tl = AlertTimeline()
        s = tl.summary()
        assert s["total"] == 0


# ── TimelineView serialization ───────────────────────────────────────

class TestTimelineViewSerialization:
    def test_full_round_trip(self):
        tl = AlertTimeline(events=_make_events(15))
        view = tl.query(severity="alert", sort_field=SortField.TIME,
                        page=1, page_size=5)
        d = view.to_dict()
        assert isinstance(d["entries"], list)
        assert d["sort_field"] == "time"
        assert d["filters_applied"]["severity"] == "alert"
        assert d["total_pages"] >= 1
