# PRD: Intel Module - Alert Timeline UI Data Layer
# Reference: PHASE_2_SPEC.md
#
# Provides the data model, filtering, sorting, pagination, and
# drill-down logic for the alert timeline component (D3.js frontend).
#
# Each timeline entry carries: timestamp, asset, event type, severity,
# category, description, and a full detail payload for drill-down.
#
# The frontend receives a ``TimelineView`` dict that it can render
# directly — all filtering, sorting, and pagination are server-side
# so the UI stays thin.

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .event_aggregator import AggregatedEvent, EventCategory


# ── Enums ────────────────────────────────────────────────────────────

class SortField(str, Enum):
    """Fields on which the timeline can be sorted."""

    TIME = "time"
    SEVERITY = "severity"
    ASSET = "asset"
    EVENT_TYPE = "event_type"
    CATEGORY = "category"


class SortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"


# Numeric severity for sorting (higher = more severe)
_SEVERITY_RANK: Dict[str, int] = {
    "info": 0,
    "investigate": 1,
    "low": 0,
    "medium": 2,
    "alert": 3,
    "high": 3,
    "critical": 4,
}


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class TimelineEntry:
    """A single row in the alert timeline."""

    event_id: str = ""
    timestamp: str = ""
    asset_id: str = ""
    event_type: str = ""
    category: str = ""
    severity: str = ""
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_event(event: AggregatedEvent) -> "TimelineEntry":
        return TimelineEntry(
            event_id=event.event_id,
            timestamp=event.timestamp,
            asset_id=event.asset_id or "",
            event_type=event.event_type,
            category=event.category.value,
            severity=event.severity,
            description=event.message,
            details=event.details or {},
        )


@dataclass
class DrillDownView:
    """Expanded detail view for a single timeline event."""

    entry: TimelineEntry = field(default_factory=TimelineEntry)
    related_events: List[TimelineEntry] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry": self.entry.to_dict(),
            "related_events": [e.to_dict() for e in self.related_events],
            "context": self.context,
        }


@dataclass
class TimelineView:
    """Complete paginated, filtered, sorted timeline response."""

    entries: List[TimelineEntry] = field(default_factory=list)
    total_unfiltered: int = 0
    total_filtered: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 0
    sort_field: str = "time"
    sort_order: str = "desc"
    filters_applied: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "total_unfiltered": self.total_unfiltered,
            "total_filtered": self.total_filtered,
            "page": self.page,
            "page_size": self.page_size,
            "total_pages": self.total_pages,
            "sort_field": self.sort_field,
            "sort_order": self.sort_order,
            "filters_applied": self.filters_applied,
        }


# ── Filtering ────────────────────────────────────────────────────────

def filter_entries(
    entries: List[TimelineEntry],
    asset_id: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    category: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    search: Optional[str] = None,
) -> List[TimelineEntry]:
    """Apply zero or more filters to a list of timeline entries."""
    result = entries

    if asset_id:
        result = [e for e in result if e.asset_id == asset_id]

    if severity:
        sev_lower = severity.lower()
        result = [e for e in result if e.severity.lower() == sev_lower]

    if event_type:
        result = [e for e in result if e.event_type == event_type]

    if category:
        cat_lower = category.lower()
        result = [e for e in result if e.category.lower() == cat_lower]

    if since:
        result = [e for e in result if e.timestamp >= since]

    if until:
        result = [e for e in result if e.timestamp <= until]

    if search:
        q = search.lower()
        result = [
            e for e in result
            if q in e.description.lower()
            or q in e.event_type.lower()
            or q in e.asset_id.lower()
        ]

    return result


# ── Sorting ──────────────────────────────────────────────────────────

def sort_entries(
    entries: List[TimelineEntry],
    sort_field: SortField = SortField.TIME,
    sort_order: SortOrder = SortOrder.DESC,
) -> List[TimelineEntry]:
    """Sort entries by the given field and order."""
    reverse = sort_order == SortOrder.DESC

    if sort_field == SortField.TIME:
        key = lambda e: e.timestamp
    elif sort_field == SortField.SEVERITY:
        key = lambda e: _SEVERITY_RANK.get(e.severity.lower(), 0)
    elif sort_field == SortField.ASSET:
        key = lambda e: e.asset_id
    elif sort_field == SortField.EVENT_TYPE:
        key = lambda e: e.event_type
    elif sort_field == SortField.CATEGORY:
        key = lambda e: e.category
    else:
        key = lambda e: e.timestamp

    return sorted(entries, key=key, reverse=reverse)


# ── Pagination ───────────────────────────────────────────────────────

def paginate(
    entries: List[TimelineEntry],
    page: int = 1,
    page_size: int = 50,
) -> Tuple[List[TimelineEntry], int]:
    """Return a page slice and total page count."""
    total = len(entries)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size
    end = start + page_size
    return entries[start:end], total_pages


# ── Drill-down ───────────────────────────────────────────────────────

def drill_down(
    event_id: str,
    all_entries: List[TimelineEntry],
    related_window_minutes: int = 30,
    max_related: int = 20,
) -> Optional[DrillDownView]:
    """Build a drill-down view for a specific event.

    Finds the target event, then gathers related events that share
    the same asset or event type within ``related_window_minutes``.
    """
    target = None
    for entry in all_entries:
        if entry.event_id == event_id:
            target = entry
            break

    if target is None:
        return None

    # Parse target timestamp for window calculation
    try:
        target_ts = datetime.fromisoformat(target.timestamp)
    except (ValueError, TypeError):
        target_ts = datetime.utcnow()

    window_start = (target_ts - timedelta(minutes=related_window_minutes)).isoformat()
    window_end = (target_ts + timedelta(minutes=related_window_minutes)).isoformat()

    related: List[TimelineEntry] = []
    for entry in all_entries:
        if entry.event_id == target.event_id:
            continue
        if entry.timestamp < window_start or entry.timestamp > window_end:
            continue
        # Related if same asset or same event type
        if entry.asset_id == target.asset_id and target.asset_id:
            related.append(entry)
        elif entry.event_type == target.event_type:
            related.append(entry)
        if len(related) >= max_related:
            break

    context: Dict[str, Any] = {
        "severity_rank": _SEVERITY_RANK.get(target.severity.lower(), 0),
        "related_count": len(related),
        "window_minutes": related_window_minutes,
    }

    return DrillDownView(
        entry=target,
        related_events=related,
        context=context,
    )


# ── High-level query API ────────────────────────────────────────────

class AlertTimeline:
    """Query interface over a list of ``AggregatedEvent`` objects.

    Converts raw events into ``TimelineEntry`` rows and provides
    filtering, sorting, pagination, and drill-down.
    """

    def __init__(self, events: Optional[List[AggregatedEvent]] = None):
        self._entries: List[TimelineEntry] = []
        if events:
            self.load(events)

    def load(self, events: List[AggregatedEvent]) -> int:
        """Replace internal entries from raw events. Returns count loaded."""
        self._entries = [TimelineEntry.from_event(e) for e in events]
        return len(self._entries)

    def append(self, event: AggregatedEvent) -> TimelineEntry:
        """Add a single event to the timeline."""
        entry = TimelineEntry.from_event(event)
        self._entries.append(entry)
        return entry

    @property
    def size(self) -> int:
        return len(self._entries)

    def query(
        self,
        asset_id: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        category: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        search: Optional[str] = None,
        sort_field: SortField = SortField.TIME,
        sort_order: SortOrder = SortOrder.DESC,
        page: int = 1,
        page_size: int = 50,
    ) -> TimelineView:
        """Full query with filtering, sorting, and pagination."""
        total_unfiltered = len(self._entries)

        filtered = filter_entries(
            self._entries,
            asset_id=asset_id,
            severity=severity,
            event_type=event_type,
            category=category,
            since=since,
            until=until,
            search=search,
        )
        total_filtered = len(filtered)

        sorted_entries = sort_entries(filtered, sort_field, sort_order)
        page_entries, total_pages = paginate(sorted_entries, page, page_size)

        filters_applied: Dict[str, str] = {}
        if asset_id:
            filters_applied["asset_id"] = asset_id
        if severity:
            filters_applied["severity"] = severity
        if event_type:
            filters_applied["event_type"] = event_type
        if category:
            filters_applied["category"] = category
        if since:
            filters_applied["since"] = since
        if until:
            filters_applied["until"] = until
        if search:
            filters_applied["search"] = search

        return TimelineView(
            entries=page_entries,
            total_unfiltered=total_unfiltered,
            total_filtered=total_filtered,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            sort_field=sort_field.value,
            sort_order=sort_order.value,
            filters_applied=filters_applied,
        )

    def drill_down(
        self,
        event_id: str,
        related_window_minutes: int = 30,
        max_related: int = 20,
    ) -> Optional[DrillDownView]:
        """Get drill-down detail for a specific event."""
        return drill_down(
            event_id, self._entries,
            related_window_minutes=related_window_minutes,
            max_related=max_related,
        )

    def unique_assets(self) -> List[str]:
        """Return sorted list of unique asset IDs (for filter dropdowns)."""
        return sorted({e.asset_id for e in self._entries if e.asset_id})

    def unique_event_types(self) -> List[str]:
        """Return sorted list of unique event types (for filter dropdowns)."""
        return sorted({e.event_type for e in self._entries})

    def unique_severities(self) -> List[str]:
        """Return sorted list of unique severity values."""
        return sorted(
            {e.severity for e in self._entries},
            key=lambda s: _SEVERITY_RANK.get(s.lower(), 0),
        )

    def unique_categories(self) -> List[str]:
        """Return sorted list of unique categories."""
        return sorted({e.category for e in self._entries})

    def summary(self) -> Dict[str, Any]:
        """Quick summary stats for the timeline."""
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_asset: Dict[str, int] = {}
        for e in self._entries:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_category[e.category] = by_category.get(e.category, 0) + 1
            if e.asset_id:
                by_asset[e.asset_id] = by_asset.get(e.asset_id, 0) + 1
        return {
            "total": len(self._entries),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_asset": by_asset,
            "unique_assets": len(by_asset),
            "unique_event_types": len(self.unique_event_types()),
        }
