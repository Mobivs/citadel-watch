# PRD: Intel Module - Multi-Asset View
# Reference: PHASE_2_SPEC.md
#
# Provides the data model, sorting, filtering, and drill-down logic
# for the multi-asset overview table:
#   1. Columns: asset name, status, threat level, last event, 24h count
#   2. Sortable by every column
#   3. Filterable by status and threat level
#   4. Colour-coded row styling
#   5. Click-through: asset → full timeline for that asset
#
# All output follows a dict-serialisable convention so the frontend
# can render the table directly from the JSON payload.

import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .assets import Asset, AssetInventory, AssetStatus
from .event_aggregator import AggregatedEvent, EventCategory
from .threat_scorer import RiskLevel, ScoredThreat, _RISK_RANK


# ── Enums ────────────────────────────────────────────────────────────

class AssetSortField(str, Enum):
    """Columns by which the asset table can be sorted."""

    NAME = "name"
    STATUS = "status"
    THREAT_LEVEL = "threat_level"
    LAST_EVENT = "last_event"
    EVENT_COUNT = "event_count"


class AssetSortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"


# ── Row colour mapping ──────────────────────────────────────────────

_ROW_COLOURS: Dict[str, str] = {
    "critical": "rgba(239, 68, 68, 0.15)",    # red tint
    "high": "rgba(249, 115, 22, 0.15)",       # orange tint
    "medium": "rgba(245, 158, 11, 0.10)",     # amber tint
    "low": "rgba(16, 185, 129, 0.08)",        # emerald tint
}

_STATUS_COLOURS: Dict[str, str] = {
    "online": "rgba(16, 185, 129, 0.9)",      # emerald
    "offline": "rgba(107, 114, 128, 0.9)",    # gray
    "protected": "rgba(59, 130, 246, 0.9)",   # blue
    "compromised": "rgba(239, 68, 68, 0.9)",  # red
}

# Numeric rank for status sorting (higher = worse)
_STATUS_RANK: Dict[str, int] = {
    "online": 0,
    "protected": 1,
    "offline": 2,
    "compromised": 3,
}


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class AssetRow:
    """A single row in the multi-asset overview table."""

    asset_id: str = ""
    asset_name: str = ""
    status: str = "online"
    threat_level: str = "low"
    last_event: str = ""
    event_count_24h: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    row_colour: str = ""
    status_colour: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AssetTableView:
    """Complete asset overview table response."""

    rows: List[AssetRow] = field(default_factory=list)
    total_assets: int = 0
    total_filtered: int = 0
    sort_field: str = "threat_level"
    sort_order: str = "desc"
    filters_applied: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rows": [r.to_dict() for r in self.rows],
            "total_assets": self.total_assets,
            "total_filtered": self.total_filtered,
            "sort_field": self.sort_field,
            "sort_order": self.sort_order,
            "filters_applied": self.filters_applied,
        }


@dataclass
class AssetDetail:
    """Drill-down detail for a single asset (click-through view)."""

    asset_id: str = ""
    asset_name: str = ""
    status: str = "online"
    platform: str = ""
    hostname: str = ""
    ip_address: str = ""
    threat_level: str = "low"
    event_count_24h: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    recent_events: List[Dict[str, Any]] = field(default_factory=list)
    threat_timeline: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Filtering ───────────────────────────────────────────────────────

def filter_asset_rows(
    rows: List[AssetRow],
    status: Optional[str] = None,
    threat_level: Optional[str] = None,
) -> List[AssetRow]:
    """Filter asset rows by status and/or threat level."""
    result = rows

    if status:
        s = status.lower()
        result = [r for r in result if r.status.lower() == s]

    if threat_level:
        tl = threat_level.lower()
        result = [r for r in result if r.threat_level.lower() == tl]

    return result


# ── Sorting ─────────────────────────────────────────────────────────

def sort_asset_rows(
    rows: List[AssetRow],
    sort_field: AssetSortField = AssetSortField.THREAT_LEVEL,
    sort_order: AssetSortOrder = AssetSortOrder.DESC,
) -> List[AssetRow]:
    """Sort asset rows by the given column and order."""
    reverse = sort_order == AssetSortOrder.DESC

    if sort_field == AssetSortField.NAME:
        key = lambda r: r.asset_name.lower()
    elif sort_field == AssetSortField.STATUS:
        key = lambda r: _STATUS_RANK.get(r.status.lower(), 0)
    elif sort_field == AssetSortField.THREAT_LEVEL:
        key = lambda r: _RISK_RANK.get(RiskLevel(r.threat_level.lower()), 0)
    elif sort_field == AssetSortField.LAST_EVENT:
        key = lambda r: r.last_event or ""
    elif sort_field == AssetSortField.EVENT_COUNT:
        key = lambda r: r.event_count_24h
    else:
        key = lambda r: _RISK_RANK.get(RiskLevel(r.threat_level.lower()), 0)

    return sorted(rows, key=key, reverse=reverse)


# ── Row builder ─────────────────────────────────────────────────────

def build_asset_row(
    asset: Asset,
    events_24h: List[AggregatedEvent],
    scored_threats: Optional[List[ScoredThreat]] = None,
) -> AssetRow:
    """Build a single table row from an asset and its recent data."""
    # Last event timestamp
    last_event = ""
    if events_24h:
        last_event = max(e.timestamp for e in events_24h)

    # Threat level from scored threats
    threat_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if scored_threats:
        for st in scored_threats:
            level = st.risk_level.value
            if level in threat_counts:
                threat_counts[level] += 1

    # Determine highest threat level
    if threat_counts["critical"] > 0:
        threat_level = "critical"
    elif threat_counts["high"] > 0:
        threat_level = "high"
    elif threat_counts["medium"] > 0:
        threat_level = "medium"
    else:
        threat_level = "low"

    return AssetRow(
        asset_id=asset.asset_id,
        asset_name=asset.name or asset.hostname or asset.asset_id,
        status=asset.status.value,
        threat_level=threat_level,
        last_event=last_event,
        event_count_24h=len(events_24h),
        critical_count=threat_counts["critical"],
        high_count=threat_counts["high"],
        medium_count=threat_counts["medium"],
        low_count=threat_counts["low"],
        row_colour=_ROW_COLOURS.get(threat_level, _ROW_COLOURS["low"]),
        status_colour=_STATUS_COLOURS.get(asset.status.value, _STATUS_COLOURS["online"]),
    )


# ── AssetView engine ────────────────────────────────────────────────

class AssetView:
    """Multi-asset overview table engine.

    Combines ``AssetInventory`` data with event history and threat
    scores to produce a sortable, filterable table for the dashboard.

    Args:
        inventory: Optional ``AssetInventory`` for registered assets.
    """

    def __init__(self, inventory: Optional[AssetInventory] = None):
        self._inventory = inventory
        self._lock = threading.RLock()
        self._events: Dict[str, List[AggregatedEvent]] = defaultdict(list)
        self._threats: Dict[str, List[ScoredThreat]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Data ingestion
    # ------------------------------------------------------------------

    def ingest_events(self, events: List[AggregatedEvent]) -> int:
        """Index events by asset ID. Returns count ingested."""
        with self._lock:
            count = 0
            for e in events:
                aid = e.asset_id or "_unknown"
                self._events[aid].append(e)
                count += 1
            return count

    def ingest_threats(self, threats: List[ScoredThreat]) -> int:
        """Index scored threats by asset ID. Returns count ingested."""
        with self._lock:
            count = 0
            for t in threats:
                aid = t.asset_id or "_unknown"
                self._threats[aid].append(t)
                count += 1
            return count

    def clear(self) -> None:
        """Clear all cached events and threats."""
        with self._lock:
            self._events.clear()
            self._threats.clear()

    # ------------------------------------------------------------------
    # 24-hour windowing
    # ------------------------------------------------------------------

    def _events_24h(self, asset_id: str) -> List[AggregatedEvent]:
        """Filter events for the last 24 hours."""
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        return [
            e for e in self._events.get(asset_id, [])
            if e.timestamp >= cutoff
        ]

    def _threats_24h(self, asset_id: str) -> List[ScoredThreat]:
        """Filter scored threats for the last 24 hours."""
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        return [
            t for t in self._threats.get(asset_id, [])
            if t.timestamp >= cutoff
        ]

    # ------------------------------------------------------------------
    # Table building
    # ------------------------------------------------------------------

    def _build_rows(self) -> List[AssetRow]:
        """Build one row per known asset."""
        with self._lock:
            # Collect asset IDs from both inventory and ingested data
            asset_ids: set = set()
            if self._inventory:
                for a in self._inventory.all():
                    asset_ids.add(a.asset_id)
            asset_ids.update(self._events.keys())
            asset_ids.update(self._threats.keys())
            asset_ids.discard("_unknown")

            rows: List[AssetRow] = []
            for aid in asset_ids:
                asset = self._inventory.get(aid) if self._inventory else None
                if asset is None:
                    # Synthesise a minimal Asset
                    asset = Asset(asset_id=aid, name=aid, status=AssetStatus.ONLINE)

                events = self._events_24h(aid)
                threats = self._threats_24h(aid)
                rows.append(build_asset_row(asset, events, threats))

            return rows

    def query(
        self,
        status: Optional[str] = None,
        threat_level: Optional[str] = None,
        sort_field: AssetSortField = AssetSortField.THREAT_LEVEL,
        sort_order: AssetSortOrder = AssetSortOrder.DESC,
    ) -> AssetTableView:
        """Full query with filtering and sorting."""
        all_rows = self._build_rows()
        total_assets = len(all_rows)

        filtered = filter_asset_rows(all_rows, status=status, threat_level=threat_level)
        total_filtered = len(filtered)

        sorted_rows = sort_asset_rows(filtered, sort_field, sort_order)

        filters_applied: Dict[str, str] = {}
        if status:
            filters_applied["status"] = status
        if threat_level:
            filters_applied["threat_level"] = threat_level

        return AssetTableView(
            rows=sorted_rows,
            total_assets=total_assets,
            total_filtered=total_filtered,
            sort_field=sort_field.value,
            sort_order=sort_order.value,
            filters_applied=filters_applied,
        )

    # ------------------------------------------------------------------
    # Drill-down: click asset → full timeline
    # ------------------------------------------------------------------

    def asset_detail(self, asset_id: str) -> Optional[AssetDetail]:
        """Build a drill-down detail view for a single asset."""
        with self._lock:
            asset = self._inventory.get(asset_id) if self._inventory else None
            if asset is None and asset_id not in self._events and asset_id not in self._threats:
                return None

            if asset is None:
                asset = Asset(asset_id=asset_id, name=asset_id, status=AssetStatus.ONLINE)

            events = self._events_24h(asset_id)
            threats = self._threats_24h(asset_id)

            # Threat level counts
            threat_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for t in threats:
                level = t.risk_level.value
                if level in threat_counts:
                    threat_counts[level] += 1

            if threat_counts["critical"] > 0:
                threat_level = "critical"
            elif threat_counts["high"] > 0:
                threat_level = "high"
            elif threat_counts["medium"] > 0:
                threat_level = "medium"
            else:
                threat_level = "low"

            # Recent events (latest 20, sorted newest-first)
            sorted_events = sorted(events, key=lambda e: e.timestamp, reverse=True)[:20]
            recent = [e.to_dict() for e in sorted_events]

            # Threat timeline (scored threats, sorted newest-first)
            sorted_threats = sorted(threats, key=lambda t: t.timestamp, reverse=True)[:20]
            timeline = [t.to_dict() for t in sorted_threats]

            return AssetDetail(
                asset_id=asset.asset_id,
                asset_name=asset.name or asset.hostname or asset.asset_id,
                status=asset.status.value,
                platform=asset.platform.value,
                hostname=asset.hostname,
                ip_address=asset.ip_address,
                threat_level=threat_level,
                event_count_24h=len(events),
                critical_count=threat_counts["critical"],
                high_count=threat_counts["high"],
                medium_count=threat_counts["medium"],
                low_count=threat_counts["low"],
                recent_events=recent,
                threat_timeline=timeline,
            )

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Quick stats for the asset table."""
        rows = self._build_rows()
        by_status: Dict[str, int] = defaultdict(int)
        by_threat: Dict[str, int] = defaultdict(int)
        for r in rows:
            by_status[r.status] += 1
            by_threat[r.threat_level] += 1
        return {
            "total_assets": len(rows),
            "by_status": dict(by_status),
            "by_threat_level": dict(by_threat),
        }
