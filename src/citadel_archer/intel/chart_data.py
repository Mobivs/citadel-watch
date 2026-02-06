# PRD: Intel Module - Charts & Trend Visualization Data Layer
# Reference: PHASE_2_SPEC.md
#
# Transforms raw event data into Chart.js-compatible structures:
#   1. Threat trend chart  — Time × Count (hourly/daily buckets)
#   2. Severity distribution — Pie/doughnut breakdown
#   3. Timeline scatter plot — Events × severity over time
#
# Output format follows Chart.js dataset conventions so the
# frontend can pass data directly to ``new Chart(ctx, config)``.

import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .event_aggregator import AggregatedEvent, EventCategory


# ── Enums ────────────────────────────────────────────────────────────

class AggregationInterval(str, Enum):
    """Time-bucket granularity for trend charts."""

    HOURLY = "hourly"
    DAILY = "daily"


# ── Theme colours (glassmorphic dark theme) ──────────────────────────

class ChartTheme:
    """Colour constants aligned with the glassmorphic dark theme."""

    # Severity colours (RGBA)
    LOW = "rgba(16, 185, 129, {a})"          # emerald / green
    MEDIUM = "rgba(245, 158, 11, {a})"       # amber / yellow
    HIGH = "rgba(249, 115, 22, {a})"         # orange
    CRITICAL = "rgba(239, 68, 68, {a})"      # red

    # Category colours
    CATEGORY_COLOURS: Dict[str, str] = {
        "file": "rgba(59, 130, 246, {a})",       # blue
        "process": "rgba(168, 85, 247, {a})",    # purple
        "network": "rgba(0, 217, 255, {a})",     # neon-blue
        "vault": "rgba(245, 158, 11, {a})",      # amber
        "system": "rgba(107, 114, 128, {a})",    # gray
        "ai": "rgba(236, 72, 153, {a})",         # pink
        "user": "rgba(16, 185, 129, {a})",       # emerald
        "intel": "rgba(249, 115, 22, {a})",      # orange
    }

    @classmethod
    def severity_colour(cls, severity: str, alpha: float = 1.0) -> str:
        mapping = {
            "info": cls.LOW,
            "investigate": cls.MEDIUM,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "alert": cls.HIGH,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        template = mapping.get(severity.lower(), cls.LOW)
        return template.format(a=alpha)

    @classmethod
    def category_colour(cls, category: str, alpha: float = 1.0) -> str:
        template = cls.CATEGORY_COLOURS.get(
            category.lower(), "rgba(107, 114, 128, {a})"
        )
        return template.format(a=alpha)


# ── Data structures ──────────────────────────────────────────────────

# Severity numeric mapping for scatter plot Y-axis
_SEVERITY_Y: Dict[str, float] = {
    "info": 1.0,
    "investigate": 2.0,
    "low": 1.0,
    "medium": 2.0,
    "alert": 3.0,
    "high": 3.0,
    "critical": 4.0,
}


@dataclass
class ChartDataset:
    """A single Chart.js dataset."""

    label: str = ""
    data: List[Any] = field(default_factory=list)
    backgroundColor: Any = ""
    borderColor: str = ""
    borderWidth: int = 2
    fill: bool = False
    tension: float = 0.4
    pointRadius: int = 3

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChartConfig:
    """Chart.js-compatible config payload."""

    chart_type: str = "line"             # line, bar, pie, doughnut, scatter
    labels: List[str] = field(default_factory=list)
    datasets: List[ChartDataset] = field(default_factory=list)
    title: str = ""
    responsive: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.chart_type,
            "data": {
                "labels": self.labels,
                "datasets": [ds.to_dict() for ds in self.datasets],
            },
            "options": {
                "responsive": self.responsive,
                "plugins": {"title": {"display": bool(self.title), "text": self.title}},
            },
        }


# ── Formatters ───────────────────────────────────────────────────────

def _bucket_key(ts: datetime, interval: AggregationInterval) -> str:
    if interval == AggregationInterval.HOURLY:
        return ts.strftime("%Y-%m-%dT%H:00")
    return ts.strftime("%Y-%m-%d")


def _label_format(key: str, interval: AggregationInterval) -> str:
    if interval == AggregationInterval.HOURLY:
        try:
            dt = datetime.fromisoformat(key)
            return dt.strftime("%H:%M")
        except ValueError:
            return key
    return key


def _generate_bucket_keys(
    start: datetime, end: datetime, interval: AggregationInterval
) -> List[str]:
    keys: List[str] = []
    step = timedelta(hours=1) if interval == AggregationInterval.HOURLY else timedelta(days=1)
    cursor = start.replace(minute=0, second=0, microsecond=0)
    if interval == AggregationInterval.DAILY:
        cursor = cursor.replace(hour=0)
    while cursor <= end:
        keys.append(_bucket_key(cursor, interval))
        cursor += step
    return keys


# ── Public API ───────────────────────────────────────────────────────

def threat_trend_chart(
    events: List[AggregatedEvent],
    interval: AggregationInterval = AggregationInterval.HOURLY,
    hours: int = 24,
) -> ChartConfig:
    """Build a stacked area / line chart of threat counts over time.

    Returns a ``ChartConfig`` with four datasets: low, medium, high,
    critical — one value per time bucket.
    """
    now = datetime.utcnow()
    start = now - timedelta(hours=hours)

    bucket_keys = _generate_bucket_keys(start, now, interval)
    buckets: Dict[str, Dict[str, int]] = {
        k: {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for k in bucket_keys
    }

    for evt in events:
        try:
            ts = datetime.fromisoformat(evt.timestamp)
        except (ValueError, TypeError):
            continue
        if ts < start:
            continue
        key = _bucket_key(ts, interval)
        if key not in buckets:
            continue
        sev = evt.severity.lower()
        if sev in ("info", "investigate"):
            buckets[key]["low"] += 1
        elif sev in ("alert",):
            buckets[key]["high"] += 1
        elif sev in ("critical",):
            buckets[key]["critical"] += 1
        else:
            buckets[key]["medium"] += 1

    labels = [_label_format(k, interval) for k in bucket_keys]

    datasets = [
        ChartDataset(
            label="Low",
            data=[buckets[k]["low"] for k in bucket_keys],
            backgroundColor=ChartTheme.LOW.format(a=0.3),
            borderColor=ChartTheme.LOW.format(a=1),
            fill=True,
        ),
        ChartDataset(
            label="Medium",
            data=[buckets[k]["medium"] for k in bucket_keys],
            backgroundColor=ChartTheme.MEDIUM.format(a=0.3),
            borderColor=ChartTheme.MEDIUM.format(a=1),
            fill=True,
        ),
        ChartDataset(
            label="High",
            data=[buckets[k]["high"] for k in bucket_keys],
            backgroundColor=ChartTheme.HIGH.format(a=0.3),
            borderColor=ChartTheme.HIGH.format(a=1),
            fill=True,
        ),
        ChartDataset(
            label="Critical",
            data=[buckets[k]["critical"] for k in bucket_keys],
            backgroundColor=ChartTheme.CRITICAL.format(a=0.3),
            borderColor=ChartTheme.CRITICAL.format(a=1),
            fill=True,
        ),
    ]

    return ChartConfig(
        chart_type="line",
        labels=labels,
        datasets=datasets,
        title="Threat Trends",
    )


def severity_distribution_chart(
    events: List[AggregatedEvent],
) -> ChartConfig:
    """Build a pie / doughnut chart of severity distribution.

    Returns a ``ChartConfig`` with a single dataset whose ``data``
    list corresponds to [low, medium, high, critical] counts.
    """
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for evt in events:
        sev = evt.severity.lower()
        if sev in ("info", "investigate"):
            counts["low"] += 1
        elif sev in ("alert",):
            counts["high"] += 1
        elif sev in ("critical",):
            counts["critical"] += 1
        else:
            counts["medium"] += 1

    labels = ["Low", "Medium", "High", "Critical"]
    data = [counts["low"], counts["medium"], counts["high"], counts["critical"]]

    bg_colours = [
        ChartTheme.LOW.format(a=0.8),
        ChartTheme.MEDIUM.format(a=0.8),
        ChartTheme.HIGH.format(a=0.8),
        ChartTheme.CRITICAL.format(a=0.8),
    ]
    border_colours = [
        ChartTheme.LOW.format(a=1),
        ChartTheme.MEDIUM.format(a=1),
        ChartTheme.HIGH.format(a=1),
        ChartTheme.CRITICAL.format(a=1),
    ]

    dataset = ChartDataset(
        label="Severity",
        data=data,
        backgroundColor=bg_colours,
        borderColor=border_colours,
        borderWidth=1,
    )

    return ChartConfig(
        chart_type="doughnut",
        labels=labels,
        datasets=[dataset],
        title="Severity Distribution",
    )


def timeline_scatter_chart(
    events: List[AggregatedEvent],
    hours: int = 24,
) -> ChartConfig:
    """Build a scatter plot of events over time, Y = severity level.

    Each point is ``{x: ISO-timestamp, y: severity_ordinal}``.
    Points are colour-coded by severity.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=hours)

    # Group points by severity for separate datasets
    groups: Dict[str, List[Dict[str, Any]]] = {
        "low": [],
        "medium": [],
        "high": [],
        "critical": [],
    }

    for evt in events:
        try:
            ts = datetime.fromisoformat(evt.timestamp)
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue

        sev = evt.severity.lower()
        y = _SEVERITY_Y.get(sev, 1.0)
        point = {"x": evt.timestamp, "y": y}

        if sev in ("info", "investigate"):
            groups["low"].append(point)
        elif sev in ("alert",):
            groups["high"].append(point)
        elif sev in ("critical",):
            groups["critical"].append(point)
        else:
            groups["medium"].append(point)

    theme_map = {
        "low": (ChartTheme.LOW, "Low"),
        "medium": (ChartTheme.MEDIUM, "Medium"),
        "high": (ChartTheme.HIGH, "High"),
        "critical": (ChartTheme.CRITICAL, "Critical"),
    }

    datasets = []
    for key in ("low", "medium", "high", "critical"):
        colour_tpl, label = theme_map[key]
        datasets.append(ChartDataset(
            label=label,
            data=groups[key],
            backgroundColor=colour_tpl.format(a=0.7),
            borderColor=colour_tpl.format(a=1),
            pointRadius=5,
        ))

    return ChartConfig(
        chart_type="scatter",
        labels=[],  # scatter uses x/y points, not labels
        datasets=datasets,
        title="Event Timeline",
    )


def category_breakdown_chart(
    events: List[AggregatedEvent],
) -> ChartConfig:
    """Build a horizontal bar chart of event counts by category."""
    counts: Dict[str, int] = defaultdict(int)
    for evt in events:
        counts[evt.category.value] += 1

    ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    labels = [k.capitalize() for k, _ in ordered]
    data = [v for _, v in ordered]
    bg = [ChartTheme.category_colour(k, 0.7) for k, _ in ordered]
    border = [ChartTheme.category_colour(k, 1.0) for k, _ in ordered]

    dataset = ChartDataset(
        label="Events",
        data=data,
        backgroundColor=bg,
        borderColor=border,
        borderWidth=1,
    )

    return ChartConfig(
        chart_type="bar",
        labels=labels,
        datasets=[dataset],
        title="Events by Category",
    )


# ── Convenience: format everything at once ───────────────────────────

def build_all_charts(
    events: List[AggregatedEvent],
    interval: AggregationInterval = AggregationInterval.HOURLY,
    hours: int = 24,
) -> Dict[str, Dict[str, Any]]:
    """Return all four chart configs in a single dict.

    Keys: ``trend``, ``severity``, ``timeline``, ``category``.
    Values: Chart.js-ready dicts (via ``ChartConfig.to_dict()``).
    """
    return {
        "trend": threat_trend_chart(events, interval, hours).to_dict(),
        "severity": severity_distribution_chart(events).to_dict(),
        "timeline": timeline_scatter_chart(events, hours).to_dict(),
        "category": category_breakdown_chart(events).to_dict(),
    }
