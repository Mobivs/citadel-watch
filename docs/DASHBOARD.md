# Citadel Archer - Dashboard Guide

Guide to the Citadel Archer dashboard: charts, alert timeline, risk metrics, and multi-asset overview.

## Overview

The dashboard is a dark glassmorphic UI built with Vanilla JavaScript and Web Components (Shadow DOM). The backend provides Chart.js-compatible and D3.js-compatible data structures so the frontend can render visualisations directly.

All dashboard data is served from `/api/` endpoints with 5-minute TTL caching for expensive queries.

---

## Charts & Trend Visualization

### Threat Trend Chart

**Type:** Line chart (stacked area)
**Endpoint:** `GET /api/charts`
**Library:** Chart.js

Displays threat counts over time with four severity datasets:

| Dataset | Colour | Severity Mapping |
|---------|--------|-----------------|
| Low | Emerald (green) | info, investigate |
| Medium | Amber (yellow) | medium, default |
| High | Orange | alert |
| Critical | Red | critical |

**Configuration:**
- Default window: 24 hours
- Default bucket: 1 hour
- Stacked area fill with 0.3 alpha backgrounds
- Tension: 0.4 (smooth curves)

**Python API:**
```python
from citadel_archer.intel import threat_trend_chart, AggregationInterval

config = threat_trend_chart(events, interval=AggregationInterval.HOURLY, hours=24)
chart_js_payload = config.to_dict()
# Pass directly to: new Chart(ctx, chart_js_payload)
```

### Severity Distribution Chart

**Type:** Doughnut chart
**Library:** Chart.js

Pie/doughnut breakdown of events by severity level: Low, Medium, High, Critical.

```python
from citadel_archer.intel import severity_distribution_chart

config = severity_distribution_chart(events)
```

### Timeline Scatter Plot

**Type:** Scatter chart
**Library:** Chart.js

Each event plotted as a point: X = timestamp, Y = severity ordinal (1-4). Points colour-coded by severity.

| Severity | Y Value |
|----------|---------|
| info / low | 1.0 |
| investigate / medium | 2.0 |
| alert / high | 3.0 |
| critical | 4.0 |

### Category Breakdown Chart

**Type:** Bar chart (horizontal)
**Library:** Chart.js

Event counts grouped by category (File, Process, Network, Vault, System, AI, User, Intel), sorted descending. Each bar uses the category's theme colour.

### Building All Charts

```python
from citadel_archer.intel import build_all_charts

charts = build_all_charts(events, hours=24)
# Returns: { "trend": {...}, "severity": {...}, "timeline": {...}, "category": {...} }
# Each value is a ready-to-use Chart.js config dict.
```

---

## Risk Metrics Panel

### Threat Counts

Four counters showing the number of threats at each risk level:

| Counter | Colour | Threshold |
|---------|--------|-----------|
| Critical | Red | risk_score >= 0.80 |
| High | Orange | risk_score >= 0.55 |
| Medium | Amber | risk_score >= 0.30 |
| Low | Green | risk_score < 0.30 |

### Threat Level Gauge

**Type:** Doughnut (half-gauge)
**Library:** Chart.js

A single value (0.0-1.0) representing overall risk, mapped to four zones:

| Zone | Range | Colour | Label |
|------|-------|--------|-------|
| Safe | 0.00 - 0.24 | Emerald | Safe |
| Elevated | 0.25 - 0.49 | Amber | Elevated |
| High | 0.50 - 0.74 | Orange | High |
| Critical | 0.75 - 1.00 | Red | Critical |

**Overall risk formula:**

```
weighted_sum = (critical * 4) + (high * 3) + (medium * 2) + (low * 1)
max_possible = total_threats * 4
overall_risk = weighted_sum / max_possible
```

**Python API:**
```python
from citadel_archer.intel import RiskMetrics

metrics = RiskMetrics()
metrics.ingest_scored(scored_threats)

gauge = metrics.build_gauge()
print(f"Risk: {gauge.value:.2f} ({gauge.label})")

# Chart.js config
gauge_config = metrics.gauge_chart_config()
```

### Threats per Hour Trend

**Type:** Line chart
**Library:** Chart.js

Displays three datasets over the last 24 hours:
- **Total** (purple, filled area)
- **Critical** (red, line only)
- **High** (orange, line only)

```python
trend_config = metrics.trend_chart_config(hours=24)
```

### Asset Risk Bar Chart

**Type:** Stacked bar chart
**Library:** Chart.js

Per-asset breakdown with four stacked segments (Critical, High, Medium, Low), sorted by total threats descending.

```python
asset_config = metrics.asset_chart_config()
```

### Complete Snapshot

```python
snap = metrics.snapshot()
# snap.counts       -> ThreatCounts (critical, high, medium, low, total)
# snap.gauge         -> GaugeData (value, zone, label, zones)
# snap.asset_risks   -> List[AssetRisk] (per-asset breakdown)
# snap.trend         -> List[TrendPoint] (hourly buckets)
# snap.sensitivity   -> "moderate"

# Serialise for API response
payload = snap.to_dict()
```

---

## Alert Timeline

### Overview

The alert timeline displays security events chronologically with filtering, sorting, pagination, and drill-down. The data layer produces structures compatible with D3.js rendering.

### Timeline Entry Fields

| Field | Description |
|-------|-------------|
| event_id | Unique event identifier |
| timestamp | ISO 8601 timestamp |
| asset_id | Asset that generated the event |
| event_type | e.g. file.modified, process.started |
| category | file, process, network, vault, system |
| severity | info, investigate, alert, critical |
| description | Human-readable event message |
| details | Full event payload (drill-down) |

### Filtering

Filter by any combination of:

| Filter | Parameter | Example |
|--------|-----------|---------|
| Asset | `asset_id` | `"srv-web-01"` |
| Severity | `severity` | `"critical"` |
| Event type | `event_type` | `"file.modified"` |
| Category | `category` | `"network"` |
| Time range | `since` / `until` | ISO timestamps |
| Text search | `search` | `"malware"` |

### Sorting

| Sort Field | Description |
|------------|-------------|
| TIME | Timestamp (default, DESC) |
| SEVERITY | Numeric rank (info=0, critical=4) |
| ASSET | Asset ID alphabetical |
| EVENT_TYPE | Event type alphabetical |
| CATEGORY | Category alphabetical |

### Pagination

Server-side pagination with configurable page size (default 50):

```python
from citadel_archer.intel import AlertTimeline, SortField, SortOrder

timeline = AlertTimeline(events)
view = timeline.query(
    asset_id="srv-web-01",
    severity="alert",
    sort_field=SortField.TIME,
    sort_order=SortOrder.DESC,
    page=1,
    page_size=50,
)
# view.entries          -> List[TimelineEntry] (page slice)
# view.total_unfiltered -> int (total before filters)
# view.total_filtered   -> int (total after filters)
# view.total_pages      -> int
# view.filters_applied  -> dict
```

### Drill-Down

Click an event to expand its detail view:

```python
detail = timeline.drill_down(event_id="uuid-1234", related_window_minutes=30)
# detail.entry           -> TimelineEntry (target event)
# detail.related_events  -> List[TimelineEntry] (same asset/type within window)
# detail.context         -> dict (severity_rank, related_count, window_minutes)
```

### Filter Dropdowns

Helper methods for populating filter UI dropdowns:

```python
timeline.unique_assets()       # sorted list of asset IDs
timeline.unique_event_types()  # sorted list of event types
timeline.unique_severities()   # sorted by severity rank
timeline.unique_categories()   # sorted list of categories
```

---

## Multi-Asset Overview

### Asset Table

A sortable, filterable table showing all managed assets:

| Column | Description | Sortable |
|--------|-------------|----------|
| Asset Name | Display name or hostname | Yes (A-Z) |
| Status | ONLINE / OFFLINE / PROTECTED / COMPROMISED | Yes (by rank) |
| Threat Level | CRITICAL / HIGH / MEDIUM / LOW | Yes (by rank) |
| Last Event | Most recent event timestamp | Yes |
| Events (24h) | Event count in last 24 hours | Yes |

### Row Colour Coding

Rows are tinted by threat level:

| Threat Level | Row Background |
|--------------|----------------|
| Critical | Red tint (0.15 alpha) |
| High | Orange tint (0.15 alpha) |
| Medium | Amber tint (0.10 alpha) |
| Low | Emerald tint (0.08 alpha) |

Status badges use matching colours:
- Online: Emerald
- Protected: Blue
- Offline: Gray
- Compromised: Red

### Filtering

```python
from citadel_archer.intel import AssetView, AssetSortField, AssetSortOrder

av = AssetView(inventory=asset_inventory)
av.ingest_events(events)
av.ingest_threats(scored_threats)

table = av.query(
    status="online",
    threat_level="critical",
    sort_field=AssetSortField.THREAT_LEVEL,
    sort_order=AssetSortOrder.DESC,
)
```

### Asset Drill-Down

Click an asset row to see its full detail view:

```python
detail = av.asset_detail("srv-web-01")
# detail.asset_id       -> str
# detail.status         -> str
# detail.platform       -> str
# detail.threat_level   -> str
# detail.event_count_24h -> int
# detail.recent_events  -> List[dict] (latest 20 events)
# detail.threat_timeline -> List[dict] (latest 20 scored threats)
```

---

## Theme

All visualisations use the glassmorphic dark theme:

| Element | Colour |
|---------|--------|
| Background | Dark gray with transparency |
| Low / Safe | Emerald `rgba(16, 185, 129)` |
| Medium / Elevated | Amber `rgba(245, 158, 11)` |
| High | Orange `rgba(249, 115, 22)` |
| Critical | Red `rgba(239, 68, 68)` |
| Network | Neon blue `rgba(0, 217, 255)` |
| Process | Purple `rgba(168, 85, 247)` |
| File | Blue `rgba(59, 130, 246)` |

---

## Real-Time Updates

The dashboard receives live events via WebSocket (`/ws` for Phase 1, `EventBroadcaster` for Phase 2). When a new event arrives:

1. The event appears at the top of the alert timeline
2. Threat counts update in the risk metrics panel
3. Chart data refreshes (cached data is invalidated)
4. The asset table updates the affected asset's row

Use `POST /api/cache/clear` to force a refresh of all cached dashboard data.
