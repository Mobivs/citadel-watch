# PRD: Intel Module - Risk Metrics Display
# Reference: PHASE_2_SPEC.md
#
# Computes and formats risk metrics for the dashboard panel:
#   1. Threat counts by risk level (Critical / High / Medium / Low)
#   2. Threat level distribution gauge chart (Chart.js compatible)
#   3. Asset risk status bar chart (per-asset breakdown)
#   4. Trending: threats per hour over the last 24 h
#   5. Sensitivity control (LOW / MODERATE / HIGH)
#
# All chart outputs follow Chart.js conventions so the frontend
# can pass data directly to ``new Chart(ctx, config)``.

import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .anomaly_detector import Sensitivity
from .chart_data import ChartConfig, ChartDataset, ChartTheme
from .event_aggregator import AggregatedEvent
from .threat_scorer import RiskLevel, ScoredThreat, ThreatScorer, _RISK_RANK


# ── Enums ────────────────────────────────────────────────────────────

class GaugeZone(str, Enum):
    """Visual zones for the threat-level gauge."""

    SAFE = "safe"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


# Gauge colour constants (glassmorphic dark theme)
_GAUGE_COLOURS: Dict[GaugeZone, str] = {
    GaugeZone.SAFE: "rgba(16, 185, 129, {a})",       # emerald
    GaugeZone.ELEVATED: "rgba(245, 158, 11, {a})",   # amber
    GaugeZone.HIGH: "rgba(249, 115, 22, {a})",       # orange
    GaugeZone.CRITICAL: "rgba(239, 68, 68, {a})",    # red
}


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class ThreatCounts:
    """Threat counts by risk level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["total"] = self.total
        return d


@dataclass
class TrendPoint:
    """A single point in the threats-per-hour trend line."""

    hour_label: str = ""        # e.g. "14:00"
    timestamp_iso: str = ""     # bucket start ISO
    count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AssetRisk:
    """Risk summary for a single asset."""

    asset_id: str = ""
    total_threats: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    highest_risk: str = "low"
    avg_risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GaugeData:
    """Data payload for the threat-level gauge chart."""

    value: float = 0.0          # 0.0 – 1.0 overall risk
    zone: GaugeZone = GaugeZone.SAFE
    label: str = "Safe"
    zones: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["zone"] = self.zone.value
        return d


@dataclass
class RiskMetricsSnapshot:
    """Complete risk-metrics panel payload."""

    counts: ThreatCounts = field(default_factory=ThreatCounts)
    gauge: GaugeData = field(default_factory=GaugeData)
    asset_risks: List[AssetRisk] = field(default_factory=list)
    trend: List[TrendPoint] = field(default_factory=list)
    sensitivity: str = "moderate"
    generated_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts.to_dict(),
            "gauge": self.gauge.to_dict(),
            "asset_risks": [a.to_dict() for a in self.asset_risks],
            "trend": [t.to_dict() for t in self.trend],
            "sensitivity": self.sensitivity,
            "generated_at": self.generated_at,
        }


# ── Helper functions ─────────────────────────────────────────────────

def _classify_risk(threat: ScoredThreat) -> str:
    """Return the risk level value string for a scored threat."""
    return threat.risk_level.value


def _gauge_zone(value: float) -> Tuple[GaugeZone, str]:
    """Map an overall risk value (0-1) to a gauge zone and label."""
    if value >= 0.75:
        return GaugeZone.CRITICAL, "Critical"
    if value >= 0.50:
        return GaugeZone.HIGH, "High"
    if value >= 0.25:
        return GaugeZone.ELEVATED, "Elevated"
    return GaugeZone.SAFE, "Safe"


def _build_gauge_zones() -> List[Dict[str, Any]]:
    """Static zone definitions for the gauge rendering."""
    return [
        {"min": 0.0, "max": 0.25, "colour": _GAUGE_COLOURS[GaugeZone.SAFE].format(a=0.8), "label": "Safe"},
        {"min": 0.25, "max": 0.50, "colour": _GAUGE_COLOURS[GaugeZone.ELEVATED].format(a=0.8), "label": "Elevated"},
        {"min": 0.50, "max": 0.75, "colour": _GAUGE_COLOURS[GaugeZone.HIGH].format(a=0.8), "label": "High"},
        {"min": 0.75, "max": 1.0, "colour": _GAUGE_COLOURS[GaugeZone.CRITICAL].format(a=0.8), "label": "Critical"},
    ]


# ── Chart builders ───────────────────────────────────────────────────

def gauge_chart(gauge_data: GaugeData) -> ChartConfig:
    """Build a Chart.js doughnut config representing a gauge.

    Uses a half-doughnut pattern: the data array has the value slice
    and a transparent remainder slice.  The ``zones`` list provides
    the colour gradient backdrop.
    """
    value = max(0.0, min(1.0, gauge_data.value))
    remainder = 1.0 - value

    # Determine active zone colour
    zone, _label = _gauge_zone(value)
    active_colour = _GAUGE_COLOURS[zone].format(a=0.9)

    dataset = ChartDataset(
        label="Risk Level",
        data=[value, remainder],
        backgroundColor=[active_colour, "rgba(55, 65, 81, 0.3)"],
        borderColor=["rgba(255,255,255,0.1)", "rgba(255,255,255,0.05)"],
        borderWidth=1,
    )

    return ChartConfig(
        chart_type="doughnut",
        labels=["Risk", ""],
        datasets=[dataset],
        title="Threat Level",
        responsive=True,
    )


def asset_risk_bar_chart(asset_risks: List[AssetRisk]) -> ChartConfig:
    """Build a stacked bar chart of per-asset threat counts."""
    if not asset_risks:
        return ChartConfig(
            chart_type="bar",
            labels=[],
            datasets=[],
            title="Asset Risk Status",
        )

    # Sort by total threats descending
    sorted_assets = sorted(asset_risks, key=lambda a: a.total_threats, reverse=True)
    labels = [a.asset_id for a in sorted_assets]

    datasets = [
        ChartDataset(
            label="Critical",
            data=[a.critical for a in sorted_assets],
            backgroundColor=ChartTheme.CRITICAL.format(a=0.8),
            borderColor=ChartTheme.CRITICAL.format(a=1),
            borderWidth=1,
        ),
        ChartDataset(
            label="High",
            data=[a.high for a in sorted_assets],
            backgroundColor=ChartTheme.HIGH.format(a=0.8),
            borderColor=ChartTheme.HIGH.format(a=1),
            borderWidth=1,
        ),
        ChartDataset(
            label="Medium",
            data=[a.medium for a in sorted_assets],
            backgroundColor=ChartTheme.MEDIUM.format(a=0.8),
            borderColor=ChartTheme.MEDIUM.format(a=1),
            borderWidth=1,
        ),
        ChartDataset(
            label="Low",
            data=[a.low for a in sorted_assets],
            backgroundColor=ChartTheme.LOW.format(a=0.8),
            borderColor=ChartTheme.LOW.format(a=1),
            borderWidth=1,
        ),
    ]

    return ChartConfig(
        chart_type="bar",
        labels=labels,
        datasets=datasets,
        title="Asset Risk Status",
    )


def trend_line_chart(
    trend_points: List[TrendPoint],
) -> ChartConfig:
    """Build a line chart of threats per hour (last 24 h)."""
    labels = [tp.hour_label for tp in trend_points]

    datasets = [
        ChartDataset(
            label="Total",
            data=[tp.count for tp in trend_points],
            backgroundColor="rgba(147, 51, 234, 0.2)",
            borderColor="rgba(147, 51, 234, 1)",
            fill=True,
            tension=0.3,
        ),
        ChartDataset(
            label="Critical",
            data=[tp.critical for tp in trend_points],
            backgroundColor=ChartTheme.CRITICAL.format(a=0.15),
            borderColor=ChartTheme.CRITICAL.format(a=1),
            fill=False,
            tension=0.3,
            borderWidth=1,
            pointRadius=2,
        ),
        ChartDataset(
            label="High",
            data=[tp.high for tp in trend_points],
            backgroundColor=ChartTheme.HIGH.format(a=0.15),
            borderColor=ChartTheme.HIGH.format(a=1),
            fill=False,
            tension=0.3,
            borderWidth=1,
            pointRadius=2,
        ),
    ]

    return ChartConfig(
        chart_type="line",
        labels=labels,
        datasets=datasets,
        title="Threats / Hour (24 h)",
    )


# ── RiskMetrics engine ───────────────────────────────────────────────

class RiskMetrics:
    """Computes risk metrics from scored threats for dashboard display.

    Args:
        scorer: Optional ``ThreatScorer`` for live event scoring.
        sensitivity: Initial sensitivity preset (passed through to
            the ``ThreatScorer`` / ``AnomalyDetector``).
    """

    def __init__(
        self,
        scorer: Optional[ThreatScorer] = None,
        sensitivity: Sensitivity = Sensitivity.MODERATE,
    ):
        self._scorer = scorer
        self._sensitivity = sensitivity
        self._lock = threading.RLock()
        self._scored_cache: List[ScoredThreat] = []

    # ------------------------------------------------------------------
    # Sensitivity control
    # ------------------------------------------------------------------

    @property
    def sensitivity(self) -> Sensitivity:
        return self._sensitivity

    def set_sensitivity(self, sensitivity: Sensitivity) -> None:
        """Change sensitivity level."""
        with self._lock:
            self._sensitivity = sensitivity

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_scored(self, threats: List[ScoredThreat]) -> None:
        """Add pre-scored threats to the internal cache."""
        with self._lock:
            self._scored_cache.extend(threats)

    def score_and_ingest(self, events: List[AggregatedEvent]) -> List[ScoredThreat]:
        """Score events via the ThreatScorer and store results.

        Returns the scored threats.
        """
        if self._scorer is None:
            return []
        scored = self._scorer.score_batch(events)
        with self._lock:
            self._scored_cache.extend(scored)
        return scored

    def clear(self) -> None:
        """Clear the scored-threat cache."""
        with self._lock:
            self._scored_cache.clear()

    # ------------------------------------------------------------------
    # Metric computation
    # ------------------------------------------------------------------

    def threat_counts(
        self, threats: Optional[List[ScoredThreat]] = None,
    ) -> ThreatCounts:
        """Count threats by risk level."""
        data = threats if threats is not None else self._scored_cache
        counts = ThreatCounts()
        for t in data:
            level = t.risk_level
            if level == RiskLevel.CRITICAL:
                counts.critical += 1
            elif level == RiskLevel.HIGH:
                counts.high += 1
            elif level == RiskLevel.MEDIUM:
                counts.medium += 1
            else:
                counts.low += 1
        return counts

    def overall_risk(
        self, threats: Optional[List[ScoredThreat]] = None,
    ) -> float:
        """Compute a single 0-1 overall risk value.

        Uses a weighted formula that emphasises the most severe threats:
        ``weighted_sum / max_possible`` where critical=4, high=3,
        medium=2, low=1.
        """
        data = threats if threats is not None else self._scored_cache
        if not data:
            return 0.0
        weights = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
        }
        total_weight = sum(weights[t.risk_level] for t in data)
        max_possible = len(data) * 4  # all critical
        return round(min(1.0, total_weight / max_possible), 4)

    def build_gauge(
        self, threats: Optional[List[ScoredThreat]] = None,
    ) -> GaugeData:
        """Build gauge data from the current threat set."""
        value = self.overall_risk(threats)
        zone, label = _gauge_zone(value)
        return GaugeData(
            value=value,
            zone=zone,
            label=label,
            zones=_build_gauge_zones(),
        )

    def asset_risk_breakdown(
        self, threats: Optional[List[ScoredThreat]] = None,
    ) -> List[AssetRisk]:
        """Compute per-asset risk summaries."""
        data = threats if threats is not None else self._scored_cache
        assets: Dict[str, Dict[str, Any]] = {}

        for t in data:
            aid = t.asset_id or "_unknown"
            if aid not in assets:
                assets[aid] = {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "scores": [],
                    "highest_rank": 0,
                }
            entry = assets[aid]
            entry["total"] += 1
            level = t.risk_level.value
            entry[level] = entry.get(level, 0) + 1
            entry["scores"].append(t.risk_score)
            rank = _RISK_RANK.get(t.risk_level, 0)
            if rank > entry["highest_rank"]:
                entry["highest_rank"] = rank

        # Map rank back to level string
        rank_to_level = {v: k.value for k, v in _RISK_RANK.items()}

        result: List[AssetRisk] = []
        for aid, info in assets.items():
            avg_score = (
                sum(info["scores"]) / len(info["scores"])
                if info["scores"]
                else 0.0
            )
            result.append(AssetRisk(
                asset_id=aid,
                total_threats=info["total"],
                critical=info["critical"],
                high=info["high"],
                medium=info["medium"],
                low=info["low"],
                highest_risk=rank_to_level.get(info["highest_rank"], "low"),
                avg_risk_score=round(avg_score, 4),
            ))

        # Sort by highest risk then by total count
        result.sort(
            key=lambda a: (_RISK_RANK.get(RiskLevel(a.highest_risk), 0), a.total_threats),
            reverse=True,
        )
        return result

    def trending(
        self,
        threats: Optional[List[ScoredThreat]] = None,
        hours: int = 24,
    ) -> List[TrendPoint]:
        """Compute threats-per-hour for the last ``hours`` hours."""
        data = threats if threats is not None else self._scored_cache
        now = datetime.utcnow()
        start = now - timedelta(hours=hours)

        # Build hourly buckets
        buckets: Dict[str, Dict[str, int]] = {}
        cursor = start.replace(minute=0, second=0, microsecond=0)
        bucket_keys: List[Tuple[str, str]] = []  # (label, iso)
        while cursor <= now:
            label = cursor.strftime("%H:%M")
            iso = cursor.isoformat()
            buckets[iso] = {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            bucket_keys.append((label, iso))
            cursor += timedelta(hours=1)

        # Place threats in buckets
        for t in data:
            try:
                ts = datetime.fromisoformat(t.timestamp)
            except (ValueError, TypeError):
                continue
            if ts < start:
                continue
            # Find the bucket
            bucket_ts = ts.replace(minute=0, second=0, microsecond=0).isoformat()
            if bucket_ts in buckets:
                buckets[bucket_ts]["count"] += 1
                level = t.risk_level.value
                if level in buckets[bucket_ts]:
                    buckets[bucket_ts][level] += 1

        return [
            TrendPoint(
                hour_label=label,
                timestamp_iso=iso,
                count=buckets[iso]["count"],
                critical=buckets[iso]["critical"],
                high=buckets[iso]["high"],
                medium=buckets[iso]["medium"],
                low=buckets[iso]["low"],
            )
            for label, iso in bucket_keys
        ]

    # ------------------------------------------------------------------
    # Full snapshot
    # ------------------------------------------------------------------

    def snapshot(
        self,
        threats: Optional[List[ScoredThreat]] = None,
        hours: int = 24,
    ) -> RiskMetricsSnapshot:
        """Generate a complete risk-metrics snapshot for the dashboard."""
        with self._lock:
            data = threats if threats is not None else list(self._scored_cache)

        counts = self.threat_counts(data)
        gauge = self.build_gauge(data)
        asset_risks = self.asset_risk_breakdown(data)
        trend = self.trending(data, hours)

        return RiskMetricsSnapshot(
            counts=counts,
            gauge=gauge,
            asset_risks=asset_risks,
            trend=trend,
            sensitivity=self._sensitivity.value,
        )

    # ------------------------------------------------------------------
    # Chart configs (ready for frontend)
    # ------------------------------------------------------------------

    def gauge_chart_config(
        self, threats: Optional[List[ScoredThreat]] = None,
    ) -> Dict[str, Any]:
        """Return Chart.js config for the threat-level gauge."""
        gauge_data = self.build_gauge(threats)
        return gauge_chart(gauge_data).to_dict()

    def asset_chart_config(
        self, threats: Optional[List[ScoredThreat]] = None,
    ) -> Dict[str, Any]:
        """Return Chart.js config for the asset risk bar chart."""
        assets = self.asset_risk_breakdown(threats)
        return asset_risk_bar_chart(assets).to_dict()

    def trend_chart_config(
        self,
        threats: Optional[List[ScoredThreat]] = None,
        hours: int = 24,
    ) -> Dict[str, Any]:
        """Return Chart.js config for the threats/hour trend line."""
        points = self.trending(threats, hours)
        return trend_line_chart(points).to_dict()

    def all_chart_configs(
        self,
        threats: Optional[List[ScoredThreat]] = None,
        hours: int = 24,
    ) -> Dict[str, Dict[str, Any]]:
        """Return all risk-metric chart configs in one dict."""
        return {
            "gauge": self.gauge_chart_config(threats),
            "asset_risk": self.asset_chart_config(threats),
            "trend": self.trend_chart_config(threats, hours),
        }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "cached_threats": len(self._scored_cache),
                "sensitivity": self._sensitivity.value,
                "has_scorer": self._scorer is not None,
            }
