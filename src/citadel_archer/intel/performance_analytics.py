"""Performance analytics — compute per-asset attention scores and fleet health.

Answers the question: "which systems need attention right now, and why?"

Each asset receives a composite attention score (0-100) based on:
  - System status (compromised/offline/unknown) — max 40 pts
  - Threat risk level (from RiskMetrics) — max 25 pts
  - Patch status (pending updates, staleness) — max 20 pts
  - Heartbeat staleness (agent check-in age) — max 10 pts
  - Guardian coverage (active/inactive) — max 5 pts

Pure computation module — no FastAPI, no I/O, no database calls.
All inputs are plain dicts/dataclasses from existing data sources.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .risk_metrics import AssetRisk

# ── Category thresholds ──────────────────────────────────────────────

CATEGORY_THRESHOLDS = [
    (75, "critical", "#ff3333"),
    (50, "attention", "#ff9900"),
    (25, "watch", "#e6b800"),
    (0, "healthy", "#00cc66"),
]

# Threat risk weights by highest-risk level
_HIGHEST_RISK_WEIGHT = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.4,
    "low": 0.1,
}


# ── Dataclasses ──────────────────────────────────────────────────────


@dataclass
class PatchInsight:
    """Parsed and scored patch status from a Remote Shield agent."""

    pending_count: int = 0
    oldest_pending_days: int = 0
    reboot_required: bool = False
    check_status: str = "unknown"
    patch_score: int = 0  # computed 0-20


@dataclass
class HeartbeatInsight:
    """Heartbeat staleness scoring."""

    last_heartbeat: Optional[str] = None
    hours_since: float = 0.0
    heartbeat_score: int = 0  # computed 0-10
    stale: bool = False  # True if > 6h


@dataclass
class AssetAttentionScore:
    """Composite attention score for a single asset."""

    asset_id: str = ""
    name: str = ""
    hostname: str = ""
    platform: str = ""
    status: str = "unknown"
    guardian_active: bool = False
    ip_address: str = ""

    # Sub-scores
    status_score: int = 0  # 0-40
    threat_score: int = 0  # 0-25
    patch_score: int = 0  # 0-20
    heartbeat_score: int = 0  # 0-10
    guardian_score: int = 0  # 0-5
    attention_score: int = 0  # sum, capped at 100

    # Category
    category: str = "healthy"
    category_color: str = "#00cc66"

    # Context
    reasons: List[str] = field(default_factory=list)
    patch: Optional[PatchInsight] = None
    heartbeat: Optional[HeartbeatInsight] = None
    threat_summary: Optional[Dict[str, Any]] = None
    agent_id: Optional[str] = None
    last_seen: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class FleetHealthSummary:
    """Fleet-wide aggregated health metrics."""

    total_systems: int = 0
    healthy: int = 0
    watch: int = 0
    attention: int = 0
    critical: int = 0
    fleet_score: float = 0.0  # weighted avg attention_score, 0-100
    fleet_category: str = "healthy"
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Engine ───────────────────────────────────────────────────────────


class PerformanceAnalytics:
    """Computes per-asset attention scores from existing data sources.

    All inputs are plain dicts as returned by the existing DB/inventory
    methods — no coupling to SQLite or FastAPI layers.
    """

    def compute_fleet(
        self,
        assets: List[dict],
        asset_risks: List[AssetRisk],
        agents: List[dict],
        now: Optional[datetime] = None,
    ) -> Tuple[FleetHealthSummary, List[AssetAttentionScore]]:
        """Compute fleet summary + sorted per-asset scores (worst first).

        Args:
            assets: From AssetInventory.all() → [a.to_dict() for a in ...]
            asset_risks: From RiskMetrics.asset_risk_breakdown()
            agents: From RemoteShieldDatabase.list_agents()
            now: Override for testing.

        Returns:
            (FleetHealthSummary, sorted list of AssetAttentionScore)
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # Build lookup dicts
        risk_by_asset = {r.asset_id: r for r in asset_risks}
        agent_by_asset = {}
        for ag in agents:
            aid = ag.get("asset_id")
            if aid:
                agent_by_asset[aid] = ag

        # Compute per-asset
        scores = []
        for asset in assets:
            aid = asset.get("asset_id", "")
            score = self.compute_attention_score(
                asset=asset,
                asset_risk=risk_by_asset.get(aid),
                agent=agent_by_asset.get(aid),
                now=now,
            )
            scores.append(score)

        # Sort worst-first
        scores.sort(key=lambda s: s.attention_score, reverse=True)

        # Fleet summary
        counts = {"healthy": 0, "watch": 0, "attention": 0, "critical": 0}
        for s in scores:
            if s.category in counts:
                counts[s.category] += 1

        total = len(scores)
        avg = sum(s.attention_score for s in scores) / total if total > 0 else 0.0
        fleet_cat, _ = self._category(round(avg))

        summary = FleetHealthSummary(
            total_systems=total,
            healthy=counts["healthy"],
            watch=counts["watch"],
            attention=counts["attention"],
            critical=counts["critical"],
            fleet_score=round(avg, 1),
            fleet_category=fleet_cat,
            generated_at=now.isoformat(),
        )

        return summary, scores

    def compute_attention_score(
        self,
        asset: dict,
        asset_risk: Optional[AssetRisk] = None,
        agent: Optional[dict] = None,
        now: Optional[datetime] = None,
    ) -> AssetAttentionScore:
        """Compute attention score for a single asset."""
        if now is None:
            now = datetime.now(timezone.utc)

        reasons: List[str] = []

        # Sub-scores
        status_val, status_reasons = self._status_score(asset.get("status", "unknown"))
        reasons.extend(status_reasons)

        threat_val, threat_reasons = self._threat_score(asset_risk)
        reasons.extend(threat_reasons)

        # Patch & heartbeat only for assets with an agent
        patch_insight = None
        hb_insight = None
        patch_val = 0
        hb_val = 0

        if agent is not None:
            patch_status = agent.get("patch_status") or {}
            patch_insight, patch_reasons = self._patch_score(patch_status)
            patch_val = patch_insight.patch_score
            reasons.extend(patch_reasons)

            hb_insight, hb_reasons = self._heartbeat_score(
                agent.get("last_heartbeat"), now
            )
            hb_val = hb_insight.heartbeat_score
            reasons.extend(hb_reasons)

        guardian_val, guardian_reasons = self._guardian_score(
            asset.get("guardian_active", False)
        )
        reasons.extend(guardian_reasons)

        # Composite
        total = min(100, status_val + threat_val + patch_val + hb_val + guardian_val)
        category, color = self._category(total)

        # Threat summary dict
        threat_summary = None
        if asset_risk is not None:
            threat_summary = asset_risk.to_dict()

        return AssetAttentionScore(
            asset_id=asset.get("asset_id", ""),
            name=asset.get("name", ""),
            hostname=asset.get("hostname", ""),
            platform=asset.get("platform", ""),
            status=asset.get("status", "unknown"),
            guardian_active=asset.get("guardian_active", False),
            ip_address=asset.get("ip_address", ""),
            status_score=status_val,
            threat_score=threat_val,
            patch_score=patch_val,
            heartbeat_score=hb_val,
            guardian_score=guardian_val,
            attention_score=total,
            category=category,
            category_color=color,
            reasons=reasons,
            patch=patch_insight,
            heartbeat=hb_insight,
            threat_summary=threat_summary,
            agent_id=agent.get("id") if agent else None,
            last_seen=asset.get("last_seen", ""),
        )

    # ── Sub-score helpers ─────────────────────────────────────────────

    @staticmethod
    def _status_score(status: str) -> Tuple[int, List[str]]:
        """Score based on asset status. Max 40."""
        if status == "compromised":
            return 40, ["Compromised status"]
        if status == "offline":
            return 25, ["Offline"]
        if status == "unknown":
            return 15, ["Unknown status"]
        return 0, []

    @staticmethod
    def _threat_score(asset_risk: Optional[AssetRisk]) -> Tuple[int, List[str]]:
        """Score based on threat risk level. Max 25."""
        if asset_risk is None or asset_risk.total_threats == 0:
            return 0, []

        reasons = []
        avg_component = (asset_risk.avg_risk_score / 100) * 15
        weight = _HIGHEST_RISK_WEIGHT.get(asset_risk.highest_risk, 0.1)
        highest_component = weight * 10

        score = min(25, round(avg_component + highest_component))

        if asset_risk.critical > 0:
            reasons.append(f"{asset_risk.critical} critical threat{'s' if asset_risk.critical > 1 else ''}")
        if asset_risk.high > 0:
            reasons.append(f"{asset_risk.high} high threat{'s' if asset_risk.high > 1 else ''}")

        return score, reasons

    @staticmethod
    def _patch_score(patch_status: dict) -> Tuple[PatchInsight, List[str]]:
        """Score based on patch status. Max 20."""
        if not patch_status:
            return PatchInsight(), []

        pending = patch_status.get("pending_count", 0)
        oldest_days = patch_status.get("oldest_pending_days", 0)
        reboot = patch_status.get("reboot_required", False)
        check_status = patch_status.get("check_status", "unknown")

        reasons = []
        score = 0

        # Pending updates: 2 pts each, max 10
        score += min(10, pending * 2)
        if pending > 0:
            reasons.append(f"{pending} patch{'es' if pending != 1 else ''} pending")

        # Oldest pending: 1 pt per week, max 8
        score += min(8, oldest_days // 7)
        if oldest_days > 14:
            reasons.append(f"Patch {oldest_days} days overdue")

        # Reboot required: flat 2 pts
        if reboot:
            score += 2
            reasons.append("Reboot required")

        score = min(20, score)

        insight = PatchInsight(
            pending_count=pending,
            oldest_pending_days=oldest_days,
            reboot_required=reboot,
            check_status=check_status,
            patch_score=score,
        )
        return insight, reasons

    @staticmethod
    def _heartbeat_score(
        last_heartbeat: Optional[str], now: datetime
    ) -> Tuple[HeartbeatInsight, List[str]]:
        """Score based on heartbeat staleness. Max 10."""
        if not last_heartbeat:
            return HeartbeatInsight(), []

        try:
            hb_time = datetime.fromisoformat(last_heartbeat)
            if hb_time.tzinfo is None:
                hb_time = hb_time.replace(tzinfo=timezone.utc)
            hours_since = (now - hb_time).total_seconds() / 3600
        except (ValueError, TypeError):
            return HeartbeatInsight(), []

        score = 0
        reasons = []

        if hours_since > 72:
            score = 10
        elif hours_since > 24:
            score = 8
        elif hours_since > 6:
            score = 5
        elif hours_since > 1:
            score = 2

        stale = hours_since > 6

        if stale:
            if hours_since >= 24:
                reasons.append(f"No heartbeat for {int(hours_since)}h")
            else:
                reasons.append(f"No heartbeat for {hours_since:.0f}h")

        insight = HeartbeatInsight(
            last_heartbeat=last_heartbeat,
            hours_since=round(hours_since, 1),
            heartbeat_score=score,
            stale=stale,
        )
        return insight, reasons

    @staticmethod
    def _guardian_score(guardian_active: bool) -> Tuple[int, List[str]]:
        """Score based on guardian protection. Max 5."""
        if guardian_active:
            return 0, []
        return 5, ["Guardian inactive"]

    @staticmethod
    def _category(score: int) -> Tuple[str, str]:
        """Map attention score to category name and color."""
        for threshold, name, color in CATEGORY_THRESHOLDS:
            if score >= threshold:
                return name, color
        return "healthy", "#00cc66"
