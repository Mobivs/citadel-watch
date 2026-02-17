"""Performance analytics API routes — fleet health and per-asset attention scores.

v0.3.34: Read-only analytics over existing data sources. No new agent protocol changes.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..intel.performance_analytics import PerformanceAnalytics
from ..intel.risk_metrics import RiskMetrics
from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/performance", tags=["performance"])


# ── Pydantic Response Models ─────────────────────────────────────────


class PatchInsightModel(BaseModel):
    pending_count: int = 0
    oldest_pending_days: int = 0
    reboot_required: bool = False
    check_status: str = "unknown"
    patch_score: int = 0


class HeartbeatInsightModel(BaseModel):
    last_heartbeat: Optional[str] = None
    hours_since: float = 0.0
    heartbeat_score: int = 0
    stale: bool = False


class AssetAttentionModel(BaseModel):
    asset_id: str = ""
    name: str = ""
    hostname: str = ""
    platform: str = ""
    status: str = "unknown"
    guardian_active: bool = False
    ip_address: str = ""
    attention_score: int = 0
    category: str = "healthy"
    category_color: str = "#00cc66"
    reasons: List[str] = Field(default_factory=list)
    status_score: int = 0
    threat_score: int = 0
    patch_score: int = 0
    heartbeat_score: int = 0
    guardian_score: int = 0
    patch: Optional[PatchInsightModel] = None
    heartbeat: Optional[HeartbeatInsightModel] = None
    threat_summary: Optional[Dict[str, Any]] = None
    agent_id: Optional[str] = None
    last_seen: str = ""


class FleetSummaryModel(BaseModel):
    total_systems: int = 0
    healthy: int = 0
    watch: int = 0
    attention: int = 0
    critical: int = 0
    fleet_score: float = 0.0
    fleet_category: str = "healthy"
    generated_at: str = ""


class PerformanceResponse(BaseModel):
    fleet: FleetSummaryModel
    assets: List[AssetAttentionModel]
    generated_at: str = ""


# ── Data Gathering ───────────────────────────────────────────────────


def _gather_performance_data() -> dict:
    """Collect data from existing services and compute attention scores."""
    from .dashboard_ext import services

    now = datetime.now(timezone.utc)
    analytics = PerformanceAnalytics()

    # 1. Assets
    assets_raw = []
    if services.asset_inventory is not None:
        assets_raw = [a.to_dict() for a in services.asset_inventory.all()]

    # 2. Agents
    agents = []
    if services.shield_db is not None:
        try:
            agents = services.shield_db.list_agents()
        except Exception:
            logger.warning("Could not load agents for performance analytics", exc_info=True)

    # 3. Threat risk per asset
    asset_risks = []
    if services.threat_scorer is not None and services.event_aggregator is not None:
        try:
            events = services.event_aggregator.recent(limit=500)
            scored = services.threat_scorer.score_batch(events)
            rm = RiskMetrics()
            asset_risks = rm.asset_risk_breakdown(scored)
        except Exception:
            logger.warning("Could not compute threat risks for performance analytics", exc_info=True)

    # 4. Compute fleet
    summary, scores = analytics.compute_fleet(assets_raw, asset_risks, agents, now=now)

    return {
        "fleet": summary.to_dict(),
        "assets": [s.to_dict() for s in scores],
        "generated_at": now.isoformat(),
    }


# ── Routes ───────────────────────────────────────────────────────────


@router.get("")
async def get_performance(
    _user: dict = Depends(verify_session_token),
):
    """Fleet performance analytics — which systems need attention."""
    return _gather_performance_data()


@router.get("/{asset_id}")
async def get_asset_performance(
    asset_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Attention score for a single asset."""
    data = _gather_performance_data()
    for asset in data["assets"]:
        if asset["asset_id"] == asset_id:
            return asset
    raise HTTPException(status_code=404, detail="Asset not found")
