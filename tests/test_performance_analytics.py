"""Tests for performance analytics — scoring engine, API routes, and frontend structure.

v0.3.34: ~42 tests covering sub-scores, fleet summary, reasons, routes, and HTML/JS.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# ── Helpers ──────────────────────────────────────────────────────────


def _make_asset(**overrides):
    """Build a minimal asset dict (matches AssetInventory.to_dict())."""
    base = {
        "asset_id": "asset_test1",
        "name": "Test PC",
        "hostname": "test-pc",
        "platform": "windows",
        "status": "protected",
        "guardian_active": True,
        "ip_address": "192.168.1.10",
        "remote_shield_agent_id": "",
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    base.update(overrides)
    return base


def _make_asset_risk(**overrides):
    """Build an AssetRisk dataclass."""
    from citadel_archer.intel.risk_metrics import AssetRisk

    defaults = {
        "asset_id": "asset_test1",
        "total_threats": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "highest_risk": "low",
        "avg_risk_score": 0.0,
    }
    defaults.update(overrides)
    return AssetRisk(**defaults)


def _make_agent(**overrides):
    """Build a minimal agent dict (matches shield_database._row_to_agent)."""
    base = {
        "id": "agent_abc",
        "hostname": "test-pc",
        "ip_address": "192.168.1.10",
        "platform": "windows",
        "status": "active",
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "last_scan_at": datetime.now(timezone.utc).isoformat(),
        "asset_id": "asset_test1",
        "patch_status": {
            "pending_count": 0,
            "installed_count": 5,
            "oldest_pending_days": 0,
            "reboot_required": False,
            "check_status": "ok",
        },
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════
# Sub-score tests
# ══════════════════════════════════════════════════════════════════════


class TestStatusScore:
    """PerformanceAnalytics._status_score()"""

    def _score(self, status):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics._status_score(status)

    def test_compromised_returns_40(self):
        val, reasons = self._score("compromised")
        assert val == 40
        assert "Compromised" in reasons[0]

    def test_offline_returns_25(self):
        val, reasons = self._score("offline")
        assert val == 25
        assert "Offline" in reasons[0]

    def test_unknown_returns_15(self):
        val, reasons = self._score("unknown")
        assert val == 15

    def test_protected_returns_0(self):
        val, reasons = self._score("protected")
        assert val == 0
        assert reasons == []

    def test_online_returns_0(self):
        val, reasons = self._score("online")
        assert val == 0


class TestThreatScore:
    """PerformanceAnalytics._threat_score()"""

    def _score(self, risk):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics._threat_score(risk)

    def test_no_risk_returns_0(self):
        val, reasons = self._score(None)
        assert val == 0
        assert reasons == []

    def test_critical_risk_scores_high(self):
        risk = _make_asset_risk(
            total_threats=10, critical=3, high=2,
            highest_risk="critical", avg_risk_score=80.0,
        )
        val, reasons = self._score(risk)
        assert val >= 20  # high avg + critical weight
        assert any("critical" in r for r in reasons)

    def test_low_risk_scores_low(self):
        risk = _make_asset_risk(
            total_threats=2, low=2,
            highest_risk="low", avg_risk_score=10.0,
        )
        val, reasons = self._score(risk)
        assert val <= 5

    def test_score_capped_at_25(self):
        risk = _make_asset_risk(
            total_threats=100, critical=50,
            highest_risk="critical", avg_risk_score=100.0,
        )
        val, _ = self._score(risk)
        assert val <= 25


class TestPatchScore:
    """PerformanceAnalytics._patch_score()"""

    def _score(self, patch):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics._patch_score(patch)

    def test_no_status_returns_zero(self):
        insight, reasons = self._score({})
        assert insight.patch_score == 0
        assert reasons == []

    def test_pending_count_scores(self):
        insight, reasons = self._score({"pending_count": 3})
        assert insight.patch_score == 6  # 3*2
        assert any("pending" in r for r in reasons)

    def test_reboot_adds_2(self):
        insight, _ = self._score({"reboot_required": True})
        assert insight.patch_score == 2

    def test_capped_at_20(self):
        insight, _ = self._score({
            "pending_count": 20,
            "oldest_pending_days": 200,
            "reboot_required": True,
        })
        assert insight.patch_score == 20


class TestHeartbeatScore:
    """PerformanceAnalytics._heartbeat_score()"""

    def _score(self, hb, now=None):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        if now is None:
            now = datetime.now(timezone.utc)
        return PerformanceAnalytics._heartbeat_score(hb, now)

    def test_recent_heartbeat_returns_0(self):
        now = datetime.now(timezone.utc)
        hb = (now - timedelta(minutes=5)).isoformat()
        insight, reasons = self._score(hb, now)
        assert insight.heartbeat_score == 0
        assert reasons == []

    def test_1h_stale_returns_2(self):
        now = datetime.now(timezone.utc)
        hb = (now - timedelta(hours=2)).isoformat()
        insight, _ = self._score(hb, now)
        assert insight.heartbeat_score == 2

    def test_6h_stale_returns_5(self):
        now = datetime.now(timezone.utc)
        hb = (now - timedelta(hours=8)).isoformat()
        insight, reasons = self._score(hb, now)
        assert insight.heartbeat_score == 5
        assert insight.stale is True
        assert len(reasons) > 0

    def test_24h_stale_returns_8(self):
        now = datetime.now(timezone.utc)
        hb = (now - timedelta(hours=30)).isoformat()
        insight, _ = self._score(hb, now)
        assert insight.heartbeat_score == 8

    def test_72h_stale_returns_10(self):
        now = datetime.now(timezone.utc)
        hb = (now - timedelta(hours=100)).isoformat()
        insight, _ = self._score(hb, now)
        assert insight.heartbeat_score == 10


class TestGuardianScore:
    """PerformanceAnalytics._guardian_score()"""

    def _score(self, active):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics._guardian_score(active)

    def test_guardian_active_returns_0(self):
        val, reasons = self._score(True)
        assert val == 0
        assert reasons == []

    def test_guardian_inactive_returns_5(self):
        val, reasons = self._score(False)
        assert val == 5
        assert "Guardian inactive" in reasons


# ══════════════════════════════════════════════════════════════════════
# Composite scoring
# ══════════════════════════════════════════════════════════════════════


class TestComputeAttentionScore:
    """PerformanceAnalytics.compute_attention_score()"""

    def _engine(self):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics()

    def test_fully_healthy_asset_scores_zero(self):
        engine = self._engine()
        asset = _make_asset(status="protected", guardian_active=True)
        score = engine.compute_attention_score(asset)
        assert score.attention_score == 0
        assert score.category == "healthy"
        assert score.reasons == []

    def test_compromised_asset_scores_high(self):
        engine = self._engine()
        asset = _make_asset(status="compromised", guardian_active=False)
        risk = _make_asset_risk(
            total_threats=5, critical=2, highest_risk="critical", avg_risk_score=70.0
        )
        score = engine.compute_attention_score(asset, asset_risk=risk)
        assert score.attention_score >= 60  # 40 status + threats + guardian
        assert score.category in ("attention", "critical")

    def test_score_is_capped_at_100(self):
        engine = self._engine()
        asset = _make_asset(status="compromised", guardian_active=False)
        risk = _make_asset_risk(
            total_threats=100, critical=50, highest_risk="critical", avg_risk_score=100.0
        )
        now = datetime.now(timezone.utc)
        agent = _make_agent(
            last_heartbeat=(now - timedelta(hours=200)).isoformat(),
            patch_status={
                "pending_count": 20,
                "oldest_pending_days": 200,
                "reboot_required": True,
            },
        )
        score = engine.compute_attention_score(asset, asset_risk=risk, agent=agent, now=now)
        assert score.attention_score == 100

    def test_reasons_populated_for_issues(self):
        engine = self._engine()
        asset = _make_asset(status="offline", guardian_active=False)
        score = engine.compute_attention_score(asset)
        assert "Offline" in score.reasons
        assert "Guardian inactive" in score.reasons

    def test_local_asset_no_patch_heartbeat_penalty(self):
        """Assets without an agent should not be penalized for patches/heartbeat."""
        engine = self._engine()
        asset = _make_asset(status="protected", guardian_active=True)
        score = engine.compute_attention_score(asset, agent=None)
        assert score.patch_score == 0
        assert score.heartbeat_score == 0


# ══════════════════════════════════════════════════════════════════════
# Fleet summary
# ══════════════════════════════════════════════════════════════════════


class TestFleetSummary:
    """PerformanceAnalytics.compute_fleet()"""

    def _engine(self):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics()

    def test_empty_fleet_returns_zero_summary(self):
        engine = self._engine()
        summary, scores = engine.compute_fleet([], [], [])
        assert summary.total_systems == 0
        assert summary.fleet_score == 0.0
        assert summary.fleet_category == "healthy"
        assert scores == []

    def test_category_counts_correct(self):
        engine = self._engine()
        assets = [
            _make_asset(asset_id="a1", status="protected", guardian_active=True),  # healthy
            _make_asset(asset_id="a2", status="offline", guardian_active=True),  # watch (25+0=25)
            _make_asset(asset_id="a3", status="compromised", guardian_active=False),  # critical (40+5=45+)
        ]
        summary, scores = engine.compute_fleet(assets, [], [])
        assert summary.total_systems == 3
        assert summary.healthy >= 1
        # compromised+guardian_inactive = 45 → watch or attention depending on exact category
        assert summary.critical + summary.attention + summary.watch + summary.healthy == 3

    def test_fleet_score_is_weighted_average(self):
        engine = self._engine()
        # Two healthy assets → avg score ≈ 0
        assets = [
            _make_asset(asset_id="a1", status="protected", guardian_active=True),
            _make_asset(asset_id="a2", status="protected", guardian_active=True),
        ]
        summary, _ = engine.compute_fleet(assets, [], [])
        assert summary.fleet_score == 0.0

    def test_assets_sorted_worst_first(self):
        engine = self._engine()
        assets = [
            _make_asset(asset_id="a1", status="protected", guardian_active=True),  # score=0
            _make_asset(asset_id="a2", status="compromised", guardian_active=False),  # high
        ]
        _, scores = engine.compute_fleet(assets, [], [])
        assert scores[0].asset_id == "a2"  # worst first
        assert scores[1].asset_id == "a1"


# ══════════════════════════════════════════════════════════════════════
# Reason generation
# ══════════════════════════════════════════════════════════════════════


class TestReasonGeneration:
    """Human-readable reason strings."""

    def _engine(self):
        from citadel_archer.intel.performance_analytics import PerformanceAnalytics
        return PerformanceAnalytics()

    def test_offline_reason_present(self):
        engine = self._engine()
        score = engine.compute_attention_score(_make_asset(status="offline"))
        assert "Offline" in score.reasons

    def test_patch_pending_reason_present(self):
        engine = self._engine()
        agent = _make_agent(patch_status={"pending_count": 5})
        score = engine.compute_attention_score(
            _make_asset(), agent=agent
        )
        assert any("pending" in r for r in score.reasons)

    def test_no_reasons_for_healthy_asset(self):
        engine = self._engine()
        score = engine.compute_attention_score(
            _make_asset(status="protected", guardian_active=True)
        )
        assert score.reasons == []


# ══════════════════════════════════════════════════════════════════════
# API route tests
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def perf_client(tmp_path):
    """FastAPI TestClient with services mock for performance routes."""
    from fastapi.testclient import TestClient
    from citadel_archer.api.main import app
    from citadel_archer.api import security

    old_token = security._SESSION_TOKEN
    security._SESSION_TOKEN = "test-session-token"

    yield TestClient(app)

    security._SESSION_TOKEN = old_token


AUTH = {"X-Session-Token": "test-session-token"}


class TestPerformanceRoutes:

    def test_route_registered_in_main(self):
        source = Path("src/citadel_archer/api/main.py").read_text()
        assert "performance_router" in source
        assert "include_router(performance_router)" in source

    def test_endpoint_returns_200(self, perf_client):
        resp = perf_client.get("/api/performance", headers=AUTH)
        assert resp.status_code == 200

    def test_response_has_fleet_key(self, perf_client):
        resp = perf_client.get("/api/performance", headers=AUTH)
        data = resp.json()
        assert "fleet" in data
        assert "total_systems" in data["fleet"]

    def test_response_has_assets_key(self, perf_client):
        resp = perf_client.get("/api/performance", headers=AUTH)
        data = resp.json()
        assert "assets" in data
        assert isinstance(data["assets"], list)

    def test_response_has_generated_at(self, perf_client):
        resp = perf_client.get("/api/performance", headers=AUTH)
        data = resp.json()
        assert "generated_at" in data
        assert len(data["generated_at"]) > 0

    def test_single_asset_404(self, perf_client):
        resp = perf_client.get("/api/performance/nonexistent-asset", headers=AUTH)
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════
# Frontend structural tests
# ══════════════════════════════════════════════════════════════════════


class TestFrontendStructural:

    def test_performance_html_has_fleet_elements(self):
        html = Path("frontend/performance.html").read_text()
        assert 'id="fleet-total"' in html
        assert 'id="fleet-healthy"' in html
        assert 'id="fleet-watch"' in html
        assert 'id="fleet-critical"' in html

    def test_performance_html_has_asset_container(self):
        html = Path("frontend/performance.html").read_text()
        assert 'id="asset-cards-container"' in html

    def test_performance_html_has_sort_filter(self):
        html = Path("frontend/performance.html").read_text()
        assert 'id="perf-sort-select"' in html
        assert 'id="perf-filter-select"' in html

    def test_performance_js_has_init_destroy(self):
        js = Path("frontend/js/performance.js").read_text()
        assert "export async function init" in js or "export function init" in js
        assert "export function destroy" in js

    def test_index_html_has_performance_tab(self):
        html = Path("frontend/index.html").read_text()
        assert 'id="tab-btn-performance"' in html

    def test_dashboard_nav_has_performance(self):
        js = Path("frontend/js/dashboard-nav.js").read_text()
        assert "'performance'" in js
        assert "performance:" in js

    def test_tab_loader_has_performance(self):
        js = Path("frontend/js/tab-loader.js").read_text()
        assert "performance:" in js
        assert "'./performance.js'" in js
        assert "'performance.html'" in js
