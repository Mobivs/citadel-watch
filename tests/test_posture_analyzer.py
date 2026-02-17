"""
Tests for Trigger 3a: Scheduled Daily Security Posture Analysis

Verifies that:
- PostureAnalyzer lifecycle (start/stop/run_now) works correctly
- Data gathering handles all sources present, missing, and failing
- Summary format satisfies AI Bridge trigger (contains "critical"/"high" keywords)
- Summary prefixed with "[Security Posture]"
- MessageType.EVENT is used for all messages
- Chat failure is non-blocking
- run_now() sends immediately without waiting for interval
- _is_recent helper correctly classifies timestamps
"""

import asyncio
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.chat.message import MessageType
from citadel_archer.chat.posture_analyzer import (
    ANALYSIS_INTERVAL,
    INITIAL_DELAY,
    PostureAnalyzer,
    _is_recent,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_chat():
    """Build a mock ChatManager with an async send_system."""
    chat = AsyncMock()
    chat.send_system = AsyncMock()
    return chat


def _make_aggregator(events=None):
    """Build a mock EventAggregator."""
    agg = MagicMock()
    if events is None:
        events = []
    agg.since.return_value = events
    return agg


def _make_event(severity="info"):
    """Build a minimal event object with a severity attribute."""
    ev = MagicMock()
    ev.severity = severity
    return ev


def _make_inventory(stats=None):
    """Build a mock AssetInventory."""
    inv = MagicMock()
    if stats is None:
        stats = {"total": 0, "by_platform": {}, "by_status": {}}
    inv.stats.return_value = stats
    return inv


def _make_shield_db(agents=None, threats=None):
    """Build a mock RemoteShieldDatabase."""
    db = MagicMock()
    db.list_agents.return_value = agents or []
    db.list_threats.return_value = threats or []
    return db


def _make_anomaly(stats=None):
    """Build a mock AnomalyDetector."""
    det = MagicMock()
    if stats is None:
        stats = {"anomalies_detected": 0, "model_fitted": False}
    det.stats.return_value = stats
    return det


def _make_analyzer(**kwargs):
    """Build a PostureAnalyzer with defaults overridden by kwargs."""
    defaults = {
        "chat_manager": _make_chat(),
        "interval": 1,         # fast interval for tests
        "initial_delay": 0,    # no delay for tests
    }
    defaults.update(kwargs)
    return PostureAnalyzer(**defaults)


# ── Test: Lifecycle ──────────────────────────────────────────────────


class TestLifecycle:
    """start/stop/run_now/properties."""

    @pytest.mark.asyncio
    async def test_start_sets_running(self):
        pa = _make_analyzer()
        await pa.start()
        assert pa.running is True
        await pa.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_running(self):
        pa = _make_analyzer()
        await pa.start()
        await pa.stop()
        assert pa.running is False

    @pytest.mark.asyncio
    async def test_double_start_is_idempotent(self):
        pa = _make_analyzer()
        await pa.start()
        await pa.start()  # Should not create a second task
        assert pa.running is True
        await pa.stop()

    @pytest.mark.asyncio
    async def test_double_stop_is_safe(self):
        pa = _make_analyzer()
        await pa.start()
        await pa.stop()
        await pa.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_run_now_sends_immediately(self):
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat)
        await pa.run_now()
        chat.send_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_now_increments_count(self):
        pa = _make_analyzer()
        assert pa.run_count == 0
        await pa.run_now()
        assert pa.run_count == 1
        await pa.run_now()
        assert pa.run_count == 2

    @pytest.mark.asyncio
    async def test_run_now_sets_last_run(self):
        pa = _make_analyzer()
        assert pa.last_run is None
        await pa.run_now()
        assert pa.last_run is not None
        assert isinstance(pa.last_run, datetime)

    @pytest.mark.asyncio
    async def test_initial_state(self):
        pa = _make_analyzer()
        assert pa.running is False
        assert pa.last_run is None
        assert pa.run_count == 0

    @pytest.mark.asyncio
    async def test_default_constants(self):
        """Check default interval and delay when not overridden."""
        chat = _make_chat()
        pa = PostureAnalyzer(chat_manager=chat)
        assert pa._interval == ANALYSIS_INTERVAL
        assert pa._initial_delay == INITIAL_DELAY

    @pytest.mark.asyncio
    async def test_analysis_loop_runs_periodically(self):
        """start() should run analysis on a schedule (fast interval for test)."""
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, interval=0.05, initial_delay=0)
        await pa.start()
        # Wait long enough for at least 2 analysis cycles
        await asyncio.sleep(0.2)
        await pa.stop()
        assert pa.run_count >= 2
        assert chat.send_system.call_count >= 2

    @pytest.mark.asyncio
    async def test_analysis_loop_respects_initial_delay(self):
        """Analysis should not run before initial_delay elapses."""
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, interval=0.05, initial_delay=0.3)
        await pa.start()
        await asyncio.sleep(0.1)  # Less than initial_delay
        assert pa.run_count == 0
        await pa.stop()


# ── Test: Data Gathering — All Sources ────────────────────────────────


class TestDataGatheringAllSources:
    """All data sources present and returning data."""

    def test_report_contains_all_sections(self):
        events = [_make_event("critical"), _make_event("info"), _make_event("info")]
        agg = _make_aggregator(events)
        inv = _make_inventory({"total": 5, "by_platform": {}, "by_status": {"protected": 3}})
        db = _make_shield_db(
            agents=[{"id": "a1", "last_heartbeat": datetime.utcnow().isoformat()}],
            threats=[{"id": "t1"}],
        )
        anomaly = _make_anomaly({"anomalies_detected": 2, "model_fitted": True})

        pa = _make_analyzer(
            aggregator=agg,
            inventory=inv,
            shield_db=db,
            anomaly_detector=anomaly,
        )
        report = pa._gather_posture()

        assert "events" in report
        assert "assets" in report
        assert "agents" in report
        assert "anomaly" in report

    def test_event_counts_by_severity(self):
        events = [
            _make_event("critical"),
            _make_event("critical"),
            _make_event("info"),
            _make_event("alert"),
        ]
        agg = _make_aggregator(events)
        pa = _make_analyzer(aggregator=agg)
        report = pa._gather_posture()

        assert report["events"]["total"] == 4
        assert report["events"]["by_severity"]["critical"] == 2
        assert report["events"]["by_severity"]["info"] == 1
        assert report["events"]["by_severity"]["alert"] == 1

    def test_agent_health_active_vs_stale(self):
        now = datetime.utcnow()
        agents = [
            {"id": "a1", "last_heartbeat": now.isoformat()},                      # active
            {"id": "a2", "last_heartbeat": (now - timedelta(hours=2)).isoformat()},  # stale
            {"id": "a3", "last_heartbeat": (now - timedelta(minutes=30)).isoformat()},  # active
        ]
        db = _make_shield_db(agents=agents, threats=[{"id": "t1"}, {"id": "t2"}])
        pa = _make_analyzer(shield_db=db)
        report = pa._gather_posture()

        assert report["agents"]["total"] == 3
        assert report["agents"]["active"] == 2
        assert report["agents"]["stale"] == 1
        assert report["agents"]["open_threats"] == 2


# ── Test: Data Gathering — Missing Sources ────────────────────────────


class TestDataGatheringMissingSources:
    """Missing data sources produce partial reports."""

    def test_no_sources_returns_empty_report(self):
        pa = _make_analyzer()
        report = pa._gather_posture()
        assert report == {}

    def test_only_aggregator(self):
        agg = _make_aggregator([_make_event("info")])
        pa = _make_analyzer(aggregator=agg)
        report = pa._gather_posture()
        assert "events" in report
        assert "assets" not in report
        assert "agents" not in report
        assert "anomaly" not in report

    def test_only_inventory(self):
        inv = _make_inventory({"total": 3, "by_platform": {}, "by_status": {}})
        pa = _make_analyzer(inventory=inv)
        report = pa._gather_posture()
        assert "assets" in report
        assert "events" not in report


# ── Test: Data Gathering — Failing Sources ────────────────────────────


class TestDataGatheringFailingSources:
    """A failing source is skipped; other sections still collected."""

    def test_aggregator_raises_skipped(self):
        agg = MagicMock()
        agg.since.side_effect = RuntimeError("DB down")
        inv = _make_inventory({"total": 1, "by_platform": {}, "by_status": {}})

        pa = _make_analyzer(aggregator=agg, inventory=inv)
        report = pa._gather_posture()

        assert "events" not in report   # skipped
        assert "assets" in report       # still collected

    def test_inventory_raises_skipped(self):
        inv = MagicMock()
        inv.stats.side_effect = RuntimeError("File locked")
        agg = _make_aggregator([_make_event("info")])

        pa = _make_analyzer(aggregator=agg, inventory=inv)
        report = pa._gather_posture()

        assert "events" in report
        assert "assets" not in report

    def test_shield_db_raises_skipped(self):
        db = MagicMock()
        db.list_agents.side_effect = RuntimeError("SQLite locked")

        pa = _make_analyzer(shield_db=db)
        report = pa._gather_posture()

        assert "agents" not in report

    def test_anomaly_raises_skipped(self):
        det = MagicMock()
        det.stats.side_effect = RuntimeError("Model corrupt")

        pa = _make_analyzer(anomaly_detector=det)
        report = pa._gather_posture()

        assert "anomaly" not in report


# ── Test: Summary Format ──────────────────────────────────────────────


class TestSummaryFormat:
    """Summary text satisfies format requirements."""

    @pytest.mark.asyncio
    async def test_prefix(self):
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat)
        await pa.run_now()
        text = chat.send_system.call_args[0][0]
        assert text.startswith("[Security Posture]")

    @pytest.mark.asyncio
    async def test_always_contains_trigger_keywords(self):
        """Even with no data, 'critical' and 'high' must be present."""
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat)
        await pa.run_now()
        text = chat.send_system.call_args[0][0].lower()
        assert "critical" in text
        assert "high" in text

    @pytest.mark.asyncio
    async def test_event_counts_in_summary(self):
        events = [_make_event("critical"), _make_event("info"), _make_event("info")]
        agg = _make_aggregator(events)
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, aggregator=agg)
        await pa.run_now()
        text = chat.send_system.call_args[0][0]
        assert "3 total" in text
        assert "1 critical" in text

    @pytest.mark.asyncio
    async def test_asset_stats_in_summary(self):
        inv = _make_inventory({
            "total": 5,
            "by_platform": {},
            "by_status": {"protected": 3, "online": 1, "offline": 1},
        })
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, inventory=inv)
        await pa.run_now()
        text = chat.send_system.call_args[0][0]
        assert "5 managed" in text
        assert "3 protected" in text

    @pytest.mark.asyncio
    async def test_agent_stats_in_summary(self):
        now = datetime.utcnow()
        agents = [{"id": "a1", "last_heartbeat": now.isoformat()}]
        threats = [{"id": "t1"}, {"id": "t2"}]
        db = _make_shield_db(agents=agents, threats=threats)
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, shield_db=db)
        await pa.run_now()
        text = chat.send_system.call_args[0][0]
        assert "1 deployed" in text
        assert "2 open threats" in text

    @pytest.mark.asyncio
    async def test_anomaly_stats_in_summary(self):
        anomaly = _make_anomaly({"anomalies_detected": 5, "model_fitted": True})
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, anomaly_detector=anomaly)
        await pa.run_now()
        text = chat.send_system.call_args[0][0]
        assert "5 anomalies" in text
        assert "fitted" in text

    @pytest.mark.asyncio
    async def test_anomaly_cold_start_in_summary(self):
        anomaly = _make_anomaly({"anomalies_detected": 0, "model_fitted": False})
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat, anomaly_detector=anomaly)
        await pa.run_now()
        text = chat.send_system.call_args[0][0]
        assert "cold start" in text

    @pytest.mark.asyncio
    async def test_message_type_is_event(self):
        chat = _make_chat()
        pa = _make_analyzer(chat_manager=chat)
        await pa.run_now()
        msg_type = chat.send_system.call_args[0][1]
        assert msg_type == MessageType.EVENT


# ── Test: Chat Failure Non-Blocking ──────────────────────────────────


class TestChatFailure:
    """Chat failures must not crash the analysis loop."""

    @pytest.mark.asyncio
    async def test_chat_failure_non_blocking(self):
        chat = _make_chat()
        chat.send_system.side_effect = RuntimeError("WebSocket dead")
        pa = _make_analyzer(chat_manager=chat)
        # Should not raise
        await pa.run_now()

    @pytest.mark.asyncio
    async def test_chat_failure_still_increments_count(self):
        chat = _make_chat()
        chat.send_system.side_effect = ConnectionError("refused")
        pa = _make_analyzer(chat_manager=chat)
        await pa.run_now()
        assert pa.run_count == 1
        assert pa.last_run is not None


# ── Test: _is_recent Helper ──────────────────────────────────────────


class TestIsRecent:
    """_is_recent timestamp classification."""

    def test_recent_timestamp(self):
        now = datetime.utcnow()
        ts = (now - timedelta(minutes=30)).isoformat()
        assert _is_recent(ts, now, hours=1) is True

    def test_stale_timestamp(self):
        now = datetime.utcnow()
        ts = (now - timedelta(hours=2)).isoformat()
        assert _is_recent(ts, now, hours=1) is False

    def test_exact_boundary(self):
        now = datetime.utcnow()
        ts = (now - timedelta(hours=1, seconds=1)).isoformat()
        assert _is_recent(ts, now, hours=1) is False

    def test_invalid_timestamp(self):
        now = datetime.utcnow()
        assert _is_recent("not-a-date", now) is False

    def test_none_timestamp(self):
        now = datetime.utcnow()
        assert _is_recent(None, now) is False

    def test_utc_z_suffix(self):
        now = datetime.utcnow()
        ts = (now - timedelta(minutes=10)).isoformat() + "Z"
        assert _is_recent(ts, now, hours=1) is True

    def test_agent_with_no_heartbeat(self):
        """Agent dict with missing heartbeat → stale (via caller guard)."""
        now = datetime.utcnow()
        # This simulates what _gather_posture does: hb could be None
        assert _is_recent(None, now) is False

    def test_tz_aware_now(self):
        """Works correctly when now is timezone-aware (M2 fix)."""
        from datetime import timezone
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=10)).isoformat()
        assert _is_recent(ts, now, hours=1) is True

    def test_naive_ts_with_tz_aware_now(self):
        """Naive timestamp + tz-aware now should not crash."""
        from datetime import timezone
        now = datetime.now(timezone.utc)
        # Naive ISO timestamp (no Z or offset)
        ts = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        assert _is_recent(ts, now, hours=1) is True

    def test_empty_string_timestamp(self):
        now = datetime.utcnow()
        assert _is_recent("", now) is False
