"""
Tests for Trigger 3b: Startup Catch-Up

Verifies that:
- StartupCatchup runs once and marks completed
- Offline duration is correctly determined from SYSTEM_STOP events
- Skips when offline < 5 minutes
- First-run fallback to 24-hour lookback works
- Maximum 7-day lookback is enforced
- Data gathering handles present, missing, and failing sources
- Summary format satisfies AI Bridge trigger keywords
- Summary prefixed with "[Startup Catch-Up]"
- MessageType.EVENT is used
- Chat failure is non-blocking
- Double-run prevention works
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.chat.message import MessageType
from citadel_archer.chat.startup_catchup import (
    CATCHUP_DELAY,
    DEFAULT_LOOKBACK_HOURS,
    MAX_LOOKBACK_DAYS,
    MIN_OFFLINE_MINUTES,
    StartupCatchup,
    _format_duration,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_chat():
    """Build a mock ChatManager with an async send_system."""
    chat = AsyncMock()
    chat.send_system = AsyncMock()
    return chat


def _make_audit_logger(events=None, stop_events=None):
    """Build a mock AuditLogger.

    Args:
        events: Events returned for general query_events calls.
        stop_events: Events returned when filtering for SYSTEM_STOP.
    """
    audit = MagicMock()

    def query_side_effect(event_types=None, severity=None,
                          start_time=None, end_time=None, limit=100):
        # If querying for SYSTEM_STOP specifically
        if event_types and stop_events is not None:
            from citadel_archer.core.audit_log import EventType
            if EventType.SYSTEM_STOP in event_types:
                return stop_events
        return events if events is not None else []

    audit.query_events.side_effect = query_side_effect
    return audit


def _make_inventory(assets=None):
    """Build a mock AssetInventory."""
    inv = MagicMock()
    inv.all.return_value = assets or []
    return inv


def _make_asset(name="test-vps", status="online", ip="10.0.0.1"):
    """Build a minimal asset mock."""
    asset = MagicMock()
    asset.name = name
    asset.status.value = status
    asset.ip_address = ip
    return asset


def _make_shield_db(agents=None, threats=None):
    """Build a mock RemoteShieldDatabase."""
    db = MagicMock()
    db.list_agents.return_value = agents or []
    db.list_threats.return_value = threats or []
    return db


def _stop_event(hours_ago=2):
    """Build a SYSTEM_STOP audit event from N hours ago."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    return {
        "event_type": "system.stop",
        "severity": "info",
        "message": "Citadel Archer shutting down",
        "timestamp": ts,
    }


# ── Lifecycle ────────────────────────────────────────────────────────


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_initial_state(self):
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        assert catchup.completed is False
        assert catchup.skipped is False
        assert catchup.skip_reason is None

    @pytest.mark.asyncio
    async def test_run_now_sets_completed(self):
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()
        assert catchup.completed is True

    @pytest.mark.asyncio
    async def test_run_now_sends_message(self):
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()
        chat.send_system.assert_called_once()
        args = chat.send_system.call_args
        assert args[0][1] == MessageType.EVENT

    @pytest.mark.asyncio
    async def test_double_run_prevented(self):
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()
        assert catchup.completed is True

        # Reset mock to verify no second call
        chat.send_system.reset_mock()

        # run() should be a no-op since completed is True
        await catchup.run()
        # Task should not have been created
        assert catchup._task is None


# ── Offline Window Detection ─────────────────────────────────────────


class TestOfflineWindow:
    @pytest.mark.asyncio
    async def test_finds_system_stop(self):
        """When SYSTEM_STOP exists, offline window starts from that time."""
        chat = _make_chat()
        stop_time = datetime.now(timezone.utc) - timedelta(hours=2)
        audit = _make_audit_logger(
            stop_events=[{"timestamp": stop_time.isoformat()}],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True
        assert catchup.skipped is False

        # Verify the summary mentions the offline duration (~2h)
        summary = chat.send_system.call_args[0][0]
        assert "offline" in summary.lower()

    @pytest.mark.asyncio
    async def test_finds_system_stop_naive_timestamp(self):
        """SYSTEM_STOP with naive timestamp (no tz suffix) is normalized."""
        chat = _make_chat()
        # Simulate naive timestamp like datetime.utcnow().isoformat() produces
        audit = _make_audit_logger(
            stop_events=[{"timestamp": "2026-02-14T10:00:00"}],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True
        assert catchup.skipped is False

    @pytest.mark.asyncio
    async def test_no_system_stop_uses_default_lookback(self):
        """First run: no SYSTEM_STOP → falls back to DEFAULT_LOOKBACK_HOURS."""
        chat = _make_chat()
        audit = _make_audit_logger(stop_events=[], events=[])
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True

        summary = chat.send_system.call_args[0][0]
        assert "First run" in summary

    @pytest.mark.asyncio
    async def test_no_audit_logger_uses_default_lookback(self):
        """No audit logger at all → first run behavior."""
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()
        assert catchup.completed is True

        summary = chat.send_system.call_args[0][0]
        assert "First run" in summary

    @pytest.mark.asyncio
    async def test_max_lookback_capped(self):
        """Offline for 30 days → capped at MAX_LOOKBACK_DAYS."""
        chat = _make_chat()
        stop_time = datetime.now(timezone.utc) - timedelta(days=30)
        audit = _make_audit_logger(
            stop_events=[{"timestamp": stop_time.isoformat()}],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True
        assert not catchup.skipped

        # Summary should show ~7 days, not 30
        summary = chat.send_system.call_args[0][0]
        assert "7d" in summary

    @pytest.mark.asyncio
    async def test_skip_if_offline_under_5_minutes(self):
        """Restart scenario: offline < 5 min → skip."""
        chat = _make_chat()
        stop_time = datetime.now(timezone.utc) - timedelta(minutes=2)
        audit = _make_audit_logger(
            stop_events=[{"timestamp": stop_time.isoformat()}],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True
        assert catchup.skipped is True
        assert "too short" in catchup.skip_reason
        chat.send_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_reason_contains_duration(self):
        """Skip reason includes actual offline duration."""
        chat = _make_chat()
        stop_time = datetime.now(timezone.utc) - timedelta(minutes=3)
        audit = _make_audit_logger(
            stop_events=[{"timestamp": stop_time.isoformat()}],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert "3." in catchup.skip_reason  # "3.0min" or similar


# ── Data Gathering ───────────────────────────────────────────────────


class TestDataGathering:
    @pytest.mark.asyncio
    async def test_audit_events_collected(self):
        """Audit events are counted by severity."""
        chat = _make_chat()
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[
                {"severity": "critical", "event_type": "file.quarantined",
                 "message": "Malware found", "timestamp": "2026-01-01T12:00:00"},
                {"severity": "alert", "event_type": "process.killed",
                 "message": "Suspicious process", "timestamp": "2026-01-01T12:01:00"},
                {"severity": "info", "event_type": "system.start",
                 "message": "Started", "timestamp": "2026-01-01T12:02:00"},
            ],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "3 total" in summary
        assert "1 critical" in summary
        assert "1 alert" in summary

    @pytest.mark.asyncio
    async def test_audit_notable_events_in_summary(self):
        """Notable events (alert/critical) appear as detail lines."""
        chat = _make_chat()
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[
                {"severity": "critical", "event_type": "file.quarantined",
                 "message": "Rootkit detected in /usr/bin", "timestamp": "2026-01-01T12:00:00"},
            ],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "Rootkit detected" in summary
        assert "[critical]" in summary

    @pytest.mark.asyncio
    async def test_remote_shield_threats_collected(self):
        """New threats during offline appear in summary."""
        chat = _make_chat()
        # Threat detected 1 hour ago (within 2h offline window)
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        shield_db = _make_shield_db(
            threats=[
                {"title": "SSH brute force", "severity": "high",
                 "hostname": "vps1", "detected_at": recent,
                 "reported_at": recent, "status": "open"},
            ],
            agents=[
                {"hostname": "vps1", "last_heartbeat": recent},
            ],
        )
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit,
            shield_db=shield_db, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "1 new threats" in summary
        assert "SSH brute force" in summary

    @pytest.mark.asyncio
    async def test_remote_shield_threats_with_naive_timestamps(self):
        """Threats with naive timestamps (no tz suffix) are correctly filtered."""
        chat = _make_chat()
        # shield_database stores naive UTC via datetime.utcnow().isoformat()
        recent_naive = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        shield_db = _make_shield_db(
            threats=[
                {"title": "Cron tampered", "severity": 8,
                 "hostname": "vps2", "detected_at": recent_naive,
                 "reported_at": recent_naive, "status": "open"},
            ],
            agents=[],
        )
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit,
            shield_db=shield_db, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "1 new threats" in summary
        assert "Cron tampered" in summary

    @pytest.mark.asyncio
    async def test_remote_shield_stale_agents(self):
        """Stale agents (heartbeat before offline start) are reported."""
        chat = _make_chat()
        old_hb = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        shield_db = _make_shield_db(
            threats=[],
            agents=[
                {"hostname": "stale-vps", "last_heartbeat": old_hb},
            ],
        )
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit,
            shield_db=shield_db, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "stale-vps" in summary.lower()

    @pytest.mark.asyncio
    async def test_asset_compromised_reported(self):
        """Compromised assets appear in summary."""
        chat = _make_chat()
        inv = _make_inventory(assets=[
            _make_asset("prod-server", "compromised", "10.0.0.5"),
        ])
        catchup = StartupCatchup(
            chat_manager=chat, inventory=inv, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "COMPROMISED" in summary
        assert "prod-server" in summary

    @pytest.mark.asyncio
    async def test_asset_offline_reported(self):
        """Offline assets appear in summary."""
        chat = _make_chat()
        inv = _make_inventory(assets=[
            _make_asset("backup-vps", "offline", "10.0.0.6"),
        ])
        catchup = StartupCatchup(
            chat_manager=chat, inventory=inv, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "offline" in summary.lower()
        assert "backup-vps" in summary

    @pytest.mark.asyncio
    async def test_all_healthy_assets(self):
        """When all assets are healthy, summary says so."""
        chat = _make_chat()
        inv = _make_inventory(assets=[
            _make_asset("good-vps", "online", "10.0.0.7"),
            _make_asset("good-vps2", "protected", "10.0.0.8"),
        ])
        catchup = StartupCatchup(
            chat_manager=chat, inventory=inv, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "all healthy" in summary.lower()


# ── Graceful Degradation ─────────────────────────────────────────────


class TestGracefulDegradation:
    @pytest.mark.asyncio
    async def test_no_sources_still_completes(self):
        """With no data sources at all, catch-up still runs and completes."""
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()
        assert catchup.completed is True
        chat.send_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_only_audit_logger(self):
        """Works with only audit logger, no other sources."""
        chat = _make_chat()
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[{"severity": "info", "event_type": "system.start",
                     "message": "Started", "timestamp": "2026-01-01T12:00:00"}],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True

        summary = chat.send_system.call_args[0][0]
        assert "Audit events" in summary
        assert "Remote Shield" not in summary
        assert "Assets" not in summary

    @pytest.mark.asyncio
    async def test_only_inventory(self):
        """Works with only inventory, no other sources."""
        chat = _make_chat()
        inv = _make_inventory(assets=[_make_asset()])
        catchup = StartupCatchup(
            chat_manager=chat, inventory=inv, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True

        summary = chat.send_system.call_args[0][0]
        assert "Assets" in summary

    @pytest.mark.asyncio
    async def test_audit_raises_skipped(self):
        """If audit logger raises, other sources still work."""
        chat = _make_chat()
        audit = MagicMock()
        audit.query_events.side_effect = RuntimeError("DB locked")
        inv = _make_inventory(assets=[_make_asset()])
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit,
            inventory=inv, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True

        summary = chat.send_system.call_args[0][0]
        # Audit section missing but assets present
        assert "Assets" in summary

    @pytest.mark.asyncio
    async def test_shield_db_raises_skipped(self):
        """If shield DB raises, other sources still work."""
        chat = _make_chat()
        shield_db = MagicMock()
        shield_db.list_threats.side_effect = RuntimeError("DB error")
        inv = _make_inventory(assets=[_make_asset()])
        catchup = StartupCatchup(
            chat_manager=chat, shield_db=shield_db,
            inventory=inv, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True

    @pytest.mark.asyncio
    async def test_inventory_raises_skipped(self):
        """If inventory raises, catch-up still completes."""
        chat = _make_chat()
        inv = MagicMock()
        inv.all.side_effect = RuntimeError("Asset DB error")
        catchup = StartupCatchup(
            chat_manager=chat, inventory=inv, delay=0,
        )
        await catchup.run_now()
        assert catchup.completed is True


# ── Summary Format ───────────────────────────────────────────────────


class TestSummaryFormat:
    @pytest.mark.asyncio
    async def test_prefix_startup_catchup(self):
        """Summary starts with [Startup Catch-Up]."""
        chat = _make_chat()
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert summary.startswith("[Startup Catch-Up]")

    @pytest.mark.asyncio
    async def test_first_run_prefix(self):
        """First-run summary says 'First run'."""
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "First run" in summary

    @pytest.mark.asyncio
    async def test_always_contains_trigger_keywords(self):
        """Summary always contains 'critical' and 'high' for AI Bridge."""
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "critical" in summary.lower()
        assert "high" in summary.lower()

    @pytest.mark.asyncio
    async def test_message_type_is_event(self):
        """Message is sent as EVENT type."""
        chat = _make_chat()
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()

        args = chat.send_system.call_args
        assert args[0][1] == MessageType.EVENT

    @pytest.mark.asyncio
    async def test_offline_duration_in_summary(self):
        """Summary includes human-readable offline duration."""
        chat = _make_chat()
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=3)],
            events=[],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "3h" in summary

    @pytest.mark.asyncio
    async def test_audit_counts_in_summary(self):
        """Severity counts appear in formatted summary."""
        chat = _make_chat()
        audit = _make_audit_logger(
            stop_events=[_stop_event(hours_ago=2)],
            events=[
                {"severity": "critical", "event_type": "x", "message": "a",
                 "timestamp": "2026-01-01T12:00:00"},
                {"severity": "critical", "event_type": "x", "message": "b",
                 "timestamp": "2026-01-01T12:01:00"},
                {"severity": "info", "event_type": "x", "message": "c",
                 "timestamp": "2026-01-01T12:02:00"},
            ],
        )
        catchup = StartupCatchup(
            chat_manager=chat, audit_logger=audit, delay=0,
        )
        await catchup.run_now()

        summary = chat.send_system.call_args[0][0]
        assert "2 critical" in summary
        assert "1 info" in summary


# ── Chat Failure ─────────────────────────────────────────────────────


class TestChatFailure:
    @pytest.mark.asyncio
    async def test_chat_failure_non_blocking(self):
        """If ChatManager.send_system raises, catch-up still completes."""
        chat = AsyncMock()
        chat.send_system = AsyncMock(side_effect=RuntimeError("WS down"))
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        await catchup.run_now()
        assert catchup.completed is True

    @pytest.mark.asyncio
    async def test_chat_failure_does_not_raise(self):
        """Chat failure is logged but doesn't propagate."""
        chat = AsyncMock()
        chat.send_system = AsyncMock(side_effect=ConnectionError("offline"))
        catchup = StartupCatchup(chat_manager=chat, delay=0)
        # Should not raise
        await catchup.run_now()


# ── Format Duration Helper ───────────────────────────────────────────


class TestFormatDuration:
    def test_minutes_only(self):
        assert _format_duration(timedelta(minutes=42)) == "42m"

    def test_hours_and_minutes(self):
        assert _format_duration(timedelta(hours=3, minutes=15)) == "3h 15m"

    def test_days_hours_minutes(self):
        assert _format_duration(timedelta(days=2, hours=5, minutes=30)) == "2d 5h 30m"

    def test_zero_duration(self):
        assert _format_duration(timedelta(0)) == "0m"

    def test_negative_duration(self):
        assert _format_duration(timedelta(seconds=-100)) == "0m"

    def test_exact_hours(self):
        assert _format_duration(timedelta(hours=1)) == "1h 0m"

    def test_exact_days(self):
        assert _format_duration(timedelta(days=1)) == "1d 0h 0m"
