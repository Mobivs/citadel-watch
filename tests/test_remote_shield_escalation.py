"""
Tests for v0.3.12: RemoteShieldEscalation — VPS event escalation to AI.

Covers: severity filter, category filter, batching, dedup, rate limit,
per-asset grouping in summaries, flush format, AI trigger text.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventAggregator,
    EventCategory,
)
from citadel_archer.chat.remote_shield_escalation import (
    RemoteShieldEscalation,
    ESCALATION_SEVERITIES,
    REMOTE_CATEGORIES,
    BATCH_WINDOW_SECONDS,
    DEDUP_WINDOW_SECONDS,
    RATE_LIMIT_PER_HOUR,
)


def _make_event(
    event_type="remote.auth_log",
    category=EventCategory.REMOTE,
    severity="critical",
    asset_id="vps1",
    message="SSH brute force detected",
) -> AggregatedEvent:
    return AggregatedEvent(
        event_type=event_type,
        category=category,
        severity=severity,
        asset_id=asset_id,
        message=message,
    )


@pytest.fixture
def aggregator():
    return EventAggregator(max_history=100)


@pytest.fixture
def chat_manager():
    mgr = MagicMock()
    mgr.send_system = AsyncMock()
    return mgr


class TestRemoteShieldEscalationFilters:
    """Severity and category filtering."""

    def test_severity_filter_accepts_critical(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event(severity="critical")
        esc._on_event(evt)
        assert esc.buffer_size == 1

    def test_severity_filter_accepts_high(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event(severity="high")
        esc._on_event(evt)
        assert esc.buffer_size == 1

    def test_severity_filter_accepts_alert(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event(severity="alert")
        esc._on_event(evt)
        assert esc.buffer_size == 1

    def test_severity_filter_rejects_info(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event(severity="info")
        esc._on_event(evt)
        assert esc.buffer_size == 0

    def test_category_filter_rejects_file(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event(category=EventCategory.FILE)
        esc._on_event(evt)
        assert esc.buffer_size == 0

    def test_category_filter_rejects_process(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event(category=EventCategory.PROCESS)
        esc._on_event(evt)
        assert esc.buffer_size == 0


class TestRemoteShieldEscalationDedup:
    """Deduplication within 5-minute windows."""

    def test_dedup_same_event(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event()
        esc._on_event(evt)
        esc._on_event(evt)  # same type + asset
        assert esc.buffer_size == 1

    def test_dedup_different_asset_accepted(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        esc._on_event(_make_event(asset_id="vps1"))
        esc._on_event(_make_event(asset_id="vps2"))
        assert esc.buffer_size == 2

    def test_dedup_different_type_accepted(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        esc._on_event(_make_event(event_type="remote.auth_log"))
        esc._on_event(_make_event(event_type="remote.file_integrity"))
        assert esc.buffer_size == 2

    def test_dedup_eviction(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        evt = _make_event()
        esc._on_event(evt)
        # Expire the dedup entry
        for key in esc._dedup_cache:
            esc._dedup_cache[key] = time.monotonic() - DEDUP_WINDOW_SECONDS - 1
        esc._on_event(evt)
        assert esc.buffer_size == 2


class TestRemoteShieldEscalationFlush:
    """Batch flush format and rate limiting."""

    @pytest.mark.asyncio
    async def test_flush_sends_summary(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        esc._on_event(_make_event(asset_id="vps1", message="brute force"))
        esc._on_event(_make_event(
            event_type="remote.file_integrity",
            asset_id="vps2",
            message="config changed",
        ))

        await esc._flush_batch()
        chat_manager.send_system.assert_called_once()
        summary = chat_manager.send_system.call_args[0][0]
        # Must contain "critical" or "high" for AI Bridge trigger
        assert "critical" in summary.lower() or "high" in summary.lower()
        assert "Remote Shield" in summary
        assert "vps1" in summary
        assert "vps2" in summary

    @pytest.mark.asyncio
    async def test_flush_groups_by_asset(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        for i in range(3):
            esc._on_event(_make_event(
                event_type=f"remote.sensor_{i}",
                asset_id="vps1",
                message=f"alert {i}",
            ))
        esc._on_event(_make_event(
            event_type="remote.auth_log",
            asset_id="vps2",
            message="login attempt",
        ))

        await esc._flush_batch()
        summary = chat_manager.send_system.call_args[0][0]
        assert "vps1: 3 event(s)" in summary
        assert "vps2: 1 event(s)" in summary

    @pytest.mark.asyncio
    async def test_rate_limit(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        esc._escalation_count = RATE_LIMIT_PER_HOUR

        esc._on_event(_make_event())
        await esc._flush_batch()
        chat_manager.send_system.assert_not_called()
        assert esc.buffer_size == 0  # Events dropped

    @pytest.mark.asyncio
    async def test_rate_limit_resets_after_hour(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        esc._running = True
        esc._escalation_count = RATE_LIMIT_PER_HOUR
        esc._hour_start = time.monotonic() - 3601  # expired

        esc._on_event(_make_event())
        await esc._flush_batch()
        chat_manager.send_system.assert_called_once()
        assert esc.escalation_count == 1


class TestRemoteShieldEscalationLifecycle:
    """Start/stop and introspection."""

    def test_start_stop(self, aggregator, chat_manager):
        loop = asyncio.new_event_loop()
        try:
            esc = RemoteShieldEscalation(aggregator, chat_manager, loop=loop)
            esc.start()
            assert esc.running is True
            esc.stop()
            assert esc.running is False
        finally:
            loop.close()

    def test_start_without_loop_raises(self, aggregator, chat_manager):
        esc = RemoteShieldEscalation(aggregator, chat_manager)
        with pytest.raises(RuntimeError, match="event loop"):
            esc.start()
