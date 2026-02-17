"""
Tests for Trigger 2b: GuardianEscalation — Local Guardian → AI via SecureChat.

Covers: severity filtering, category filtering, deduplication,
dedup cache eviction, rate limiting, batch aggregation, summary format,
send failure re-queue, event loop lifecycle, concurrency, end-to-end flow.
"""

import asyncio
import concurrent.futures
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventAggregator,
    EventCategory,
)
from citadel_archer.chat.guardian_escalation import (
    GuardianEscalation,
    BATCH_WINDOW_SECONDS,
    DEDUP_WINDOW_SECONDS,
    ESCALATION_SEVERITIES,
    GUARDIAN_CATEGORIES,
    RATE_LIMIT_PER_HOUR,
)


# ===================================================================
# Helpers
# ===================================================================


def _make_event(
    severity="critical",
    category=EventCategory.FILE,
    event_type="file.modified",
    asset_id=None,
    message="Suspicious file detected",
) -> AggregatedEvent:
    """Create a test AggregatedEvent."""
    return AggregatedEvent(
        event_type=event_type,
        category=category,
        severity=severity,
        asset_id=asset_id,
        message=message,
    )


def _make_chat_manager() -> MagicMock:
    """Create a mock ChatManager with async send_system."""
    mgr = MagicMock()
    mgr.send_system = AsyncMock()
    return mgr


def _make_escalation(aggregator=None, chat_manager=None, loop=None):
    """Create a GuardianEscalation with mocks."""
    agg = aggregator or EventAggregator(max_history=100)
    chat = chat_manager or _make_chat_manager()
    esc = GuardianEscalation(
        aggregator=agg,
        chat_manager=chat,
        loop=loop,
    )
    return esc, agg, chat


# ===================================================================
# Test: Severity Filtering
# ===================================================================


class TestSeverityFiltering:
    """Only ALERT and CRITICAL severity events should pass the filter."""

    def test_critical_event_buffered(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(severity="critical")
        esc._on_event(event)
        assert esc.buffer_size == 1

    def test_alert_event_buffered(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(severity="alert")
        esc._on_event(event)
        assert esc.buffer_size == 1

    def test_info_event_ignored(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(severity="info")
        esc._on_event(event)
        assert esc.buffer_size == 0

    def test_investigate_event_ignored(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(severity="investigate")
        esc._on_event(event)
        assert esc.buffer_size == 0

    def test_case_insensitive_severity(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(severity="CRITICAL")
        esc._on_event(event)
        assert esc.buffer_size == 1

    def test_mixed_case_alert(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(severity="Alert")
        esc._on_event(event)
        assert esc.buffer_size == 1


# ===================================================================
# Test: Category Filtering
# ===================================================================


class TestCategoryFiltering:
    """Only FILE and PROCESS category events should pass."""

    def test_file_category_passes(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(category=EventCategory.FILE)
        esc._on_event(event)
        assert esc.buffer_size == 1

    def test_process_category_passes(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(
            category=EventCategory.PROCESS,
            event_type="process.suspicious",
        )
        esc._on_event(event)
        assert esc.buffer_size == 1

    def test_network_category_blocked(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(
            category=EventCategory.NETWORK,
            event_type="network.blocked",
        )
        esc._on_event(event)
        assert esc.buffer_size == 0

    def test_vault_category_blocked(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(
            category=EventCategory.VAULT,
            event_type="vault.error",
        )
        esc._on_event(event)
        assert esc.buffer_size == 0

    def test_system_category_blocked(self):
        esc, agg, chat = _make_escalation()
        event = _make_event(
            category=EventCategory.SYSTEM,
            event_type="system.start",
        )
        esc._on_event(event)
        assert esc.buffer_size == 0


# ===================================================================
# Test: Deduplication
# ===================================================================


class TestDeduplication:
    """Same event_type + asset_id should not re-escalate within 5 min."""

    def test_duplicate_within_window_blocked(self):
        esc, agg, chat = _make_escalation()
        event1 = _make_event(event_type="file.modified", asset_id="local")
        event2 = _make_event(event_type="file.modified", asset_id="local")
        esc._on_event(event1)
        esc._on_event(event2)
        assert esc.buffer_size == 1  # second was deduped

    def test_different_event_type_not_deduped(self):
        esc, agg, chat = _make_escalation()
        event1 = _make_event(event_type="file.modified")
        event2 = _make_event(event_type="file.created")
        esc._on_event(event1)
        esc._on_event(event2)
        assert esc.buffer_size == 2

    def test_different_asset_not_deduped(self):
        esc, agg, chat = _make_escalation()
        event1 = _make_event(event_type="file.modified", asset_id="asset1")
        event2 = _make_event(event_type="file.modified", asset_id="asset2")
        esc._on_event(event1)
        esc._on_event(event2)
        assert esc.buffer_size == 2

    def test_dedup_expires_after_window(self):
        esc, agg, chat = _make_escalation()
        event1 = _make_event(event_type="file.modified", asset_id="local")
        esc._on_event(event1)
        assert esc.buffer_size == 1

        # Simulate time passing beyond dedup window
        dedup_key = "file.modified:local"
        esc._dedup_cache[dedup_key] = time.monotonic() - DEDUP_WINDOW_SECONDS - 1

        event2 = _make_event(event_type="file.modified", asset_id="local")
        esc._on_event(event2)
        assert esc.buffer_size == 2  # allowed after expiry

    def test_null_asset_id_uses_local(self):
        """Events without asset_id should use 'local' for dedup key."""
        esc, agg, chat = _make_escalation()
        event1 = _make_event(event_type="file.modified", asset_id=None)
        event2 = _make_event(event_type="file.modified", asset_id=None)
        esc._on_event(event1)
        esc._on_event(event2)
        assert esc.buffer_size == 1  # both map to "file.modified:local"


# ===================================================================
# Test: Rate Limiting
# ===================================================================


class TestRateLimiting:
    """No more than RATE_LIMIT_PER_HOUR escalations per hour."""

    @pytest.mark.asyncio
    async def test_rate_limit_drops_events(self):
        esc, agg, chat = _make_escalation()
        # Pretend we've already exhausted the limit
        esc._escalation_count = RATE_LIMIT_PER_HOUR
        esc._hour_start = time.monotonic()

        # Add an event to the buffer
        esc._buffer.append(_make_event())
        await esc._flush_batch()

        # Chat should NOT have been called
        chat.send_system.assert_not_called()
        # Buffer should be cleared (dropped)
        assert esc.buffer_size == 0

    @pytest.mark.asyncio
    async def test_rate_limit_resets_after_hour(self):
        esc, agg, chat = _make_escalation()
        esc._escalation_count = RATE_LIMIT_PER_HOUR
        # Set hour_start to over an hour ago
        esc._hour_start = time.monotonic() - 3601

        esc._buffer.append(_make_event())
        await esc._flush_batch()

        # Counter should have reset, message should be sent
        chat.send_system.assert_called_once()
        assert esc._escalation_count == 1


# ===================================================================
# Test: Batch Aggregation
# ===================================================================


class TestBatchAggregation:
    """Multiple events within one batch window → one summary message."""

    @pytest.mark.asyncio
    async def test_multiple_events_one_message(self):
        esc, agg, chat = _make_escalation()

        # Buffer 3 different events
        esc._on_event(_make_event(event_type="file.modified", message="File A changed"))
        esc._on_event(_make_event(event_type="file.created", message="File B created"))
        esc._on_event(
            _make_event(
                event_type="process.suspicious",
                category=EventCategory.PROCESS,
                message="Process C suspicious",
            )
        )

        assert esc.buffer_size == 3
        await esc._flush_batch()

        # Exactly one message sent
        chat.send_system.assert_called_once()
        assert esc.buffer_size == 0

    @pytest.mark.asyncio
    async def test_empty_buffer_no_message(self):
        esc, agg, chat = _make_escalation()
        await esc._flush_batch()
        chat.send_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_more_than_3_events_shows_overflow(self):
        esc, agg, chat = _make_escalation()

        for i in range(5):
            esc._on_event(
                _make_event(
                    event_type=f"file.modified.{i}",
                    message=f"Event {i}",
                )
            )

        await esc._flush_batch()
        call_args = chat.send_system.call_args
        summary_text = call_args[0][0]
        assert "(+2 more)" in summary_text


# ===================================================================
# Test: Summary Format
# ===================================================================


class TestSummaryFormat:
    """Summary must trigger AI Bridge (contains 'critical/high', '[Local Guardian]')."""

    @pytest.mark.asyncio
    async def test_contains_critical_high_keyword(self):
        esc, agg, chat = _make_escalation()
        esc._on_event(_make_event(message="Suspicious double extension"))
        await esc._flush_batch()

        summary = chat.send_system.call_args[0][0]
        assert "critical/high" in summary

    @pytest.mark.asyncio
    async def test_contains_local_guardian_prefix(self):
        esc, agg, chat = _make_escalation()
        esc._on_event(_make_event(message="Malware keyword detected"))
        await esc._flush_batch()

        summary = chat.send_system.call_args[0][0]
        assert "[Local Guardian]" in summary

    @pytest.mark.asyncio
    async def test_contains_event_count(self):
        esc, agg, chat = _make_escalation()
        esc._on_event(_make_event(event_type="file.modified", message="File changed"))
        esc._on_event(_make_event(event_type="file.created", message="File created"))
        await esc._flush_batch()

        summary = chat.send_system.call_args[0][0]
        assert "2 critical/high event(s)" in summary

    @pytest.mark.asyncio
    async def test_message_type_is_event(self):
        """send_system should be called with MessageType.EVENT."""
        esc, agg, chat = _make_escalation()
        esc._on_event(_make_event())
        await esc._flush_batch()

        from citadel_archer.chat.message import MessageType

        call_args = chat.send_system.call_args
        assert call_args[0][1] == MessageType.EVENT

    @pytest.mark.asyncio
    async def test_message_truncates_long_summaries(self):
        esc, agg, chat = _make_escalation()
        long_msg = "A" * 200
        esc._on_event(_make_event(message=long_msg))
        await esc._flush_batch()

        summary = chat.send_system.call_args[0][0]
        # Each event message is truncated to 100 chars
        assert "A" * 100 in summary
        assert "A" * 101 not in summary


# ===================================================================
# Test: End-to-End (EventAggregator → GuardianEscalation → Chat)
# ===================================================================


class TestEndToEnd:
    """Full flow: ingest event into aggregator → filter → buffer → flush → chat."""

    @pytest.mark.asyncio
    async def test_aggregator_to_chat(self):
        """Ingest a critical file event and verify it reaches ChatManager."""
        agg = EventAggregator(max_history=100)
        chat = _make_chat_manager()
        esc = GuardianEscalation(
            aggregator=agg,
            chat_manager=chat,
        )

        # Subscribe (normally done by start(), but we do it manually
        # to avoid needing a real event loop for the flush task)
        agg.subscribe(esc._on_event)

        # Ingest a critical file event through the aggregator
        agg.ingest(
            event_type="file.modified",
            severity="critical",
            asset_id=None,
            message="Shadow file modified",
        )

        # Event should be buffered
        assert esc.buffer_size == 1

        # Manually flush (simulates the timer)
        await esc._flush_batch()

        # Chat should have received the escalation
        chat.send_system.assert_called_once()
        summary = chat.send_system.call_args[0][0]
        assert "[Local Guardian]" in summary
        assert "Shadow file modified" in summary
        assert "critical/high" in summary

    @pytest.mark.asyncio
    async def test_info_event_does_not_reach_chat(self):
        """Info-level events should never reach the chat."""
        agg = EventAggregator(max_history=100)
        chat = _make_chat_manager()
        esc = GuardianEscalation(aggregator=agg, chat_manager=chat)
        agg.subscribe(esc._on_event)

        # Ingest info-level event
        agg.ingest(
            event_type="file.modified",
            severity="info",
            message="Normal file change",
        )

        assert esc.buffer_size == 0
        await esc._flush_batch()
        chat.send_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_network_critical_does_not_reach_chat(self):
        """Critical network events are NOT Guardian-sourced, should not escalate."""
        agg = EventAggregator(max_history=100)
        chat = _make_chat_manager()
        esc = GuardianEscalation(aggregator=agg, chat_manager=chat)
        agg.subscribe(esc._on_event)

        agg.ingest(
            event_type="network.blocked",
            severity="critical",
            message="IP blocked",
        )

        assert esc.buffer_size == 0

    @pytest.mark.asyncio
    async def test_escalation_count_increments(self):
        esc, agg, chat = _make_escalation()
        assert esc.escalation_count == 0

        esc._on_event(_make_event())
        await esc._flush_batch()
        assert esc.escalation_count == 1

        # Different event type to avoid dedup
        esc._on_event(_make_event(event_type="file.created"))
        await esc._flush_batch()
        assert esc.escalation_count == 2


# ===================================================================
# Test: Lifecycle
# ===================================================================


class TestLifecycle:

    def test_start_sets_running(self):
        loop = asyncio.new_event_loop()
        try:
            esc, agg, chat = _make_escalation(loop=loop)
            esc.start()
            assert esc.running is True
        finally:
            esc.stop()
            loop.close()

    def test_stop_clears_running(self):
        loop = asyncio.new_event_loop()
        try:
            esc, agg, chat = _make_escalation(loop=loop)
            esc.start()
            esc.stop()
            assert esc.running is False
        finally:
            loop.close()

    def test_double_start_is_safe(self):
        loop = asyncio.new_event_loop()
        try:
            esc, agg, chat = _make_escalation(loop=loop)
            esc.start()
            esc.start()  # should not error
            assert esc.running is True
        finally:
            esc.stop()
            loop.close()

    def test_stop_without_start_is_safe(self):
        esc, agg, chat = _make_escalation()
        esc.stop()  # should not error
        assert esc.running is False

    def test_start_without_loop_raises(self):
        """start() without a loop and outside async context should raise."""
        esc, agg, chat = _make_escalation()
        # No loop passed, and we're not in an async context
        with pytest.raises(RuntimeError, match="requires an explicit event loop"):
            esc.start()
        # Should NOT be left in a running state
        assert esc.running is False


# ===================================================================
# Test: Dedup Cache Eviction (Fix #2)
# ===================================================================


class TestDedupEviction:
    """Stale dedup entries should be evicted to prevent memory leaks."""

    def test_stale_entries_evicted(self):
        esc, agg, chat = _make_escalation()

        # Add 100 unique events (all will be cached)
        for i in range(100):
            esc._on_event(
                _make_event(event_type=f"file.modified.{i}", message=f"Event {i}")
            )
        assert esc.dedup_cache_size == 100
        assert esc.buffer_size == 100

        # Age all entries beyond the dedup window
        now = time.monotonic()
        for key in esc._dedup_cache:
            esc._dedup_cache[key] = now - DEDUP_WINDOW_SECONDS - 1

        # Next event triggers eviction
        esc._on_event(_make_event(event_type="file.new", message="Trigger eviction"))
        assert esc.dedup_cache_size == 1  # only the new one remains

    def test_fresh_entries_not_evicted(self):
        esc, agg, chat = _make_escalation()
        esc._on_event(_make_event(event_type="file.modified"))
        esc._on_event(_make_event(event_type="file.created"))
        assert esc.dedup_cache_size == 2

        # Trigger another event — fresh entries should survive eviction
        esc._on_event(
            _make_event(
                event_type="process.suspicious",
                category=EventCategory.PROCESS,
            )
        )
        assert esc.dedup_cache_size == 3


# ===================================================================
# Test: Send Failure Re-queue (Fix #3)
# ===================================================================


class TestSendFailureRequeue:
    """Events should be re-queued if send_system() fails."""

    @pytest.mark.asyncio
    async def test_events_requeued_on_failure(self):
        esc, agg, chat = _make_escalation()
        chat.send_system = AsyncMock(side_effect=RuntimeError("DB locked"))

        esc._on_event(_make_event(event_type="file.modified", message="Important event"))
        assert esc.buffer_size == 1

        await esc._flush_batch()

        # Events should be back in the buffer, not lost
        assert esc.buffer_size == 1
        # Escalation count should NOT have incremented
        assert esc.escalation_count == 0

    @pytest.mark.asyncio
    async def test_requeued_events_sent_on_retry(self):
        esc, agg, chat = _make_escalation()
        call_count = 0

        async def fail_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Transient failure")
            # Second call succeeds

        chat.send_system = AsyncMock(side_effect=fail_then_succeed)

        esc._on_event(_make_event(event_type="file.modified", message="Retry event"))

        # First flush fails — events re-queued
        await esc._flush_batch()
        assert esc.buffer_size == 1
        assert esc.escalation_count == 0

        # Second flush succeeds
        await esc._flush_batch()
        assert esc.buffer_size == 0
        assert esc.escalation_count == 1


# ===================================================================
# Test: Concurrency (Fix #7)
# ===================================================================


class TestConcurrency:
    """Thread-safety under concurrent event ingestion."""

    def test_concurrent_ingestion_no_corruption(self):
        """Multiple threads calling _on_event() should not corrupt buffer."""
        esc, agg, chat = _make_escalation()

        def ingest_from_thread(thread_id):
            for i in range(50):
                # Use unique asset_id per event to avoid dedup
                # (event_type stays mapped to FILE category)
                esc._on_event(
                    _make_event(
                        event_type="file.modified",
                        asset_id=f"t{thread_id}_e{i}",
                        message=f"Thread {thread_id} event {i}",
                    )
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(ingest_from_thread, i) for i in range(5)]
            for f in concurrent.futures.as_completed(futures):
                f.result()  # raise if any thread errored

        # All 250 unique events should be buffered (unique asset_id = no dedup)
        assert esc.buffer_size == 250

    @pytest.mark.asyncio
    async def test_concurrent_ingestion_flush_safe(self):
        """Buffer can be flushed while new events are being ingested."""
        esc, agg, chat = _make_escalation()

        # Pre-fill buffer with unique asset_ids
        for i in range(10):
            esc._on_event(
                _make_event(
                    event_type="file.modified",
                    asset_id=f"pre_{i}",
                    message=f"Pre-event {i}",
                )
            )
        assert esc.buffer_size == 10

        # Flush while more events arrive on another thread
        def add_more():
            for i in range(10):
                esc._on_event(
                    _make_event(
                        event_type="file.modified",
                        asset_id=f"post_{i}",
                        message=f"Post-event {i}",
                    )
                )

        import threading
        t = threading.Thread(target=add_more)
        t.start()
        await esc._flush_batch()
        t.join()

        # Chat should have been called at least once
        chat.send_system.assert_called()
        # Any events added after the drain should be in the buffer
        # (exact count depends on timing, but no crash = success)
