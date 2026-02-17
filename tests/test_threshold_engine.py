"""
Tests for Trigger 3c: ThresholdEngine — Threshold/Correlation Breach Detection.

Covers: COUNT rule basics, filtering, group-by-asset, cooldown, dedup + rate
limiting, CORRELATION rules, breach summary format, flush behavior, lifecycle,
end-to-end flow, and default rules validation.
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
from citadel_archer.chat.threshold_engine import (
    ThresholdEngine,
    ThresholdRule,
    CorrelationCondition,
    BreachRecord,
    RuleType,
    DEFAULT_RULES,
    DEDUP_WINDOW_SECONDS,
    RATE_LIMIT_PER_HOUR,
    _format_breach_summary,
    _format_window,
    _matches_fields,
    _group_key,
)


# ===================================================================
# Helpers
# ===================================================================


def _make_event(
    event_type="file.modified",
    category=EventCategory.FILE,
    severity="critical",
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


def _make_chat() -> MagicMock:
    """Create a mock ChatManager with async send_system."""
    mgr = MagicMock()
    mgr.send_system = AsyncMock()
    return mgr


def _count_rule(
    rule_id="test_count",
    event_types=None,
    categories=None,
    severities=None,
    threshold=3,
    window_seconds=3600,
    cooldown_seconds=3600,
    group_by_asset=True,
) -> ThresholdRule:
    """Create a COUNT rule for testing."""
    return ThresholdRule(
        rule_id=rule_id,
        rule_type=RuleType.COUNT,
        name=f"Test rule {rule_id}",
        event_types=frozenset({"file.modified"}) if event_types is None else frozenset(event_types),
        categories=frozenset() if categories is None else frozenset(categories),
        severities=frozenset() if severities is None else frozenset(severities),
        threshold=threshold,
        window_seconds=window_seconds,
        cooldown_seconds=cooldown_seconds,
        group_by_asset=group_by_asset,
    )


def _corr_rule(
    rule_id="test_corr",
    conditions=None,
    window_seconds=3600,
    cooldown_seconds=3600,
    group_by_asset=True,
) -> ThresholdRule:
    """Create a CORRELATION rule for testing."""
    if conditions is None:
        conditions = (
            CorrelationCondition(
                event_types=frozenset({"remote.auth_log"}),
                min_count=2,
            ),
            CorrelationCondition(
                event_types=frozenset({"file.modified"}),
                min_count=1,
            ),
        )
    return ThresholdRule(
        rule_id=rule_id,
        rule_type=RuleType.CORRELATION,
        name=f"Test correlation {rule_id}",
        conditions=conditions,
        window_seconds=window_seconds,
        cooldown_seconds=cooldown_seconds,
        group_by_asset=group_by_asset,
    )


def _make_engine(rules=None, chat=None):
    """Create a ThresholdEngine with mocks (no loop needed for unit tests)."""
    agg = EventAggregator(max_history=100)
    c = chat or _make_chat()
    eng = ThresholdEngine(
        aggregator=agg,
        chat_manager=c,
        rules=rules or [],
    )
    return eng, agg, c


# ===================================================================
# Test: COUNT Rule Basics
# ===================================================================


class TestCountRuleBasics:
    """COUNT rules fire when N matching events arrive within a window."""

    def test_below_threshold_no_breach(self):
        rule = _count_rule(threshold=3)
        eng, agg, chat = _make_engine(rules=[rule])
        # Only 2 events — below threshold of 3
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 0

    def test_at_threshold_creates_breach(self):
        rule = _count_rule(threshold=3)
        eng, agg, chat = _make_engine(rules=[rule])
        for _ in range(3):
            eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1

    def test_expired_timestamps_pruned(self):
        rule = _count_rule(threshold=3, window_seconds=10)
        eng, agg, chat = _make_engine(rules=[rule])
        # Add 2 events
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))

        # Age the timestamps beyond the window
        with eng._counter_lock:
            old_time = time.monotonic() - 20
            eng._counters[rule.rule_id]["host1"] = [old_time, old_time]

        # Third event should prune the old ones, leaving only 1
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.get_counter(rule.rule_id, "host1") == 1
        assert eng.breach_buffer_size == 0

    def test_breach_record_fields(self):
        rule = _count_rule(threshold=2)
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(asset_id="host1", message="Event A"))
        eng._on_event(_make_event(asset_id="host1", message="Event B"))
        assert eng.breach_buffer_size == 1

        with eng._breach_lock:
            breach = eng._breach_buffer[0]
        assert breach.rule_id == "test_count"
        assert breach.rule_name == "Test rule test_count"
        assert breach.asset_id == "host1"
        assert breach.event_count == 2
        assert "threshold: 2" in breach.breach_description


# ===================================================================
# Test: Filtering
# ===================================================================


class TestFiltering:
    """Events must match rule's event_types/categories/severities."""

    def test_severity_match(self):
        rule = _count_rule(severities={"critical"}, threshold=1)
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(severity="critical"))
        assert eng.breach_buffer_size == 1

    def test_severity_mismatch(self):
        rule = _count_rule(severities={"critical"}, threshold=1)
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(severity="info"))
        assert eng.breach_buffer_size == 0

    def test_category_match(self):
        rule = _count_rule(
            categories={EventCategory.FILE},
            threshold=1,
        )
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(category=EventCategory.FILE))
        assert eng.breach_buffer_size == 1

    def test_empty_filters_match_all(self):
        """Empty event_types/categories/severities means 'match all'."""
        rule = _count_rule(
            event_types=set(),
            categories=set(),
            severities=set(),
            threshold=1,
        )
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(
            _make_event(
                event_type="anything.goes",
                category=EventCategory.NETWORK,
                severity="info",
            )
        )
        # With empty event_types, event_type filter is skipped but
        # rule.event_types is frozenset() → empty → matches all
        assert eng.breach_buffer_size == 1


# ===================================================================
# Test: Group-by-Asset
# ===================================================================


class TestGroupByAsset:
    """group_by_asset=True counts per asset; False counts globally."""

    def test_per_asset_counting(self):
        rule = _count_rule(threshold=2, group_by_asset=True)
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host2"))
        # Neither asset has 2 events
        assert eng.breach_buffer_size == 0

    def test_global_counting(self):
        rule = _count_rule(threshold=2, group_by_asset=False)
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host2"))
        # Global count is 2 → breach
        assert eng.breach_buffer_size == 1

    def test_null_asset_maps_to_local(self):
        rule = _count_rule(threshold=2, group_by_asset=True)
        eng, agg, chat = _make_engine(rules=[rule])
        eng._on_event(_make_event(asset_id=None))
        eng._on_event(_make_event(asset_id=None))
        # Both map to "local" → count = 2 → breach
        assert eng.breach_buffer_size == 1
        assert eng.get_counter(rule.rule_id, "local") == 2


# ===================================================================
# Test: Cooldown
# ===================================================================


class TestCooldown:
    """After a rule fires, it shouldn't re-fire within cooldown_seconds."""

    def test_cooldown_prevents_refire(self):
        rule = _count_rule(threshold=2, cooldown_seconds=3600)
        eng, agg, chat = _make_engine(rules=[rule])
        # First breach
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1

        # More events — still within cooldown
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1  # no new breach

    def test_cooldown_expires(self):
        rule = _count_rule(threshold=2, cooldown_seconds=10)
        eng, agg, chat = _make_engine(rules=[rule])

        # First breach
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1

        # Expire both cooldown AND dedup window
        cd_key = f"{rule.rule_id}:host1"
        expired_time = time.monotonic() - DEDUP_WINDOW_SECONDS - 1
        eng._cooldowns[cd_key] = expired_time
        eng._breach_dedup[cd_key] = expired_time

        # New events should trigger a new breach
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 2

    def test_per_asset_cooldown_isolation(self):
        rule = _count_rule(threshold=2, cooldown_seconds=3600, group_by_asset=True)
        eng, agg, chat = _make_engine(rules=[rule])

        # Breach on host1
        eng._on_event(_make_event(asset_id="host1"))
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1

        # host2 should still be able to breach independently
        eng._on_event(_make_event(asset_id="host2"))
        eng._on_event(_make_event(asset_id="host2"))
        assert eng.breach_buffer_size == 2


# ===================================================================
# Test: Dedup and Rate Limiting
# ===================================================================


class TestDedupAndRateLimit:
    """Dedup prevents duplicate breaches; rate limit caps escalations/hr."""

    def test_dedup_prevents_duplicate(self):
        rule = _count_rule(threshold=1, cooldown_seconds=0)
        eng, agg, chat = _make_engine(rules=[rule])

        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1

        # Dedup key is still fresh — no second breach
        eng._on_event(_make_event(asset_id="host1"))
        assert eng.breach_buffer_size == 1

    @pytest.mark.asyncio
    async def test_rate_limit_drops_breaches(self):
        rule = _count_rule(threshold=1)
        eng, agg, chat = _make_engine(rules=[rule])

        eng._escalation_count = RATE_LIMIT_PER_HOUR
        eng._hour_start = time.monotonic()

        # Buffer a breach
        with eng._breach_lock:
            eng._breach_buffer.append(BreachRecord(
                rule_id="test", rule_name="Test", asset_id=None,
                breach_time=time.monotonic(), event_count=5,
                sample_messages=["msg"], breach_description="desc",
            ))

        await eng._flush_breaches()
        chat.send_system.assert_not_called()
        assert eng.breach_buffer_size == 0  # dropped, not queued

    @pytest.mark.asyncio
    async def test_rate_limit_resets_after_window(self):
        rule = _count_rule(threshold=1)
        eng, agg, chat = _make_engine(rules=[rule])

        eng._escalation_count = RATE_LIMIT_PER_HOUR
        eng._hour_start = time.monotonic() - 3601  # over an hour ago

        with eng._breach_lock:
            eng._breach_buffer.append(BreachRecord(
                rule_id="test", rule_name="Test", asset_id=None,
                breach_time=time.monotonic(), event_count=5,
                sample_messages=["msg"], breach_description="desc",
            ))

        await eng._flush_breaches()
        chat.send_system.assert_called_once()
        assert eng._escalation_count == 1

    @pytest.mark.asyncio
    async def test_rate_limit_logs_warning(self):
        eng, agg, chat = _make_engine(rules=[])
        eng._escalation_count = RATE_LIMIT_PER_HOUR
        eng._hour_start = time.monotonic()

        with eng._breach_lock:
            eng._breach_buffer.append(BreachRecord(
                rule_id="test", rule_name="Test", asset_id=None,
                breach_time=time.monotonic(), event_count=5,
                sample_messages=["msg"], breach_description="desc",
            ))

        with patch("citadel_archer.chat.threshold_engine.logger") as mock_logger:
            await eng._flush_breaches()
            mock_logger.warning.assert_called_once()
            assert "rate limit" in mock_logger.warning.call_args[0][0].lower()


# ===================================================================
# Test: CORRELATION Rules
# ===================================================================


class TestCorrelationRules:
    """CORRELATION rules fire when ALL conditions are met in window."""

    def test_all_conditions_met_creates_breach(self):
        rule = _corr_rule(group_by_asset=False)
        eng, agg, chat = _make_engine(rules=[rule])

        # Condition 0: 2 auth_log events
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
        ))
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
        ))
        # Condition 1: 1 file.modified event
        eng._on_event(_make_event(
            event_type="file.modified", category=EventCategory.FILE,
        ))

        eng._evaluate_correlation_rules()
        assert eng.breach_buffer_size == 1

    def test_partial_conditions_no_breach(self):
        rule = _corr_rule(group_by_asset=False)
        eng, agg, chat = _make_engine(rules=[rule])

        # Only condition 0 met
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
        ))
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
        ))

        eng._evaluate_correlation_rules()
        assert eng.breach_buffer_size == 0

    def test_outside_window_no_breach(self):
        rule = _corr_rule(window_seconds=10, group_by_asset=False)
        eng, agg, chat = _make_engine(rules=[rule])

        # Add condition 0 events
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
        ))
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
        ))

        # Age condition 0 timestamps beyond window
        cond_key = f"{rule.rule_id}:cond:0"
        with eng._counter_lock:
            eng._counters[cond_key]["_global_"] = [
                time.monotonic() - 20, time.monotonic() - 20,
            ]

        # Add condition 1 event (fresh)
        eng._on_event(_make_event(
            event_type="file.modified", category=EventCategory.FILE,
        ))

        eng._evaluate_correlation_rules()
        assert eng.breach_buffer_size == 0

    def test_min_count_enforced(self):
        """min_count > 1 on a condition should require that many events."""
        conditions = (
            CorrelationCondition(
                event_types=frozenset({"remote.auth_log"}),
                min_count=5,
            ),
            CorrelationCondition(
                event_types=frozenset({"file.modified"}),
                min_count=1,
            ),
        )
        rule = _corr_rule(conditions=conditions, group_by_asset=False)
        eng, agg, chat = _make_engine(rules=[rule])

        # Only 3 auth_log events (need 5)
        for _ in range(3):
            eng._on_event(_make_event(
                event_type="remote.auth_log", category=EventCategory.SYSTEM,
            ))
        eng._on_event(_make_event(event_type="file.modified"))

        eng._evaluate_correlation_rules()
        assert eng.breach_buffer_size == 0

        # Add 2 more to reach 5
        for _ in range(2):
            eng._on_event(_make_event(
                event_type="remote.auth_log", category=EventCategory.SYSTEM,
            ))

        eng._evaluate_correlation_rules()
        assert eng.breach_buffer_size == 1

    def test_per_asset_correlation(self):
        """Per-asset correlation only fires when all conditions met for same asset."""
        rule = _corr_rule(group_by_asset=True)
        eng, agg, chat = _make_engine(rules=[rule])

        # Auth events on host1
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
            asset_id="host1",
        ))
        eng._on_event(_make_event(
            event_type="remote.auth_log", category=EventCategory.SYSTEM,
            asset_id="host1",
        ))
        # File event on host2 — different asset
        eng._on_event(_make_event(
            event_type="file.modified", category=EventCategory.FILE,
            asset_id="host2",
        ))

        eng._evaluate_correlation_rules()
        # No breach — conditions split across different assets
        assert eng.breach_buffer_size == 0


# ===================================================================
# Test: Breach Summary Format
# ===================================================================


class TestBreachSummaryFormat:
    """Summary text must trigger AI Bridge."""

    def test_contains_trigger_keywords(self):
        breaches = [BreachRecord(
            rule_id="test", rule_name="Test Rule", asset_id="host1",
            breach_time=time.monotonic(), event_count=5,
            sample_messages=["sample"], breach_description="5 events in 1h",
        )]
        summary = _format_breach_summary(breaches)
        assert "critical" in summary.lower()
        assert "high" in summary.lower()

    def test_contains_threshold_breach_prefix(self):
        breaches = [BreachRecord(
            rule_id="test", rule_name="Test Rule", asset_id=None,
            breach_time=time.monotonic(), event_count=3,
            sample_messages=[], breach_description="desc",
        )]
        summary = _format_breach_summary(breaches)
        assert "[Threshold Breach]" in summary

    def test_contains_rule_name(self):
        breaches = [BreachRecord(
            rule_id="test", rule_name="SSH brute force volume",
            asset_id="host1", breach_time=time.monotonic(), event_count=50,
            sample_messages=[], breach_description="50 events in 1h",
        )]
        summary = _format_breach_summary(breaches)
        assert "SSH brute force volume" in summary

    def test_overflow_indicator(self):
        breaches = [
            BreachRecord(
                rule_id=f"rule_{i}", rule_name=f"Rule {i}", asset_id=None,
                breach_time=time.monotonic(), event_count=1,
                sample_messages=[], breach_description="desc",
            )
            for i in range(8)
        ]
        summary = _format_breach_summary(breaches)
        assert "(+3 more" in summary


# ===================================================================
# Test: Flush Behavior
# ===================================================================


class TestFlushBehavior:
    """Flush sends breaches to chat and handles failures."""

    @pytest.mark.asyncio
    async def test_breaches_sent_to_chat(self):
        eng, agg, chat = _make_engine(rules=[])
        with eng._breach_lock:
            eng._breach_buffer.append(BreachRecord(
                rule_id="test", rule_name="Test", asset_id=None,
                breach_time=time.monotonic(), event_count=3,
                sample_messages=["msg"], breach_description="desc",
            ))

        await eng._flush_breaches()
        chat.send_system.assert_called_once()
        assert eng.breach_buffer_size == 0
        assert eng.escalation_count == 1

    @pytest.mark.asyncio
    async def test_empty_buffer_no_call(self):
        eng, agg, chat = _make_engine(rules=[])
        await eng._flush_breaches()
        chat.send_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_failure_requeues(self):
        chat = _make_chat()
        chat.send_system = AsyncMock(side_effect=RuntimeError("Connection lost"))
        eng, agg, _ = _make_engine(rules=[], chat=chat)

        with eng._breach_lock:
            eng._breach_buffer.append(BreachRecord(
                rule_id="test", rule_name="Test", asset_id=None,
                breach_time=time.monotonic(), event_count=3,
                sample_messages=["msg"], breach_description="desc",
            ))

        await eng._flush_breaches()
        # Breaches should be back in the buffer
        assert eng.breach_buffer_size == 1
        assert eng.escalation_count == 0

    @pytest.mark.asyncio
    async def test_retry_succeeds_after_failure(self):
        call_count = 0

        async def fail_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Transient failure")

        chat = _make_chat()
        chat.send_system = AsyncMock(side_effect=fail_then_succeed)
        eng, agg, _ = _make_engine(rules=[], chat=chat)

        with eng._breach_lock:
            eng._breach_buffer.append(BreachRecord(
                rule_id="test", rule_name="Test", asset_id=None,
                breach_time=time.monotonic(), event_count=3,
                sample_messages=["msg"], breach_description="desc",
            ))

        # First flush fails
        await eng._flush_breaches()
        assert eng.breach_buffer_size == 1

        # Second flush succeeds
        await eng._flush_breaches()
        assert eng.breach_buffer_size == 0
        assert eng.escalation_count == 1


# ===================================================================
# Test: Lifecycle
# ===================================================================


class TestLifecycle:
    """Engine start/stop and event loop management."""

    def test_start_sets_running(self):
        loop = asyncio.new_event_loop()
        try:
            eng, agg, chat = _make_engine(rules=[])
            eng._loop = loop
            eng.start()
            assert eng.running is True
        finally:
            eng.stop()
            loop.close()

    def test_stop_clears_running(self):
        loop = asyncio.new_event_loop()
        try:
            eng, agg, chat = _make_engine(rules=[])
            eng._loop = loop
            eng.start()
            eng.stop()
            assert eng.running is False
        finally:
            loop.close()

    def test_double_start_is_safe(self):
        loop = asyncio.new_event_loop()
        try:
            eng, agg, chat = _make_engine(rules=[])
            eng._loop = loop
            eng.start()
            eng.start()  # no error
            assert eng.running is True
        finally:
            eng.stop()
            loop.close()

    def test_stop_without_start_is_safe(self):
        eng, agg, chat = _make_engine(rules=[])
        eng.stop()
        assert eng.running is False

    def test_start_without_loop_raises(self):
        eng, agg, chat = _make_engine(rules=[])
        with pytest.raises(RuntimeError, match="requires an explicit event loop"):
            eng.start()
        assert eng.running is False


# ===================================================================
# Test: End-to-End (EventAggregator → ThresholdEngine → Chat)
# ===================================================================


class TestEndToEnd:
    """Full flow: ingest events → threshold breach → flush → chat."""

    @pytest.mark.asyncio
    async def test_aggregator_to_chat(self):
        rule = _count_rule(threshold=3, group_by_asset=False)
        agg = EventAggregator(max_history=100)
        chat = _make_chat()
        eng = ThresholdEngine(
            aggregator=agg, chat_manager=chat, rules=[rule],
        )

        # Subscribe manually (bypasses start() which needs a loop)
        agg.subscribe(eng._on_event)

        # Ingest events through the aggregator
        for i in range(3):
            agg.ingest(
                event_type="file.modified",
                severity="critical",
                message=f"File change {i}",
            )

        assert eng.breach_buffer_size == 1

        # Flush
        await eng._flush_breaches()
        chat.send_system.assert_called_once()
        summary = chat.send_system.call_args[0][0]
        assert "[Threshold Breach]" in summary
        assert "critical" in summary.lower()

    @pytest.mark.asyncio
    async def test_below_threshold_no_chat(self):
        rule = _count_rule(threshold=5, group_by_asset=False)
        agg = EventAggregator(max_history=100)
        chat = _make_chat()
        eng = ThresholdEngine(
            aggregator=agg, chat_manager=chat, rules=[rule],
        )
        agg.subscribe(eng._on_event)

        # Only 2 events (need 5)
        agg.ingest(event_type="file.modified", severity="info", message="A")
        agg.ingest(event_type="file.modified", severity="info", message="B")

        assert eng.breach_buffer_size == 0
        await eng._flush_breaches()
        chat.send_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_custom_rules_respected(self):
        """Engine should use custom rules, not defaults, when provided."""
        custom = _count_rule(
            rule_id="custom_1",
            event_types={"network.blocked"},
            threshold=2,
            group_by_asset=False,
        )
        eng, agg, chat = _make_engine(rules=[custom])
        agg.subscribe(eng._on_event)

        # Events matching custom rule
        agg.ingest(event_type="network.blocked", severity="alert", message="Block 1")
        agg.ingest(event_type="network.blocked", severity="alert", message="Block 2")

        assert eng.breach_buffer_size == 1

        # Default rules should NOT be loaded
        assert eng.rule_count == 1


# ===================================================================
# Test: Default Rules
# ===================================================================


class TestDefaultRules:
    """Validate the shape and uniqueness of DEFAULT_RULES."""

    def test_default_rule_count(self):
        assert len(DEFAULT_RULES) == 10  # 6 original + 4 VPS rules (v0.3.12)

    def test_unique_rule_ids(self):
        ids = [r.rule_id for r in DEFAULT_RULES]
        assert len(ids) == len(set(ids))

    def test_all_have_names(self):
        for rule in DEFAULT_RULES:
            assert rule.name, f"Rule {rule.rule_id} has no name"

    def test_count_rules_have_thresholds(self):
        for rule in DEFAULT_RULES:
            if rule.rule_type == RuleType.COUNT:
                assert rule.threshold > 0, f"Rule {rule.rule_id} has no threshold"

    def test_correlation_rules_have_conditions(self):
        for rule in DEFAULT_RULES:
            if rule.rule_type == RuleType.CORRELATION:
                assert len(rule.conditions) >= 2, (
                    f"Correlation rule {rule.rule_id} needs 2+ conditions"
                )


# ===================================================================
# Test: Helper Functions
# ===================================================================


class TestHelpers:
    """Unit tests for module-level helper functions."""

    def test_format_window_seconds(self):
        assert _format_window(30) == "30s"

    def test_format_window_minutes(self):
        assert _format_window(600) == "10m"

    def test_format_window_hours(self):
        assert _format_window(3600) == "1h"

    def test_format_window_days(self):
        assert _format_window(86400) == "1d"

    def test_matches_fields_all_empty(self):
        event = _make_event()
        assert _matches_fields(event, frozenset(), frozenset(), frozenset())

    def test_matches_fields_event_type_miss(self):
        event = _make_event(event_type="file.modified")
        assert not _matches_fields(
            event, frozenset({"process.suspicious"}), frozenset(), frozenset(),
        )

    def test_group_key_with_asset(self):
        event = _make_event(asset_id="host1")
        rule = _count_rule(group_by_asset=True)
        assert _group_key(event, rule) == "host1"

    def test_group_key_global(self):
        event = _make_event(asset_id="host1")
        rule = _count_rule(group_by_asset=False)
        assert _group_key(event, rule) == "_global_"

    def test_group_key_null_asset(self):
        event = _make_event(asset_id=None)
        rule = _count_rule(group_by_asset=True)
        assert _group_key(event, rule) == "local"
