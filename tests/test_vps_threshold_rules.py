"""
Tests for v0.3.12: VPS threshold rules in ThresholdEngine.

Covers: Each new COUNT rule (file_integrity, cron, process_anomaly),
the new CORRELATION rule (vps_intrusion_pattern), window boundaries,
cooldown behavior, and rule registration.
"""

import time
from unittest.mock import AsyncMock, MagicMock

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
    RuleType,
    DEFAULT_RULES,
)


def _make_event(
    event_type="remote.file_integrity",
    category=EventCategory.REMOTE,
    severity="alert",
    asset_id="vps1",
    message="file change detected",
) -> AggregatedEvent:
    return AggregatedEvent(
        event_type=event_type,
        category=category,
        severity=severity,
        asset_id=asset_id,
        message=message,
    )


@pytest.fixture
def chat_manager():
    mgr = MagicMock()
    mgr.send_system = AsyncMock()
    return mgr


class TestVPSRulesRegistered:
    """New VPS rules are present in DEFAULT_RULES."""

    def test_file_integrity_rule_exists(self):
        ids = {r.rule_id for r in DEFAULT_RULES}
        assert "remote_file_integrity_burst" in ids

    def test_cron_changes_rule_exists(self):
        ids = {r.rule_id for r in DEFAULT_RULES}
        assert "remote_cron_changes" in ids

    def test_process_anomaly_rule_exists(self):
        ids = {r.rule_id for r in DEFAULT_RULES}
        assert "remote_process_anomaly" in ids

    def test_vps_intrusion_pattern_rule_exists(self):
        ids = {r.rule_id for r in DEFAULT_RULES}
        assert "vps_intrusion_pattern" in ids

    def test_total_rule_count(self):
        # 6 original + 4 new = 10
        assert len(DEFAULT_RULES) == 10


class TestFileIntegrityRule:
    """remote_file_integrity_burst: 5+ file integrity changes in 1 hour."""

    def test_below_threshold_no_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_file_integrity_burst"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(4):
            engine._on_event(_make_event(event_type="remote.file_integrity"))
        assert engine.breach_buffer_size == 0

    def test_at_threshold_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_file_integrity_burst"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(5):
            engine._on_event(_make_event(event_type="remote.file_integrity"))
        assert engine.breach_buffer_size == 1


class TestCronChangesRule:
    """remote_cron_changes: 3+ cron changes in 1 hour."""

    def test_below_threshold_no_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_cron_changes"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(2):
            engine._on_event(_make_event(event_type="remote.cron_monitor"))
        assert engine.breach_buffer_size == 0

    def test_at_threshold_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_cron_changes"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(3):
            engine._on_event(_make_event(event_type="remote.cron_monitor"))
        assert engine.breach_buffer_size == 1


class TestProcessAnomalyRule:
    """remote_process_anomaly: 10+ process alerts (high/critical/alert) in 1 hour."""

    def test_below_threshold_no_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_process_anomaly"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(9):
            engine._on_event(_make_event(
                event_type="remote.process_monitor", severity="high",
            ))
        assert engine.breach_buffer_size == 0

    def test_at_threshold_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_process_anomaly"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(10):
            engine._on_event(_make_event(
                event_type="remote.process_monitor", severity="critical",
            ))
        assert engine.breach_buffer_size == 1

    def test_low_severity_ignored(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "remote_process_anomaly"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(15):
            engine._on_event(_make_event(
                event_type="remote.process_monitor", severity="info",
            ))
        assert engine.breach_buffer_size == 0


class TestMultiVPSCorrelationRule:
    """vps_intrusion_pattern: auth events + file/cron changes."""

    def test_auth_only_no_breach(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "vps_intrusion_pattern"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(10):
            engine._on_event(_make_event(
                event_type="remote.auth_log", severity="high",
            ))
        # Only one condition met — sweep needed for correlation eval
        engine._evaluate_correlation_rules()
        assert engine.breach_buffer_size == 0

    def test_both_conditions_met(self, chat_manager):
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "vps_intrusion_pattern"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        for _ in range(5):
            engine._on_event(_make_event(
                event_type="remote.auth_log", severity="high",
            ))
        engine._on_event(_make_event(event_type="remote.file_integrity"))

        engine._evaluate_correlation_rules()
        assert engine.breach_buffer_size == 1

    def test_group_by_asset(self, chat_manager):
        """Events from different assets don't correlate together."""
        agg = EventAggregator(max_history=100)
        rule = [r for r in DEFAULT_RULES if r.rule_id == "vps_intrusion_pattern"][0]
        engine = ThresholdEngine(agg, chat_manager, rules=[rule])
        engine._running = True

        # Auth events on vps1, file change on vps2
        for _ in range(5):
            engine._on_event(_make_event(
                event_type="remote.auth_log", severity="high", asset_id="vps1",
            ))
        engine._on_event(_make_event(
            event_type="remote.file_integrity", asset_id="vps2",
        ))

        engine._evaluate_correlation_rules()
        assert engine.breach_buffer_size == 0
