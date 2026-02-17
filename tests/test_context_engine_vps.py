"""
Tests for v0.3.12: Context Engine VPS behavior types.

Covers: REMOTE_AUTH + REMOTE_SENSOR behavior types, per-VPS baselines,
cold-start, anomaly detection for auth patterns, granular event key
extraction for remote events.
"""

from datetime import datetime, timedelta

import pytest

from citadel_archer.intel.context_engine import (
    AssetBaseline,
    BehaviorType,
    ContextEngine,
    _CATEGORY_TO_BEHAVIOR,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)


class TestVPSBehaviorTypes:
    """REMOTE_AUTH and REMOTE_SENSOR exist and are mapped."""

    def test_remote_auth_exists(self):
        assert BehaviorType.REMOTE_AUTH == "remote_auth"

    def test_remote_sensor_exists(self):
        assert BehaviorType.REMOTE_SENSOR == "remote_sensor"

    def test_remote_category_mapped(self):
        assert EventCategory.REMOTE in _CATEGORY_TO_BEHAVIOR
        assert _CATEGORY_TO_BEHAVIOR[EventCategory.REMOTE] == BehaviorType.REMOTE_SENSOR

    def test_asset_baseline_tracks_new_types(self):
        """AssetBaseline initializes pattern dicts for new behavior types."""
        bl = AssetBaseline("vps1")
        assert BehaviorType.REMOTE_AUTH in bl._patterns
        assert BehaviorType.REMOTE_SENSOR in bl._patterns


class TestContextEngineRemoteProcessing:
    """ContextEngine processes REMOTE events with granular behavior mapping."""

    def test_auth_log_maps_to_remote_auth(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.auth_log",
            category=EventCategory.REMOTE,
            severity="high",
            asset_id="vps1",
            details={"detail": "failed_password"},
        )
        result = engine.process_event(evt)
        assert result is not None
        assert result.behavior_type == BehaviorType.REMOTE_AUTH

    def test_file_integrity_maps_to_remote_sensor(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.file_integrity",
            category=EventCategory.REMOTE,
            severity="alert",
            asset_id="vps1",
            details={"sensor": "fim", "path": "/etc/passwd"},
        )
        result = engine.process_event(evt)
        assert result is not None
        assert result.behavior_type == BehaviorType.REMOTE_SENSOR

    def test_cron_monitor_maps_to_remote_sensor(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.cron_monitor",
            category=EventCategory.REMOTE,
            severity="alert",
            asset_id="vps1",
            details={"sensor": "cron"},
        )
        result = engine.process_event(evt)
        assert result is not None
        assert result.behavior_type == BehaviorType.REMOTE_SENSOR


class TestVPSEventKeyExtraction:
    """Remote events extract meaningful keys for pattern tracking."""

    def test_auth_log_key_uses_detail(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.auth_log",
            category=EventCategory.REMOTE,
            asset_id="vps1",
            details={"detail": "failed_password"},
        )
        key = engine._event_key(evt)
        assert key == "auth:failed_password"

    def test_auth_log_key_uses_auth_type(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.auth_log",
            category=EventCategory.REMOTE,
            asset_id="vps1",
            details={"auth_type": "publickey"},
        )
        key = engine._event_key(evt)
        assert key == "auth:publickey"

    def test_sensor_event_key_uses_sensor(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.file_integrity",
            category=EventCategory.REMOTE,
            asset_id="vps1",
            details={"sensor": "fim"},
        )
        key = engine._event_key(evt)
        assert key == "fim"

    def test_sensor_event_key_uses_check(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.cron_monitor",
            category=EventCategory.REMOTE,
            asset_id="vps1",
            details={"check": "cron_added"},
        )
        key = engine._event_key(evt)
        assert key == "cron_added"

    def test_sensor_event_fallback_to_event_type(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.network_anomaly",
            category=EventCategory.REMOTE,
            asset_id="vps1",
            details={},
        )
        key = engine._event_key(evt)
        assert key == "remote.network_anomaly"


class TestVPSBaselines:
    """Per-VPS baselines for REMOTE events."""

    def test_per_asset_baseline_created(self):
        engine = ContextEngine()
        for i in range(3):
            engine.process_event(AggregatedEvent(
                event_type="remote.auth_log",
                category=EventCategory.REMOTE,
                severity="high",
                asset_id="vps1",
                details={"detail": "failed_password"},
            ))
        assert "vps1" in engine.asset_ids()
        bl = engine.get_baseline("vps1")
        assert bl is not None
        assert bl.pattern_count(BehaviorType.REMOTE_AUTH) >= 1

    def test_cold_start_always_matches(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="remote.auth_log",
            category=EventCategory.REMOTE,
            severity="high",
            asset_id="vps_new",
            details={"detail": "failed_password"},
        )
        result = engine.process_event(evt)
        assert result.cold_start is True
        assert result.baseline_match is True

    def test_learn_from_history_handles_remote(self):
        engine = ContextEngine()
        events = [
            AggregatedEvent(
                event_type="remote.auth_log",
                category=EventCategory.REMOTE,
                severity="high",
                asset_id="vps1",
                details={"detail": "failed_password"},
                timestamp=(datetime.utcnow() - timedelta(days=i)).isoformat(),
            )
            for i in range(10)
        ]
        count = engine.learn_from_history(events)
        assert count == 10
        bl = engine.get_baseline("vps1")
        assert bl.pattern_count(BehaviorType.REMOTE_AUTH) >= 1
