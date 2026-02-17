"""
Tests for v0.3.12: REMOTE event category in EventAggregator.

Covers: REMOTE enum value, explicit remote.* mappings, prefix fallback
for unknown remote sensor types, and categorize_event() behavior.
"""

import pytest

from citadel_archer.intel.event_aggregator import (
    EventCategory,
    categorize_event,
    _EVENT_CATEGORY_MAP,
    EventAggregator,
    AggregatedEvent,
)


class TestRemoteEventCategory:
    """REMOTE category exists and is properly wired."""

    def test_remote_category_exists(self):
        assert hasattr(EventCategory, "REMOTE")
        assert EventCategory.REMOTE.value == "remote"

    def test_explicit_remote_mappings(self):
        """All 5 known remote sensor types are in the category map."""
        expected = [
            "remote.auth_log",
            "remote.process_monitor",
            "remote.file_integrity",
            "remote.cron_monitor",
            "remote.network_anomaly",
        ]
        for et in expected:
            assert _EVENT_CATEGORY_MAP.get(et) == EventCategory.REMOTE, (
                f"{et} should map to REMOTE"
            )

    def test_categorize_known_remote_event(self):
        """categorize_event returns REMOTE for known remote types."""
        assert categorize_event("remote.auth_log") == EventCategory.REMOTE
        assert categorize_event("remote.file_integrity") == EventCategory.REMOTE

    def test_categorize_prefix_fallback(self):
        """Unknown remote.* types auto-categorize via prefix fallback."""
        assert categorize_event("remote.new_sensor_2027") == EventCategory.REMOTE
        assert categorize_event("remote.custom_check") == EventCategory.REMOTE

    def test_non_remote_still_works(self):
        """Existing categories are unaffected."""
        assert categorize_event("file.modified") == EventCategory.FILE
        assert categorize_event("process.suspicious") == EventCategory.PROCESS
        assert categorize_event("network.blocked") == EventCategory.NETWORK
        assert categorize_event("vault.unlocked") == EventCategory.VAULT
        assert categorize_event("unknown.event") == EventCategory.SYSTEM

    def test_aggregator_categorizes_remote_events(self):
        """EventAggregator.ingest() tags remote events correctly."""
        agg = EventAggregator(max_history=100)
        evt = agg.ingest(
            event_type="remote.auth_log",
            severity="high",
            asset_id="vps1",
            message="SSH brute force detected",
        )
        assert evt.category == EventCategory.REMOTE
        assert agg.stats()["by_category"].get("remote") == 1

    def test_aggregator_by_category_remote(self):
        """by_category(REMOTE) filters correctly."""
        agg = EventAggregator(max_history=100)
        agg.ingest("remote.auth_log", severity="high", asset_id="vps1")
        agg.ingest("file.modified", severity="info", asset_id="local")
        agg.ingest("remote.cron_monitor", severity="alert", asset_id="vps2")

        remote_events = agg.by_category(EventCategory.REMOTE)
        assert len(remote_events) == 2
        assert all(e.category == EventCategory.REMOTE for e in remote_events)
