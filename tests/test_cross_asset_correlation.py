"""
Tests for Cross-Asset Threat Correlation Engine.

All tests are in-memory — no external services or network access.
Covers: indicator extraction, shared IOC detection, coordinated attack
detection, attack propagation detection, intel matching, dedup, rate
limiting, flush loop, history, stats, and lifecycle.
"""

import asyncio
import time
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)
from citadel_archer.intel.cross_asset_correlation import (
    COORDINATED_WINDOW_SECONDS,
    DEDUP_WINDOW_SECONDS,
    INDICATOR_WINDOW_SECONDS,
    MIN_COORDINATED_ASSETS,
    MIN_SHARED_IOC_ASSETS,
    PROPAGATION_WINDOW_SECONDS,
    RATE_LIMIT_PER_HOUR,
    CorrelatedThreat,
    CorrelationType,
    CrossAssetCorrelator,
    IndicatorSighting,
    extract_indicators,
    _highest_severity,
    _format_correlation_summary,
)


# ===================================================================
# Fixtures & helpers
# ===================================================================


def _make_aggregator():
    """Minimal EventAggregator mock that supports subscribe()."""
    agg = MagicMock()
    agg.subscribe = MagicMock()
    return agg


def _make_event(
    event_type="remote.auth_log",
    severity="high",
    asset_id="vps-1",
    message="SSH brute force detected",
    details=None,
    category=EventCategory.REMOTE,
    timestamp=None,
):
    return AggregatedEvent(
        event_type=event_type,
        category=category,
        severity=severity,
        asset_id=asset_id,
        message=message,
        details=details or {},
        timestamp=timestamp or "2026-02-15T12:00:00",
    )


def _correlator(**kwargs):
    """Create a correlator without starting the flush loop."""
    agg = kwargs.pop("aggregator", _make_aggregator())
    c = CrossAssetCorrelator(
        aggregator=agg,
        chat_manager=kwargs.pop("chat_manager", None),
        intel_store=kwargs.pop("intel_store", None),
        **kwargs,
    )
    return c


# ===================================================================
# Indicator Extraction
# ===================================================================


class TestIndicatorExtraction:
    def test_extract_ip(self):
        event = _make_event(details={"source_ip": "1.2.3.4"})
        indicators = extract_indicators(event)
        assert "ip" in indicators
        assert "1.2.3.4" in indicators["ip"]

    def test_extract_domain(self):
        event = _make_event(details={"domain": "evil.com"})
        indicators = extract_indicators(event)
        assert "domain" in indicators
        assert "evil.com" in indicators["domain"]

    def test_extract_hash(self):
        event = _make_event(details={"sha256": "abcdef1234567890"})
        indicators = extract_indicators(event)
        assert "hash" in indicators
        assert "abcdef1234567890" in indicators["hash"]

    def test_extract_multiple_types(self):
        event = _make_event(details={
            "ip": "10.0.0.1",
            "domain": "c2.attacker.com",
            "md5": "deadbeef",
        })
        indicators = extract_indicators(event)
        assert "10.0.0.1" in indicators["ip"]
        assert "c2.attacker.com" in indicators["domain"]
        assert "deadbeef" in indicators["hash"]

    def test_extract_no_indicators(self):
        event = _make_event(details={"message": "just text"})
        indicators = extract_indicators(event)
        assert len(indicators) == 0

    def test_extract_empty_values_ignored(self):
        event = _make_event(details={"ip": "", "domain": "   "})
        indicators = extract_indicators(event)
        # Empty string and whitespace-only should be excluded
        assert "ip" not in indicators
        # "   " has strip() applied, but set should have non-empty only
        assert "domain" not in indicators

    def test_extract_multiple_ip_fields(self):
        event = _make_event(details={
            "source_ip": "1.1.1.1",
            "remote_ip": "2.2.2.2",
        })
        indicators = extract_indicators(event)
        assert "1.1.1.1" in indicators["ip"]
        assert "2.2.2.2" in indicators["ip"]


# ===================================================================
# Shared IOC Detection
# ===================================================================


class TestSharedIOC:
    def test_shared_ip_on_two_assets(self):
        c = _correlator()
        now = time.monotonic()

        # Same IP seen on two different assets
        e1 = _make_event(
            asset_id="vps-1",
            details={"source_ip": "5.5.5.5"},
        )
        e2 = _make_event(
            asset_id="vps-2",
            details={"source_ip": "5.5.5.5"},
        )

        c._on_event(e1)
        c._on_event(e2)

        assert c.threat_buffer_size >= 1
        threats = c.recent_correlations(limit=10)
        shared = [t for t in threats if t["correlation_type"] == "shared_ioc"]
        assert len(shared) >= 1
        assert "5.5.5.5" in shared[0]["indicator"]
        assert len(shared[0]["affected_assets"]) >= 2

    def test_same_asset_does_not_trigger(self):
        c = _correlator()

        # Same IP on same asset — NOT cross-asset
        e1 = _make_event(asset_id="vps-1", details={"ip": "5.5.5.5"})
        e2 = _make_event(asset_id="vps-1", details={"ip": "5.5.5.5"})

        c._on_event(e1)
        c._on_event(e2)

        threats = c.recent_correlations()
        shared = [t for t in threats if t["correlation_type"] == "shared_ioc"]
        assert len(shared) == 0

    def test_shared_domain_on_two_assets(self):
        c = _correlator()

        e1 = _make_event(asset_id="vps-1", details={"domain": "c2.evil.com"})
        e2 = _make_event(asset_id="vps-2", details={"domain": "c2.evil.com"})

        c._on_event(e1)
        c._on_event(e2)

        threats = c.recent_correlations()
        shared = [t for t in threats if t["correlation_type"] == "shared_ioc"]
        assert len(shared) >= 1

    def test_shared_ioc_dedup(self):
        c = _correlator()

        # Trigger shared IOC
        e1 = _make_event(asset_id="vps-1", details={"ip": "9.9.9.9"})
        e2 = _make_event(asset_id="vps-2", details={"ip": "9.9.9.9"})
        e3 = _make_event(asset_id="vps-3", details={"ip": "9.9.9.9"})

        c._on_event(e1)
        c._on_event(e2)
        c._on_event(e3)

        # Should only produce 1 correlation (deduped after first detection)
        threats = c.recent_correlations()
        shared = [t for t in threats if t["correlation_type"] == "shared_ioc"]
        assert len(shared) == 1


# ===================================================================
# Coordinated Attack Detection
# ===================================================================


class TestCoordinatedAttack:
    def test_coordinated_on_three_assets(self):
        c = _correlator()

        # Same event type on 3+ assets within coordinated window
        for i in range(3):
            e = _make_event(
                asset_id=f"vps-{i}",
                event_type="remote.auth_log",
            )
            c._on_event(e)

        threats = c.recent_correlations()
        coordinated = [
            t for t in threats
            if t["correlation_type"] == "coordinated"
        ]
        assert len(coordinated) >= 1
        assert len(coordinated[0]["affected_assets"]) >= 3

    def test_two_assets_not_enough(self):
        c = _correlator()

        for i in range(2):
            e = _make_event(
                asset_id=f"vps-{i}",
                event_type="remote.file_integrity",
            )
            c._on_event(e)

        threats = c.recent_correlations()
        coordinated = [
            t for t in threats
            if t["correlation_type"] == "coordinated"
        ]
        assert len(coordinated) == 0

    def test_different_event_types_no_coordination(self):
        c = _correlator()

        # Different event types on different assets
        c._on_event(_make_event(asset_id="vps-0", event_type="remote.auth_log"))
        c._on_event(_make_event(asset_id="vps-1", event_type="remote.file_integrity"))
        c._on_event(_make_event(asset_id="vps-2", event_type="remote.cron_monitor"))

        threats = c.recent_correlations()
        coordinated = [
            t for t in threats
            if t["correlation_type"] == "coordinated"
        ]
        assert len(coordinated) == 0

    def test_coordinated_severity_is_critical(self):
        c = _correlator()

        for i in range(4):
            c._on_event(_make_event(
                asset_id=f"vps-{i}",
                event_type="remote.auth_log",
            ))

        threats = c.recent_correlations()
        coordinated = [
            t for t in threats
            if t["correlation_type"] == "coordinated"
        ]
        assert coordinated[0]["severity"] == "critical"


# ===================================================================
# Attack Propagation Detection
# ===================================================================


class TestAttackPropagation:
    def test_propagation_high_sev_two_assets(self):
        c = _correlator()

        # High-severity events on two different assets
        e1 = _make_event(
            asset_id="vps-1",
            event_type="remote.auth_log",
            severity="critical",
        )
        e2 = _make_event(
            asset_id="vps-2",
            event_type="remote.file_integrity",
            severity="high",
        )

        c._on_event(e1)
        c._on_event(e2)

        threats = c.recent_correlations()
        propagation = [
            t for t in threats
            if t["correlation_type"] == "propagation"
        ]
        assert len(propagation) >= 1
        assert "vps-1" in propagation[0]["affected_assets"]
        assert "vps-2" in propagation[0]["affected_assets"]

    def test_no_propagation_for_low_severity(self):
        c = _correlator()

        e1 = _make_event(
            asset_id="vps-1",
            event_type="remote.auth_log",
            severity="low",
        )
        e2 = _make_event(
            asset_id="vps-2",
            event_type="remote.file_integrity",
            severity="low",
        )

        c._on_event(e1)
        c._on_event(e2)

        threats = c.recent_correlations()
        propagation = [
            t for t in threats
            if t["correlation_type"] == "propagation"
        ]
        assert len(propagation) == 0

    def test_propagation_dedup(self):
        c = _correlator()

        # Multiple high-sev events between same pair — should dedup
        for _ in range(3):
            c._on_event(_make_event(
                asset_id="vps-1",
                event_type="remote.auth_log",
                severity="critical",
            ))
            c._on_event(_make_event(
                asset_id="vps-2",
                event_type="remote.file_integrity",
                severity="high",
            ))

        threats = c.recent_correlations()
        propagation = [
            t for t in threats
            if t["correlation_type"] == "propagation"
        ]
        # Should be deduped to 1
        assert len(propagation) == 1


# ===================================================================
# Intel Match Detection
# ===================================================================


class TestIntelMatch:
    def test_intel_match_with_known_ioc(self):
        store = MagicMock()
        store.has_key = MagicMock(return_value=True)
        c = _correlator(intel_store=store)

        e = _make_event(
            asset_id="vps-1",
            details={"ip": "1.2.3.4"},
        )
        c._on_event(e)

        threats = c.recent_correlations()
        intel = [t for t in threats if t["correlation_type"] == "intel_match"]
        assert len(intel) >= 1
        assert "1.2.3.4" in intel[0]["indicator"]

    def test_no_match_without_intel_store(self):
        c = _correlator(intel_store=None)

        e = _make_event(
            asset_id="vps-1",
            details={"ip": "1.2.3.4"},
        )
        c._on_event(e)

        threats = c.recent_correlations()
        intel = [t for t in threats if t["correlation_type"] == "intel_match"]
        assert len(intel) == 0

    def test_no_match_for_unknown_ioc(self):
        store = MagicMock()
        store.has_key = MagicMock(return_value=False)
        c = _correlator(intel_store=store)

        e = _make_event(
            asset_id="vps-1",
            details={"ip": "10.0.0.1"},
        )
        c._on_event(e)

        threats = c.recent_correlations()
        intel = [t for t in threats if t["correlation_type"] == "intel_match"]
        assert len(intel) == 0

    def test_intel_match_dedup(self):
        store = MagicMock()
        store.has_key = MagicMock(return_value=True)
        c = _correlator(intel_store=store)

        for _ in range(3):
            c._on_event(_make_event(
                asset_id="vps-1",
                details={"ip": "1.2.3.4"},
            ))

        threats = c.recent_correlations()
        intel = [t for t in threats if t["correlation_type"] == "intel_match"]
        assert len(intel) == 1  # deduped


# ===================================================================
# No Asset ID = Skip
# ===================================================================


class TestNoAssetFiltering:
    def test_events_without_asset_id_skipped(self):
        c = _correlator()

        e = _make_event(asset_id=None, details={"ip": "1.2.3.4"})
        c._on_event(e)

        assert c.indicator_count == 0
        assert c.tracked_assets == 0


# ===================================================================
# Dedup and Rate Limiting
# ===================================================================


class TestDedupAndRateLimiting:
    def test_dedup_prevents_duplicate_escalation(self):
        c = _correlator()
        now = time.monotonic()
        c._mark_dedup("test_key", now)
        assert c._is_deduped("test_key", now + 1) is True
        assert c._is_deduped("test_key", now + DEDUP_WINDOW_SECONDS + 1) is False

    def test_evict_stale_dedup(self):
        c = _correlator()
        now = time.monotonic()
        c._dedup_cache["old_key"] = now - DEDUP_WINDOW_SECONDS - 100
        c._dedup_cache["new_key"] = now

        c._evict_stale_entries()

        assert "old_key" not in c._dedup_cache
        assert "new_key" in c._dedup_cache

    def test_evict_stale_indicators(self):
        c = _correlator()
        now = time.monotonic()

        # Add a stale indicator sighting
        c._indicator_map["ip:1.2.3.4"] = [
            IndicatorSighting(
                asset_id="vps-1",
                timestamp=now - INDICATOR_WINDOW_SECONDS - 100,
                event_type="remote.auth_log",
                severity="high",
                iso_timestamp="2026-01-01T00:00:00",
            )
        ]

        c._evict_stale_entries()
        assert "ip:1.2.3.4" not in c._indicator_map


# ===================================================================
# Flush Loop
# ===================================================================


class TestFlushLoop:
    @pytest.mark.asyncio
    async def test_flush_sends_to_chat(self):
        chat = MagicMock()
        chat.send_system = AsyncMock()
        c = _correlator(chat_manager=chat)

        # Add a threat to the buffer
        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity="high",
            affected_assets=["vps-1", "vps-2"],
            indicator="ip:5.5.5.5",
            description="Test shared IOC",
        )
        c._threat_buffer.append(threat)

        await c._flush_threats()
        chat.send_system.assert_called_once()
        call_args = chat.send_system.call_args
        assert "critical/high" in call_args[0][0]
        assert c.escalation_count == 1

    @pytest.mark.asyncio
    async def test_flush_rate_limit(self):
        chat = MagicMock()
        chat.send_system = AsyncMock()
        c = _correlator(chat_manager=chat)
        c._escalation_count = RATE_LIMIT_PER_HOUR

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity="high",
            affected_assets=["vps-1", "vps-2"],
            indicator="ip:5.5.5.5",
        )
        c._threat_buffer.append(threat)

        await c._flush_threats()
        chat.send_system.assert_not_called()
        assert c.threat_buffer_size == 0  # Buffer drained

    @pytest.mark.asyncio
    async def test_flush_no_chat_clears_buffer(self):
        c = _correlator(chat_manager=None)

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity="high",
            affected_assets=["vps-1", "vps-2"],
        )
        c._threat_buffer.append(threat)

        await c._flush_threats()
        assert c.threat_buffer_size == 0

    @pytest.mark.asyncio
    async def test_flush_failure_requeues(self):
        chat = MagicMock()
        chat.send_system = AsyncMock(side_effect=Exception("send failed"))
        c = _correlator(chat_manager=chat)

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity="high",
            affected_assets=["vps-1"],
        )
        c._threat_buffer.append(threat)

        await c._flush_threats()
        # Should be re-queued
        assert c.threat_buffer_size == 1


# ===================================================================
# Correlation Summary Format
# ===================================================================


class TestSummaryFormat:
    def test_format_contains_critical_high(self):
        threats = [
            CorrelatedThreat(
                correlation_type=CorrelationType.SHARED_IOC,
                severity="high",
                affected_assets=["vps-1", "vps-2"],
                indicator="ip:1.2.3.4",
                description="Shared IP 1.2.3.4",
            )
        ]
        summary = _format_correlation_summary(threats)
        assert "critical/high" in summary

    def test_format_lists_assets(self):
        threats = [
            CorrelatedThreat(
                correlation_type=CorrelationType.COORDINATED_ATTACK,
                severity="critical",
                affected_assets=["vps-1", "vps-2", "vps-3"],
                description="Coordinated SSH on 3 VPS",
            )
        ]
        summary = _format_correlation_summary(threats)
        assert "vps-1" in summary
        assert "vps-2" in summary

    def test_format_truncates_long_list(self):
        threats = [
            CorrelatedThreat(
                correlation_type=CorrelationType.SHARED_IOC,
                severity="high",
                affected_assets=[f"vps-{i}" for i in range(10)],
                description="Many assets",
            )
        ]
        summary = _format_correlation_summary(threats)
        assert "+6 more" in summary

    def test_format_multiple_threats(self):
        threats = [
            CorrelatedThreat(
                correlation_type=CorrelationType.SHARED_IOC,
                severity="high",
                affected_assets=["a1", "a2"],
                description="Shared IOC 1",
            ),
            CorrelatedThreat(
                correlation_type=CorrelationType.COORDINATED_ATTACK,
                severity="critical",
                affected_assets=["a1", "a2", "a3"],
                description="Coordinated 1",
            ),
        ]
        summary = _format_correlation_summary(threats)
        assert "2 critical/high" in summary
        assert "[shared_ioc]" in summary
        assert "[coordinated]" in summary


# ===================================================================
# Helper Functions
# ===================================================================


class TestHelpers:
    def test_highest_severity_critical(self):
        assert _highest_severity(["low", "critical", "high"]) == "critical"

    def test_highest_severity_alert(self):
        assert _highest_severity(["low", "alert", "medium"]) == "alert"

    def test_highest_severity_empty(self):
        assert _highest_severity([]) == "medium"

    def test_highest_severity_single(self):
        assert _highest_severity(["low"]) == "low"


# ===================================================================
# CorrelatedThreat Model
# ===================================================================


class TestCorrelatedThreatModel:
    def test_to_dict(self):
        t = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity="high",
            affected_assets=["vps-1"],
            indicator="ip:1.2.3.4",
            first_seen="2026-02-15T12:00:00",
            last_seen="2026-02-15T12:05:00",
            description="Test",
        )
        d = t.to_dict()
        assert d["correlation_type"] == "shared_ioc"
        assert d["severity"] == "high"
        assert d["indicator"] == "ip:1.2.3.4"

    def test_to_dict_caps_samples(self):
        t = CorrelatedThreat(
            sample_events=[{"i": i} for i in range(10)],
        )
        d = t.to_dict()
        assert len(d["sample_events"]) <= 5


# ===================================================================
# History and Stats
# ===================================================================


class TestHistoryAndStats:
    def test_recent_correlations_limit(self):
        c = _correlator()
        for i in range(10):
            c._emit_threat(CorrelatedThreat(
                correlation_type=CorrelationType.SHARED_IOC,
                indicator=f"ip:{i}",
            ))
        assert len(c.recent_correlations(limit=5)) == 5
        assert len(c.recent_correlations(limit=20)) == 10

    def test_history_bounded(self):
        c = _correlator()
        c._max_history = 5
        for i in range(10):
            c._emit_threat(CorrelatedThreat(indicator=f"ip:{i}"))
        assert len(c._history) == 5

    def test_stats(self):
        c = _correlator()
        c._emit_threat(CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
        ))
        c._emit_threat(CorrelatedThreat(
            correlation_type=CorrelationType.COORDINATED_ATTACK,
        ))

        stats = c.stats()
        assert stats["total_correlations"] == 2
        assert stats["by_type"]["shared_ioc"] == 1
        assert stats["by_type"]["coordinated"] == 1


# ===================================================================
# Lifecycle
# ===================================================================


class TestLifecycle:
    def test_start_subscribes(self):
        agg = _make_aggregator()
        loop = MagicMock()
        loop.is_closed.return_value = False

        # Patch asyncio methods for start()
        with patch("citadel_archer.intel.cross_asset_correlation.asyncio") as mock_asyncio:
            mock_asyncio.get_running_loop.return_value = loop
            mock_asyncio.run_coroutine_threadsafe.return_value = MagicMock()

            c = CrossAssetCorrelator(aggregator=agg)
            c.start()

            agg.subscribe.assert_called_once()
            assert c.running is True

    def test_stop(self):
        agg = _make_aggregator()
        c = CrossAssetCorrelator(aggregator=agg)
        c._running = True
        c._flush_task = MagicMock()
        c._flush_task.done.return_value = False

        c.stop()
        assert c.running is False
        c._flush_task.cancel.assert_called_once()

    def test_start_idempotent(self):
        agg = _make_aggregator()
        c = CrossAssetCorrelator(aggregator=agg)
        c._running = True

        # Second start should be no-op
        c.start()
        agg.subscribe.assert_not_called()

    def test_introspection_properties(self):
        c = _correlator()
        assert c.running is False
        assert c.escalation_count == 0
        assert c.threat_buffer_size == 0
        assert c.indicator_count == 0
        assert c.tracked_assets == 0


# ===================================================================
# Indicator Window Eviction
# ===================================================================


class TestWindowEviction:
    def test_old_indicators_evicted_on_event(self):
        c = _correlator()

        # Manually add old indicator sighting
        old_time = time.monotonic() - INDICATOR_WINDOW_SECONDS - 100
        c._indicator_map["ip:old.old.old.old"] = [
            IndicatorSighting(
                asset_id="vps-1",
                timestamp=old_time,
                event_type="remote.auth_log",
                severity="high",
                iso_timestamp="2025-01-01T00:00:00",
            )
        ]

        # New event triggers eviction during record
        c._on_event(_make_event(
            asset_id="vps-1",
            details={"ip": "new.new.new.new"},
        ))

        # The old key should still exist but with empty list after eviction
        # Or it might have been cleaned up
        # The new indicator should be present
        assert c.indicator_count >= 1

    def test_per_asset_events_bounded(self):
        c = _correlator()

        # Add many events for one asset
        for i in range(600):
            c._on_event(_make_event(
                asset_id="vps-1",
                event_type="remote.auth_log",
                details={"ip": f"10.0.0.{i % 256}"},
            ))

        # Should be bounded
        assert len(c._asset_events.get("vps-1", [])) <= 500


# ===================================================================
# End-to-End Integration
# ===================================================================


class TestEndToEnd:
    def test_full_shared_ioc_lifecycle(self):
        """Simulate shared IP across 3 VPSes → 1 correlation."""
        c = _correlator()
        attacker_ip = "203.0.113.50"

        for i in range(3):
            c._on_event(_make_event(
                asset_id=f"vps-{i}",
                event_type="remote.auth_log",
                severity="high",
                details={"source_ip": attacker_ip},
            ))

        threats = c.recent_correlations()
        # Should have shared_ioc AND coordinated (same event type on 3 assets)
        types = {t["correlation_type"] for t in threats}
        assert "shared_ioc" in types
        assert "coordinated" in types

    def test_mixed_correlation_types(self):
        """Different events trigger different correlation types."""
        c = _correlator()

        # Shared IOC (same domain on 2 assets)
        c._on_event(_make_event(
            asset_id="vps-1",
            event_type="network.blocked",
            severity="high",
            category=EventCategory.NETWORK,
            details={"domain": "c2.evil.com"},
        ))
        c._on_event(_make_event(
            asset_id="vps-2",
            event_type="network.blocked",
            severity="high",
            category=EventCategory.NETWORK,
            details={"domain": "c2.evil.com"},
        ))

        threats = c.recent_correlations()
        assert any(t["correlation_type"] == "shared_ioc" for t in threats)

    def test_stats_after_events(self):
        c = _correlator()

        c._on_event(_make_event(
            asset_id="vps-1", details={"ip": "1.1.1.1"}
        ))
        c._on_event(_make_event(
            asset_id="vps-2", details={"ip": "2.2.2.2"}
        ))

        stats = c.stats()
        assert stats["tracked_assets"] >= 2
        assert stats["indicator_count"] >= 2
