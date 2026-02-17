# Tests for T8: Context Engine & Behavior Baseline
# Covers: BehaviorType, PatternEntry, BaselineResult, AssetBaseline,
#          ContextEngine, cold-start handling, pattern detection,
#          anomaly flagging, bulk learning, and thread safety.

import threading
from datetime import datetime, timedelta

import pytest

from citadel_archer.intel.context_engine import (
    AssetBaseline,
    BaselineResult,
    BehaviorType,
    ContextEngine,
    PatternEntry,
    _CATEGORY_TO_BEHAVIOR,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)


# ── BehaviorType ─────────────────────────────────────────────────────

class TestBehaviorType:
    def test_values(self):
        assert BehaviorType.PROCESS_SPAWN == "process_spawn"
        assert BehaviorType.FILE_MODIFICATION == "file_modification"
        assert BehaviorType.NETWORK_CONNECTION == "network_connection"

    def test_category_mapping_covers_three_types(self):
        assert EventCategory.PROCESS in _CATEGORY_TO_BEHAVIOR
        assert EventCategory.FILE in _CATEGORY_TO_BEHAVIOR
        assert EventCategory.NETWORK in _CATEGORY_TO_BEHAVIOR
        # Vault, AI, etc. should NOT map
        assert EventCategory.VAULT not in _CATEGORY_TO_BEHAVIOR
        assert EventCategory.AI not in _CATEGORY_TO_BEHAVIOR


# ── PatternEntry ─────────────────────────────────────────────────────

class TestPatternEntry:
    def test_to_dict(self):
        pe = PatternEntry(key="sshd", hour=14, occurrences=5,
                          first_seen="t1", last_seen="t2")
        d = pe.to_dict()
        assert d["key"] == "sshd"
        assert d["occurrences"] == 5

    def test_defaults(self):
        pe = PatternEntry()
        assert pe.key == ""
        assert pe.hour == -1
        assert pe.occurrences == 0


# ── BaselineResult ───────────────────────────────────────────────────

class TestBaselineResult:
    def test_to_dict(self):
        br = BaselineResult(
            baseline_match=True, confidence=0.85,
            behavior_type=BehaviorType.FILE_MODIFICATION,
            event_key="/etc/passwd",
        )
        d = br.to_dict()
        assert d["baseline_match"] is True
        assert d["behavior_type"] == "file_modification"

    def test_defaults(self):
        br = BaselineResult()
        assert br.baseline_match is True
        assert br.confidence == 1.0
        assert br.cold_start is False


# ── AssetBaseline ────────────────────────────────────────────────────

class TestAssetBaselineColdStart:
    """Cold-start behavior: days 0 through window_days - 1."""

    def test_brand_new_baseline_is_cold(self):
        bl = AssetBaseline("a1", window_days=7)
        assert bl.is_cold_start is True
        assert bl.days_of_data == 0

    def test_day_zero_compare_returns_match(self):
        bl = AssetBaseline("a1", window_days=7)
        # Record a single event (no time span → 0 days)
        now = datetime.utcnow().isoformat()
        bl.record(BehaviorType.PROCESS_SPAWN, "bash", now)
        result = bl.compare(BehaviorType.PROCESS_SPAWN, "never_seen")
        assert result.baseline_match is True
        assert result.cold_start is True
        assert result.reason == "cold_start"

    def test_confidence_ramps_linearly(self):
        bl = AssetBaseline("a1", window_days=7)
        base = datetime.utcnow()
        # Simulate events over 3 days
        for day in range(4):
            ts = (base + timedelta(days=day)).isoformat()
            bl.record(BehaviorType.PROCESS_SPAWN, "bash", ts)
        # 3 days of data (delta between first and last)
        assert bl.days_of_data == 3
        assert bl.is_cold_start is True
        result = bl.compare(BehaviorType.PROCESS_SPAWN, "bash")
        # confidence = (3 + 1) / 7 ≈ 0.5714
        assert 0.55 <= result.confidence <= 0.60

    def test_exits_cold_start_at_window_days(self):
        bl = AssetBaseline("a1", window_days=7)
        base = datetime.utcnow()
        for day in range(8):
            ts = (base + timedelta(days=day)).isoformat()
            bl.record(BehaviorType.PROCESS_SPAWN, "bash", ts)
        assert bl.days_of_data == 7
        assert bl.is_cold_start is False


class TestAssetBaselinePatternDetection:
    """Pattern recording and comparison after cold start."""

    def _mature_baseline(self) -> AssetBaseline:
        """Create a baseline with >7 days of data."""
        bl = AssetBaseline("a1", window_days=7)
        base = datetime.utcnow() - timedelta(days=10)
        # Record daily "backup" process and "sshd" process
        for day in range(10):
            ts = (base + timedelta(days=day, hours=2)).isoformat()
            bl.record(BehaviorType.PROCESS_SPAWN, "backup", ts)
            ts2 = (base + timedelta(days=day, hours=8)).isoformat()
            bl.record(BehaviorType.PROCESS_SPAWN, "sshd", ts2)
        return bl

    def test_known_pattern_matches(self):
        bl = self._mature_baseline()
        result = bl.compare(BehaviorType.PROCESS_SPAWN, "backup")
        assert result.baseline_match is True
        assert result.confidence >= 0.5
        assert result.reason == "pattern_match"
        assert result.cold_start is False

    def test_unknown_pattern_is_anomaly(self):
        bl = self._mature_baseline()
        result = bl.compare(BehaviorType.PROCESS_SPAWN, "cryptominer")
        assert result.baseline_match is False
        assert result.reason == "unseen_key"
        assert result.confidence == 0.9

    def test_known_keys(self):
        bl = self._mature_baseline()
        keys = bl.known_keys(BehaviorType.PROCESS_SPAWN)
        assert "backup" in keys
        assert "sshd" in keys

    def test_pattern_count(self):
        bl = self._mature_baseline()
        assert bl.pattern_count(BehaviorType.PROCESS_SPAWN) == 2
        assert bl.pattern_count(BehaviorType.FILE_MODIFICATION) == 0

    def test_stats_structure(self):
        bl = self._mature_baseline()
        s = bl.stats()
        assert s["asset_id"] == "a1"
        assert s["event_count"] == 20
        assert s["cold_start"] is False
        assert "process_spawn" in s["patterns"]

    def test_hour_bonus_increases_confidence(self):
        bl = AssetBaseline("a1", window_days=7)
        base = datetime.utcnow() - timedelta(days=10)
        # All events at hour 14
        for day in range(10):
            ts = (base + timedelta(days=day, hours=14)).isoformat()
            bl.record(BehaviorType.FILE_MODIFICATION, "app.log", ts)
        # Compare at hour 14 (matching) vs hour 3 (non-matching)
        ts_match = (datetime.utcnow().replace(hour=14, minute=0)).isoformat()
        ts_off = (datetime.utcnow().replace(hour=3, minute=0)).isoformat()
        r1 = bl.compare(BehaviorType.FILE_MODIFICATION, "app.log", ts_match)
        r2 = bl.compare(BehaviorType.FILE_MODIFICATION, "app.log", ts_off)
        # Same key, but hour-matching should boost confidence
        assert r1.confidence >= r2.confidence


# ── ContextEngine ────────────────────────────────────────────────────

class TestContextEngineProcessEvent:
    def test_process_event_returns_result_for_tracked_category(self):
        engine = ContextEngine(window_days=7)
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            severity="info",
            asset_id="box1",
            details={"process_name": "nginx"},
        )
        result = engine.process_event(evt)
        assert result is not None
        assert isinstance(result, BaselineResult)
        assert result.behavior_type == BehaviorType.PROCESS_SPAWN

    def test_process_event_returns_none_for_untracked(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="vault.created",
            category=EventCategory.VAULT,
            severity="info",
        )
        assert engine.process_event(evt) is None

    def test_uses_global_asset_when_no_asset_id(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            severity="info",
            asset_id=None,
            details={"path": "/tmp/test"},
        )
        engine.process_event(evt)
        assert "_global" in engine.asset_ids()


class TestContextEngineEventKey:
    def test_extracts_process_name(self):
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            details={"process_name": "sshd"},
        )
        assert ContextEngine._event_key(evt) == "sshd"

    def test_extracts_file_path(self):
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            details={"file_path": "/etc/shadow"},
        )
        assert ContextEngine._event_key(evt) == "/etc/shadow"

    def test_extracts_ip(self):
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            details={"ip": "10.0.0.1"},
        )
        assert ContextEngine._event_key(evt) == "10.0.0.1"

    def test_falls_back_to_event_type(self):
        evt = AggregatedEvent(
            event_type="network.blocked",
            category=EventCategory.NETWORK,
            details={},
        )
        assert ContextEngine._event_key(evt) == "network.blocked"


class TestContextEngineBulkLearn:
    def test_learn_from_history(self):
        engine = ContextEngine()
        events = [
            AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="a1",
                details={"process_name": "bash"},
                timestamp=(datetime.utcnow() - timedelta(days=i)).isoformat(),
            )
            for i in range(10)
        ]
        count = engine.learn_from_history(events)
        assert count == 10
        bl = engine.get_baseline("a1")
        assert bl is not None
        assert bl.pattern_count(BehaviorType.PROCESS_SPAWN) == 1
        assert "bash" in bl.known_keys(BehaviorType.PROCESS_SPAWN)

    def test_learn_skips_untracked_categories(self):
        engine = ContextEngine()
        events = [
            AggregatedEvent(
                event_type="vault.created",
                category=EventCategory.VAULT,
                asset_id="a1",
            ),
            AggregatedEvent(
                event_type="ai.decision",
                category=EventCategory.AI,
                asset_id="a1",
            ),
        ]
        count = engine.learn_from_history(events)
        assert count == 0


class TestContextEngineCompare:
    def _build_engine(self) -> ContextEngine:
        engine = ContextEngine(window_days=7)
        base = datetime.utcnow() - timedelta(days=10)
        events = []
        for day in range(10):
            events.append(AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="srv1",
                details={"process_name": "cron"},
                timestamp=(base + timedelta(days=day, hours=2)).isoformat(),
            ))
            events.append(AggregatedEvent(
                event_type="file.modified",
                category=EventCategory.FILE,
                asset_id="srv1",
                details={"path": "/var/log/syslog"},
                timestamp=(base + timedelta(days=day, hours=3)).isoformat(),
            ))
        engine.learn_from_history(events)
        return engine

    def test_known_process_matches(self):
        engine = self._build_engine()
        result = engine.compare("srv1", BehaviorType.PROCESS_SPAWN, "cron")
        assert result.baseline_match is True

    def test_unknown_process_anomaly(self):
        engine = self._build_engine()
        result = engine.compare("srv1", BehaviorType.PROCESS_SPAWN, "ransomware")
        assert result.baseline_match is False

    def test_known_patterns_query(self):
        engine = self._build_engine()
        patterns = engine.known_patterns("srv1", BehaviorType.PROCESS_SPAWN)
        assert "cron" in patterns

    def test_known_patterns_empty_for_missing_asset(self):
        engine = ContextEngine()
        assert engine.known_patterns("no_such", BehaviorType.PROCESS_SPAWN) == []


class TestContextEngineSubscription:
    def test_ingest_aggregated_callback(self):
        engine = ContextEngine()
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            asset_id="box1",
            details={"path": "/etc/hosts"},
        )
        # Should not raise; fire-and-forget
        engine.ingest_aggregated(evt)
        assert "box1" in engine.asset_ids()


class TestContextEngineStats:
    def test_stats_structure(self):
        engine = ContextEngine(window_days=7)
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            asset_id="fw1",
            details={"ip": "8.8.8.8"},
        )
        engine.process_event(evt)
        s = engine.stats()
        assert s["window_days"] == 7
        assert s["total_processed"] == 1
        assert s["assets_tracked"] == 1
        assert "fw1" in s["per_asset"]

    def test_anomaly_counter(self):
        engine = ContextEngine(window_days=7)
        base = datetime.utcnow() - timedelta(days=10)
        # Build mature baseline
        for day in range(10):
            evt = AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="a1",
                details={"process_name": "safe"},
                timestamp=(base + timedelta(days=day)).isoformat(),
            )
            engine.process_event(evt)
        # Now introduce anomaly
        anomaly = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="a1",
            details={"process_name": "evil"},
            timestamp=datetime.utcnow().isoformat(),
        )
        result = engine.process_event(anomaly)
        assert result.baseline_match is False
        assert engine.stats()["total_anomalies"] >= 1


class TestContextEngineReset:
    def test_reset_single_asset(self):
        engine = ContextEngine()
        for aid in ("a1", "a2"):
            evt = AggregatedEvent(
                event_type="file.modified",
                category=EventCategory.FILE,
                asset_id=aid,
                details={"path": "/tmp/x"},
            )
            engine.process_event(evt)
        engine.reset(asset_id="a1")
        assert "a1" not in engine.asset_ids()
        assert "a2" in engine.asset_ids()

    def test_reset_all(self):
        engine = ContextEngine()
        for aid in ("a1", "a2"):
            evt = AggregatedEvent(
                event_type="file.modified",
                category=EventCategory.FILE,
                asset_id=aid,
                details={"path": "/tmp/x"},
            )
            engine.process_event(evt)
        engine.reset()
        assert engine.asset_ids() == []
        assert engine.stats()["total_processed"] == 0


class TestContextEngineThreadSafety:
    def test_concurrent_process_events(self):
        engine = ContextEngine()
        errors = []

        def worker(asset_id):
            try:
                for i in range(50):
                    evt = AggregatedEvent(
                        event_type="process.started",
                        category=EventCategory.PROCESS,
                        asset_id=asset_id,
                        details={"process_name": f"proc_{i}"},
                        timestamp=datetime.utcnow().isoformat(),
                    )
                    engine.process_event(evt)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"a{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert engine.stats()["total_processed"] == 200

    def test_concurrent_learn_and_compare(self):
        engine = ContextEngine(window_days=7)
        errors = []

        def learner():
            try:
                base = datetime.utcnow() - timedelta(days=10)
                events = [
                    AggregatedEvent(
                        event_type="file.modified",
                        category=EventCategory.FILE,
                        asset_id="shared",
                        details={"path": f"/var/{i}"},
                        timestamp=(base + timedelta(days=i)).isoformat(),
                    )
                    for i in range(10)
                ]
                engine.learn_from_history(events)
            except Exception as exc:
                errors.append(exc)

        def comparer():
            try:
                for _ in range(20):
                    engine.compare(
                        "shared", BehaviorType.FILE_MODIFICATION, "/var/0"
                    )
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=learner)
        t2 = threading.Thread(target=comparer)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert errors == []


class TestColdStartProgression:
    """End-to-end test: cold start → learning → mature baseline."""

    def test_full_lifecycle(self):
        engine = ContextEngine(window_days=7)
        base = datetime.utcnow() - timedelta(days=10)

        # Day 0: first event → cold start
        evt0 = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="srv",
            details={"process_name": "nginx"},
            timestamp=base.isoformat(),
        )
        r0 = engine.process_event(evt0)
        assert r0.cold_start is True
        assert r0.baseline_match is True

        # Days 1-7: keep learning
        for day in range(1, 8):
            evt = AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="srv",
                details={"process_name": "nginx"},
                timestamp=(base + timedelta(days=day)).isoformat(),
            )
            r = engine.process_event(evt)
            assert r.cold_start is True
            assert r.baseline_match is True

        # Day 7+: mature baseline
        evt_mature = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="srv",
            details={"process_name": "nginx"},
            timestamp=(base + timedelta(days=8)).isoformat(),
        )
        r_mature = engine.process_event(evt_mature)
        assert r_mature.cold_start is False
        assert r_mature.baseline_match is True
        assert r_mature.confidence >= 0.5

        # New unseen process should be flagged as anomaly
        evt_bad = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="srv",
            details={"process_name": "rootkit"},
            timestamp=(base + timedelta(days=9)).isoformat(),
        )
        r_bad = engine.process_event(evt_bad)
        assert r_bad.baseline_match is False
        assert r_bad.reason == "unseen_key"
