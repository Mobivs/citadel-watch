"""
Tests for T6: IntelAggregator coordinator.

Covers: scheduling (APScheduler), parallel fetching, cross-feed
deduplication, severity merge, partial failure handling, audit
logging, callbacks, and stats.
"""

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from citadel_archer.intel.aggregator import (
    AggregationReport,
    FetchResult,
    IntelAggregator,
    _SEVERITY_ORDER,
    _severity_rank,
)
from citadel_archer.intel.fetcher import IntelFetcher
from citadel_archer.intel.models import (
    CVE,
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
)
from citadel_archer.intel.store import IntelStore


# ===================================================================
# Helpers
# ===================================================================

class StubFetcher(IntelFetcher):
    """Controllable stub fetcher for tests."""

    def __init__(self, name: str = "stub", items: Optional[List[IntelItem]] = None):
        super().__init__(name)
        self._items = items or []
        self._configured = False
        self._should_fail = False
        self._fail_error = "fetch failed"

    def configure(self, **kwargs):
        self._configured = True

    def fetch(self, since=None):
        if self._should_fail:
            raise RuntimeError(self._fail_error)
        self.record_fetch(len(self._items))
        return list(self._items)

    def health_check(self):
        return not self._should_fail


def _make_cve_item(
    cve_id: str = "CVE-2024-1234",
    severity: IntelSeverity = IntelSeverity.HIGH,
    source: str = "feed-a",
    ingested_at: Optional[str] = None,
) -> IntelItem:
    cve = CVE(
        cve_id=cve_id,
        description=f"Test {cve_id}",
        severity=severity,
    )
    return IntelItem(
        intel_type=IntelType.CVE,
        payload=cve,
        source_feed=source,
        ingested_at=ingested_at or datetime.utcnow().isoformat(),
    )


def _make_ioc_item(
    value: str = "10.0.0.1",
    severity: IntelSeverity = IntelSeverity.MEDIUM,
    source: str = "feed-a",
) -> IntelItem:
    ioc = IOC(
        ioc_type=IOCType.IP_ADDRESS,
        value=value,
        severity=severity,
        source=source,
    )
    return IntelItem(
        intel_type=IntelType.IOC,
        payload=ioc,
        source_feed=source,
    )


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test_intel.db"
    s = IntelStore(str(db))
    yield s
    s.close()


@pytest.fixture
def audit_log(tmp_path):
    return str(tmp_path / "audit.log")


@pytest.fixture
def aggregator(store, audit_log):
    agg = IntelAggregator(store, audit_log=audit_log)
    yield agg
    agg.stop()


# ===================================================================
# FetchResult
# ===================================================================

class TestFetchResult:
    def test_success(self):
        r = FetchResult("test-feed")
        r.items = [_make_cve_item()]
        assert r.success is True
        assert r.to_dict()["items_count"] == 1

    def test_failure(self):
        r = FetchResult("test-feed")
        r.error = "connection timeout"
        assert r.success is False
        assert r.to_dict()["error"] == "connection timeout"

    def test_duration(self):
        r = FetchResult("test-feed")
        r.duration_ms = 123.456
        assert r.to_dict()["duration_ms"] == 123.5


# ===================================================================
# AggregationReport
# ===================================================================

class TestAggregationReport:
    def test_empty_report(self):
        rpt = AggregationReport()
        assert rpt.feeds_succeeded == 0
        assert rpt.feeds_failed == 0

    def test_mixed_results(self):
        rpt = AggregationReport()
        ok = FetchResult("a")
        fail = FetchResult("b")
        fail.error = "failed"
        rpt.fetch_results = [ok, fail]
        assert rpt.feeds_succeeded == 1
        assert rpt.feeds_failed == 1

    def test_to_dict(self):
        rpt = AggregationReport()
        rpt.total_fetched = 10
        rpt.total_stored = 8
        rpt.finished = "2024-01-01T00:00:00"
        d = rpt.to_dict()
        assert d["total_fetched"] == 10
        assert d["total_stored"] == 8
        assert d["finished"] == "2024-01-01T00:00:00"


# ===================================================================
# Severity ranking
# ===================================================================

class TestSeverityRank:
    def test_ordering(self):
        assert _severity_rank(IntelSeverity.NONE) < _severity_rank(IntelSeverity.LOW)
        assert _severity_rank(IntelSeverity.LOW) < _severity_rank(IntelSeverity.MEDIUM)
        assert _severity_rank(IntelSeverity.MEDIUM) < _severity_rank(IntelSeverity.HIGH)
        assert _severity_rank(IntelSeverity.HIGH) < _severity_rank(IntelSeverity.CRITICAL)

    def test_all_severities_ranked(self):
        for sev in IntelSeverity:
            assert _severity_rank(sev) >= 0


# ===================================================================
# Registration
# ===================================================================

class TestRegistration:
    def test_register_fetcher(self, aggregator):
        assert aggregator.fetcher_count == 0
        aggregator.register(StubFetcher("a"))
        assert aggregator.fetcher_count == 1

    def test_register_multiple(self, aggregator):
        aggregator.register(StubFetcher("a"))
        aggregator.register(StubFetcher("b"))
        aggregator.register(StubFetcher("c"))
        assert aggregator.fetcher_count == 3


# ===================================================================
# Core aggregation
# ===================================================================

class TestRunNow:
    def test_empty_fetchers(self, aggregator):
        report = aggregator.run_now()
        assert report.feeds_succeeded == 0
        assert report.total_fetched == 0
        assert report.finished is not None

    def test_single_fetcher_items_stored(self, aggregator, store):
        items = [_make_cve_item("CVE-2024-0001"), _make_cve_item("CVE-2024-0002")]
        aggregator.register(StubFetcher("feed-a", items))
        report = aggregator.run_now()
        assert report.feeds_succeeded == 1
        assert report.total_fetched == 2
        assert report.total_stored == 2
        assert store.count() == 2

    def test_multiple_fetchers(self, aggregator, store):
        f1 = StubFetcher("feed-a", [_make_cve_item("CVE-2024-0001")])
        f2 = StubFetcher("feed-b", [_make_cve_item("CVE-2024-0002")])
        aggregator.register(f1)
        aggregator.register(f2)
        report = aggregator.run_now()
        assert report.feeds_succeeded == 2
        assert report.total_fetched == 2
        assert store.count() == 2

    def test_since_parameter_passed(self, aggregator):
        fetcher = StubFetcher("feed-a")
        fetcher.fetch = MagicMock(return_value=[])
        fetcher.record_fetch = MagicMock()
        aggregator.register(fetcher)
        aggregator.run_now(since="2024-06-01T00:00:00")
        fetcher.fetch.assert_called_once_with(since="2024-06-01T00:00:00")


# ===================================================================
# Deduplication across feeds
# ===================================================================

class TestDeduplication:
    def test_same_cve_from_two_feeds(self, aggregator, store):
        """Same CVE ID from different feeds should be deduped to one."""
        f1 = StubFetcher("feed-a", [_make_cve_item("CVE-2024-0001", source="feed-a")])
        f2 = StubFetcher("feed-b", [_make_cve_item("CVE-2024-0001", source="feed-b")])
        aggregator.register(f1)
        aggregator.register(f2)
        report = aggregator.run_now()
        assert report.total_fetched == 2
        assert report.total_after_dedup == 1
        assert report.total_merged == 1
        assert store.count() == 1

    def test_different_cves_not_deduped(self, aggregator, store):
        f1 = StubFetcher("feed-a", [_make_cve_item("CVE-2024-0001")])
        f2 = StubFetcher("feed-b", [_make_cve_item("CVE-2024-0002")])
        aggregator.register(f1)
        aggregator.register(f2)
        report = aggregator.run_now()
        assert report.total_after_dedup == 2
        assert report.total_merged == 0

    def test_ioc_dedup_by_value_and_type(self, aggregator, store):
        item_a = _make_ioc_item("10.0.0.1", source="feed-a")
        item_b = _make_ioc_item("10.0.0.1", source="feed-b")
        aggregator.register(StubFetcher("feed-a", [item_a]))
        aggregator.register(StubFetcher("feed-b", [item_b]))
        report = aggregator.run_now()
        assert report.total_after_dedup == 1

    def test_three_feeds_same_item(self, aggregator, store):
        items = [
            _make_cve_item("CVE-2024-0001", source=f"feed-{i}")
            for i in range(3)
        ]
        for i, item in enumerate(items):
            aggregator.register(StubFetcher(f"feed-{i}", [item]))
        report = aggregator.run_now()
        assert report.total_fetched == 3
        assert report.total_after_dedup == 1


# ===================================================================
# Severity merge
# ===================================================================

class TestSeverityMerge:
    def test_upgrade_to_higher_severity(self, aggregator, store):
        """When merging dupes, keep the highest severity."""
        low = _make_cve_item("CVE-2024-0001", severity=IntelSeverity.LOW,
                             ingested_at="2024-01-01T00:00:00")
        critical = _make_cve_item("CVE-2024-0001", severity=IntelSeverity.CRITICAL,
                                  ingested_at="2024-01-01T00:00:01")
        aggregator.register(StubFetcher("feed-a", [low]))
        aggregator.register(StubFetcher("feed-b", [critical]))
        report = aggregator.run_now()
        assert report.total_after_dedup == 1
        # The stored item should have CRITICAL severity
        rows = store.query()
        assert len(rows) == 1
        assert rows[0]["severity"] == "critical"

    def test_older_higher_severity_still_wins(self, aggregator, store):
        """Severity upgrade applies even if the higher-sev item is older."""
        older_critical = _make_cve_item(
            "CVE-2024-0001", severity=IntelSeverity.CRITICAL,
            ingested_at="2024-01-01T00:00:00",
        )
        newer_low = _make_cve_item(
            "CVE-2024-0001", severity=IntelSeverity.LOW,
            ingested_at="2024-06-01T00:00:00",
        )
        aggregator.register(StubFetcher("a", [older_critical]))
        aggregator.register(StubFetcher("b", [newer_low]))
        report = aggregator.run_now()
        rows = store.query()
        assert rows[0]["severity"] == "critical"

    def test_same_severity_no_change(self, aggregator, store):
        a = _make_cve_item("CVE-2024-0001", severity=IntelSeverity.HIGH)
        b = _make_cve_item("CVE-2024-0001", severity=IntelSeverity.HIGH)
        aggregator.register(StubFetcher("a", [a]))
        aggregator.register(StubFetcher("b", [b]))
        report = aggregator.run_now()
        rows = store.query()
        assert rows[0]["severity"] == "high"


# ===================================================================
# Partial failure handling
# ===================================================================

class TestPartialFailure:
    def test_one_fails_one_succeeds(self, aggregator, store):
        good = StubFetcher("good", [_make_cve_item("CVE-2024-0001")])
        bad = StubFetcher("bad")
        bad._should_fail = True
        aggregator.register(good)
        aggregator.register(bad)
        report = aggregator.run_now()
        assert report.feeds_succeeded == 1
        assert report.feeds_failed == 1
        assert report.total_stored == 1
        assert store.count() == 1

    def test_all_fail(self, aggregator, store):
        bad1 = StubFetcher("bad1")
        bad1._should_fail = True
        bad2 = StubFetcher("bad2")
        bad2._should_fail = True
        aggregator.register(bad1)
        aggregator.register(bad2)
        report = aggregator.run_now()
        assert report.feeds_succeeded == 0
        assert report.feeds_failed == 2
        assert report.total_stored == 0
        assert store.count() == 0

    def test_three_of_four_fail(self, aggregator, store):
        for i in range(3):
            bad = StubFetcher(f"bad-{i}")
            bad._should_fail = True
            aggregator.register(bad)
        good = StubFetcher("good", [_make_cve_item()])
        aggregator.register(good)
        report = aggregator.run_now()
        assert report.feeds_succeeded == 1
        assert report.feeds_failed == 3
        assert report.total_stored == 1


# ===================================================================
# Audit logging
# ===================================================================

class TestAuditLogging:
    def test_audit_log_written(self, aggregator, audit_log):
        aggregator.register(StubFetcher("a", [_make_cve_item()]))
        aggregator.run_now()
        content = Path(audit_log).read_text()
        event = json.loads(content.strip())
        assert event["event"] == "intel_aggregation"
        assert event["total_fetched"] == 1
        assert event["total_stored"] == 1

    def test_audit_log_appends(self, aggregator, audit_log):
        aggregator.register(StubFetcher("a", [_make_cve_item()]))
        aggregator.run_now()
        aggregator.run_now()
        lines = Path(audit_log).read_text().strip().splitlines()
        assert len(lines) == 2

    def test_audit_log_dir_created(self, tmp_path):
        log_path = str(tmp_path / "sub" / "dir" / "audit.log")
        s = IntelStore(str(tmp_path / "intel.db"))
        agg = IntelAggregator(s, audit_log=log_path)
        agg.register(StubFetcher("a"))
        agg.run_now()
        assert Path(log_path).exists()
        s.close()

    def test_audit_log_failure_doesnt_crash(self, store):
        agg = IntelAggregator(store, audit_log="/proc/nonexistent/audit.log")
        agg.register(StubFetcher("a"))
        # Should not raise even though audit log write will fail
        report = agg.run_now()
        assert report.finished is not None


# ===================================================================
# Callbacks
# ===================================================================

class TestCallbacks:
    def test_on_complete_called(self, aggregator):
        callback = MagicMock()
        aggregator.set_on_complete(callback)
        aggregator.register(StubFetcher("a"))
        aggregator.run_now()
        callback.assert_called_once()
        report = callback.call_args[0][0]
        assert isinstance(report, AggregationReport)

    def test_on_complete_exception_ignored(self, aggregator):
        def bad_callback(report):
            raise ValueError("callback error")

        aggregator.set_on_complete(bad_callback)
        aggregator.register(StubFetcher("a"))
        # Should not raise
        report = aggregator.run_now()
        assert report.finished is not None


# ===================================================================
# Scheduling
# ===================================================================

class TestScheduling:
    def test_start_and_stop(self, aggregator):
        assert aggregator.is_running is False
        aggregator.start()
        assert aggregator.is_running is True
        aggregator.stop()
        assert aggregator.is_running is False

    def test_start_idempotent(self, aggregator):
        aggregator.start()
        aggregator.start()  # second call should not error
        assert aggregator.is_running is True
        aggregator.stop()

    def test_stop_without_start(self, aggregator):
        # Should not raise
        aggregator.stop()
        assert aggregator.is_running is False

    def test_custom_schedule(self, store, audit_log):
        agg = IntelAggregator(
            store, audit_log=audit_log,
            schedule_hour=5, schedule_minute=30,
        )
        stats = agg.stats()
        assert stats["schedule"] == "05:30 UTC"
        agg.stop()


# ===================================================================
# Stats & reports
# ===================================================================

class TestStats:
    def test_stats_before_run(self, aggregator):
        aggregator.register(StubFetcher("a"))
        s = aggregator.stats()
        assert s["fetcher_count"] == 1
        assert s["fetchers"] == ["a"]
        assert s["last_report"] is None
        assert s["running"] is False

    def test_stats_after_run(self, aggregator):
        aggregator.register(StubFetcher("a", [_make_cve_item()]))
        aggregator.run_now()
        s = aggregator.stats()
        assert s["last_report"] is not None
        assert s["last_report"]["total_fetched"] == 1

    def test_get_last_report_none(self, aggregator):
        assert aggregator.get_last_report() is None

    def test_get_last_report_after_run(self, aggregator):
        aggregator.register(StubFetcher("a"))
        aggregator.run_now()
        rpt = aggregator.get_last_report()
        assert rpt is not None
        assert "started" in rpt
        assert "finished" in rpt

    def test_store_stats_included(self, aggregator, store):
        aggregator.register(StubFetcher("a", [_make_cve_item()]))
        aggregator.run_now()
        s = aggregator.stats()
        assert s["store_stats"]["total"] == 1


# ===================================================================
# Parallel execution
# ===================================================================

class TestParallelExecution:
    def test_fetchers_run_concurrently(self, store, audit_log):
        """Verify that fetchers actually run in parallel threads."""
        thread_ids = []

        class SlowFetcher(IntelFetcher):
            def __init__(self, name):
                super().__init__(name)

            def configure(self, **kw):
                pass

            def fetch(self, since=None):
                thread_ids.append(threading.current_thread().ident)
                time.sleep(0.05)
                return [_make_cve_item(f"CVE-2024-{self.name}")]

            def health_check(self):
                return True

        agg = IntelAggregator(store, audit_log=audit_log, max_workers=4)
        for i in range(4):
            agg.register(SlowFetcher(f"{i:04d}"))

        start = time.time()
        report = agg.run_now()
        elapsed = time.time() - start

        assert report.feeds_succeeded == 4
        # If run sequentially, would take >= 0.2s (4 * 0.05s)
        # Parallel should complete in roughly 0.05s + overhead
        assert elapsed < 0.2
        # Multiple distinct thread IDs used
        assert len(set(thread_ids)) > 1
        agg.stop()


# ===================================================================
# Store deduplication (items already in DB)
# ===================================================================

class TestStoreLevelDedup:
    def test_second_run_dedupes_in_store(self, aggregator, store):
        item = _make_cve_item("CVE-2024-0001")
        aggregator.register(StubFetcher("a", [item]))
        r1 = aggregator.run_now()
        assert r1.total_stored == 1

        # Run again — same item should be rejected by store
        r2 = aggregator.run_now()
        assert r2.total_fetched == 1
        assert r2.total_store_dupes == 1
        assert r2.total_stored == 0
        assert store.count() == 1
