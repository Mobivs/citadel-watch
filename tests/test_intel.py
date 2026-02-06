"""
Tests for Intel Module - Threat Intelligence Foundation.

Covers: data models (CVE, IOC, TTP, Vulnerability, IntelItem),
SQLite store (insert, dedup, query, stats, purge),
abstract fetcher base, and thread-safe ingestion queue.
"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from citadel_archer.intel.models import (
    CVE,
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
    TTP,
    Vulnerability,
)
from citadel_archer.intel.store import IntelStore
from citadel_archer.intel.fetcher import IntelFetcher
from citadel_archer.intel.queue import IntelQueue


# ===================================================================
# Helpers
# ===================================================================

def _make_cve(cve_id="CVE-2024-1234", score=9.8) -> CVE:
    return CVE(
        cve_id=cve_id,
        description="Remote code execution in example service",
        cvss_score=score,
        affected_products=["example-server 1.0"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        published_date="2024-01-15T00:00:00",
    )


def _make_ioc(value="192.168.1.100", ioc_type=IOCType.IP_ADDRESS) -> IOC:
    return IOC(
        ioc_type=ioc_type,
        value=value,
        description="Known C2 server",
        severity=IntelSeverity.HIGH,
        tags=["c2", "apt"],
        source="test-feed",
        confidence=0.95,
    )


def _make_ttp() -> TTP:
    return TTP(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="execution",
        description="Adversaries use PowerShell for execution",
        severity=IntelSeverity.HIGH,
        platforms=["windows"],
        data_sources=["process", "command"],
    )


def _make_vuln() -> Vulnerability:
    return Vulnerability(
        product="openssh",
        version="8.9p1",
        cve_id="CVE-2024-5678",
        description="Buffer overflow in openssh",
        severity=IntelSeverity.CRITICAL,
        fix_version="9.0p1",
        is_exploited=True,
        patch_available=True,
    )


def _wrap(payload, intel_type=IntelType.CVE, source="test") -> IntelItem:
    return IntelItem(
        intel_type=intel_type,
        payload=payload,
        source_feed=source,
    )


class StubFetcher(IntelFetcher):
    """Concrete fetcher stub for testing the abstract base."""

    def __init__(self):
        super().__init__("stub-feed")
        self.configured = False
        self.healthy = True
        self._items: List[IntelItem] = []

    def configure(self, **kwargs):
        self.configured = True
        self.api_key = kwargs.get("api_key", "")

    def fetch(self, since=None):
        items = list(self._items)
        self.record_fetch(len(items))
        return items

    def health_check(self):
        return self.healthy


# ===================================================================
# Data Model Tests
# ===================================================================

class TestIntelSeverity:
    def test_from_cvss_none(self):
        assert IntelSeverity.from_cvss(0.0) == IntelSeverity.NONE

    def test_from_cvss_low(self):
        assert IntelSeverity.from_cvss(2.5) == IntelSeverity.LOW

    def test_from_cvss_medium(self):
        assert IntelSeverity.from_cvss(5.0) == IntelSeverity.MEDIUM

    def test_from_cvss_high(self):
        assert IntelSeverity.from_cvss(8.0) == IntelSeverity.HIGH

    def test_from_cvss_critical(self):
        assert IntelSeverity.from_cvss(9.5) == IntelSeverity.CRITICAL

    def test_from_cvss_boundary_3_9(self):
        assert IntelSeverity.from_cvss(3.9) == IntelSeverity.LOW

    def test_from_cvss_boundary_6_9(self):
        assert IntelSeverity.from_cvss(6.9) == IntelSeverity.MEDIUM

    def test_from_cvss_boundary_8_9(self):
        assert IntelSeverity.from_cvss(8.9) == IntelSeverity.HIGH


class TestCVE:
    def test_basic_creation(self):
        cve = _make_cve()
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.cvss_score == 9.8

    def test_auto_severity_from_score(self):
        cve = _make_cve(score=9.8)
        assert cve.severity == IntelSeverity.CRITICAL

    def test_dedup_key(self):
        cve = _make_cve("CVE-2024-9999")
        assert cve.dedup_key == "cve:CVE-2024-9999"

    def test_to_dict(self):
        cve = _make_cve()
        d = cve.to_dict()
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["cvss_score"] == 9.8
        assert "affected_products" in d

    def test_low_score_severity(self):
        cve = _make_cve(score=2.0)
        assert cve.severity == IntelSeverity.LOW


class TestIOC:
    def test_ip_ioc(self):
        ioc = _make_ioc("10.0.0.1", IOCType.IP_ADDRESS)
        assert ioc.value == "10.0.0.1"
        assert ioc.ioc_type == IOCType.IP_ADDRESS

    def test_hash_ioc(self):
        ioc = _make_ioc("abc123def456", IOCType.FILE_HASH_SHA256)
        assert ioc.dedup_key == "ioc:sha256:abc123def456"

    def test_dedup_key_includes_type(self):
        ioc_ip = _make_ioc("1.2.3.4", IOCType.IP_ADDRESS)
        ioc_domain = _make_ioc("1.2.3.4", IOCType.DOMAIN)
        assert ioc_ip.dedup_key != ioc_domain.dedup_key

    def test_to_dict(self):
        ioc = _make_ioc()
        d = ioc.to_dict()
        assert d["ioc_type"] == "ip"
        assert d["value"] == "192.168.1.100"
        assert "tags" in d

    def test_confidence(self):
        ioc = _make_ioc()
        assert ioc.confidence == 0.95


class TestTTP:
    def test_creation(self):
        ttp = _make_ttp()
        assert ttp.technique_id == "T1059.001"
        assert ttp.tactic == "execution"

    def test_dedup_key(self):
        ttp = _make_ttp()
        assert ttp.dedup_key == "ttp:T1059.001"

    def test_to_dict(self):
        ttp = _make_ttp()
        d = ttp.to_dict()
        assert d["name"] == "PowerShell"
        assert "platforms" in d


class TestVulnerability:
    def test_creation(self):
        v = _make_vuln()
        assert v.product == "openssh"
        assert v.is_exploited is True

    def test_dedup_key_with_cve(self):
        v = _make_vuln()
        assert v.dedup_key == "vuln:openssh:8.9p1:CVE-2024-5678"

    def test_dedup_key_without_cve(self):
        v = Vulnerability(product="nginx", version="1.25.0")
        assert v.dedup_key == "vuln:nginx:1.25.0"

    def test_to_dict(self):
        v = _make_vuln()
        d = v.to_dict()
        assert d["fix_version"] == "9.0p1"
        assert d["patch_available"] is True


class TestIntelItem:
    def test_wraps_cve(self):
        item = _wrap(_make_cve(), IntelType.CVE)
        assert item.intel_type == IntelType.CVE
        assert item.dedup_key == "cve:CVE-2024-1234"

    def test_wraps_ioc(self):
        item = _wrap(_make_ioc(), IntelType.IOC)
        assert item.intel_type == IntelType.IOC

    def test_severity_passthrough(self):
        item = _wrap(_make_cve(score=9.8))
        assert item.severity == IntelSeverity.CRITICAL

    def test_to_dict(self):
        item = _wrap(_make_cve(), source="nvd")
        d = item.to_dict()
        assert d["intel_type"] == "cve"
        assert d["source_feed"] == "nvd"
        assert "payload" in d

    def test_auto_generates_id(self):
        a = _wrap(_make_cve())
        b = _wrap(_make_cve())
        assert a.item_id != b.item_id

    def test_auto_generates_timestamp(self):
        item = _wrap(_make_cve())
        assert item.ingested_at  # non-empty


class TestIntelType:
    def test_all_types(self):
        assert set(IntelType) == {
            IntelType.CVE, IntelType.IOC,
            IntelType.TTP, IntelType.VULNERABILITY,
        }


class TestIOCType:
    def test_all_subtypes(self):
        assert len(IOCType) == 8


# ===================================================================
# Store Tests
# ===================================================================

@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test_intel.db"
    s = IntelStore(str(db))
    yield s
    s.close()


class TestIntelStore:
    def test_insert_and_retrieve(self, store):
        item = _wrap(_make_cve())
        assert store.insert(item) is True
        row = store.get_by_id(item.item_id)
        assert row is not None
        assert row["intel_type"] == "cve"

    def test_dedup_rejects_duplicate(self, store):
        cve = _make_cve("CVE-2024-0001")
        item1 = _wrap(cve)
        item2 = _wrap(cve)  # same dedup_key
        # Force different item_id but same dedup_key
        assert store.insert(item1) is True
        assert store.insert(item2) is False

    def test_has_key(self, store):
        item = _wrap(_make_cve())
        assert store.has_key(item.dedup_key) is False
        store.insert(item)
        assert store.has_key(item.dedup_key) is True

    def test_count(self, store):
        assert store.count() == 0
        store.insert(_wrap(_make_cve("CVE-2024-0001")))
        store.insert(_wrap(_make_cve("CVE-2024-0002")))
        assert store.count() == 2

    def test_count_by_type(self, store):
        store.insert(_wrap(_make_cve(), IntelType.CVE))
        store.insert(_wrap(_make_ioc(), IntelType.IOC))
        assert store.count(intel_type=IntelType.CVE) == 1
        assert store.count(intel_type=IntelType.IOC) == 1

    def test_query_by_type(self, store):
        store.insert(_wrap(_make_cve(), IntelType.CVE))
        store.insert(_wrap(_make_ioc(), IntelType.IOC))
        results = store.query(intel_type=IntelType.CVE)
        assert len(results) == 1
        assert results[0]["intel_type"] == "cve"

    def test_query_by_severity(self, store):
        store.insert(_wrap(_make_cve(score=9.8), IntelType.CVE))
        store.insert(_wrap(_make_cve(score=2.0), IntelType.CVE))
        results = store.query(severity=IntelSeverity.CRITICAL)
        assert len(results) == 1

    def test_query_limit_offset(self, store):
        for i in range(5):
            store.insert(_wrap(_make_cve(f"CVE-2024-{i:04d}")))
        assert len(store.query(limit=3)) == 3
        assert len(store.query(limit=3, offset=3)) == 2

    def test_delete_by_id(self, store):
        item = _wrap(_make_cve())
        store.insert(item)
        assert store.delete_by_id(item.item_id) is True
        assert store.get_by_id(item.item_id) is None

    def test_delete_nonexistent(self, store):
        assert store.delete_by_id("no-such-id") is False

    def test_bulk_insert(self, store):
        items = [_wrap(_make_cve(f"CVE-2024-{i:04d}")) for i in range(5)]
        result = store.bulk_insert(items)
        assert result["inserted"] == 5
        assert result["duplicates"] == 0
        # Insert same batch again
        items2 = [_wrap(_make_cve(f"CVE-2024-{i:04d}")) for i in range(5)]
        result2 = store.bulk_insert(items2)
        assert result2["inserted"] == 0
        assert result2["duplicates"] == 5

    def test_stats(self, store):
        store.insert(_wrap(_make_cve(), IntelType.CVE))
        store.insert(_wrap(_make_ioc(), IntelType.IOC))
        s = store.stats()
        assert s["total"] == 2
        assert s["by_type"]["cve"] == 1
        assert s["by_type"]["ioc"] == 1

    def test_query_by_source(self, store):
        store.insert(_wrap(_make_cve(), source="nvd"))
        store.insert(_wrap(_make_ioc(), source="otx"))
        results = store.query(source_feed="nvd")
        assert len(results) == 1


# ===================================================================
# Fetcher Tests
# ===================================================================

class TestIntelFetcher:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            IntelFetcher("bad")

    def test_stub_configure(self):
        f = StubFetcher()
        assert f.configured is False
        f.configure(api_key="test-key")
        assert f.configured is True
        assert f.api_key == "test-key"

    def test_stub_fetch(self):
        f = StubFetcher()
        f.configure()
        assert f.fetch() == []

    def test_health_check(self):
        f = StubFetcher()
        assert f.health_check() is True
        f.healthy = False
        assert f.health_check() is False

    def test_record_fetch_stats(self):
        f = StubFetcher()
        f.configure()
        f._items = [_wrap(_make_cve())]
        f.fetch()
        stats = f.get_stats()
        assert stats["total_fetched"] == 1
        assert stats["name"] == "stub-feed"
        assert stats["last_fetch"] is not None

    def test_record_error(self):
        f = StubFetcher()
        f.record_error()
        f.record_error()
        assert f.get_stats()["total_errors"] == 2


# ===================================================================
# Queue Tests
# ===================================================================

class TestIntelQueue:
    def test_put_and_get(self):
        q = IntelQueue()
        item = _wrap(_make_cve())
        assert q.put(item) is True
        assert q.size == 1
        got = q.get()
        assert got.item_id == item.item_id
        assert q.is_empty

    def test_dedup_rejects_same_key(self):
        q = IntelQueue()
        cve = _make_cve("CVE-2024-0001")
        assert q.put(_wrap(cve)) is True
        assert q.put(_wrap(cve)) is False  # same dedup_key
        assert q.size == 1

    def test_fifo_order(self):
        q = IntelQueue()
        items = [_wrap(_make_cve(f"CVE-2024-{i:04d}")) for i in range(3)]
        for it in items:
            q.put(it)
        for i in range(3):
            got = q.get()
            assert got.item_id == items[i].item_id

    def test_get_batch(self):
        q = IntelQueue()
        for i in range(10):
            q.put(_wrap(_make_cve(f"CVE-2024-{i:04d}")))
        batch = q.get_batch(5)
        assert len(batch) == 5
        assert q.size == 5

    def test_get_batch_partial(self):
        q = IntelQueue()
        q.put(_wrap(_make_cve()))
        batch = q.get_batch(100)
        assert len(batch) == 1

    def test_peek_does_not_remove(self):
        q = IntelQueue()
        item = _wrap(_make_cve())
        q.put(item)
        peeked = q.peek()
        assert peeked.item_id == item.item_id
        assert q.size == 1

    def test_peek_empty(self):
        q = IntelQueue()
        assert q.peek() is None

    def test_get_empty(self):
        q = IntelQueue()
        assert q.get() is None

    def test_maxsize_drops_oldest(self):
        q = IntelQueue(maxsize=3)
        items = [_wrap(_make_cve(f"CVE-2024-{i:04d}")) for i in range(5)]
        for it in items:
            q.put(it)
        assert q.size == 3
        # Oldest two should have been dropped
        got = q.get()
        assert got.item_id == items[2].item_id

    def test_put_many(self):
        q = IntelQueue()
        items = [_wrap(_make_cve(f"CVE-2024-{i:04d}")) for i in range(5)]
        result = q.put_many(items)
        assert result["enqueued"] == 5
        assert result["deduped"] == 0

    def test_put_many_with_dups(self):
        q = IntelQueue()
        cve = _make_cve("CVE-2024-0001")
        items = [_wrap(cve) for _ in range(3)]
        result = q.put_many(items)
        assert result["enqueued"] == 1
        assert result["deduped"] == 2

    def test_clear(self):
        q = IntelQueue()
        for i in range(5):
            q.put(_wrap(_make_cve(f"CVE-2024-{i:04d}")))
        count = q.clear()
        assert count == 5
        assert q.is_empty

    def test_clear_dedup_cache(self):
        q = IntelQueue()
        cve = _make_cve()
        q.put(_wrap(cve))
        q.clear()
        # Dedup cache still has the key
        assert q.put(_wrap(cve)) is False
        # Clear cache
        q.clear_dedup_cache()
        # Now it should be accepted
        assert q.put(_wrap(cve)) is True

    def test_stats(self):
        q = IntelQueue(maxsize=100, dedup_window=200)
        cve = _make_cve()
        q.put(_wrap(cve))
        q.put(_wrap(cve))  # deduped
        s = q.stats()
        assert s["current_size"] == 1
        assert s["maxsize"] == 100
        assert s["total_enqueued"] == 1
        assert s["total_deduped"] == 1

    def test_is_full(self):
        q = IntelQueue(maxsize=2)
        assert q.is_full is False
        q.put(_wrap(_make_cve("CVE-2024-0001")))
        q.put(_wrap(_make_cve("CVE-2024-0002")))
        assert q.is_full is True

    def test_dedup_window_eviction(self):
        q = IntelQueue(dedup_window=3)
        # Fill dedup window
        for i in range(5):
            q.put(_wrap(_make_cve(f"CVE-2024-{i:04d}")))
        # Oldest keys should have been evicted from dedup cache
        # Re-inserting CVE-2024-0000 should succeed (evicted from window)
        q.clear()
        result = q.put(_wrap(_make_cve("CVE-2024-0000")))
        assert result is True  # key was evicted from dedup window

    def test_thread_safety(self):
        q = IntelQueue(maxsize=1000)
        errors = []

        def producer(start, count):
            try:
                for i in range(count):
                    q.put(_wrap(_make_cve(f"CVE-2024-{start + i:06d}")))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=producer, args=(i * 100, 100))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert q.size <= 1000  # bounded by maxsize
        assert q.stats()["total_enqueued"] > 0


# ===================================================================
# Integration: Queue -> Store pipeline
# ===================================================================

class TestQueueStorePipeline:
    def test_drain_queue_to_store(self, tmp_path):
        db = tmp_path / "pipeline.db"
        store = IntelStore(str(db))
        q = IntelQueue()

        # Enqueue items
        for i in range(10):
            q.put(_wrap(_make_cve(f"CVE-2024-{i:04d}")))

        # Drain into store
        inserted = 0
        while not q.is_empty:
            batch = q.get_batch(5)
            result = store.bulk_insert(batch)
            inserted += result["inserted"]

        assert inserted == 10
        assert store.count() == 10
        store.close()

    def test_dedup_across_queue_and_store(self, tmp_path):
        db = tmp_path / "dedup.db"
        store = IntelStore(str(db))
        q = IntelQueue()

        cve = _make_cve("CVE-2024-DUPE")
        item = _wrap(cve)

        # Insert into store first
        store.insert(item)

        # Queue same item
        q.put(_wrap(cve))
        batch = q.get_batch(10)

        # Store rejects the duplicate
        result = store.bulk_insert(batch)
        assert result["duplicates"] == 1
        assert store.count() == 1
        store.close()
