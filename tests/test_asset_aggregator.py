"""
Tests for T7: Asset Inventory & Event Aggregation.

Covers: Asset model, AssetPlatform/AssetStatus enums, AssetInventory
CRUD and queries, EventCategory mapping, AggregatedEvent, EventAggregator
ingestion/queries/subscriptions/bus-adapter, and cross-module integration.
"""

import threading
import time
from datetime import datetime
from typing import List
from unittest.mock import MagicMock

import pytest

from citadel_archer.intel.assets import (
    Asset,
    AssetInventory,
    AssetPlatform,
    AssetStatus,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventAggregator,
    EventCategory,
    _EVENT_CATEGORY_MAP,
    categorize_event,
)


# ===================================================================
# Helpers
# ===================================================================

def _make_asset(
    name: str = "dev-box",
    platform: AssetPlatform = AssetPlatform.LOCAL,
    hostname: str = "dev-box.local",
    ip: str = "192.168.1.10",
) -> Asset:
    return Asset(
        name=name,
        platform=platform,
        hostname=hostname,
        ip_address=ip,
        os_version="Linux 6.8",
    )


# ===================================================================
# AssetPlatform enum
# ===================================================================

class TestAssetPlatform:
    def test_all_platforms(self):
        assert set(AssetPlatform) == {
            AssetPlatform.LOCAL,
            AssetPlatform.VPS,
            AssetPlatform.WINDOWS,
            AssetPlatform.MAC,
            AssetPlatform.LINUX,
        }

    def test_string_values(self):
        assert AssetPlatform.VPS == "vps"
        assert AssetPlatform.MAC == "macos"


# ===================================================================
# AssetStatus enum
# ===================================================================

class TestAssetStatus:
    def test_all_statuses(self):
        assert set(AssetStatus) == {
            AssetStatus.ONLINE,
            AssetStatus.OFFLINE,
            AssetStatus.PROTECTED,
            AssetStatus.COMPROMISED,
            AssetStatus.UNKNOWN,
        }

    def test_is_healthy(self):
        assert AssetStatus.ONLINE.is_healthy is True
        assert AssetStatus.PROTECTED.is_healthy is True
        assert AssetStatus.OFFLINE.is_healthy is False
        assert AssetStatus.COMPROMISED.is_healthy is False


# ===================================================================
# Asset model
# ===================================================================

class TestAsset:
    def test_defaults(self):
        a = Asset()
        assert a.asset_id  # auto-generated UUID
        assert a.status == AssetStatus.UNKNOWN
        assert a.platform == AssetPlatform.LOCAL
        assert a.guardian_active is False

    def test_custom_fields(self):
        a = _make_asset(name="vps-1", platform=AssetPlatform.VPS)
        assert a.name == "vps-1"
        assert a.platform == AssetPlatform.VPS

    def test_to_dict(self):
        a = _make_asset()
        d = a.to_dict()
        assert d["platform"] == "local"
        assert d["status"] == "unknown"
        assert d["hostname"] == "dev-box.local"

    def test_touch_updates_last_seen(self):
        a = _make_asset()
        old_ts = a.last_seen
        time.sleep(0.01)
        a.touch()
        assert a.last_seen > old_ts

    def test_unique_ids(self):
        a = Asset()
        b = Asset()
        assert a.asset_id != b.asset_id

    def test_tags_and_metadata(self):
        a = Asset(tags=["production", "critical"], metadata={"region": "us-east"})
        assert "production" in a.tags
        assert a.metadata["region"] == "us-east"


# ===================================================================
# AssetInventory
# ===================================================================

class TestAssetInventory:
    def test_register_and_get(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset()
        aid = inv.register(a)
        assert inv.get(aid) is a

    def test_get_nonexistent(self):
        inv = AssetInventory(db_path=None)
        assert inv.get("no-such-id") is None

    def test_count(self):
        inv = AssetInventory(db_path=None)
        assert inv.count == 0
        inv.register(_make_asset(name="a"))
        inv.register(_make_asset(name="b"))
        assert inv.count == 2

    def test_remove(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset()
        inv.register(a)
        assert inv.remove(a.asset_id) is True
        assert inv.get(a.asset_id) is None
        assert inv.count == 0

    def test_remove_nonexistent(self):
        inv = AssetInventory(db_path=None)
        assert inv.remove("no-such") is False

    def test_all(self):
        inv = AssetInventory(db_path=None)
        a1 = _make_asset(name="a")
        a2 = _make_asset(name="b")
        inv.register(a1)
        inv.register(a2)
        names = {a.name for a in inv.all()}
        assert names == {"a", "b"}


class TestAssetStatusManagement:
    def test_set_status(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset()
        inv.register(a)
        assert inv.set_status(a.asset_id, AssetStatus.PROTECTED) is True
        assert inv.get(a.asset_id).status == AssetStatus.PROTECTED

    def test_set_status_nonexistent(self):
        inv = AssetInventory(db_path=None)
        assert inv.set_status("no-such", AssetStatus.OFFLINE) is False

    def test_mark_helpers(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset()
        inv.register(a)

        inv.mark_protected(a.asset_id)
        assert a.status == AssetStatus.PROTECTED

        inv.mark_offline(a.asset_id)
        assert a.status == AssetStatus.OFFLINE

        inv.mark_online(a.asset_id)
        assert a.status == AssetStatus.ONLINE

        inv.mark_compromised(a.asset_id)
        assert a.status == AssetStatus.COMPROMISED

    def test_status_updates_last_seen(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset()
        inv.register(a)
        old_ts = a.last_seen
        time.sleep(0.01)
        inv.mark_protected(a.asset_id)
        assert a.last_seen > old_ts


class TestAssetQueries:
    def test_by_platform(self):
        inv = AssetInventory(db_path=None)
        inv.register(_make_asset(name="a", platform=AssetPlatform.VPS))
        inv.register(_make_asset(name="b", platform=AssetPlatform.LOCAL))
        inv.register(_make_asset(name="c", platform=AssetPlatform.VPS))
        vps = inv.by_platform(AssetPlatform.VPS)
        assert len(vps) == 2
        assert all(a.platform == AssetPlatform.VPS for a in vps)

    def test_by_status(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset(name="a")
        b = _make_asset(name="b")
        inv.register(a)
        inv.register(b)
        inv.mark_online(a.asset_id)
        inv.mark_offline(b.asset_id)
        online = inv.by_status(AssetStatus.ONLINE)
        assert len(online) == 1
        assert online[0].name == "a"

    def test_healthy(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset(name="a")
        b = _make_asset(name="b")
        c = _make_asset(name="c")
        inv.register(a)
        inv.register(b)
        inv.register(c)
        inv.mark_protected(a.asset_id)
        inv.mark_offline(b.asset_id)
        inv.mark_compromised(c.asset_id)
        h = inv.healthy()
        assert len(h) == 1
        assert h[0].name == "a"

    def test_find_by_hostname(self):
        inv = AssetInventory(db_path=None)
        a = _make_asset(hostname="MyServer.local")
        inv.register(a)
        found = inv.find_by_hostname("myserver.local")  # case-insensitive
        assert found is a

    def test_find_by_hostname_not_found(self):
        inv = AssetInventory(db_path=None)
        assert inv.find_by_hostname("nope.local") is None

    def test_stats(self):
        inv = AssetInventory(db_path=None)
        inv.register(_make_asset(platform=AssetPlatform.VPS))
        inv.register(_make_asset(platform=AssetPlatform.VPS))
        inv.register(_make_asset(platform=AssetPlatform.LOCAL))
        s = inv.stats()
        assert s["total"] == 3
        assert s["by_platform"]["vps"] == 2
        assert s["by_platform"]["local"] == 1


# ===================================================================
# EventCategory mapping
# ===================================================================

class TestEventCategory:
    def test_file_events(self):
        assert categorize_event("file.created") == EventCategory.FILE
        assert categorize_event("file.modified") == EventCategory.FILE
        assert categorize_event("file.deleted") == EventCategory.FILE
        assert categorize_event("file.quarantined") == EventCategory.FILE

    def test_process_events(self):
        assert categorize_event("process.started") == EventCategory.PROCESS
        assert categorize_event("process.killed") == EventCategory.PROCESS
        assert categorize_event("process.suspicious") == EventCategory.PROCESS

    def test_network_events(self):
        assert categorize_event("network.connection") == EventCategory.NETWORK
        assert categorize_event("network.blocked") == EventCategory.NETWORK

    def test_vault_events(self):
        assert categorize_event("vault.unlocked") == EventCategory.VAULT
        assert categorize_event("vault.password.added") == EventCategory.VAULT

    def test_ai_events(self):
        assert categorize_event("ai.decision") == EventCategory.AI
        assert categorize_event("ai.alert") == EventCategory.AI

    def test_system_events(self):
        assert categorize_event("system.start") == EventCategory.SYSTEM
        assert categorize_event("security.level.changed") == EventCategory.SYSTEM

    def test_user_events(self):
        assert categorize_event("user.login") == EventCategory.USER

    def test_unknown_defaults_to_system(self):
        assert categorize_event("unknown.something") == EventCategory.SYSTEM

    def test_all_core_event_types_mapped(self):
        """Every entry in the map should resolve to a valid category."""
        for event_type, category in _EVENT_CATEGORY_MAP.items():
            assert isinstance(category, EventCategory)


# ===================================================================
# AggregatedEvent
# ===================================================================

class TestAggregatedEvent:
    def test_defaults(self):
        e = AggregatedEvent()
        assert e.event_id  # auto UUID
        assert e.category == EventCategory.SYSTEM
        assert e.severity == "info"

    def test_to_dict(self):
        e = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            severity="alert",
            asset_id="asset-1",
            message="suspicious file change",
        )
        d = e.to_dict()
        assert d["category"] == "file"
        assert d["asset_id"] == "asset-1"
        assert d["event_type"] == "file.modified"


# ===================================================================
# EventAggregator ingestion
# ===================================================================

class TestEventAggregatorIngestion:
    def test_ingest_basic(self):
        agg = EventAggregator()
        evt = agg.ingest("file.created", severity="info", message="new file")
        assert evt.event_type == "file.created"
        assert evt.category == EventCategory.FILE
        assert agg.size == 1

    def test_ingest_with_asset(self):
        agg = EventAggregator()
        agg.ingest("process.started", asset_id="a1")
        events = agg.by_asset("a1")
        assert len(events) == 1

    def test_ingest_with_details(self):
        agg = EventAggregator()
        evt = agg.ingest(
            "file.modified",
            details={"path": "/etc/passwd", "change_type": "modified"},
        )
        assert evt.details["path"] == "/etc/passwd"

    def test_ingest_custom_timestamp(self):
        agg = EventAggregator()
        ts = "2024-01-15T10:30:00"
        evt = agg.ingest("system.start", timestamp=ts)
        assert evt.timestamp == ts

    def test_max_history_bounded(self):
        agg = EventAggregator(max_history=5)
        for i in range(10):
            agg.ingest(f"file.created", message=f"event-{i}")
        assert agg.size == 5
        # Oldest events should be evicted
        events = agg.recent(10)
        assert events[0].message == "event-5"

    def test_ingest_bus_event(self):
        agg = EventAggregator()
        bus_data = {
            "event_type": "process.suspicious",
            "severity": "alert",
            "asset_id": "vps-1",
            "message": "crypto miner detected",
            "details": {"pid": 1234, "name": "xmrig"},
            "timestamp": "2024-06-01T12:00:00",
        }
        evt = agg.ingest_bus_event(bus_data)
        assert evt.event_type == "process.suspicious"
        assert evt.category == EventCategory.PROCESS
        assert evt.asset_id == "vps-1"
        assert evt.details["pid"] == 1234

    def test_ingest_bus_event_fallback_key(self):
        """Bus events may use 'event' instead of 'event_type'."""
        agg = EventAggregator()
        evt = agg.ingest_bus_event({"event": "vault.locked"})
        assert evt.event_type == "vault.locked"
        assert evt.category == EventCategory.VAULT


# ===================================================================
# EventAggregator queries
# ===================================================================

class TestEventAggregatorQueries:
    def _populated(self) -> EventAggregator:
        agg = EventAggregator()
        agg.ingest("file.created", severity="info", asset_id="a1",
                    timestamp="2024-01-01T01:00:00")
        agg.ingest("file.modified", severity="alert", asset_id="a1",
                    timestamp="2024-01-01T02:00:00")
        agg.ingest("process.started", severity="info", asset_id="a2",
                    timestamp="2024-01-01T03:00:00")
        agg.ingest("vault.unlocked", severity="info", asset_id="a1",
                    timestamp="2024-01-01T04:00:00")
        agg.ingest("network.blocked", severity="critical", asset_id="a2",
                    timestamp="2024-01-01T05:00:00")
        return agg

    def test_recent(self):
        agg = self._populated()
        r = agg.recent(3)
        assert len(r) == 3
        assert r[-1].event_type == "network.blocked"

    def test_by_category(self):
        agg = self._populated()
        file_events = agg.by_category(EventCategory.FILE)
        assert len(file_events) == 2

    def test_by_asset(self):
        agg = self._populated()
        a1_events = agg.by_asset("a1")
        assert len(a1_events) == 3  # file.created, file.modified, vault.unlocked

    def test_by_severity(self):
        agg = self._populated()
        alerts = agg.by_severity("alert")
        assert len(alerts) == 1
        assert alerts[0].event_type == "file.modified"

    def test_by_event_type(self):
        agg = self._populated()
        results = agg.by_event_type("vault.unlocked")
        assert len(results) == 1

    def test_since(self):
        agg = self._populated()
        results = agg.since("2024-01-01T03:00:00")
        assert len(results) == 3

    def test_for_asset_by_category(self):
        agg = self._populated()
        results = agg.for_asset_by_category("a1", EventCategory.FILE)
        assert len(results) == 2

    def test_for_asset_by_category_empty(self):
        agg = self._populated()
        results = agg.for_asset_by_category("a2", EventCategory.VAULT)
        assert len(results) == 0


# ===================================================================
# Subscriptions
# ===================================================================

class TestSubscriptions:
    def test_subscriber_called(self):
        agg = EventAggregator()
        received: List[AggregatedEvent] = []
        agg.subscribe(lambda evt: received.append(evt))
        agg.ingest("file.created")
        assert len(received) == 1
        assert received[0].event_type == "file.created"

    def test_multiple_subscribers(self):
        agg = EventAggregator()
        count_a = {"n": 0}
        count_b = {"n": 0}
        agg.subscribe(lambda evt: count_a.__setitem__("n", count_a["n"] + 1))
        agg.subscribe(lambda evt: count_b.__setitem__("n", count_b["n"] + 1))
        agg.ingest("file.created")
        assert count_a["n"] == 1
        assert count_b["n"] == 1

    def test_subscriber_exception_ignored(self):
        agg = EventAggregator()
        agg.subscribe(lambda evt: 1 / 0)  # ZeroDivisionError
        # Should not raise
        agg.ingest("file.created")
        assert agg.size == 1


# ===================================================================
# Stats & clear
# ===================================================================

class TestStatsAndClear:
    def test_stats(self):
        agg = EventAggregator(max_history=100)
        agg.ingest("file.created", asset_id="a1")
        agg.ingest("file.modified", asset_id="a1")
        agg.ingest("process.started", asset_id="a2")
        s = agg.stats()
        assert s["total_received"] == 3
        assert s["current_size"] == 3
        assert s["by_category"]["file"] == 2
        assert s["by_category"]["process"] == 1
        assert s["by_asset"]["a1"] == 2
        assert s["by_asset"]["a2"] == 1

    def test_clear(self):
        agg = EventAggregator()
        agg.ingest("file.created")
        agg.ingest("file.modified")
        count = agg.clear()
        assert count == 2
        assert agg.size == 0

    def test_stats_persist_after_clear(self):
        agg = EventAggregator()
        agg.ingest("file.created")
        agg.clear()
        s = agg.stats()
        # total_received is lifetime, not reset by clear
        assert s["total_received"] == 1
        assert s["current_size"] == 0


# ===================================================================
# Thread safety
# ===================================================================

class TestThreadSafety:
    def test_concurrent_ingest(self):
        agg = EventAggregator(max_history=5000)
        errors = []

        def producer(start, count):
            try:
                for i in range(count):
                    agg.ingest(
                        "file.created",
                        asset_id=f"asset-{start}",
                        message=f"event-{start}-{i}",
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=producer, args=(i, 100))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert agg.stats()["total_received"] == 400

    def test_concurrent_inventory_ops(self):
        inv = AssetInventory(db_path=None)
        errors = []

        def worker(idx):
            try:
                a = _make_asset(name=f"asset-{idx}", hostname=f"host-{idx}.local")
                inv.register(a)
                inv.mark_protected(a.asset_id)
                inv.by_platform(AssetPlatform.LOCAL)
                inv.mark_online(a.asset_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert inv.count == 10


# ===================================================================
# Integration: Asset + EventAggregator
# ===================================================================

class TestAssetEventIntegration:
    def test_events_attributed_to_asset(self):
        inv = AssetInventory(db_path=None)
        agg = EventAggregator()

        vps = _make_asset(name="prod-vps", platform=AssetPlatform.VPS)
        inv.register(vps)
        inv.mark_protected(vps.asset_id)

        # Simulate guardian events on this asset
        agg.ingest("file.modified", asset_id=vps.asset_id,
                    severity="alert", details={"path": "/etc/passwd"})
        agg.ingest("process.suspicious", asset_id=vps.asset_id,
                    severity="critical", details={"pid": 666, "name": "xmrig"})

        # Query events for this asset
        asset_events = agg.by_asset(vps.asset_id)
        assert len(asset_events) == 2

        file_events = agg.for_asset_by_category(vps.asset_id, EventCategory.FILE)
        assert len(file_events) == 1

        proc_events = agg.for_asset_by_category(vps.asset_id, EventCategory.PROCESS)
        assert len(proc_events) == 1

    def test_auto_compromise_on_critical_event(self):
        """Demonstrate marking asset compromised based on aggregated events."""
        inv = AssetInventory(db_path=None)
        agg = EventAggregator()

        workstation = _make_asset(name="dev-ws", platform=AssetPlatform.WINDOWS)
        inv.register(workstation)
        inv.mark_protected(workstation.asset_id)

        # Subscribe: if a critical process event arrives, mark compromised
        def auto_respond(evt: AggregatedEvent):
            if (evt.severity == "critical"
                    and evt.category == EventCategory.PROCESS
                    and evt.asset_id):
                inv.mark_compromised(evt.asset_id)

        agg.subscribe(auto_respond)

        agg.ingest("process.suspicious", severity="critical",
                    asset_id=workstation.asset_id,
                    details={"name": "mimikatz"})

        assert inv.get(workstation.asset_id).status == AssetStatus.COMPROMISED

    def test_multi_asset_event_separation(self):
        inv = AssetInventory(db_path=None)
        agg = EventAggregator()

        a1 = _make_asset(name="vps-1", platform=AssetPlatform.VPS)
        a2 = _make_asset(name="vps-2", platform=AssetPlatform.VPS)
        inv.register(a1)
        inv.register(a2)

        agg.ingest("file.created", asset_id=a1.asset_id)
        agg.ingest("file.created", asset_id=a1.asset_id)
        agg.ingest("file.created", asset_id=a2.asset_id)

        assert len(agg.by_asset(a1.asset_id)) == 2
        assert len(agg.by_asset(a2.asset_id)) == 1
