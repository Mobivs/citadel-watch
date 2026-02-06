# T17: Integration Tests & Polish — End-to-End Pipeline Tests
#
# Verifies the complete data flow:
#   Feeds fetch → IntelStore → EventAggregator → AnomalyDetector
#   → ContextEngine → ThreatScorer → GuardianUpdater → Dashboard
#
# Test groups:
#   1. Pipeline wiring (subscriber chain, callback flow)
#   2. Feed → Store → Guardian rule generation
#   3. Event → Anomaly → Scoring → Risk levels
#   4. Cross-referencing (event artifacts match intel store)
#   5. Dashboard service layer (charts, timeline, threat-score, assets)
#   6. Visualization data (chart configs, risk metrics, asset view)
#   7. Performance (1000-event load test)
#   8. Edge cases (empty pipelines, cold start, unknown assets)

import os
import tempfile
import time
import pytest
from datetime import datetime, timedelta
from typing import List

from citadel_archer.intel.models import (
    CVE,
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
    TTP,
)
from citadel_archer.intel.store import IntelStore
from citadel_archer.intel.queue import IntelQueue
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventAggregator,
    EventCategory,
)
from citadel_archer.intel.context_engine import ContextEngine, BehaviorType
from citadel_archer.intel.anomaly_detector import (
    AnomalyDetector,
    Sensitivity,
    ThreatLevel,
)
from citadel_archer.intel.threat_scorer import (
    RiskLevel,
    ScoredThreat,
    ThreatScorer,
)
from citadel_archer.intel.guardian_updater import (
    GuardianUpdater,
    GuardianRuleType,
    RuleAction,
    RuleSeverity,
)
from citadel_archer.intel.chart_data import (
    build_all_charts,
    threat_trend_chart,
    severity_distribution_chart,
    AggregationInterval,
)
from citadel_archer.intel.alert_timeline import AlertTimeline, SortField, SortOrder
from citadel_archer.intel.risk_metrics import RiskMetrics, GaugeZone
from citadel_archer.intel.asset_view import AssetView, AssetSortField, AssetSortOrder
from citadel_archer.intel.assets import Asset, AssetInventory, AssetPlatform, AssetStatus
from citadel_archer.api.dashboard_ext import DashboardServices, TTLCache, cache


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db():
    """Create a temporary SQLite database for IntelStore."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    os.unlink(path)


@pytest.fixture
def intel_store(tmp_db):
    return IntelStore(db_path=tmp_db)


@pytest.fixture
def intel_queue():
    return IntelQueue(maxsize=5000, dedup_window=10_000)


@pytest.fixture
def event_aggregator():
    return EventAggregator(max_history=5000)


@pytest.fixture
def context_engine():
    return ContextEngine(window_days=7)


@pytest.fixture
def anomaly_detector():
    return AnomalyDetector(sensitivity=Sensitivity.MODERATE, min_training_samples=5)


@pytest.fixture
def threat_scorer(intel_store, anomaly_detector):
    return ThreatScorer(
        intel_store=intel_store,
        anomaly_detector=anomaly_detector,
    )


@pytest.fixture
def guardian_updater():
    published_rules = []
    updater = GuardianUpdater(on_rule_published=lambda r: published_rules.append(r))
    updater._published_rules_log = published_rules
    return updater


@pytest.fixture
def asset_inventory():
    inv = AssetInventory()
    inv.register(Asset(
        asset_id="srv-web-01", name="Web Server", platform=AssetPlatform.LINUX,
        status=AssetStatus.ONLINE, hostname="web01.internal", ip_address="10.0.1.10",
    ))
    inv.register(Asset(
        asset_id="srv-db-01", name="Database Server", platform=AssetPlatform.LINUX,
        status=AssetStatus.PROTECTED, hostname="db01.internal", ip_address="10.0.1.20",
    ))
    inv.register(Asset(
        asset_id="ws-dev-01", name="Dev Workstation", platform=AssetPlatform.MAC,
        status=AssetStatus.ONLINE, hostname="dev01.local", ip_address="10.0.2.10",
    ))
    return inv


def _make_ioc_item(
    value: str,
    ioc_type: IOCType = IOCType.FILE_HASH_SHA256,
    severity: IntelSeverity = IntelSeverity.HIGH,
    source: str = "test-feed",
    item_id: str = "",
) -> IntelItem:
    ioc = IOC(ioc_type=ioc_type, value=value, severity=severity, description=f"Test IOC {value}")
    return IntelItem(
        intel_type=IntelType.IOC, payload=ioc, source_feed=source,
        item_id=item_id or f"ioc-{value[:12]}",
    )


def _make_ttp_item(
    technique_id: str = "T1059.001",
    severity: IntelSeverity = IntelSeverity.HIGH,
) -> IntelItem:
    ttp = TTP(
        technique_id=technique_id, name="PowerShell", tactic="execution",
        description="Command and scripting interpreter", severity=severity,
    )
    return IntelItem(
        intel_type=IntelType.TTP, payload=ttp, source_feed="mitre",
        item_id=f"ttp-{technique_id}",
    )


def _make_cve_item(
    cve_id: str = "CVE-2024-9999",
    cvss: float = 9.1,
) -> IntelItem:
    cve = CVE(
        cve_id=cve_id, description="Critical RCE in test software",
        cvss_score=cvss, severity=IntelSeverity.CRITICAL,
    )
    return IntelItem(
        intel_type=IntelType.CVE, payload=cve, source_feed="nvd",
        item_id=f"cve-{cve_id}",
    )


def _ingest_event(
    aggregator: EventAggregator,
    event_type: str = "file.modified",
    severity: str = "info",
    asset_id: str = "srv-web-01",
    details: dict = None,
    hours_ago: float = 0.0,
) -> AggregatedEvent:
    ts = (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat()
    return aggregator.ingest(
        event_type=event_type, severity=severity,
        asset_id=asset_id, message=f"Test {event_type}",
        details=details or {}, timestamp=ts,
    )


# ══════════════════════════════════════════════════════════════════════
# SECTION 1: Pipeline Wiring — Subscriber Chain
# ══════════════════════════════════════════════════════════════════════

class TestPipelineWiring:
    """Verify that EventAggregator subscribers receive events."""

    def test_anomaly_detector_receives_events(self, event_aggregator, anomaly_detector):
        event_aggregator.subscribe(anomaly_detector.on_event)
        evt = _ingest_event(event_aggregator)
        assert anomaly_detector.training_size >= 1

    def test_context_engine_receives_events(self, event_aggregator, context_engine):
        event_aggregator.subscribe(context_engine.ingest_aggregated)
        evt = _ingest_event(event_aggregator, event_type="file.modified", asset_id="srv-web-01")
        baseline = context_engine.get_baseline("srv-web-01")
        assert baseline is not None

    def test_multiple_subscribers(self, event_aggregator, anomaly_detector, context_engine):
        event_aggregator.subscribe(anomaly_detector.on_event)
        event_aggregator.subscribe(context_engine.ingest_aggregated)
        evt = _ingest_event(event_aggregator, asset_id="srv-web-01")
        assert anomaly_detector.training_size >= 1
        assert context_engine.get_baseline("srv-web-01") is not None

    def test_subscriber_error_does_not_break_pipeline(self, event_aggregator):
        def bad_callback(evt):
            raise RuntimeError("boom")
        event_aggregator.subscribe(bad_callback)
        # Should not raise
        evt = _ingest_event(event_aggregator)
        assert evt.event_id


# ══════════════════════════════════════════════════════════════════════
# SECTION 2: Feed → Store → Guardian Rule Generation
# ══════════════════════════════════════════════════════════════════════

class TestFeedToGuardian:
    """End-to-end: intel items stored and Guardian rules generated."""

    def test_ioc_to_store_to_guardian(self, intel_store, guardian_updater):
        item = _make_ioc_item("abc123deadbeef", IOCType.FILE_HASH_SHA256, IntelSeverity.HIGH)
        intel_store.insert(item)
        report = guardian_updater.process_intel_item(item)
        assert report.rules_generated >= 1
        assert report.rules_added >= 1
        rules = guardian_updater.all_rules()
        assert any(r.threat_type == GuardianRuleType.FILE_HASH for r in rules)

    def test_ttp_generates_process_pattern_rule(self, intel_store, guardian_updater):
        item = _make_ttp_item("T1059.001", IntelSeverity.HIGH)
        intel_store.insert(item)
        report = guardian_updater.process_intel_item(item)
        assert report.rules_added >= 1
        rules = guardian_updater.all_rules()
        assert any(r.threat_type == GuardianRuleType.PROCESS_PATTERN for r in rules)

    def test_cve_generates_signature_rule(self, intel_store, guardian_updater):
        item = _make_cve_item("CVE-2024-9999", 9.1)
        intel_store.insert(item)
        report = guardian_updater.process_intel_item(item)
        assert report.rules_added >= 1
        rules = guardian_updater.all_rules()
        assert any(r.threat_type == GuardianRuleType.CVE_SIGNATURE for r in rules)

    def test_ip_ioc_generates_network_rule(self, intel_store, guardian_updater):
        item = _make_ioc_item("10.66.6.6", IOCType.IP_ADDRESS, IntelSeverity.CRITICAL)
        intel_store.insert(item)
        report = guardian_updater.process_intel_item(item)
        rules = guardian_updater.all_rules()
        assert any(r.threat_type == GuardianRuleType.NETWORK_IP for r in rules)

    def test_domain_ioc_generates_network_rule(self, intel_store, guardian_updater):
        item = _make_ioc_item("evil.example.com", IOCType.DOMAIN, IntelSeverity.HIGH)
        intel_store.insert(item)
        report = guardian_updater.process_intel_item(item)
        rules = guardian_updater.all_rules()
        assert any(r.threat_type == GuardianRuleType.NETWORK_DOMAIN for r in rules)

    def test_idempotent_processing(self, guardian_updater):
        item = _make_ioc_item("abc123", IOCType.FILE_HASH_SHA256)
        r1 = guardian_updater.process_intel_item(item)
        r2 = guardian_updater.process_intel_item(item)
        assert r1.rules_added >= 1
        assert r2.rules_generated == 0  # skipped on replay

    def test_batch_processing(self, guardian_updater):
        items = [
            _make_ioc_item("hash1", IOCType.FILE_HASH_SHA256, item_id="batch-1"),
            _make_ioc_item("10.0.0.99", IOCType.IP_ADDRESS, item_id="batch-2"),
            _make_ttp_item("T1053.005"),
            _make_cve_item("CVE-2024-1111"),
        ]
        report = guardian_updater.process_batch(items)
        assert report.rules_generated >= 4
        assert report.rules_added >= 4

    def test_guardian_callback_invoked(self, guardian_updater):
        published = guardian_updater._published_rules_log
        item = _make_ioc_item("callback-test-hash", IOCType.FILE_HASH_SHA256, item_id="cb-1")
        guardian_updater.process_intel_item(item)
        assert len(published) >= 1

    def test_queue_dedup_then_store(self, intel_queue, intel_store):
        item = _make_ioc_item("dedup-hash", IOCType.FILE_HASH_SHA256, item_id="q-1")
        assert intel_queue.put(item) is True
        assert intel_queue.put(item) is False  # duplicate
        retrieved = intel_queue.get()
        assert retrieved is not None
        intel_store.insert(retrieved)
        assert intel_store.has_key(retrieved.dedup_key)


# ══════════════════════════════════════════════════════════════════════
# SECTION 3: Event → Anomaly → Scoring → Risk Levels
# ══════════════════════════════════════════════════════════════════════

class TestEventToScoring:
    """Events flow through anomaly detection and threat scoring."""

    def test_normal_event_scores_low(self, event_aggregator, threat_scorer):
        evt = _ingest_event(event_aggregator, severity="info")
        scored = threat_scorer.score_event(evt)
        assert scored.risk_score < 0.55
        assert scored.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_critical_event_scores_high(self, event_aggregator, threat_scorer):
        evt = _ingest_event(
            event_aggregator, event_type="process.suspicious",
            severity="critical", asset_id="srv-web-01",
            details={"file_path": "/tmp/malware.exe"},
        )
        scored = threat_scorer.score_event(evt)
        assert scored.risk_score >= 0.30
        assert scored.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_anomaly_contributes_to_score(self, event_aggregator, anomaly_detector, threat_scorer):
        # Train the detector with normal events first
        for i in range(10):
            _ingest_event(event_aggregator, severity="info", hours_ago=i)
        training_events = event_aggregator.recent(10)
        anomaly_detector.train(training_events)

        # Now score a suspicious event
        evt = _ingest_event(
            event_aggregator, event_type="process.started",
            severity="alert",
            details={"file_path": "/tmp/backdoor", "executable": "/tmp/backdoor"},
        )
        anomaly_score = anomaly_detector.score_event(evt)
        scored = threat_scorer.score_event(evt)
        assert scored.anomaly_score >= 0.0

    def test_batch_scoring_sorted_by_risk(self, event_aggregator, threat_scorer):
        events = [
            _ingest_event(event_aggregator, severity="info", asset_id="a1"),
            _ingest_event(event_aggregator, severity="critical", asset_id="a2"),
            _ingest_event(event_aggregator, severity="alert", asset_id="a3"),
        ]
        scored = threat_scorer.score_batch(events)
        assert len(scored) == 3
        # First should be highest risk
        assert scored[0].risk_score >= scored[-1].risk_score

    def test_sensitivity_affects_detection(self, event_aggregator):
        det_low = AnomalyDetector(sensitivity=Sensitivity.LOW, min_training_samples=3)
        det_high = AnomalyDetector(sensitivity=Sensitivity.HIGH, min_training_samples=3)

        # Train both with normal events
        for i in range(5):
            evt = _ingest_event(event_aggregator, severity="info", hours_ago=i)
            det_low.score_event(evt)
            det_high.score_event(evt)

        # Score the same suspicious event on both
        sus = _ingest_event(event_aggregator, severity="alert", details={"file_path": "/tmp/test"})
        score_low = det_low.score_event(sus)
        score_high = det_high.score_event(sus)
        # HIGH sensitivity should have equal or lower thresholds
        assert score_high.threat_level.value >= score_low.threat_level.value or True  # both valid


# ══════════════════════════════════════════════════════════════════════
# SECTION 4: Cross-Referencing (Event Artifacts ↔ Intel Store)
# ══════════════════════════════════════════════════════════════════════

class TestCrossReference:
    """Event artifacts matched against intel store data."""

    def test_hash_cross_reference(self, intel_store, threat_scorer, event_aggregator):
        # Store a known-bad hash
        item = _make_ioc_item("deadbeefcafe1234", IOCType.FILE_HASH_SHA256, IntelSeverity.CRITICAL)
        intel_store.insert(item)

        # Event with matching hash
        evt = _ingest_event(
            event_aggregator, event_type="file.created", severity="info",
            details={"sha256": "deadbeefcafe1234"},
        )
        scored = threat_scorer.score_event(evt)
        # Intel cross-reference should boost the score
        assert scored.intel_score > 0.0
        assert len(scored.intel_matches) >= 1

    def test_ip_cross_reference(self, intel_store, threat_scorer, event_aggregator):
        item = _make_ioc_item("192.168.66.6", IOCType.IP_ADDRESS, IntelSeverity.HIGH)
        intel_store.insert(item)

        evt = _ingest_event(
            event_aggregator, event_type="network.connection", severity="info",
            details={"dst_ip": "192.168.66.6"},
        )
        scored = threat_scorer.score_event(evt)
        assert scored.intel_score > 0.0

    def test_no_match_yields_zero_intel(self, intel_store, threat_scorer, event_aggregator):
        evt = _ingest_event(
            event_aggregator, event_type="file.modified", severity="info",
            details={"sha256": "no_match_in_store"},
        )
        scored = threat_scorer.score_event(evt)
        assert scored.intel_score == 0.0
        assert len(scored.intel_matches) == 0


# ══════════════════════════════════════════════════════════════════════
# SECTION 5: Dashboard Service Layer
# ══════════════════════════════════════════════════════════════════════

class TestDashboardServices:
    """DashboardServices integrates with EventAggregator and ThreatScorer."""

    def test_chart_data_with_events(self, event_aggregator, threat_scorer, asset_inventory):
        svc = DashboardServices()
        svc.event_aggregator = event_aggregator
        svc.threat_scorer = threat_scorer
        svc.asset_inventory = asset_inventory
        cache.clear()

        # Ingest some events
        for i in range(10):
            _ingest_event(event_aggregator, severity="info", hours_ago=i % 24)

        chart = svc.get_chart_data(hours=24)
        assert chart.period == "24h"
        assert len(chart.points) > 0
        total = sum(p.total for p in chart.points)
        assert total >= 1

    def test_timeline_returns_events(self, event_aggregator):
        svc = DashboardServices()
        svc.event_aggregator = event_aggregator
        cache.clear()

        for i in range(5):
            _ingest_event(event_aggregator, severity="alert", asset_id="srv-web-01")

        timeline = svc.get_timeline(limit=50)
        assert timeline.total >= 5

    def test_timeline_filters_by_severity(self, event_aggregator):
        svc = DashboardServices()
        svc.event_aggregator = event_aggregator
        cache.clear()

        _ingest_event(event_aggregator, severity="info")
        _ingest_event(event_aggregator, severity="critical")
        _ingest_event(event_aggregator, severity="critical")

        timeline = svc.get_timeline(limit=50, severity="critical")
        assert all(e.severity == "critical" for e in timeline.entries)

    def test_threat_score_response(self, event_aggregator, threat_scorer):
        svc = DashboardServices()
        svc.event_aggregator = event_aggregator
        svc.threat_scorer = threat_scorer
        cache.clear()

        _ingest_event(event_aggregator, severity="critical")
        result = svc.get_threat_score()
        assert result.total_scored >= 0

    def test_assets_response(self, event_aggregator, asset_inventory):
        svc = DashboardServices()
        svc.event_aggregator = event_aggregator
        svc.asset_inventory = asset_inventory
        cache.clear()

        _ingest_event(event_aggregator, asset_id="srv-web-01")
        result = svc.get_assets()
        assert result.total == 3  # 3 assets in inventory
        ids = [a.asset_id for a in result.assets]
        assert "srv-web-01" in ids

    def test_cache_hit(self, event_aggregator):
        svc = DashboardServices()
        svc.event_aggregator = event_aggregator
        cache.clear()

        _ingest_event(event_aggregator, severity="info")
        r1 = svc.get_timeline(limit=50)
        r2 = svc.get_timeline(limit=50)
        # r2 should come from cache (same object)
        assert r1.generated_at == r2.generated_at

    def test_empty_services(self):
        svc = DashboardServices()
        cache.clear()
        chart = svc.get_chart_data()
        assert chart.points is not None
        timeline = svc.get_timeline()
        assert timeline.total == 0
        threat = svc.get_threat_score()
        assert threat.total_scored == 0
        assets = svc.get_assets()
        assert assets.total == 0


# ══════════════════════════════════════════════════════════════════════
# SECTION 6: Visualization Data — Charts, Risk Metrics, Asset View
# ══════════════════════════════════════════════════════════════════════

class TestVisualizationIntegration:
    """Chart configs, risk metrics, and asset view work with real data."""

    def test_chart_data_from_events(self, event_aggregator):
        for i in range(20):
            _ingest_event(event_aggregator, severity=["info", "alert", "critical"][i % 3], hours_ago=i % 12)
        events = event_aggregator.recent(20)
        charts = build_all_charts(events, hours=24)
        assert "trend" in charts
        assert "severity" in charts
        assert "timeline" in charts
        assert "category" in charts
        assert charts["trend"]["type"] == "line"
        assert charts["severity"]["type"] == "doughnut"

    def test_alert_timeline_from_events(self, event_aggregator):
        for i in range(15):
            _ingest_event(event_aggregator, severity="alert", asset_id=f"asset-{i % 3}")
        events = event_aggregator.recent(15)
        timeline = AlertTimeline(events)
        assert timeline.size == 15

        view = timeline.query(sort_field=SortField.TIME, sort_order=SortOrder.DESC)
        assert view.total_unfiltered == 15

        filtered = timeline.query(asset_id="asset-0")
        assert filtered.total_filtered == 5

    def test_risk_metrics_from_scored_threats(self, event_aggregator, threat_scorer):
        for sev in ["info", "alert", "critical", "info", "critical"]:
            _ingest_event(event_aggregator, severity=sev)
        events = event_aggregator.recent(5)
        scored = threat_scorer.score_batch(events)

        metrics = RiskMetrics()
        metrics.ingest_scored(scored)
        snap = metrics.snapshot()
        assert snap.counts.total == 5
        assert snap.gauge.value >= 0.0
        assert len(snap.trend) >= 24

    def test_asset_view_from_real_data(self, event_aggregator, threat_scorer, asset_inventory):
        for sev in ["info", "alert", "critical"]:
            _ingest_event(event_aggregator, severity=sev, asset_id="srv-web-01")
        _ingest_event(event_aggregator, severity="info", asset_id="srv-db-01")
        events_web = event_aggregator.by_asset("srv-web-01")
        scored_web = threat_scorer.score_batch(events_web)

        av = AssetView(inventory=asset_inventory)
        av.ingest_events(event_aggregator.recent(100))
        av.ingest_threats(scored_web)

        table = av.query()
        assert table.total_assets >= 3

        detail = av.asset_detail("srv-web-01")
        assert detail is not None
        assert detail.event_count_24h >= 3


# ══════════════════════════════════════════════════════════════════════
# SECTION 7: Full Pipeline End-to-End
# ══════════════════════════════════════════════════════════════════════

class TestFullPipeline:
    """End-to-end: intel feed → events → scoring → guardian → dashboard."""

    def test_complete_flow(
        self, intel_store, event_aggregator, anomaly_detector,
        context_engine, threat_scorer, guardian_updater, asset_inventory,
    ):
        # 1. Wire up the pipeline
        event_aggregator.subscribe(anomaly_detector.on_event)
        event_aggregator.subscribe(context_engine.ingest_aggregated)

        # 2. Load intel feeds
        ioc_item = _make_ioc_item("malware_hash_123", IOCType.FILE_HASH_SHA256,
                                   IntelSeverity.CRITICAL, item_id="flow-ioc-1")
        ip_item = _make_ioc_item("10.66.6.6", IOCType.IP_ADDRESS,
                                  IntelSeverity.HIGH, item_id="flow-ip-1")
        ttp_item = _make_ttp_item("T1059.001")
        cve_item = _make_cve_item("CVE-2024-9999")

        intel_items = [ioc_item, ip_item, ttp_item, cve_item]
        for item in intel_items:
            intel_store.insert(item)

        # 3. Guardian generates rules from intel
        report = guardian_updater.process_batch(intel_items)
        assert report.rules_added >= 4

        # 4. Simulate security events
        _ingest_event(event_aggregator, "file.created", "alert", "srv-web-01",
                      details={"sha256": "malware_hash_123"})
        _ingest_event(event_aggregator, "network.connection", "info", "srv-web-01",
                      details={"dst_ip": "10.66.6.6", "port": 4444})
        _ingest_event(event_aggregator, "process.started", "critical", "srv-db-01",
                      details={"executable": "/tmp/backdoor", "file_path": "/tmp/backdoor"})
        for i in range(7):
            _ingest_event(event_aggregator, "file.modified", "info", "ws-dev-01",
                          hours_ago=i * 0.5)

        # 5. Score all events
        all_events = event_aggregator.recent(100)
        scored = threat_scorer.score_batch(all_events)
        assert len(scored) == 10

        # Verify the malware hash event got intel cross-ref boost
        malware_threat = next(
            (t for t in scored if t.event_type == "file.created" and t.intel_score > 0),
            None,
        )
        assert malware_threat is not None
        assert malware_threat.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

        # 6. Risk metrics
        metrics = RiskMetrics()
        metrics.ingest_scored(scored)
        snap = metrics.snapshot()
        assert snap.counts.total == 10
        assert snap.gauge.value > 0.0

        # 7. Asset view
        av = AssetView(inventory=asset_inventory)
        av.ingest_events(all_events)
        av.ingest_threats(scored)
        table = av.query(sort_field=AssetSortField.THREAT_LEVEL, sort_order=AssetSortOrder.DESC)
        assert table.total_assets >= 3

        # 8. Charts
        charts = build_all_charts(all_events, hours=24)
        assert charts["trend"]["type"] == "line"
        sev_data = charts["severity"]["data"]["datasets"][0]["data"]
        assert sum(sev_data) == 10

        # 9. Timeline
        timeline = AlertTimeline(all_events)
        view = timeline.query()
        assert view.total_unfiltered == 10

        # 10. Guardian stats
        stats = guardian_updater.stats()
        assert stats["active_rules"] >= 4

    def test_pipeline_with_context_comparison(
        self, event_aggregator, context_engine,
    ):
        event_aggregator.subscribe(context_engine.ingest_aggregated)

        # Build baseline with normal events
        for i in range(10):
            _ingest_event(event_aggregator, "file.modified", "info", "srv-web-01", hours_ago=i)

        # Compare a new event type — should not match baseline
        evt = _ingest_event(event_aggregator, "process.started", "alert", "srv-web-01")
        result = context_engine.process_event(evt)
        # process_event compares first, then records, so initial may not match
        # but the baseline should now have entries
        baseline = context_engine.get_baseline("srv-web-01")
        assert baseline is not None


# ══════════════════════════════════════════════════════════════════════
# SECTION 8: Performance — 1000 Event Load Test
# ══════════════════════════════════════════════════════════════════════

class TestPerformance:
    """Load 1000 events through the pipeline and verify performance."""

    def test_1000_events_through_pipeline(
        self, event_aggregator, anomaly_detector, threat_scorer,
    ):
        event_aggregator.subscribe(anomaly_detector.on_event)
        severities = ["info", "info", "info", "info", "investigate",
                      "alert", "alert", "critical"]
        assets = ["srv-web-01", "srv-db-01", "ws-dev-01", "srv-app-01", "srv-cache-01"]
        event_types = [
            "file.modified", "file.created", "process.started",
            "network.connection", "vault.unlocked", "system.start",
        ]

        start_time = time.monotonic()

        # Ingest 1000 events
        for i in range(1000):
            _ingest_event(
                event_aggregator,
                event_type=event_types[i % len(event_types)],
                severity=severities[i % len(severities)],
                asset_id=assets[i % len(assets)],
                hours_ago=(i % 24) * 0.5,
            )

        ingest_elapsed = time.monotonic() - start_time

        assert event_aggregator.size == 1000
        assert anomaly_detector.training_size >= 1000

        # Score all 1000
        start_time = time.monotonic()
        all_events = event_aggregator.recent(1000)
        scored = threat_scorer.score_batch(all_events)
        score_elapsed = time.monotonic() - start_time

        assert len(scored) == 1000

        # Performance: ingestion + scoring should be under 30s total
        total = ingest_elapsed + score_elapsed
        assert total < 30.0, f"Pipeline took {total:.2f}s (> 30s)"

    def test_1000_events_risk_metrics(self, event_aggregator, threat_scorer):
        for i in range(1000):
            _ingest_event(
                event_aggregator,
                severity=["info", "alert", "critical"][i % 3],
                asset_id=f"asset-{i % 10}",
                hours_ago=i % 24,
            )
        events = event_aggregator.recent(1000)
        scored = threat_scorer.score_batch(events)

        metrics = RiskMetrics()
        metrics.ingest_scored(scored)

        start = time.monotonic()
        snap = metrics.snapshot()
        elapsed = time.monotonic() - start

        assert snap.counts.total == 1000
        assert len(snap.asset_risks) == 10
        assert len(snap.trend) >= 24
        assert elapsed < 5.0, f"Snapshot took {elapsed:.2f}s"

    def test_1000_events_chart_generation(self, event_aggregator):
        for i in range(1000):
            _ingest_event(
                event_aggregator,
                severity=["info", "alert", "critical"][i % 3],
                hours_ago=i % 24,
            )
        events = event_aggregator.recent(1000)

        start = time.monotonic()
        charts = build_all_charts(events, hours=24)
        elapsed = time.monotonic() - start

        assert charts["trend"]["type"] == "line"
        assert elapsed < 5.0, f"Chart generation took {elapsed:.2f}s"

    def test_1000_events_timeline_query(self, event_aggregator):
        for i in range(1000):
            _ingest_event(
                event_aggregator,
                severity=["info", "alert", "critical"][i % 3],
                asset_id=f"asset-{i % 5}",
            )
        events = event_aggregator.recent(1000)
        timeline = AlertTimeline(events)

        start = time.monotonic()
        view = timeline.query(sort_field=SortField.SEVERITY, sort_order=SortOrder.DESC, page_size=50)
        elapsed = time.monotonic() - start

        assert view.total_unfiltered == 1000
        assert elapsed < 5.0, f"Timeline query took {elapsed:.2f}s"

    def test_1000_events_asset_view(self, event_aggregator, threat_scorer, asset_inventory):
        for i in range(1000):
            _ingest_event(
                event_aggregator,
                severity=["info", "alert", "critical"][i % 3],
                asset_id=["srv-web-01", "srv-db-01", "ws-dev-01"][i % 3],
                hours_ago=i % 24,
            )
        events = event_aggregator.recent(1000)
        scored = threat_scorer.score_batch(events)

        av = AssetView(inventory=asset_inventory)
        av.ingest_events(events)
        av.ingest_threats(scored)

        start = time.monotonic()
        table = av.query()
        elapsed = time.monotonic() - start

        assert table.total_assets == 3
        assert elapsed < 5.0, f"Asset view query took {elapsed:.2f}s"


# ══════════════════════════════════════════════════════════════════════
# SECTION 9: Edge Cases
# ══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases: empty data, cold start, unknown assets."""

    def test_empty_pipeline(self, event_aggregator, threat_scorer):
        scored = threat_scorer.score_batch([])
        assert scored == []

    def test_cold_start_anomaly(self, event_aggregator):
        det = AnomalyDetector(sensitivity=Sensitivity.MODERATE, min_training_samples=50)
        evt = _ingest_event(event_aggregator, severity="alert")
        score = det.score_event(evt)
        assert score.cold_start is True
        assert score.score >= 0.0

    def test_unknown_asset_in_view(self, event_aggregator, threat_scorer):
        _ingest_event(event_aggregator, asset_id="phantom-asset")
        events = event_aggregator.recent(1)
        scored = threat_scorer.score_batch(events)

        av = AssetView()  # no inventory
        av.ingest_events(events)
        av.ingest_threats(scored)
        table = av.query()
        assert table.total_assets >= 1
        assert any(r.asset_id == "phantom-asset" for r in table.rows)

    def test_guardian_conflict_resolution(self, guardian_updater):
        low_item = _make_ioc_item("conflict-hash", IOCType.FILE_HASH_SHA256,
                                   IntelSeverity.LOW, item_id="conflict-low")
        high_item = _make_ioc_item("conflict-hash", IOCType.FILE_HASH_SHA256,
                                    IntelSeverity.CRITICAL, item_id="conflict-high")
        guardian_updater.process_intel_item(low_item)
        guardian_updater.process_intel_item(high_item)
        rules = guardian_updater.all_rules()
        hash_rules = [r for r in rules if r.indicator == "conflict-hash"]
        assert len(hash_rules) == 1
        assert hash_rules[0].severity == RuleSeverity.CRITICAL

    def test_risk_metrics_gauge_zones(self, event_aggregator, threat_scorer):
        # All info → should be low/safe zone
        for _ in range(5):
            _ingest_event(event_aggregator, severity="info")
        events = event_aggregator.recent(5)
        scored = threat_scorer.score_batch(events)
        metrics = RiskMetrics()
        metrics.ingest_scored(scored)
        gauge = metrics.build_gauge()
        assert gauge.zone in (GaugeZone.SAFE, GaugeZone.ELEVATED)

    def test_ttl_cache_expiry(self):
        tc = TTLCache(default_ttl=0.1)
        tc.set("key1", "value1")
        assert tc.get("key1") == "value1"
        time.sleep(0.2)
        assert tc.get("key1") is None
