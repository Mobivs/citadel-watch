# Tests for T10: Threat Scorer (Risk Assessment)
# Covers: RiskLevel, IntelMatch, ScoredThreat, risk matrix,
#          intel cross-referencing, anomaly integration, priority
#          sorting, batch scoring, and stats.

import threading

import pytest

from citadel_archer.intel.anomaly_detector import (
    AnomalyDetector,
    Sensitivity,
    ThreatLevel,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)
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
from citadel_archer.intel.threat_scorer import (
    IntelMatch,
    RiskLevel,
    ScoredThreat,
    ThreatScorer,
    _RISK_THRESHOLDS,
    _SEVERITY_WEIGHT,
)


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def intel_store(tmp_path):
    """IntelStore with a few known IOCs, CVEs, and TTPs."""
    db = tmp_path / "test_intel.db"
    store = IntelStore(str(db))

    # IOC: malicious hash
    store.insert(IntelItem(
        intel_type=IntelType.IOC,
        payload=IOC(
            ioc_type=IOCType.FILE_HASH_SHA256,
            value="abc123deadbeef",
            severity=IntelSeverity.HIGH,
            source="test",
        ),
        source_feed="abuse.ch",
    ))

    # IOC: malicious IP
    store.insert(IntelItem(
        intel_type=IntelType.IOC,
        payload=IOC(
            ioc_type=IOCType.IP_ADDRESS,
            value="10.66.6.6",
            severity=IntelSeverity.CRITICAL,
            source="test",
        ),
        source_feed="otx",
    ))

    # IOC: malicious domain
    store.insert(IntelItem(
        intel_type=IntelType.IOC,
        payload=IOC(
            ioc_type=IOCType.DOMAIN,
            value="evil.example.com",
            severity=IntelSeverity.HIGH,
            source="test",
        ),
        source_feed="otx",
    ))

    # CVE
    store.insert(IntelItem(
        intel_type=IntelType.CVE,
        payload=CVE(
            cve_id="CVE-2024-9999",
            description="Critical RCE",
            cvss_score=9.8,
        ),
        source_feed="nvd",
    ))

    # TTP
    store.insert(IntelItem(
        intel_type=IntelType.TTP,
        payload=TTP(
            technique_id="T1059.001",
            name="PowerShell",
            tactic="execution",
            severity=IntelSeverity.HIGH,
        ),
        source_feed="mitre",
    ))

    yield store
    store.close()


@pytest.fixture
def detector():
    """A minimal AnomalyDetector (cold-start, no sklearn needed)."""
    return AnomalyDetector(min_training_samples=5)


# ── RiskLevel ────────────────────────────────────────────────────────

class TestRiskLevel:
    def test_values(self):
        assert RiskLevel.LOW == "low"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.CRITICAL == "critical"

    def test_ordering(self):
        assert RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH < RiskLevel.CRITICAL


# ── IntelMatch / ScoredThreat ────────────────────────────────────────

class TestDataStructures:
    def test_intel_match_to_dict(self):
        m = IntelMatch(intel_type="ioc", dedup_key="ioc:ip:1.2.3.4",
                       severity="high", payload_summary="IP match")
        d = m.to_dict()
        assert d["intel_type"] == "ioc"
        assert d["severity"] == "high"

    def test_scored_threat_to_dict(self):
        t = ScoredThreat(
            event_id="e1", risk_score=0.85, risk_level=RiskLevel.CRITICAL,
        )
        d = t.to_dict()
        assert d["risk_level"] == "critical"
        assert d["risk_score"] == 0.85

    def test_scored_threat_defaults(self):
        t = ScoredThreat()
        assert t.risk_score == 0.0
        assert t.risk_level == RiskLevel.LOW
        assert t.intel_matches == []


# ── Severity × Confidence (risk matrix) ─────────────────────────────

class TestRiskMatrix:
    def test_info_severity_low_risk(self):
        scorer = ThreatScorer()
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            severity="info",
        )
        result = scorer.score_event(evt)
        assert result.risk_level == RiskLevel.LOW
        assert result.severity_weight == _SEVERITY_WEIGHT["info"]

    def test_critical_severity_boosts_score(self):
        scorer = ThreatScorer()
        evt = AggregatedEvent(
            event_type="process.suspicious",
            category=EventCategory.PROCESS,
            severity="critical",
        )
        result = scorer.score_event(evt)
        assert result.severity_weight == _SEVERITY_WEIGHT["critical"]
        assert result.risk_score > 0.0

    def test_alert_severity_moderate(self):
        scorer = ThreatScorer()
        evt = AggregatedEvent(
            event_type="network.blocked",
            category=EventCategory.NETWORK,
            severity="alert",
        )
        result = scorer.score_event(evt)
        assert result.severity_weight == _SEVERITY_WEIGHT["alert"]


# ── Intel cross-reference ────────────────────────────────────────────

class TestIntelCrossReference:
    def test_hash_match_boosts_score(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            severity="info",
            details={"sha256": "abc123deadbeef"},
        )
        result = scorer.score_event(evt)
        assert len(result.intel_matches) >= 1
        assert any("hash" in m.payload_summary.lower() for m in result.intel_matches)
        assert result.intel_score > 0.0
        assert result.risk_score > scorer._w_severity * _SEVERITY_WEIGHT["info"]

    def test_ip_match(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            severity="info",
            details={"dst_ip": "10.66.6.6"},
        )
        result = scorer.score_event(evt)
        assert any("IP" in m.payload_summary for m in result.intel_matches)
        assert result.intel_score > 0.0

    def test_domain_match(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            severity="info",
            details={"domain": "evil.example.com"},
        )
        result = scorer.score_event(evt)
        assert any("Domain" in m.payload_summary for m in result.intel_matches)

    def test_cve_match(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="system.start",
            category=EventCategory.SYSTEM,
            severity="alert",
            details={"cve_id": "CVE-2024-9999"},
        )
        result = scorer.score_event(evt)
        assert any("CVE" in m.payload_summary for m in result.intel_matches)

    def test_ttp_match(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="process.suspicious",
            category=EventCategory.PROCESS,
            severity="investigate",
            details={"technique_id": "T1059.001"},
        )
        result = scorer.score_event(evt)
        assert any("TTP" in m.payload_summary for m in result.intel_matches)
        assert result.risk_level.value >= RiskLevel.MEDIUM.value

    def test_no_match_no_boost(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            severity="info",
            details={"sha256": "clean_hash_no_match"},
        )
        result = scorer.score_event(evt)
        assert result.intel_score == 0.0

    def test_no_store_no_matches(self):
        scorer = ThreatScorer(intel_store=None)
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            details={"sha256": "anything"},
        )
        result = scorer.score_event(evt)
        assert result.intel_matches == []
        assert result.intel_score == 0.0


# ── Anomaly integration ─────────────────────────────────────────────

class TestAnomalyIntegration:
    def test_with_detector(self, detector):
        scorer = ThreatScorer(anomaly_detector=detector)
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            severity="info",
            details={"process_name": "cron"},
        )
        result = scorer.score_event(evt)
        assert result.anomaly_detail is not None

    def test_without_detector(self):
        scorer = ThreatScorer(anomaly_detector=None)
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            severity="info",
        )
        result = scorer.score_event(evt)
        assert result.anomaly_score == 0.0
        assert result.anomaly_detail is None


# ── Combined scenario ────────────────────────────────────────────────

class TestCombinedScoring:
    def test_hash_match_plus_high_severity_is_critical(self, intel_store):
        """File hash matches malware + HIGH confidence = CRITICAL."""
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            severity="critical",
            details={"sha256": "abc123deadbeef"},
        )
        result = scorer.score_event(evt)
        # severity=critical (1.0) + intel match high → should be CRITICAL
        assert result.risk_level == RiskLevel.CRITICAL

    def test_ttp_match_plus_medium_confidence_is_high(self, intel_store):
        """Process matches MITRE TTP + MEDIUM confidence = HIGH."""
        scorer = ThreatScorer(intel_store=intel_store)
        evt = AggregatedEvent(
            event_type="process.suspicious",
            category=EventCategory.PROCESS,
            severity="alert",
            details={"technique_id": "T1059.001"},
        )
        result = scorer.score_event(evt)
        assert result.risk_level.value >= RiskLevel.HIGH.value


# ── Batch & priority ────────────────────────────────────────────────

class TestBatchAndPriority:
    def test_score_batch_sorted_by_risk(self):
        scorer = ThreatScorer()
        events = [
            AggregatedEvent(event_type="file.created", category=EventCategory.FILE,
                            severity="info"),
            AggregatedEvent(event_type="process.suspicious", category=EventCategory.PROCESS,
                            severity="critical"),
            AggregatedEvent(event_type="network.blocked", category=EventCategory.NETWORK,
                            severity="alert"),
        ]
        results = scorer.score_batch(events)
        assert len(results) == 3
        # Should be sorted highest risk first
        scores = [r.risk_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_prioritised_threats_filters(self, intel_store):
        scorer = ThreatScorer(intel_store=intel_store)
        events = [
            AggregatedEvent(event_type="file.created", category=EventCategory.FILE,
                            severity="info"),
            AggregatedEvent(event_type="file.created", category=EventCategory.FILE,
                            severity="critical",
                            details={"sha256": "abc123deadbeef"}),
        ]
        high_only = scorer.prioritised_threats(events, min_level=RiskLevel.HIGH)
        # Only the critical+intel match event should pass
        assert len(high_only) >= 1
        assert all(
            r.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            for r in high_only
        )

    def test_prioritised_threats_empty_when_all_low(self):
        scorer = ThreatScorer()
        events = [
            AggregatedEvent(event_type="file.created", category=EventCategory.FILE,
                            severity="info"),
        ]
        high_only = scorer.prioritised_threats(events, min_level=RiskLevel.HIGH)
        assert high_only == []


# ── Stats ────────────────────────────────────────────────────────────

class TestThreatScorerStats:
    def test_stats_structure(self, intel_store, detector):
        scorer = ThreatScorer(intel_store=intel_store, anomaly_detector=detector)
        evt = AggregatedEvent(
            event_type="file.created", category=EventCategory.FILE, severity="info",
        )
        scorer.score_event(evt)
        s = scorer.stats()
        assert s["total_scored"] == 1
        assert s["has_intel_store"] is True
        assert s["has_anomaly_detector"] is True
        assert "severity" in s["weights"]


# ── Thread safety ────────────────────────────────────────────────────

class TestThreatScorerThreadSafety:
    def test_concurrent_scoring(self):
        scorer = ThreatScorer()
        errors = []

        def worker():
            try:
                for _ in range(25):
                    evt = AggregatedEvent(
                        event_type="process.started",
                        category=EventCategory.PROCESS,
                        severity="info",
                        details={"process_name": "worker"},
                    )
                    r = scorer.score_event(evt)
                    assert isinstance(r, ScoredThreat)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert scorer.stats()["total_scored"] == 100


# ── Risk level mapping ──────────────────────────────────────────────

class TestRiskLevelMapping:
    def test_low_score(self):
        assert ThreatScorer._map_risk_level(0.1) == RiskLevel.LOW

    def test_medium_score(self):
        assert ThreatScorer._map_risk_level(0.4) == RiskLevel.MEDIUM

    def test_high_score(self):
        assert ThreatScorer._map_risk_level(0.6) == RiskLevel.HIGH

    def test_critical_score(self):
        assert ThreatScorer._map_risk_level(0.9) == RiskLevel.CRITICAL

    def test_boundary_values(self):
        med, high, crit = _RISK_THRESHOLDS
        assert ThreatScorer._map_risk_level(med) == RiskLevel.MEDIUM
        assert ThreatScorer._map_risk_level(high) == RiskLevel.HIGH
        assert ThreatScorer._map_risk_level(crit) == RiskLevel.CRITICAL
        assert ThreatScorer._map_risk_level(med - 0.01) == RiskLevel.LOW
