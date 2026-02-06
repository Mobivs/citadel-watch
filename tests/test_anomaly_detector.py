# Tests for T9: Anomaly Detector (Isolation Forest + Rules)
# Covers: ThreatLevel, Sensitivity, AnomalyScore, DetectionRule,
#          built-in rules, feature extraction, cold start, training,
#          scoring, sensitivity adjustment, and thread safety.

import threading
from datetime import datetime, timedelta

import numpy as np
import pytest

from citadel_archer.intel.anomaly_detector import (
    AnomalyDetector,
    AnomalyScore,
    DetectionRule,
    Sensitivity,
    ThreatLevel,
    _SENSITIVITY_CONTAMINATION,
    _THREAT_THRESHOLDS,
    _default_rules,
    _rule_critical_file_modification,
    _rule_network_high_port,
    _rule_process_from_tmp,
    _rule_suspicious_severity,
    _rule_unsigned_exe_system32,
)
from citadel_archer.intel.event_aggregator import (
    AggregatedEvent,
    EventCategory,
)


# ── ThreatLevel & Sensitivity enums ─────────────────────────────────

class TestThreatLevel:
    def test_values(self):
        assert ThreatLevel.LOW == "low"
        assert ThreatLevel.MEDIUM == "medium"
        assert ThreatLevel.HIGH == "high"

    def test_string_comparison(self):
        assert ThreatLevel.LOW < ThreatLevel.MEDIUM


class TestSensitivity:
    def test_values(self):
        assert Sensitivity.LOW == "low"
        assert Sensitivity.MODERATE == "moderate"
        assert Sensitivity.HIGH == "high"

    def test_contamination_mapping(self):
        assert _SENSITIVITY_CONTAMINATION[Sensitivity.LOW] > _SENSITIVITY_CONTAMINATION[Sensitivity.HIGH]

    def test_threshold_ordering(self):
        # Higher sensitivity → lower thresholds
        low_med, low_high = _THREAT_THRESHOLDS[Sensitivity.LOW]
        high_med, high_high = _THREAT_THRESHOLDS[Sensitivity.HIGH]
        assert high_med < low_med
        assert high_high < low_high


# ── AnomalyScore ─────────────────────────────────────────────────────

class TestAnomalyScore:
    def test_to_dict(self):
        s = AnomalyScore(score=0.75, threat_level=ThreatLevel.HIGH,
                         rule_hits=["R001"], event_key="proc")
        d = s.to_dict()
        assert d["threat_level"] == "high"
        assert d["score"] == 0.75
        assert "R001" in d["rule_hits"]

    def test_defaults(self):
        s = AnomalyScore()
        assert s.score == 0.0
        assert s.threat_level == ThreatLevel.LOW
        assert s.cold_start is False
        assert s.rule_hits == []


# ── DetectionRule ────────────────────────────────────────────────────

class TestDetectionRule:
    def test_to_dict(self):
        r = DetectionRule(rule_id="X1", name="test", score=0.5)
        d = r.to_dict()
        assert d["rule_id"] == "X1"
        assert "evaluate" not in d  # callable excluded

    def test_default_evaluator_returns_false(self):
        r = DetectionRule()
        evt = AggregatedEvent(event_type="any", category=EventCategory.SYSTEM)
        assert r.evaluate(evt) is False


# ── Built-in rules ──────────────────────────────────────────────────

class TestRuleUnsignedExeSystem32:
    def test_matches_unsigned_in_system32(self):
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            details={"file_path": "C:\\Windows\\System32\\evil.exe", "signed": False},
        )
        assert _rule_unsigned_exe_system32(evt) is True

    def test_no_match_signed(self):
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            details={"file_path": "C:\\Windows\\System32\\legit.exe", "signed": True},
        )
        assert _rule_unsigned_exe_system32(evt) is False

    def test_matches_linux_sbin(self):
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            details={"path": "/usr/sbin/backdoor", "signed": False},
        )
        assert _rule_unsigned_exe_system32(evt) is True

    def test_no_match_when_no_path(self):
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            details={"signed": False},
        )
        assert _rule_unsigned_exe_system32(evt) is False


class TestRuleProcessFromTmp:
    def test_matches_tmp(self):
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            details={"executable": "/tmp/payload"},
        )
        assert _rule_process_from_tmp(evt) is True

    def test_no_match_normal_path(self):
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            details={"executable": "/usr/bin/python"},
        )
        assert _rule_process_from_tmp(evt) is False

    def test_ignores_non_process(self):
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            details={"path": "/tmp/something"},
        )
        assert _rule_process_from_tmp(evt) is False


class TestRuleNetworkHighPort:
    def test_matches_suspicious_port(self):
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            details={"dst_port": 4444},
        )
        assert _rule_network_high_port(evt) is True

    def test_no_match_normal_port(self):
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            details={"port": 443},
        )
        assert _rule_network_high_port(evt) is False

    def test_ignores_non_network(self):
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            details={"port": 4444},
        )
        assert _rule_network_high_port(evt) is False


class TestRuleCriticalFile:
    def test_matches_etc_shadow(self):
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            details={"path": "/etc/shadow"},
        )
        assert _rule_critical_file_modification(evt) is True

    def test_no_match_regular_file(self):
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            details={"path": "/home/user/notes.txt"},
        )
        assert _rule_critical_file_modification(evt) is False


class TestRuleSuspiciousSeverity:
    def test_matches_critical(self):
        evt = AggregatedEvent(
            event_type="process.suspicious",
            category=EventCategory.PROCESS,
            severity="critical",
        )
        assert _rule_suspicious_severity(evt) is True

    def test_matches_alert(self):
        evt = AggregatedEvent(
            event_type="process.suspicious",
            category=EventCategory.PROCESS,
            severity="alert",
        )
        assert _rule_suspicious_severity(evt) is True

    def test_no_match_info(self):
        evt = AggregatedEvent(
            event_type="file.created",
            category=EventCategory.FILE,
            severity="info",
        )
        assert _rule_suspicious_severity(evt) is False


class TestDefaultRules:
    def test_five_default_rules(self):
        rules = _default_rules()
        assert len(rules) == 5
        ids = {r.rule_id for r in rules}
        assert ids == {"R001", "R002", "R003", "R004", "R005"}


# ── AnomalyDetector — cold start ────────────────────────────────────

class TestAnomalyDetectorColdStart:
    def test_initial_cold_start(self):
        det = AnomalyDetector()
        assert det.is_cold_start is True
        assert det.training_size == 0

    def test_cold_start_score_is_low_threat(self):
        det = AnomalyDetector()
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="a1",
            details={"process_name": "bash"},
        )
        result = det.score_event(evt)
        assert result.cold_start is True
        # Without rules firing, cold-start model score = 0
        assert result.model_score == 0.0

    def test_exits_cold_start_after_min_samples(self):
        det = AnomalyDetector(min_training_samples=5)
        base = datetime.utcnow()
        for i in range(5):
            evt = AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="a1",
                details={"process_name": "cron"},
                timestamp=(base + timedelta(minutes=i)).isoformat(),
            )
            det.score_event(evt)
        assert det.is_cold_start is False


# ── AnomalyDetector — scoring ───────────────────────────────────────

class TestAnomalyDetectorScoring:
    def _trained_detector(self, n: int = 30) -> AnomalyDetector:
        det = AnomalyDetector(min_training_samples=10)
        base = datetime.utcnow() - timedelta(hours=n)
        events = []
        for i in range(n):
            events.append(AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="srv1",
                severity="info",
                details={"process_name": "cron"},
                timestamp=(base + timedelta(hours=i)).isoformat(),
            ))
        det.train(events)
        return det

    def test_normal_event_low_threat(self):
        det = self._trained_detector()
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="srv1",
            severity="info",
            details={"process_name": "cron"},
            timestamp=datetime.utcnow().isoformat(),
        )
        result = det.score_event(evt)
        assert result.threat_level == ThreatLevel.LOW
        assert result.cold_start is False

    def test_rule_match_raises_score(self):
        det = self._trained_detector()
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            asset_id="srv1",
            severity="info",
            details={"executable": "/tmp/dropper"},
            timestamp=datetime.utcnow().isoformat(),
        )
        result = det.score_event(evt)
        assert "R002" in result.rule_hits
        assert result.rule_score >= 0.7
        assert result.score >= 0.7

    def test_combined_score_is_max(self):
        det = self._trained_detector()
        evt = AggregatedEvent(
            event_type="file.modified",
            category=EventCategory.FILE,
            asset_id="srv1",
            severity="critical",
            details={"path": "/etc/shadow"},
        )
        result = det.score_event(evt)
        # Both R004 (critical file) and R005 (critical severity) should match
        assert "R004" in result.rule_hits
        assert "R005" in result.rule_hits
        assert result.score == max(result.model_score, result.rule_score)

    def test_score_batch(self):
        det = self._trained_detector()
        events = [
            AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="srv1",
                severity="info",
                details={"process_name": "bash"},
            ),
            AggregatedEvent(
                event_type="file.modified",
                category=EventCategory.FILE,
                asset_id="srv1",
                severity="info",
                details={"path": "/etc/shadow"},
            ),
        ]
        results = det.score_batch(events)
        assert len(results) == 2
        assert all(isinstance(r, AnomalyScore) for r in results)


# ── AnomalyDetector — sensitivity ───────────────────────────────────

class TestAnomalyDetectorSensitivity:
    def test_default_sensitivity(self):
        det = AnomalyDetector()
        assert det.sensitivity == Sensitivity.MODERATE

    def test_set_sensitivity(self):
        det = AnomalyDetector()
        det.set_sensitivity(Sensitivity.HIGH)
        assert det.sensitivity == Sensitivity.HIGH
        # Model is reset
        assert det.is_cold_start is True

    def test_high_sensitivity_lower_thresholds(self):
        det_high = AnomalyDetector(sensitivity=Sensitivity.HIGH)
        det_low = AnomalyDetector(sensitivity=Sensitivity.LOW)
        # A medium-score event should be higher threat at HIGH sensitivity
        evt = AggregatedEvent(
            event_type="process.started",
            category=EventCategory.PROCESS,
            severity="alert",
            details={"executable": "/tmp/payload"},  # rule R002 + R005
        )
        r_high = det_high.score_event(evt)
        r_low = det_low.score_event(evt)
        # Same rule score, but threshold mapping differs
        assert r_high.threat_level.value >= r_low.threat_level.value


# ── AnomalyDetector — custom rules ──────────────────────────────────

class TestAnomalyDetectorCustomRules:
    def test_add_rule(self):
        det = AnomalyDetector()
        initial = len(det.list_rules())
        det.add_rule(DetectionRule(
            rule_id="C001",
            name="custom",
            score=0.95,
            evaluate=lambda e: e.event_type == "custom.bad",
        ))
        assert len(det.list_rules()) == initial + 1

    def test_remove_rule(self):
        det = AnomalyDetector()
        assert det.remove_rule("R001") is True
        ids = {r["rule_id"] for r in det.list_rules()}
        assert "R001" not in ids

    def test_remove_nonexistent(self):
        det = AnomalyDetector()
        assert det.remove_rule("BOGUS") is False

    def test_custom_rule_fires(self):
        det = AnomalyDetector()
        det.add_rule(DetectionRule(
            rule_id="C002",
            name="always_bad",
            score=0.99,
            evaluate=lambda e: True,
        ))
        evt = AggregatedEvent(
            event_type="system.start",
            category=EventCategory.SYSTEM,
            severity="info",
        )
        result = det.score_event(evt)
        assert "C002" in result.rule_hits
        assert result.score >= 0.99

    def test_disabled_rule_skipped(self):
        det = AnomalyDetector()
        det.add_rule(DetectionRule(
            rule_id="C003",
            name="disabled",
            score=1.0,
            enabled=False,
            evaluate=lambda e: True,
        ))
        evt = AggregatedEvent(
            event_type="system.start",
            category=EventCategory.SYSTEM,
        )
        result = det.score_event(evt)
        assert "C003" not in result.rule_hits


# ── AnomalyDetector — training ──────────────────────────────────────

class TestAnomalyDetectorTraining:
    def test_train_returns_count(self):
        det = AnomalyDetector(min_training_samples=5)
        events = [
            AggregatedEvent(
                event_type="file.modified",
                category=EventCategory.FILE,
                asset_id="a1",
                details={"path": f"/var/log/{i}"},
            )
            for i in range(10)
        ]
        count = det.train(events)
        assert count == 10
        assert det.training_size >= 10
        assert det.is_cold_start is False

    def test_model_fitted_after_training(self):
        det = AnomalyDetector(min_training_samples=5)
        events = [
            AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                details={"process_name": "worker"},
            )
            for _ in range(5)
        ]
        det.train(events)
        assert det.stats()["model_fitted"] is True


# ── AnomalyDetector — stats & reset ─────────────────────────────────

class TestAnomalyDetectorStats:
    def test_stats_structure(self):
        det = AnomalyDetector()
        s = det.stats()
        assert "sensitivity" in s
        assert "model_fitted" in s
        assert "cold_start" in s
        assert "total_scored" in s
        assert "rules_count" in s
        assert s["rules_count"] == 5

    def test_reset(self):
        det = AnomalyDetector(min_training_samples=5)
        events = [
            AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                details={"process_name": "x"},
            )
            for _ in range(10)
        ]
        det.train(events)
        det.score_event(events[0])
        det.reset()
        s = det.stats()
        assert s["training_samples"] == 0
        assert s["total_scored"] == 0
        assert s["model_fitted"] is False


# ── AnomalyDetector — subscription ──────────────────────────────────

class TestAnomalyDetectorSubscription:
    def test_on_event_callback(self):
        det = AnomalyDetector()
        evt = AggregatedEvent(
            event_type="network.connection",
            category=EventCategory.NETWORK,
            details={"ip": "1.2.3.4"},
        )
        # Should not raise
        det.on_event(evt)
        assert det.stats()["total_scored"] == 1


# ── Thread safety ────────────────────────────────────────────────────

class TestAnomalyDetectorThreadSafety:
    def test_concurrent_scoring(self):
        det = AnomalyDetector(min_training_samples=5)
        # Pre-train
        train_events = [
            AggregatedEvent(
                event_type="process.started",
                category=EventCategory.PROCESS,
                asset_id="a1",
                details={"process_name": f"p{i}"},
            )
            for i in range(10)
        ]
        det.train(train_events)

        errors = []

        def worker(tid):
            try:
                for i in range(25):
                    evt = AggregatedEvent(
                        event_type="file.modified",
                        category=EventCategory.FILE,
                        asset_id=f"a{tid}",
                        details={"path": f"/data/{tid}/{i}"},
                    )
                    result = det.score_event(evt)
                    assert isinstance(result, AnomalyScore)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert det.stats()["total_scored"] == 100


# ── Threat level mapping ─────────────────────────────────────────────

class TestThreatLevelMapping:
    def test_low_score_maps_to_low(self):
        det = AnomalyDetector(sensitivity=Sensitivity.MODERATE)
        assert det._map_threat_level(0.1) == ThreatLevel.LOW

    def test_medium_score_maps_to_medium(self):
        det = AnomalyDetector(sensitivity=Sensitivity.MODERATE)
        assert det._map_threat_level(0.5) == ThreatLevel.MEDIUM

    def test_high_score_maps_to_high(self):
        det = AnomalyDetector(sensitivity=Sensitivity.MODERATE)
        assert det._map_threat_level(0.85) == ThreatLevel.HIGH

    def test_boundary_at_medium_threshold(self):
        det = AnomalyDetector(sensitivity=Sensitivity.MODERATE)
        med, _ = _THREAT_THRESHOLDS[Sensitivity.MODERATE]
        assert det._map_threat_level(med) == ThreatLevel.MEDIUM
        assert det._map_threat_level(med - 0.01) == ThreatLevel.LOW
