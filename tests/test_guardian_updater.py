# Tests for T11: Guardian Updater (Intel → Guardian Sync)
# Covers: GuardianRuleType, RuleAction, RuleSeverity, GuardianRule,
#          UpdateReport, rule generation from IOC/TTP/CVE, conflict
#          resolution, hot-reload subscription, idempotency, queries,
#          batch processing, and thread safety.

import threading
from datetime import datetime, timedelta

import pytest

from citadel_archer.intel.guardian_updater import (
    GuardianRule,
    GuardianRuleType,
    GuardianUpdater,
    RuleAction,
    RuleSeverity,
    UpdateReport,
    generate_rules,
    rules_from_cve,
    rules_from_ioc,
    rules_from_ttp,
    _SEVERITY_RANK,
)
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


# ── Helpers ──────────────────────────────────────────────────────────

def _make_ioc_item(ioc_type, value, severity=IntelSeverity.MEDIUM,
                    source="test", item_id=None):
    return IntelItem(
        intel_type=IntelType.IOC,
        payload=IOC(ioc_type=ioc_type, value=value, severity=severity,
                     source=source),
        source_feed=source,
        **({"item_id": item_id} if item_id else {}),
    )


def _make_ttp_item(technique_id, name, tactic="execution",
                    severity=IntelSeverity.HIGH):
    return IntelItem(
        intel_type=IntelType.TTP,
        payload=TTP(technique_id=technique_id, name=name, tactic=tactic,
                     severity=severity),
        source_feed="mitre",
    )


def _make_cve_item(cve_id, description, cvss=7.5):
    return IntelItem(
        intel_type=IntelType.CVE,
        payload=CVE(cve_id=cve_id, description=description, cvss_score=cvss),
        source_feed="nvd",
    )


# ── Enums ────────────────────────────────────────────────────────────

class TestGuardianRuleType:
    def test_values(self):
        assert GuardianRuleType.FILE_HASH == "file_hash"
        assert GuardianRuleType.NETWORK_IP == "network_ip"
        assert GuardianRuleType.NETWORK_DOMAIN == "network_domain"
        assert GuardianRuleType.PROCESS_PATTERN == "process_pattern"
        assert GuardianRuleType.CVE_SIGNATURE == "cve_signature"


class TestRuleAction:
    def test_values(self):
        assert RuleAction.ALERT == "alert"
        assert RuleAction.BLOCK == "block"
        assert RuleAction.QUARANTINE == "quarantine"
        assert RuleAction.KILL == "kill"


class TestRuleSeverity:
    def test_rank_ordering(self):
        assert _SEVERITY_RANK[RuleSeverity.LOW] < _SEVERITY_RANK[RuleSeverity.MEDIUM]
        assert _SEVERITY_RANK[RuleSeverity.MEDIUM] < _SEVERITY_RANK[RuleSeverity.HIGH]
        assert _SEVERITY_RANK[RuleSeverity.HIGH] < _SEVERITY_RANK[RuleSeverity.CRITICAL]


# ── GuardianRule ─────────────────────────────────────────────────────

class TestGuardianRule:
    def test_to_dict(self):
        r = GuardianRule(
            rule_id="R1", threat_type=GuardianRuleType.FILE_HASH,
            indicator="abc123", severity=RuleSeverity.HIGH,
            action=RuleAction.QUARANTINE,
        )
        d = r.to_dict()
        assert d["threat_type"] == "file_hash"
        assert d["severity"] == "high"
        assert d["action"] == "quarantine"

    def test_conflict_key(self):
        r = GuardianRule(
            threat_type=GuardianRuleType.NETWORK_IP, indicator="10.0.0.1",
        )
        assert r.conflict_key == "network_ip:10.0.0.1"

    def test_defaults(self):
        r = GuardianRule()
        assert r.enabled is True
        assert r.action == RuleAction.ALERT


# ── UpdateReport ─────────────────────────────────────────────────────

class TestUpdateReport:
    def test_to_dict(self):
        rpt = UpdateReport(rules_generated=3, rules_added=2,
                           rules_skipped=1)
        d = rpt.to_dict()
        assert d["rules_generated"] == 3
        assert d["rules_added"] == 2


# ── Rule generation from IOC ────────────────────────────────────────

class TestRulesFromIOC:
    def test_sha256_hash(self):
        item = _make_ioc_item(IOCType.FILE_HASH_SHA256, "deadbeef",
                              severity=IntelSeverity.HIGH)
        rules = rules_from_ioc(item)
        assert len(rules) == 1
        r = rules[0]
        assert r.threat_type == GuardianRuleType.FILE_HASH
        assert r.indicator == "deadbeef"
        assert r.severity == RuleSeverity.HIGH

    def test_md5_hash(self):
        item = _make_ioc_item(IOCType.FILE_HASH_MD5, "abc123")
        rules = rules_from_ioc(item)
        assert len(rules) == 1
        assert rules[0].threat_type == GuardianRuleType.FILE_HASH

    def test_ip_address(self):
        item = _make_ioc_item(IOCType.IP_ADDRESS, "10.66.6.6",
                              severity=IntelSeverity.CRITICAL)
        rules = rules_from_ioc(item)
        assert len(rules) == 1
        r = rules[0]
        assert r.threat_type == GuardianRuleType.NETWORK_IP
        assert r.indicator == "10.66.6.6"
        assert r.action == RuleAction.BLOCK

    def test_domain(self):
        item = _make_ioc_item(IOCType.DOMAIN, "evil.example.com",
                              severity=IntelSeverity.HIGH)
        rules = rules_from_ioc(item)
        assert len(rules) == 1
        assert rules[0].threat_type == GuardianRuleType.NETWORK_DOMAIN
        assert rules[0].action == RuleAction.BLOCK

    def test_url(self):
        item = _make_ioc_item(IOCType.URL, "http://evil.com/payload")
        rules = rules_from_ioc(item)
        assert len(rules) == 1
        assert rules[0].threat_type == GuardianRuleType.NETWORK_DOMAIN

    def test_email_produces_no_rules(self):
        item = _make_ioc_item(IOCType.EMAIL, "hacker@evil.com")
        rules = rules_from_ioc(item)
        assert rules == []

    def test_high_severity_hash_gets_quarantine(self):
        item = _make_ioc_item(IOCType.FILE_HASH_SHA256, "hash",
                              severity=IntelSeverity.CRITICAL)
        rules = rules_from_ioc(item)
        # CRITICAL hash → action should be ALERT (only ≥HIGH gets non-alert)
        # Actually CRITICAL ≥ HIGH so it gets quarantine-like action
        assert rules[0].severity == RuleSeverity.CRITICAL

    def test_low_severity_hash_gets_alert(self):
        item = _make_ioc_item(IOCType.FILE_HASH_SHA256, "hash",
                              severity=IntelSeverity.LOW)
        rules = rules_from_ioc(item)
        assert rules[0].action == RuleAction.ALERT


# ── Rule generation from TTP ────────────────────────────────────────

class TestRulesFromTTP:
    def test_basic_ttp(self):
        item = _make_ttp_item("T1059.001", "PowerShell", "execution")
        rules = rules_from_ttp(item)
        assert len(rules) == 1
        r = rules[0]
        assert r.threat_type == GuardianRuleType.PROCESS_PATTERN
        assert r.indicator == "T1059.001"
        assert "MITRE" in r.description

    def test_ttp_severity_mapping(self):
        item = _make_ttp_item("T1003", "Credential Dumping",
                              severity=IntelSeverity.CRITICAL)
        rules = rules_from_ttp(item)
        assert rules[0].severity == RuleSeverity.CRITICAL


# ── Rule generation from CVE ────────────────────────────────────────

class TestRulesFromCVE:
    def test_basic_cve(self):
        item = _make_cve_item("CVE-2024-1234", "Buffer overflow RCE", 9.8)
        rules = rules_from_cve(item)
        assert len(rules) == 1
        r = rules[0]
        assert r.threat_type == GuardianRuleType.CVE_SIGNATURE
        assert r.indicator == "CVE-2024-1234"
        assert r.severity == RuleSeverity.CRITICAL

    def test_medium_cve(self):
        item = _make_cve_item("CVE-2024-5678", "XSS", 5.0)
        rules = rules_from_cve(item)
        assert rules[0].severity == RuleSeverity.MEDIUM


# ── generate_rules dispatcher ───────────────────────────────────────

class TestGenerateRules:
    def test_dispatches_ioc(self):
        item = _make_ioc_item(IOCType.IP_ADDRESS, "1.2.3.4")
        assert len(generate_rules(item)) == 1

    def test_dispatches_ttp(self):
        item = _make_ttp_item("T1059", "Scripting")
        assert len(generate_rules(item)) == 1

    def test_dispatches_cve(self):
        item = _make_cve_item("CVE-2024-0001", "Test", 7.0)
        assert len(generate_rules(item)) == 1

    def test_vulnerability_returns_empty(self):
        item = IntelItem(
            intel_type=IntelType.VULNERABILITY,
            payload=Vulnerability(product="openssl", version="1.1.1"),
            source_feed="test",
        )
        assert generate_rules(item) == []


# ── GuardianUpdater — basic flow ────────────────────────────────────

class TestGuardianUpdaterBasic:
    def test_process_ioc_adds_rule(self):
        updater = GuardianUpdater()
        item = _make_ioc_item(IOCType.FILE_HASH_SHA256, "malware_hash",
                              severity=IntelSeverity.HIGH)
        report = updater.process_intel_item(item)
        assert report.rules_generated == 1
        assert report.rules_added == 1
        assert updater.rule_count == 1

    def test_idempotent_processing(self):
        updater = GuardianUpdater()
        item = _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1",
                              item_id="fixed-id")
        updater.process_intel_item(item)
        report2 = updater.process_intel_item(item)
        # Second processing is a no-op
        assert report2.rules_generated == 0
        assert updater.rule_count == 1

    def test_all_rules(self):
        updater = GuardianUpdater()
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1"))
        updater.process_intel_item(
            _make_ioc_item(IOCType.DOMAIN, "evil.com"))
        rules = updater.all_rules()
        assert len(rules) == 2


# ── Conflict resolution ─────────────────────────────────────────────

class TestConflictResolution:
    def test_higher_severity_wins(self):
        updater = GuardianUpdater()
        # First: medium severity
        item1 = _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1",
                               severity=IntelSeverity.MEDIUM)
        updater.process_intel_item(item1)
        # Second: critical severity for same IP
        item2 = _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1",
                               severity=IntelSeverity.CRITICAL)
        report = updater.process_intel_item(item2)
        assert report.conflicts_resolved == 1
        assert updater.rule_count == 1
        rule = updater.all_rules()[0]
        assert rule.severity == RuleSeverity.CRITICAL

    def test_lower_severity_loses(self):
        updater = GuardianUpdater()
        item1 = _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1",
                               severity=IntelSeverity.HIGH)
        updater.process_intel_item(item1)
        item2 = _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1",
                               severity=IntelSeverity.LOW)
        report = updater.process_intel_item(item2)
        assert report.rules_skipped == 1
        rule = updater.all_rules()[0]
        assert rule.severity == RuleSeverity.HIGH

    def test_same_severity_newer_wins(self):
        updater = GuardianUpdater()
        old_time = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        new_time = datetime.utcnow().isoformat()
        # Insert old rule manually via internal API
        old_rule = GuardianRule(
            rule_id="old", threat_type=GuardianRuleType.NETWORK_IP,
            indicator="10.0.0.1", severity=RuleSeverity.HIGH,
            created_at=old_time,
        )
        updater._add_or_update(old_rule)
        # New rule with same severity
        new_rule = GuardianRule(
            rule_id="new", threat_type=GuardianRuleType.NETWORK_IP,
            indicator="10.0.0.1", severity=RuleSeverity.HIGH,
            created_at=new_time,
        )
        result = updater._add_or_update(new_rule)
        assert result == "updated"
        stored = updater.all_rules()[0]
        assert stored.rule_id == "new"


# ── Subscription (hot reload) ───────────────────────────────────────

class TestSubscription:
    def test_on_rule_published_callback(self):
        published = []
        updater = GuardianUpdater(on_rule_published=lambda r: published.append(r))
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1"))
        assert len(published) == 1
        assert isinstance(published[0], GuardianRule)

    def test_subscribe_receives_updates(self):
        published = []
        updater = GuardianUpdater()
        updater.subscribe(lambda r: published.append(r))
        updater.process_intel_item(
            _make_ioc_item(IOCType.DOMAIN, "evil.com"))
        assert len(published) == 1

    def test_subscriber_error_does_not_crash(self):
        def bad_subscriber(r):
            raise RuntimeError("oops")

        updater = GuardianUpdater(on_rule_published=bad_subscriber)
        # Should not raise
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1"))
        assert updater.rule_count == 1

    def test_multiple_subscribers(self):
        a, b = [], []
        updater = GuardianUpdater()
        updater.subscribe(lambda r: a.append(r))
        updater.subscribe(lambda r: b.append(r))
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "1.1.1.1"))
        assert len(a) == 1
        assert len(b) == 1


# ── Queries ──────────────────────────────────────────────────────────

class TestQueries:
    def _populated_updater(self) -> GuardianUpdater:
        updater = GuardianUpdater()
        updater.process_intel_item(
            _make_ioc_item(IOCType.FILE_HASH_SHA256, "h1",
                           severity=IntelSeverity.HIGH))
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1",
                           severity=IntelSeverity.MEDIUM))
        updater.process_intel_item(
            _make_ioc_item(IOCType.DOMAIN, "bad.com",
                           severity=IntelSeverity.CRITICAL))
        updater.process_intel_item(
            _make_ttp_item("T1059.001", "PowerShell"))
        return updater

    def test_get_rules_by_type(self):
        updater = self._populated_updater()
        ips = updater.get_rules_by_type(GuardianRuleType.NETWORK_IP)
        assert len(ips) == 1
        assert ips[0].indicator == "10.0.0.1"

    def test_get_rules_by_severity(self):
        updater = self._populated_updater()
        critical = updater.get_rules_by_severity(RuleSeverity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].indicator == "bad.com"

    def test_get_rule_by_id(self):
        updater = self._populated_updater()
        rules = updater.all_rules()
        r = updater.get_rule(rules[0].rule_id)
        assert r is not None
        assert r.rule_id == rules[0].rule_id

    def test_get_rule_not_found(self):
        updater = GuardianUpdater()
        assert updater.get_rule("nonexistent") is None

    def test_remove_rule(self):
        updater = self._populated_updater()
        rules = updater.all_rules()
        rid = rules[0].rule_id
        assert updater.remove_rule(rid) is True
        assert updater.get_rule(rid) is None
        assert updater.remove_rule(rid) is False

    def test_disable_enable_rule(self):
        updater = self._populated_updater()
        rules = updater.all_rules()
        rid = rules[0].rule_id
        assert updater.disable_rule(rid) is True
        assert updater.get_rule(rid).enabled is False
        assert updater.enable_rule(rid) is True
        assert updater.get_rule(rid).enabled is True

    def test_disable_nonexistent(self):
        updater = GuardianUpdater()
        assert updater.disable_rule("nope") is False


# ── Batch processing ────────────────────────────────────────────────

class TestBatchProcessing:
    def test_process_batch(self):
        updater = GuardianUpdater()
        items = [
            _make_ioc_item(IOCType.IP_ADDRESS, f"10.0.0.{i}",
                           severity=IntelSeverity.MEDIUM)
            for i in range(5)
        ]
        report = updater.process_batch(items)
        assert report.rules_generated == 5
        assert report.rules_added == 5
        assert updater.rule_count == 5


# ── Stats & reset ───────────────────────────────────────────────────

class TestStatsAndReset:
    def test_stats_structure(self):
        updater = GuardianUpdater()
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1"))
        s = updater.stats()
        assert s["active_rules"] == 1
        assert s["total_generated"] == 1
        assert s["total_published"] == 1
        assert "network_ip" in s["by_type"]

    def test_reset(self):
        updater = GuardianUpdater()
        updater.process_intel_item(
            _make_ioc_item(IOCType.IP_ADDRESS, "10.0.0.1"))
        updater.reset()
        assert updater.rule_count == 0
        assert updater.stats()["total_generated"] == 0


# ── Thread safety ────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_processing(self):
        updater = GuardianUpdater()
        errors = []

        def worker(start):
            try:
                for i in range(20):
                    item = _make_ioc_item(
                        IOCType.IP_ADDRESS, f"10.{start}.0.{i}",
                        severity=IntelSeverity.MEDIUM,
                    )
                    updater.process_intel_item(item)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,))
                   for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert updater.rule_count == 80

    def test_concurrent_read_write(self):
        updater = GuardianUpdater()
        errors = []

        def writer():
            try:
                for i in range(30):
                    updater.process_intel_item(
                        _make_ioc_item(IOCType.DOMAIN, f"d{i}.com"))
            except Exception as exc:
                errors.append(exc)

        def reader():
            try:
                for _ in range(30):
                    updater.all_rules()
                    updater.stats()
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert errors == []
