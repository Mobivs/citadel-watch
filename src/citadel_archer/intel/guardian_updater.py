# PRD: Intel Module - Guardian Updater (Intel → Guardian Sync)
# Reference: PHASE_2_SPEC.md
#
# Monitors the Intel pipeline for new threats and auto-generates
# Guardian rules from IOCs (file hashes, C2 IPs/domains), CVEs,
# and MITRE TTP patterns.
#
# Rules are published via an event-based callback system (compatible
# with EventAggregator.subscribe) so the Guardian can hot-reload
# without restart.
#
# Conflict resolution: when two rules share the same indicator,
# the higher-severity rule wins.

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from .models import (
    CVE,
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
    TTP,
)


# ── Enums ────────────────────────────────────────────────────────────

class GuardianRuleType(str, Enum):
    """Category of auto-generated Guardian rule."""

    FILE_HASH = "file_hash"
    NETWORK_IP = "network_ip"
    NETWORK_DOMAIN = "network_domain"
    PROCESS_PATTERN = "process_pattern"
    FILE_PATTERN = "file_pattern"
    CVE_SIGNATURE = "cve_signature"


class RuleAction(str, Enum):
    """Action the Guardian should take when a rule matches."""

    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    KILL = "kill"


class RuleSeverity(str, Enum):
    """Severity classification for generated rules."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Numeric rank for conflict resolution (higher wins)
_SEVERITY_RANK: Dict[RuleSeverity, int] = {
    RuleSeverity.LOW: 0,
    RuleSeverity.MEDIUM: 1,
    RuleSeverity.HIGH: 2,
    RuleSeverity.CRITICAL: 3,
}

# Map IntelSeverity → RuleSeverity
_INTEL_TO_RULE_SEVERITY: Dict[str, RuleSeverity] = {
    "none": RuleSeverity.LOW,
    "low": RuleSeverity.LOW,
    "medium": RuleSeverity.MEDIUM,
    "high": RuleSeverity.HIGH,
    "critical": RuleSeverity.CRITICAL,
}

# Map severity → default action
_SEVERITY_DEFAULT_ACTION: Dict[RuleSeverity, RuleAction] = {
    RuleSeverity.LOW: RuleAction.ALERT,
    RuleSeverity.MEDIUM: RuleAction.ALERT,
    RuleSeverity.HIGH: RuleAction.BLOCK,
    RuleSeverity.CRITICAL: RuleAction.QUARANTINE,
}


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class GuardianRule:
    """An auto-generated rule for the Guardian subsystem."""

    rule_id: str = ""
    threat_type: GuardianRuleType = GuardianRuleType.FILE_HASH
    indicator: str = ""
    severity: RuleSeverity = RuleSeverity.MEDIUM
    action: RuleAction = RuleAction.ALERT
    description: str = ""
    source_feed: str = ""
    intel_item_id: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["severity"] = self.severity.value
        d["action"] = self.action.value
        return d

    @property
    def conflict_key(self) -> str:
        """Key used for conflict detection — same type + indicator."""
        return f"{self.threat_type.value}:{self.indicator}"


@dataclass
class UpdateReport:
    """Summary of a Guardian rule update cycle."""

    rules_generated: int = 0
    rules_added: int = 0
    rules_updated: int = 0
    rules_skipped: int = 0
    conflicts_resolved: int = 0
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Rule generation from Intel items ─────────────────────────────────

def _map_severity(intel_sev: str) -> RuleSeverity:
    return _INTEL_TO_RULE_SEVERITY.get(intel_sev.lower(), RuleSeverity.MEDIUM)


def _action_for_severity(sev: RuleSeverity) -> RuleAction:
    return _SEVERITY_DEFAULT_ACTION.get(sev, RuleAction.ALERT)


def rules_from_ioc(item: IntelItem) -> List[GuardianRule]:
    """Generate Guardian rules from an IOC IntelItem."""
    ioc: IOC = item.payload
    sev = _map_severity(ioc.severity.value if isinstance(ioc.severity, IntelSeverity) else str(ioc.severity))
    action = _action_for_severity(sev)
    base_id = f"intel-{item.item_id[:8]}"

    rules: List[GuardianRule] = []

    hash_types = {
        IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1,
        IOCType.FILE_HASH_SHA256,
    }

    if ioc.ioc_type in hash_types:
        rules.append(GuardianRule(
            rule_id=f"{base_id}-hash",
            threat_type=GuardianRuleType.FILE_HASH,
            indicator=ioc.value,
            severity=sev,
            action=action if sev >= RuleSeverity.HIGH else RuleAction.ALERT,
            description=f"Malware hash ({ioc.ioc_type.value}): {ioc.description or ioc.value}",
            source_feed=item.source_feed,
            intel_item_id=item.item_id,
        ))
    elif ioc.ioc_type == IOCType.IP_ADDRESS:
        rules.append(GuardianRule(
            rule_id=f"{base_id}-ip",
            threat_type=GuardianRuleType.NETWORK_IP,
            indicator=ioc.value,
            severity=sev,
            action=RuleAction.BLOCK if sev >= RuleSeverity.MEDIUM else RuleAction.ALERT,
            description=f"C2 IP: {ioc.description or ioc.value}",
            source_feed=item.source_feed,
            intel_item_id=item.item_id,
        ))
    elif ioc.ioc_type == IOCType.DOMAIN:
        rules.append(GuardianRule(
            rule_id=f"{base_id}-domain",
            threat_type=GuardianRuleType.NETWORK_DOMAIN,
            indicator=ioc.value,
            severity=sev,
            action=RuleAction.BLOCK if sev >= RuleSeverity.MEDIUM else RuleAction.ALERT,
            description=f"C2 domain: {ioc.description or ioc.value}",
            source_feed=item.source_feed,
            intel_item_id=item.item_id,
        ))
    elif ioc.ioc_type == IOCType.URL:
        rules.append(GuardianRule(
            rule_id=f"{base_id}-domain",
            threat_type=GuardianRuleType.NETWORK_DOMAIN,
            indicator=ioc.value,
            severity=sev,
            action=RuleAction.BLOCK if sev >= RuleSeverity.MEDIUM else RuleAction.ALERT,
            description=f"Malicious URL: {ioc.description or ioc.value}",
            source_feed=item.source_feed,
            intel_item_id=item.item_id,
        ))

    return rules


def rules_from_ttp(item: IntelItem) -> List[GuardianRule]:
    """Generate Guardian rules from a TTP IntelItem."""
    ttp: TTP = item.payload
    sev = _map_severity(ttp.severity.value if isinstance(ttp.severity, IntelSeverity) else str(ttp.severity))
    action = _action_for_severity(sev)
    base_id = f"intel-{item.item_id[:8]}"

    return [GuardianRule(
        rule_id=f"{base_id}-ttp",
        threat_type=GuardianRuleType.PROCESS_PATTERN,
        indicator=ttp.technique_id,
        severity=sev,
        action=action,
        description=f"MITRE {ttp.technique_id} ({ttp.tactic}): {ttp.name}",
        source_feed=item.source_feed,
        intel_item_id=item.item_id,
    )]


def rules_from_cve(item: IntelItem) -> List[GuardianRule]:
    """Generate Guardian rules from a CVE IntelItem."""
    cve: CVE = item.payload
    sev = _map_severity(cve.severity.value if isinstance(cve.severity, IntelSeverity) else str(cve.severity))
    action = _action_for_severity(sev)
    base_id = f"intel-{item.item_id[:8]}"

    return [GuardianRule(
        rule_id=f"{base_id}-cve",
        threat_type=GuardianRuleType.CVE_SIGNATURE,
        indicator=cve.cve_id,
        severity=sev,
        action=action,
        description=f"{cve.cve_id}: {cve.description[:120]}",
        source_feed=item.source_feed,
        intel_item_id=item.item_id,
    )]


def generate_rules(item: IntelItem) -> List[GuardianRule]:
    """Generate Guardian rules from any IntelItem type."""
    if item.intel_type == IntelType.IOC:
        return rules_from_ioc(item)
    if item.intel_type == IntelType.TTP:
        return rules_from_ttp(item)
    if item.intel_type == IntelType.CVE:
        return rules_from_cve(item)
    return []


# ── GuardianUpdater ──────────────────────────────────────────────────

class GuardianUpdater:
    """Monitors the Intel pipeline and pushes auto-generated rules
    to the Guardian subsystem via callbacks (hot reload).

    Args:
        on_rule_published: Callback invoked for each new/updated rule
            pushed to the Guardian.  Signature: ``(GuardianRule) -> None``.
    """

    def __init__(
        self,
        on_rule_published: Optional[Callable[[GuardianRule], None]] = None,
    ):
        self._lock = threading.RLock()
        self._rules: Dict[str, GuardianRule] = {}  # conflict_key → rule
        self._rule_ids: Dict[str, str] = {}         # rule_id → conflict_key
        self._subscribers: List[Callable[[GuardianRule], None]] = []
        if on_rule_published:
            self._subscribers.append(on_rule_published)
        self._processed_item_ids: Set[str] = set()

        # Stats
        self._total_generated = 0
        self._total_published = 0
        self._total_conflicts = 0

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, callback: Callable[[GuardianRule], None]) -> None:
        """Register a callback invoked when rules are published."""
        self._subscribers.append(callback)

    def _publish(self, rule: GuardianRule) -> None:
        """Notify all subscribers of a new/updated rule."""
        for sub in self._subscribers:
            try:
                sub(rule)
            except Exception:
                pass  # best-effort delivery

    # ------------------------------------------------------------------
    # Conflict resolution
    # ------------------------------------------------------------------

    def _resolve_conflict(
        self, existing: GuardianRule, incoming: GuardianRule
    ) -> GuardianRule:
        """When two rules share the same indicator, keep higher severity."""
        ex_rank = _SEVERITY_RANK.get(existing.severity, 0)
        in_rank = _SEVERITY_RANK.get(incoming.severity, 0)
        if in_rank > ex_rank:
            return incoming
        if in_rank == ex_rank:
            # Same severity — keep more recent
            if incoming.created_at >= existing.created_at:
                return incoming
        return existing

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def _add_or_update(self, rule: GuardianRule) -> str:
        """Insert or update a rule. Returns 'added', 'updated', or 'skipped'."""
        key = rule.conflict_key
        existing = self._rules.get(key)

        if existing is None:
            self._rules[key] = rule
            self._rule_ids[rule.rule_id] = key
            self._publish(rule)
            return "added"

        winner = self._resolve_conflict(existing, rule)
        if winner is rule:
            # Remove old rule_id mapping
            self._rule_ids.pop(existing.rule_id, None)
            self._rules[key] = rule
            self._rule_ids[rule.rule_id] = key
            self._total_conflicts += 1
            self._publish(rule)
            return "updated"

        return "skipped"

    def process_intel_item(self, item: IntelItem) -> UpdateReport:
        """Generate and publish rules from a single IntelItem.

        Idempotent: re-processing the same ``item_id`` is a no-op.
        """
        report = UpdateReport()

        with self._lock:
            if item.item_id in self._processed_item_ids:
                return report

            rules = generate_rules(item)
            report.rules_generated = len(rules)
            self._total_generated += len(rules)

            for rule in rules:
                result = self._add_or_update(rule)
                if result == "added":
                    report.rules_added += 1
                    self._total_published += 1
                elif result == "updated":
                    report.rules_updated += 1
                    report.conflicts_resolved += 1
                    self._total_published += 1
                else:
                    report.rules_skipped += 1

            self._processed_item_ids.add(item.item_id)

        return report

    def process_batch(self, items: List[IntelItem]) -> UpdateReport:
        """Process multiple IntelItems and return an aggregate report."""
        combined = UpdateReport()
        for item in items:
            r = self.process_intel_item(item)
            combined.rules_generated += r.rules_generated
            combined.rules_added += r.rules_added
            combined.rules_updated += r.rules_updated
            combined.rules_skipped += r.rules_skipped
            combined.conflicts_resolved += r.conflicts_resolved
            combined.errors.extend(r.errors)
        return combined

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_rule(self, rule_id: str) -> Optional[GuardianRule]:
        """Look up a rule by ID."""
        with self._lock:
            key = self._rule_ids.get(rule_id)
            if key is None:
                return None
            return self._rules.get(key)

    def get_rules_by_type(
        self, rule_type: GuardianRuleType
    ) -> List[GuardianRule]:
        """Return all rules of a given type."""
        with self._lock:
            return [
                r for r in self._rules.values()
                if r.threat_type == rule_type
            ]

    def get_rules_by_severity(
        self, severity: RuleSeverity
    ) -> List[GuardianRule]:
        """Return all rules at a given severity."""
        with self._lock:
            return [
                r for r in self._rules.values()
                if r.severity == severity
            ]

    def all_rules(self) -> List[GuardianRule]:
        """Return a snapshot of all active rules."""
        with self._lock:
            return list(self._rules.values())

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._rules)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if found."""
        with self._lock:
            key = self._rule_ids.pop(rule_id, None)
            if key is None:
                return False
            self._rules.pop(key, None)
            return True

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule without removing it."""
        with self._lock:
            rule = self.get_rule(rule_id)
            if rule is None:
                return False
            rule.enabled = False
            return True

    def enable_rule(self, rule_id: str) -> bool:
        """Re-enable a disabled rule."""
        with self._lock:
            rule = self.get_rule(rule_id)
            if rule is None:
                return False
            rule.enabled = True
            return True

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_type: Dict[str, int] = {}
            by_severity: Dict[str, int] = {}
            for r in self._rules.values():
                by_type[r.threat_type.value] = by_type.get(r.threat_type.value, 0) + 1
                by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1
            return {
                "active_rules": len(self._rules),
                "total_generated": self._total_generated,
                "total_published": self._total_published,
                "total_conflicts": self._total_conflicts,
                "processed_items": len(self._processed_item_ids),
                "by_type": by_type,
                "by_severity": by_severity,
            }

    def reset(self) -> None:
        """Clear all rules and state."""
        with self._lock:
            self._rules.clear()
            self._rule_ids.clear()
            self._processed_item_ids.clear()
            self._total_generated = 0
            self._total_published = 0
            self._total_conflicts = 0
