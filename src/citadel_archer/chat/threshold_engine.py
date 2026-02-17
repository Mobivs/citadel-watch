# PRD: AI Trigger 3c — Threshold Breach Detection (Level 2 Escalation)
# Reference: docs/PRD.md, Trigger Model — Category 3 (App-Initiated Processing)
#
# Subscribes to EventAggregator and monitors event patterns against
# configurable threshold rules. When a threshold is breached, escalates
# ONE summary to SecureChat for AI analysis.
#
# This is Level 2 in the escalation hierarchy: pure automation,
# no tokens consumed. Only breached thresholds promote to SCS.
#
# AI Bridge coupling: The summary text MUST contain "critical" or "high"
# to trigger AI processing (ai_bridge.py:224-227).

import asyncio
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, TYPE_CHECKING

from ..intel.event_aggregator import AggregatedEvent, EventCategory

if TYPE_CHECKING:
    from ..intel.event_aggregator import EventAggregator
    from .chat_manager import ChatManager

logger = logging.getLogger(__name__)

# Tuning constants
EVAL_INTERVAL_SECONDS = 30        # Periodic sweep for correlation rules + flush
DEDUP_WINDOW_SECONDS = 300        # 5 min dedup for breach notifications
DEFAULT_COOLDOWN_SECONDS = 3600   # 1 hour cooldown after a rule fires
RATE_LIMIT_PER_HOUR = 15          # Max escalations per hour
RATE_LIMIT_WINDOW = 3600


# ── Data Models ──────────────────────────────────────────────────────


class RuleType(str, Enum):
    COUNT = "count"
    CORRELATION = "correlation"


@dataclass(frozen=True)
class CorrelationCondition:
    """A single condition within a correlation rule."""

    event_types: FrozenSet[str] = field(default_factory=frozenset)
    categories: FrozenSet[EventCategory] = field(default_factory=frozenset)
    severities: FrozenSet[str] = field(default_factory=frozenset)
    min_count: int = 1


@dataclass(frozen=True)
class ThresholdRule:
    """A threshold or correlation detection rule.

    COUNT rules fire when >= threshold events matching the filters
    arrive within window_seconds.

    CORRELATION rules fire when ALL conditions are simultaneously
    met within window_seconds.
    """

    rule_id: str
    rule_type: RuleType
    name: str
    description: str = ""

    # COUNT rule fields
    event_types: FrozenSet[str] = field(default_factory=frozenset)
    categories: FrozenSet[EventCategory] = field(default_factory=frozenset)
    severities: FrozenSet[str] = field(default_factory=frozenset)
    threshold: int = 0

    # CORRELATION rule fields
    conditions: tuple = ()  # tuple of CorrelationCondition

    # Shared
    window_seconds: int = 3600
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS
    group_by_asset: bool = True


@dataclass
class BreachRecord:
    """Record of a threshold breach."""

    rule_id: str
    rule_name: str
    asset_id: Optional[str]
    breach_time: float
    event_count: int
    sample_messages: List[str]
    breach_description: str


# ── Default Rules ────────────────────────────────────────────────────


DEFAULT_RULES: List[ThresholdRule] = [
    ThresholdRule(
        rule_id="ssh_brute_force_volume",
        rule_type=RuleType.COUNT,
        name="SSH brute force volume",
        description="50+ SSH auth events in 1 hour from a single asset",
        event_types=frozenset({"remote.auth_log"}),
        threshold=50,
        window_seconds=3600,
        cooldown_seconds=3600,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="critical_file_burst",
        rule_type=RuleType.COUNT,
        name="Critical file change burst",
        description="3+ critical/alert file changes within 24 hours",
        event_types=frozenset({"file.modified", "file.created", "file.deleted"}),
        severities=frozenset({"critical", "alert"}),
        threshold=3,
        window_seconds=86400,
        cooldown_seconds=86400,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="vault_unlock_failures",
        rule_type=RuleType.COUNT,
        name="Vault unlock failure burst",
        description="5+ vault unlock failures in 10 minutes",
        event_types=frozenset({"vault.unlock.failed"}),
        threshold=5,
        window_seconds=600,
        cooldown_seconds=1800,
        group_by_asset=False,
    ),
    ThresholdRule(
        rule_id="network_block_surge",
        rule_type=RuleType.COUNT,
        name="Network block surge",
        description="20+ blocked connections in 30 minutes",
        event_types=frozenset({"network.blocked"}),
        threshold=20,
        window_seconds=1800,
        cooldown_seconds=1800,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="suspicious_process_cluster",
        rule_type=RuleType.COUNT,
        name="Suspicious process cluster",
        description="5+ suspicious process events in 1 hour",
        event_types=frozenset({"process.suspicious"}),
        threshold=5,
        window_seconds=3600,
        cooldown_seconds=3600,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="coordinated_attack",
        rule_type=RuleType.CORRELATION,
        name="Coordinated attack pattern",
        description=(
            "SSH auth events + file changes + suspicious process "
            "within 1 hour = potential coordinated intrusion"
        ),
        conditions=(
            CorrelationCondition(
                event_types=frozenset({"remote.auth_log"}),
                min_count=5,
            ),
            CorrelationCondition(
                event_types=frozenset({"file.modified", "file.created"}),
                min_count=1,
            ),
            CorrelationCondition(
                event_types=frozenset({"process.suspicious"}),
                min_count=1,
            ),
        ),
        window_seconds=3600,
        cooldown_seconds=7200,
        group_by_asset=True,
    ),
    # ── VPS Threshold Rules (v0.3.12) ─────────────────────────────────
    ThresholdRule(
        rule_id="remote_file_integrity_burst",
        rule_type=RuleType.COUNT,
        name="Remote file integrity alert burst",
        description="5+ file integrity changes on a VPS in 1 hour",
        event_types=frozenset({"remote.file_integrity"}),
        threshold=5,
        window_seconds=3600,
        cooldown_seconds=3600,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="remote_cron_changes",
        rule_type=RuleType.COUNT,
        name="Remote cron modification burst",
        description="3+ cron changes on a VPS in 1 hour (cron changes are rare)",
        event_types=frozenset({"remote.cron_monitor"}),
        threshold=3,
        window_seconds=3600,
        cooldown_seconds=3600,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="remote_process_anomaly",
        rule_type=RuleType.COUNT,
        name="Remote process anomaly cluster",
        description="10+ process alerts on a VPS in 1 hour",
        event_types=frozenset({"remote.process_monitor"}),
        severities=frozenset({"alert", "critical", "high"}),
        threshold=10,
        window_seconds=3600,
        cooldown_seconds=3600,
        group_by_asset=True,
    ),
    ThresholdRule(
        rule_id="vps_intrusion_pattern",
        rule_type=RuleType.CORRELATION,
        name="VPS intrusion pattern",
        description=(
            "Auth events + file integrity/cron changes on a single VPS "
            "within 1 hour = potential breach"
        ),
        conditions=(
            CorrelationCondition(
                event_types=frozenset({"remote.auth_log"}),
                severities=frozenset({"alert", "critical", "high"}),
                min_count=5,
            ),
            CorrelationCondition(
                event_types=frozenset({"remote.file_integrity", "remote.cron_monitor"}),
                min_count=1,
            ),
        ),
        window_seconds=3600,
        cooldown_seconds=3600,
        group_by_asset=True,
    ),
]


# ── Engine ───────────────────────────────────────────────────────────


class ThresholdEngine:
    """Threshold/Correlation Engine (Level 2 escalation, Trigger 3c).

    Subscribes to EventAggregator (sync callback), evaluates events
    against configurable threshold rules, and escalates breached
    thresholds to SecureChat for AI analysis.

    Pure automation — no AI tokens consumed until a breach promotes
    the pattern to SCS.

    Args:
        aggregator: EventAggregator instance to subscribe to.
        chat_manager: ChatManager for sending escalation messages.
        loop: asyncio event loop for sync-to-async bridging.
        rules: Optional list of ThresholdRule; uses DEFAULT_RULES if None.
    """

    def __init__(
        self,
        aggregator: "EventAggregator",
        chat_manager: "ChatManager",
        loop: Optional[asyncio.AbstractEventLoop] = None,
        rules: Optional[List[ThresholdRule]] = None,
    ):
        self._aggregator = aggregator
        self._chat = chat_manager
        self._loop = loop
        self._rules = list(rules) if rules is not None else list(DEFAULT_RULES)

        # counter_key → group_key → [monotonic timestamps]
        self._counters: Dict[str, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._counter_lock = threading.Lock()

        # Cooldown: "rule_id:group_key" → monotonic time of last fire
        self._cooldowns: Dict[str, float] = {}

        # Breach buffer
        self._breach_buffer: List[BreachRecord] = []
        self._breach_lock = threading.Lock()

        # Dedup: "rule_id:group_key" → monotonic time of last escalation
        self._breach_dedup: Dict[str, float] = {}

        # Rate limiting
        self._escalation_count = 0
        self._hour_start = time.monotonic()

        self._running = False
        self._sweep_task: Optional[asyncio.Future] = None

    # ── Lifecycle ────────────────────────────────────────────────────

    def start(self):
        """Subscribe to EventAggregator and start the periodic sweep."""
        if self._running:
            return

        self._running = True
        self._aggregator.subscribe(self._on_event)

        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._running = False
                raise RuntimeError(
                    "ThresholdEngine.start() requires an explicit event loop "
                    "when called outside an async context. Pass loop= to __init__."
                )

        self._sweep_task = asyncio.run_coroutine_threadsafe(
            self._sweep_loop(), self._loop
        )
        logger.info(
            "ThresholdEngine started (%d rules, eval=%ds, rate=%d/hr)",
            len(self._rules),
            EVAL_INTERVAL_SECONDS,
            RATE_LIMIT_PER_HOUR,
        )

    def stop(self):
        """Stop the sweep loop and clean up."""
        with self._breach_lock:
            self._running = False
        if self._sweep_task and not self._sweep_task.done():
            self._sweep_task.cancel()
        logger.info("ThresholdEngine stopped")

    # ── Event callback (sync) ────────────────────────────────────────

    def _on_event(self, event: AggregatedEvent) -> None:
        """Sync callback from EventAggregator. Records event in
        per-rule counters and checks COUNT rules for breach."""
        now = time.monotonic()

        for rule in self._rules:
            if rule.rule_type == RuleType.COUNT:
                if not _matches_fields(
                    event, rule.event_types, rule.categories, rule.severities
                ):
                    continue
                group_key = _group_key(event, rule)
                with self._counter_lock:
                    self._counters[rule.rule_id][group_key].append(now)
                    cutoff = now - rule.window_seconds
                    self._counters[rule.rule_id][group_key] = [
                        t for t in self._counters[rule.rule_id][group_key]
                        if t > cutoff
                    ]
                self._check_count_rule(rule, group_key, event, now)

            elif rule.rule_type == RuleType.CORRELATION:
                group_key = _group_key(event, rule)
                for i, cond in enumerate(rule.conditions):
                    if _matches_fields(
                        event, cond.event_types, cond.categories, cond.severities
                    ):
                        cond_key = f"{rule.rule_id}:cond:{i}"
                        with self._counter_lock:
                            self._counters[cond_key][group_key].append(now)
                            cutoff = now - rule.window_seconds
                            self._counters[cond_key][group_key] = [
                                t for t in self._counters[cond_key][group_key]
                                if t > cutoff
                            ]

    def _check_count_rule(
        self,
        rule: ThresholdRule,
        group_key: str,
        trigger_event: AggregatedEvent,
        now: float,
    ) -> None:
        """Check if a COUNT rule's threshold has been breached."""
        with self._counter_lock:
            count = len(self._counters[rule.rule_id][group_key])

        if count < rule.threshold:
            return

        cd_key = f"{rule.rule_id}:{group_key}"

        with self._counter_lock:
            # Cooldown check
            last_fire = self._cooldowns.get(cd_key)
            if last_fire is not None and (now - last_fire) < rule.cooldown_seconds:
                return

            # Dedup check
            last_dedup = self._breach_dedup.get(cd_key)
            if last_dedup is not None and (now - last_dedup) < DEDUP_WINDOW_SECONDS:
                return

            self._cooldowns[cd_key] = now
            self._breach_dedup[cd_key] = now

        breach = BreachRecord(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            asset_id=trigger_event.asset_id,
            breach_time=now,
            event_count=count,
            sample_messages=[trigger_event.message[:100]],
            breach_description=(
                f"{count} events in {_format_window(rule.window_seconds)} "
                f"(threshold: {rule.threshold})"
            ),
        )
        with self._breach_lock:
            self._breach_buffer.append(breach)

    # ── Periodic sweep (async) ───────────────────────────────────────

    async def _sweep_loop(self):
        """Periodically evaluate CORRELATION rules and flush breaches."""
        try:
            while self._running:
                await asyncio.sleep(EVAL_INTERVAL_SECONDS)
                self._evict_stale_entries()
                self._evaluate_correlation_rules()
                if self._breach_buffer:
                    await self._flush_breaches()
        except asyncio.CancelledError:
            if self._breach_buffer and self._loop and not self._loop.is_closed():
                try:
                    await self._flush_breaches()
                except Exception:
                    logger.warning(
                        "Final breach flush on shutdown failed", exc_info=True
                    )

    def _evict_stale_entries(self) -> None:
        """Remove expired cooldown/dedup entries and empty counter groups."""
        now = time.monotonic()
        max_cooldown = max(
            (r.cooldown_seconds for r in self._rules), default=3600
        )

        with self._counter_lock:
            # Evict stale cooldowns
            stale = [
                k for k, ts in self._cooldowns.items()
                if (now - ts) > max_cooldown
            ]
            for k in stale:
                del self._cooldowns[k]

            # Evict stale dedup entries
            dedup_cutoff = now - DEDUP_WINDOW_SECONDS
            stale = [
                k for k, ts in self._breach_dedup.items()
                if ts < dedup_cutoff
            ]
            for k in stale:
                del self._breach_dedup[k]

            # Remove empty counter groups
            for rule_key in list(self._counters.keys()):
                for group_key in list(self._counters[rule_key].keys()):
                    if not self._counters[rule_key][group_key]:
                        del self._counters[rule_key][group_key]

    def _evaluate_correlation_rules(self) -> None:
        """Check all CORRELATION rules for compound pattern breaches."""
        now = time.monotonic()

        for rule in self._rules:
            if rule.rule_type != RuleType.CORRELATION:
                continue

            # Collect group_keys across all condition sub-counters
            with self._counter_lock:
                group_keys: Set[str] = set()
                for i in range(len(rule.conditions)):
                    cond_key = f"{rule.rule_id}:cond:{i}"
                    group_keys.update(self._counters.get(cond_key, {}).keys())

            for group_key in group_keys:
                cd_key = f"{rule.rule_id}:{group_key}"
                with self._counter_lock:
                    last_fire = self._cooldowns.get(cd_key)
                if last_fire is not None and (now - last_fire) < rule.cooldown_seconds:
                    continue

                all_met = True
                total_events = 0

                for i, cond in enumerate(rule.conditions):
                    cond_key = f"{rule.rule_id}:cond:{i}"
                    with self._counter_lock:
                        cutoff = now - rule.window_seconds
                        timestamps = self._counters.get(cond_key, {}).get(
                            group_key, []
                        )
                        timestamps = [t for t in timestamps if t > cutoff]
                        if cond_key in self._counters:
                            self._counters[cond_key][group_key] = timestamps
                        count = len(timestamps)

                    if count < cond.min_count:
                        all_met = False
                        break
                    total_events += count

                if not all_met:
                    continue

                with self._counter_lock:
                    # Dedup check
                    last_dedup = self._breach_dedup.get(cd_key)
                    if last_dedup is not None and (now - last_dedup) < DEDUP_WINDOW_SECONDS:
                        continue

                    self._cooldowns[cd_key] = now
                    self._breach_dedup[cd_key] = now

                cond_names = [
                    ", ".join(sorted(c.event_types)) for c in rule.conditions
                ]
                breach = BreachRecord(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    asset_id=group_key if group_key != "_global_" else None,
                    breach_time=now,
                    event_count=total_events,
                    sample_messages=[],
                    breach_description=(
                        f"Correlated pattern: {' + '.join(cond_names)} "
                        f"within {_format_window(rule.window_seconds)}"
                    ),
                )
                with self._breach_lock:
                    self._breach_buffer.append(breach)

    async def _flush_breaches(self):
        """Send breach summary to SecureChat."""
        now = time.monotonic()
        if now - self._hour_start >= RATE_LIMIT_WINDOW:
            self._escalation_count = 0
            self._hour_start = now

        if self._escalation_count >= RATE_LIMIT_PER_HOUR:
            with self._breach_lock:
                dropped = len(self._breach_buffer)
                self._breach_buffer.clear()
            if dropped:
                logger.warning(
                    "ThresholdEngine rate limit reached (%d/hr), "
                    "dropped %d breach(es)",
                    RATE_LIMIT_PER_HOUR,
                    dropped,
                )
            return

        with self._breach_lock:
            breaches = self._breach_buffer[:]
            self._breach_buffer.clear()

        if not breaches:
            return

        summary = _format_breach_summary(breaches)

        try:
            from .message import MessageType

            await self._chat.send_system(summary, MessageType.EVENT)
            self._escalation_count += 1
            logger.info(
                "Threshold breach escalation sent: %d breach(es)", len(breaches)
            )
        except Exception:
            logger.exception("Failed to send threshold breach to chat")
            with self._breach_lock:
                self._breach_buffer.extend(breaches)

    # ── Introspection ────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._running

    @property
    def escalation_count(self) -> int:
        return self._escalation_count

    @property
    def breach_buffer_size(self) -> int:
        with self._breach_lock:
            return len(self._breach_buffer)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_counter(self, rule_id: str, group_key: str = "_global_") -> int:
        """Current event count for a rule+group (for testing/debug)."""
        with self._counter_lock:
            return len(self._counters.get(rule_id, {}).get(group_key, []))


# ── Helpers ──────────────────────────────────────────────────────────


def _matches_fields(
    event: AggregatedEvent,
    event_types: FrozenSet[str],
    categories: FrozenSet[EventCategory],
    severities: FrozenSet[str],
) -> bool:
    """Check if an event matches a set of filter fields.
    Empty sets mean 'match all'.
    """
    if event_types and event.event_type not in event_types:
        return False
    if categories and event.category not in categories:
        return False
    if severities and event.severity.lower() not in severities:
        return False
    return True


def _group_key(event: AggregatedEvent, rule: ThresholdRule) -> str:
    """Build the grouping key for per-asset or global counting."""
    if rule.group_by_asset:
        return event.asset_id or "local"
    return "_global_"


def _format_window(seconds: int) -> str:
    """Format a window size as a human-readable string."""
    if seconds >= 86400:
        return f"{seconds // 86400}d"
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _format_breach_summary(breaches: List[BreachRecord]) -> str:
    """Format breach records as text for SecureChat.

    MUST contain "critical" or "high" keywords to trigger AI Bridge.
    """
    count = len(breaches)
    lines = [f"[Threshold Breach] {count} critical/high pattern(s) detected"]

    for breach in breaches[:5]:
        asset_label = breach.asset_id or "local"
        lines.append(
            f"  - {breach.rule_name} on {asset_label}: "
            f"{breach.breach_description}"
        )
        for msg in breach.sample_messages[:2]:
            lines.append(f"    > {msg}")

    if count > 5:
        lines.append(f"  (+{count - 5} more breach(es))")

    lines.append(
        "Analyze these threshold breaches and recommend "
        "defensive actions for critical and high-priority patterns."
    )
    return "\n".join(lines)
