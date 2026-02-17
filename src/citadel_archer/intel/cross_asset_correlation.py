# PRD: Intel Module - Cross-Asset Threat Correlation
# Reference: docs/PRD.md v0.3.14
#
# Detects multi-asset threat patterns by tracking indicators (IPs,
# domains, hashes) and event signatures across all managed assets.
#
# Four correlation patterns:
#   1. Shared IOC — same indicator on 2+ assets within a time window
#   2. Attack Propagation — high-sev events on asset A then B
#   3. Coordinated Attack — similar event types on 3+ assets simultaneously
#   4. Intel Match — event details match known IOCs from IntelStore
#
# Escalates correlated threats to SecureChat for AI analysis via a
# batch flush loop (mirrors ThresholdEngine / RemoteShieldEscalation).
#
# Design principles:
#   - Subscribes to EventAggregator (sync callback)
#   - In-memory sliding windows (bounded), not DB queries per event
#   - Dedup + rate limiting to prevent alert fatigue
#   - Thread-safe (aggregator callbacks from any thread)

import asyncio
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, TYPE_CHECKING
from uuid import uuid4

from .event_aggregator import AggregatedEvent, EventCategory

if TYPE_CHECKING:
    from .event_aggregator import EventAggregator
    from .store import IntelStore
    from ..chat.chat_manager import ChatManager

logger = logging.getLogger(__name__)


# ── Tuning Constants ────────────────────────────────────────────────


# Sliding window for tracking indicators across assets
INDICATOR_WINDOW_SECONDS = 3600  # 1 hour
# Coordinated attack detection: narrow window
COORDINATED_WINDOW_SECONDS = 600  # 10 minutes
# Propagation detection window
PROPAGATION_WINDOW_SECONDS = 1800  # 30 minutes

# Minimum assets for coordinated attack detection
MIN_COORDINATED_ASSETS = 3
# Minimum assets for shared IOC detection
MIN_SHARED_IOC_ASSETS = 2

# Batch flush interval for escalation
FLUSH_INTERVAL_SECONDS = 30
# Dedup: same correlation not re-escalated within this window
DEDUP_WINDOW_SECONDS = 600  # 10 minutes
# Rate limit for escalation messages
RATE_LIMIT_PER_HOUR = 10
RATE_LIMIT_WINDOW = 3600

# Max indicator entries per type to prevent unbounded growth
MAX_INDICATOR_ENTRIES = 5000
# Max events in per-asset sliding window
MAX_EVENTS_PER_ASSET = 500


# ── Data Models ─────────────────────────────────────────────────────


class CorrelationType(str, Enum):
    """Types of cross-asset threat correlations."""

    SHARED_IOC = "shared_ioc"
    ATTACK_PROPAGATION = "propagation"
    COORDINATED_ATTACK = "coordinated"
    INTEL_MATCH = "intel_match"


@dataclass
class CorrelatedThreat:
    """A detected cross-asset correlation."""

    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    correlation_type: CorrelationType = CorrelationType.SHARED_IOC
    severity: str = "high"
    affected_assets: List[str] = field(default_factory=list)
    indicator: str = ""
    event_count: int = 0
    sample_events: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "correlation_type": self.correlation_type.value,
            "severity": self.severity,
            "affected_assets": self.affected_assets,
            "indicator": self.indicator,
            "event_count": self.event_count,
            "sample_events": self.sample_events[:5],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
        }


# ── Indicator Extraction ────────────────────────────────────────────

# Detail fields that contain IP addresses
_IP_FIELDS = ("ip", "ip_address", "source_ip", "src_ip", "remote_ip", "host")
# Detail fields that contain domains
_DOMAIN_FIELDS = ("domain", "hostname", "fqdn", "target")
# Detail fields that contain file hashes
_HASH_FIELDS = ("hash", "sha256", "sha1", "md5", "file_hash")

# Event types that indicate high-severity activity for propagation detection
_HIGH_SEVERITY_TYPES: FrozenSet[str] = frozenset({
    "remote.auth_log",
    "remote.file_integrity",
    "remote.cron_monitor",
    "process.suspicious",
    "file.quarantined",
    "network.blocked",
})


def extract_indicators(event: AggregatedEvent) -> Dict[str, Set[str]]:
    """Extract IOC indicators from event details.

    Returns a dict of indicator_type → set of values.
    E.g. {"ip": {"1.2.3.4"}, "domain": {"evil.com"}}
    """
    indicators: Dict[str, Set[str]] = defaultdict(set)
    details = event.details or {}

    for f in _IP_FIELDS:
        val = details.get(f)
        if val and isinstance(val, str) and val.strip():
            indicators["ip"].add(val.strip())

    for f in _DOMAIN_FIELDS:
        val = details.get(f)
        if val and isinstance(val, str) and val.strip():
            indicators["domain"].add(val.strip())

    for f in _HASH_FIELDS:
        val = details.get(f)
        if val and isinstance(val, str) and val.strip():
            indicators["hash"].add(val.strip())

    return dict(indicators)


# ── Sliding Window Entry ────────────────────────────────────────────


@dataclass
class IndicatorSighting:
    """A sighting of an indicator on a specific asset."""

    asset_id: str
    timestamp: float  # monotonic
    event_type: str
    severity: str
    iso_timestamp: str  # for reporting


@dataclass
class AssetEventEntry:
    """A recent event on an asset (for coordinated/propagation detection)."""

    event_type: str
    severity: str
    timestamp: float  # monotonic
    iso_timestamp: str
    category: EventCategory


# ── Cross-Asset Correlator ──────────────────────────────────────────


class CrossAssetCorrelator:
    """Detects threat patterns spanning multiple managed assets.

    Subscribes to EventAggregator (sync callback), tracks indicators
    across assets, and escalates correlated threats to SecureChat.

    Args:
        aggregator: EventAggregator to subscribe to.
        chat_manager: Optional ChatManager for escalation.
        intel_store: Optional IntelStore for IOC matching.
        loop: asyncio event loop for sync→async bridging.
    """

    def __init__(
        self,
        aggregator: "EventAggregator",
        chat_manager: Optional["ChatManager"] = None,
        intel_store: Optional["IntelStore"] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self._aggregator = aggregator
        self._chat = chat_manager
        self._intel_store = intel_store
        self._loop = loop
        self._ws_broadcast: Optional[Callable] = None
        self._alert_propagation_callback: Optional[Callable] = None

        # indicator_type:value → [IndicatorSighting, ...]
        self._indicator_map: Dict[str, List[IndicatorSighting]] = defaultdict(list)
        self._indicator_lock = threading.Lock()

        # asset_id → [AssetEventEntry, ...] (bounded deque-like list)
        self._asset_events: Dict[str, List[AssetEventEntry]] = defaultdict(list)
        self._asset_events_lock = threading.Lock()

        # Correlation output buffer
        self._threat_buffer: List[CorrelatedThreat] = []
        self._threat_lock = threading.Lock()

        # Dedup: dedup_key → monotonic time of last escalation
        self._dedup_cache: Dict[str, float] = {}
        self._dedup_lock = threading.Lock()

        # Rate limiting (protected by _threat_lock)
        self._escalation_count = 0
        self._hour_start = time.monotonic()

        # History of detected correlations (for querying)
        self._history: List[CorrelatedThreat] = []
        self._history_lock = threading.Lock()
        self._max_history = 200

        self._running = False
        self._flush_task: Optional[asyncio.Future] = None

    # ── Lifecycle ────────────────────────────────────────────────────

    def start(self):
        """Subscribe to EventAggregator and start the flush loop."""
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
                    "CrossAssetCorrelator.start() requires an explicit event loop "
                    "when called outside an async context. Pass loop= to __init__."
                )

        self._flush_task = asyncio.run_coroutine_threadsafe(
            self._flush_loop(), self._loop
        )
        logger.info(
            "CrossAssetCorrelator started (shared_ioc=%ds, coordinated=%ds, "
            "propagation=%ds, rate=%d/hr)",
            INDICATOR_WINDOW_SECONDS,
            COORDINATED_WINDOW_SECONDS,
            PROPAGATION_WINDOW_SECONDS,
            RATE_LIMIT_PER_HOUR,
        )

    def stop(self):
        """Stop the flush loop and clean up."""
        with self._threat_lock:
            self._running = False
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
        logger.info("CrossAssetCorrelator stopped")

    # ── Event Callback (sync) ────────────────────────────────────────

    def _on_event(self, event: AggregatedEvent) -> None:
        """Sync callback from EventAggregator."""
        if not event.asset_id:
            return  # Cannot correlate without asset attribution

        now = time.monotonic()
        iso_ts = event.timestamp or datetime.utcnow().isoformat()

        # 1. Record event in per-asset window
        self._record_asset_event(event, now, iso_ts)

        # 2. Extract and track indicators
        indicators = extract_indicators(event)
        for ind_type, values in indicators.items():
            for value in values:
                self._record_indicator(
                    ind_type, value, event.asset_id, event.event_type,
                    event.severity, now, iso_ts,
                )

        # 3. Check for shared IOC across assets
        for ind_type, values in indicators.items():
            for value in values:
                self._check_shared_ioc(ind_type, value, now)

        # 4. Check for coordinated attack patterns
        self._check_coordinated_attack(event, now, iso_ts)

        # 5. Check for attack propagation
        if event.severity.lower() in ("critical", "alert", "high"):
            self._check_propagation(event, now, iso_ts)

        # 6. Check intel store for known IOC matches
        if self._intel_store:
            self._check_intel_match(event, indicators, iso_ts)

    # ── Indicator Tracking ───────────────────────────────────────────

    def _record_indicator(
        self,
        ind_type: str,
        value: str,
        asset_id: str,
        event_type: str,
        severity: str,
        now: float,
        iso_ts: str,
    ) -> None:
        """Record an indicator sighting."""
        key = f"{ind_type}:{value}"
        sighting = IndicatorSighting(
            asset_id=asset_id,
            timestamp=now,
            event_type=event_type,
            severity=severity,
            iso_timestamp=iso_ts,
        )

        with self._indicator_lock:
            entries = self._indicator_map[key]
            entries.append(sighting)

            # Evict old entries
            cutoff = now - INDICATOR_WINDOW_SECONDS
            self._indicator_map[key] = [
                s for s in entries if s.timestamp > cutoff
            ]

            # Bound total size
            if len(self._indicator_map[key]) > MAX_INDICATOR_ENTRIES:
                self._indicator_map[key] = self._indicator_map[key][-MAX_INDICATOR_ENTRIES:]

    def _record_asset_event(
        self,
        event: AggregatedEvent,
        now: float,
        iso_ts: str,
    ) -> None:
        """Record an event in the per-asset sliding window."""
        entry = AssetEventEntry(
            event_type=event.event_type,
            severity=event.severity,
            timestamp=now,
            iso_timestamp=iso_ts,
            category=event.category,
        )

        with self._asset_events_lock:
            events = self._asset_events[event.asset_id]
            events.append(entry)

            # Evict old entries (use the longest window)
            cutoff = now - max(
                COORDINATED_WINDOW_SECONDS,
                PROPAGATION_WINDOW_SECONDS,
                INDICATOR_WINDOW_SECONDS,
            )
            self._asset_events[event.asset_id] = [
                e for e in events if e.timestamp > cutoff
            ]

            # Bound per-asset size
            if len(self._asset_events[event.asset_id]) > MAX_EVENTS_PER_ASSET:
                self._asset_events[event.asset_id] = (
                    self._asset_events[event.asset_id][-MAX_EVENTS_PER_ASSET:]
                )

    # ── Correlation Checks ───────────────────────────────────────────

    def _check_shared_ioc(
        self, ind_type: str, value: str, now: float
    ) -> None:
        """Check if an indicator has been seen on multiple assets."""
        key = f"{ind_type}:{value}"
        dedup_key = f"shared_ioc:{key}"

        # Dedup check first (outside main lock)
        if self._is_deduped(dedup_key, now):
            return

        with self._indicator_lock:
            sightings = self._indicator_map.get(key, [])
            cutoff = now - INDICATOR_WINDOW_SECONDS
            recent = [s for s in sightings if s.timestamp > cutoff]

        # Count distinct assets
        asset_ids = list(dict.fromkeys(s.asset_id for s in recent))
        if len(asset_ids) < MIN_SHARED_IOC_ASSETS:
            return

        # Determine highest severity
        severities = [s.severity.lower() for s in recent]
        severity = _highest_severity(severities)

        first_ts = min(s.iso_timestamp for s in recent)
        last_ts = max(s.iso_timestamp for s in recent)

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity=severity,
            affected_assets=asset_ids,
            indicator=f"{ind_type}:{value}",
            event_count=len(recent),
            sample_events=[
                {"asset": s.asset_id, "type": s.event_type, "time": s.iso_timestamp}
                for s in recent[:5]
            ],
            first_seen=first_ts,
            last_seen=last_ts,
            description=(
                f"Shared {ind_type} indicator '{value}' seen on "
                f"{len(asset_ids)} assets: {', '.join(asset_ids[:5])}"
            ),
        )

        self._mark_dedup(dedup_key, now)
        self._emit_threat(threat)

    def _check_coordinated_attack(
        self, event: AggregatedEvent, now: float, iso_ts: str
    ) -> None:
        """Check if similar events are hitting 3+ assets simultaneously."""
        event_type = event.event_type
        dedup_key = f"coordinated:{event_type}"

        if self._is_deduped(dedup_key, now):
            return

        cutoff = now - COORDINATED_WINDOW_SECONDS
        assets_with_type: Dict[str, int] = {}

        with self._asset_events_lock:
            for asset_id, events in self._asset_events.items():
                matching = [
                    e for e in events
                    if e.event_type == event_type and e.timestamp > cutoff
                ]
                if matching:
                    assets_with_type[asset_id] = len(matching)

        if len(assets_with_type) < MIN_COORDINATED_ASSETS:
            return

        total_events = sum(assets_with_type.values())
        asset_ids = list(assets_with_type.keys())

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.COORDINATED_ATTACK,
            severity="critical",
            affected_assets=asset_ids,
            indicator=event_type,
            event_count=total_events,
            sample_events=[
                {"asset": aid, "count": cnt}
                for aid, cnt in list(assets_with_type.items())[:5]
            ],
            first_seen=iso_ts,
            last_seen=iso_ts,
            description=(
                f"Coordinated {event_type} events on {len(asset_ids)} assets "
                f"within {COORDINATED_WINDOW_SECONDS}s: "
                f"{', '.join(asset_ids[:5])}"
            ),
        )

        self._mark_dedup(dedup_key, now)
        self._emit_threat(threat)

    def _check_propagation(
        self, event: AggregatedEvent, now: float, iso_ts: str
    ) -> None:
        """Check for attack propagation: high-sev events spreading A→B."""
        cutoff = now - PROPAGATION_WINDOW_SECONDS

        # Find other assets with recent high-severity events
        other_assets_affected: List[str] = []

        with self._asset_events_lock:
            for asset_id, events in self._asset_events.items():
                if asset_id == event.asset_id:
                    continue
                high_sev = [
                    e for e in events
                    if e.severity.lower() in ("critical", "alert", "high")
                    and e.event_type in _HIGH_SEVERITY_TYPES
                    and e.timestamp > cutoff
                ]
                if high_sev:
                    other_assets_affected.append(asset_id)

        if not other_assets_affected:
            return

        all_affected = [event.asset_id] + other_assets_affected
        dedup_key = f"propagation:{':'.join(sorted(all_affected))}"

        if self._is_deduped(dedup_key, now):
            return

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.ATTACK_PROPAGATION,
            severity="critical",
            affected_assets=all_affected,
            indicator=event.event_type,
            event_count=len(all_affected),
            sample_events=[
                {"asset": event.asset_id, "type": event.event_type, "time": iso_ts}
            ],
            first_seen=iso_ts,
            last_seen=iso_ts,
            description=(
                f"Attack propagation detected: high-severity {event.event_type} "
                f"events spreading across {len(all_affected)} assets "
                f"within {PROPAGATION_WINDOW_SECONDS}s"
            ),
        )

        self._mark_dedup(dedup_key, now)
        self._emit_threat(threat)

    def _check_intel_match(
        self,
        event: AggregatedEvent,
        indicators: Dict[str, Set[str]],
        iso_ts: str,
    ) -> None:
        """Check event indicators against known IOCs in IntelStore."""
        if not self._intel_store:
            return

        now = time.monotonic()

        for ind_type, values in indicators.items():
            for value in values:
                dedup_key = f"intel_match:{ind_type}:{value}"
                if self._is_deduped(dedup_key, now):
                    continue

                # Check IntelStore for this indicator
                if self._intel_store.has_key(f"ioc:{ind_type}:{value}"):
                    threat = CorrelatedThreat(
                        correlation_type=CorrelationType.INTEL_MATCH,
                        severity="high",
                        affected_assets=[event.asset_id] if event.asset_id else [],
                        indicator=f"{ind_type}:{value}",
                        event_count=1,
                        sample_events=[
                            {
                                "asset": event.asset_id or "unknown",
                                "type": event.event_type,
                                "time": iso_ts,
                            }
                        ],
                        first_seen=iso_ts,
                        last_seen=iso_ts,
                        description=(
                            f"Known malicious {ind_type} '{value}' matched from "
                            f"threat intel on asset {event.asset_id}"
                        ),
                    )
                    self._mark_dedup(dedup_key, now)
                    self._emit_threat(threat)

    # ── Dedup Helpers ────────────────────────────────────────────────

    def _is_deduped(self, key: str, now: float) -> bool:
        """Check if a correlation key was recently escalated."""
        with self._dedup_lock:
            last = self._dedup_cache.get(key)
            return last is not None and (now - last) < DEDUP_WINDOW_SECONDS

    def _mark_dedup(self, key: str, now: float) -> None:
        """Record that a correlation was just detected."""
        with self._dedup_lock:
            self._dedup_cache[key] = now

    def set_ws_broadcast(self, callback: Callable) -> None:
        """Set a WebSocket broadcast callback for real-time unified timeline."""
        self._ws_broadcast = callback

    def set_alert_propagation(self, callback: Callable) -> None:
        """Set callback to propagate alerts to affected remote agents."""
        self._alert_propagation_callback = callback

    def _emit_threat(self, threat: CorrelatedThreat) -> None:
        """Add a correlated threat to the buffer and history."""
        with self._threat_lock:
            self._threat_buffer.append(threat)

        with self._history_lock:
            self._history.append(threat)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

        # Broadcast to main WebSocket for unified timeline (best-effort)
        if self._ws_broadcast and self._loop and not self._loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    self._ws_broadcast({
                        "type": "threat:correlation",
                        "data": threat.to_dict(),
                    }),
                    self._loop,
                )
            except Exception:
                pass  # best-effort; never break correlation pipeline

        # Propagate alert to affected remote agents (best-effort)
        if self._alert_propagation_callback and threat.affected_assets:
            try:
                self._alert_propagation_callback(threat)
            except Exception:
                logger.debug(
                    "Alert propagation callback failed for correlation %s",
                    threat.correlation_id,
                    exc_info=True,
                )

    # ── Batch Flush Loop (async) ─────────────────────────────────────

    async def _flush_loop(self):
        """Periodically flush correlated threats as escalation messages."""
        try:
            while self._running:
                await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
                self._evict_stale_entries()
                if self._threat_buffer:
                    await self._flush_threats()
        except asyncio.CancelledError:
            if self._threat_buffer and self._loop and not self._loop.is_closed():
                try:
                    await self._flush_threats()
                except Exception:
                    logger.warning(
                        "Final correlation flush on shutdown failed",
                        exc_info=True,
                    )

    def _evict_stale_entries(self) -> None:
        """Remove expired dedup entries, old indicator sightings, and stale asset events."""
        now = time.monotonic()

        # Evict stale dedup entries
        with self._dedup_lock:
            dedup_cutoff = now - DEDUP_WINDOW_SECONDS
            stale = [k for k, ts in self._dedup_cache.items() if ts < dedup_cutoff]
            for k in stale:
                del self._dedup_cache[k]

        # Evict stale indicator sightings
        ind_cutoff = now - INDICATOR_WINDOW_SECONDS
        with self._indicator_lock:
            empty_keys = []
            for key, sightings in self._indicator_map.items():
                self._indicator_map[key] = [
                    s for s in sightings if s.timestamp > ind_cutoff
                ]
                if not self._indicator_map[key]:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._indicator_map[key]

        # Evict stale per-asset event entries
        asset_cutoff = now - max(
            COORDINATED_WINDOW_SECONDS,
            PROPAGATION_WINDOW_SECONDS,
            INDICATOR_WINDOW_SECONDS,
        )
        with self._asset_events_lock:
            empty_assets = []
            for asset_id, events in self._asset_events.items():
                self._asset_events[asset_id] = [
                    e for e in events if e.timestamp > asset_cutoff
                ]
                if not self._asset_events[asset_id]:
                    empty_assets.append(asset_id)
            for asset_id in empty_assets:
                del self._asset_events[asset_id]

    async def _flush_threats(self):
        """Send correlated threat summary to SecureChat."""
        if self._chat is None:
            with self._threat_lock:
                self._threat_buffer.clear()
            return

        # Rate limit check — protected by _threat_lock to prevent
        # concurrent access from CancelledError handler
        with self._threat_lock:
            now = time.monotonic()
            if now - self._hour_start >= RATE_LIMIT_WINDOW:
                self._escalation_count = 0
                self._hour_start = now

            if self._escalation_count >= RATE_LIMIT_PER_HOUR:
                dropped = len(self._threat_buffer)
                self._threat_buffer.clear()
                if dropped:
                    logger.warning(
                        "CrossAssetCorrelator rate limit reached (%d/hr), "
                        "dropped %d threat(s)",
                        RATE_LIMIT_PER_HOUR,
                        dropped,
                    )
                return

            # Drain buffer
            threats = self._threat_buffer[:]
            self._threat_buffer.clear()

        if not threats:
            return

        summary = _format_correlation_summary(threats)

        try:
            from ..chat.message import MessageType

            await self._chat.send_system(summary, MessageType.EVENT)
            with self._threat_lock:
                self._escalation_count += 1
            logger.info(
                "Cross-asset correlation escalation sent: %d threat(s)",
                len(threats),
            )
        except Exception:
            logger.exception(
                "Failed to send cross-asset correlation to chat"
            )
            with self._threat_lock:
                if len(self._threat_buffer) < 200:
                    self._threat_buffer.extend(threats)

    # ── Introspection ────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._running

    @property
    def escalation_count(self) -> int:
        return self._escalation_count

    @property
    def threat_buffer_size(self) -> int:
        with self._threat_lock:
            return len(self._threat_buffer)

    @property
    def indicator_count(self) -> int:
        """Number of distinct indicators being tracked."""
        with self._indicator_lock:
            return len(self._indicator_map)

    @property
    def tracked_assets(self) -> int:
        """Number of assets with recent events."""
        with self._asset_events_lock:
            return len(self._asset_events)

    def recent_correlations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent correlated threats as dicts."""
        with self._history_lock:
            return [t.to_dict() for t in self._history[-limit:]]

    def stats(self) -> Dict[str, Any]:
        """Return correlator statistics."""
        with self._history_lock:
            by_type = defaultdict(int)
            for t in self._history:
                by_type[t.correlation_type.value] += 1

        return {
            "running": self._running,
            "indicator_count": self.indicator_count,
            "tracked_assets": self.tracked_assets,
            "threat_buffer_size": self.threat_buffer_size,
            "escalation_count": self._escalation_count,
            "total_correlations": len(self._history),
            "by_type": dict(by_type),
        }


# ── Helpers ─────────────────────────────────────────────────────────


_SEVERITY_RANK = {
    "critical": 4,
    "alert": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _highest_severity(severities: List[str]) -> str:
    """Return the highest severity from a list."""
    if not severities:
        return "medium"
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))


def _format_correlation_summary(threats: List[CorrelatedThreat]) -> str:
    """Format correlated threats as text for SecureChat.

    MUST contain "critical" or "high" to trigger AI Bridge.
    """
    count = len(threats)
    lines = [
        f"[Cross-Asset Correlation] {count} critical/high "
        f"multi-asset threat(s) detected"
    ]

    for threat in threats[:5]:
        assets_str = ", ".join(threat.affected_assets[:4])
        if len(threat.affected_assets) > 4:
            assets_str += f" (+{len(threat.affected_assets) - 4} more)"
        lines.append(
            f"  - [{threat.correlation_type.value}] {threat.description}"
        )
        lines.append(f"    Assets: {assets_str}")

    if count > 5:
        lines.append(f"  (+{count - 5} more correlation(s))")

    lines.append(
        "Analyze these cross-asset correlations and recommend "
        "defensive actions for critical and high-priority patterns."
    )
    return "\n".join(lines)
