# PRD: Intel Module - Event Aggregator
# Reference: PHASE_2_SPEC.md
#
# Collects all Phase 1 security events (file, process, network, vault,
# system), attributes them to assets, and maintains an in-memory
# event history with querying capabilities.
#
# Designed to subscribe to the core EventType bus so every event
# flows through a single aggregation point.

import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional
from uuid import uuid4


class EventCategory(str, Enum):
    """High-level event category for aggregation."""

    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    VAULT = "vault"
    SYSTEM = "system"
    AI = "ai"
    USER = "user"
    INTEL = "intel"
    REMOTE = "remote"


# Map core EventType values to categories
_EVENT_CATEGORY_MAP: Dict[str, EventCategory] = {
    # File events
    "file.created": EventCategory.FILE,
    "file.modified": EventCategory.FILE,
    "file.deleted": EventCategory.FILE,
    "file.quarantined": EventCategory.FILE,
    # Process events
    "process.started": EventCategory.PROCESS,
    "process.killed": EventCategory.PROCESS,
    "process.suspicious": EventCategory.PROCESS,
    # Network events
    "network.connection": EventCategory.NETWORK,
    "network.blocked": EventCategory.NETWORK,
    # Vault events
    "vault.created": EventCategory.VAULT,
    "vault.unlocked": EventCategory.VAULT,
    "vault.locked": EventCategory.VAULT,
    "vault.unlock.failed": EventCategory.VAULT,
    "vault.password.added": EventCategory.VAULT,
    "vault.password.accessed": EventCategory.VAULT,
    "vault.password.deleted": EventCategory.VAULT,
    "vault.error": EventCategory.VAULT,
    # AI events
    "ai.decision": EventCategory.AI,
    "ai.alert": EventCategory.AI,
    # System events
    "system.start": EventCategory.SYSTEM,
    "system.stop": EventCategory.SYSTEM,
    "system.extension_scan": EventCategory.SYSTEM,
    "system.extension_risk": EventCategory.SYSTEM,
    "system.extension_install": EventCategory.SYSTEM,
    "system.extension_malicious": EventCategory.SYSTEM,
    "security.level.changed": EventCategory.SYSTEM,
    # User events
    "user.login": EventCategory.USER,
    "user.logout": EventCategory.USER,
    "user.override": EventCategory.USER,
    # Remote shield events (VPS agent sensors)
    "remote.auth_log": EventCategory.REMOTE,
    "remote.process_monitor": EventCategory.REMOTE,
    "remote.file_integrity": EventCategory.REMOTE,
    "remote.cron_monitor": EventCategory.REMOTE,
    "remote.network_anomaly": EventCategory.REMOTE,
}


def categorize_event(event_type: str) -> EventCategory:
    """Map an event type string to its category.

    Falls back to prefix matching for remote.* event types, then SYSTEM.
    """
    cat = _EVENT_CATEGORY_MAP.get(event_type)
    if cat:
        return cat
    # Prefix fallback: future remote sensor types auto-categorize
    if event_type.startswith("remote."):
        return EventCategory.REMOTE
    return EventCategory.SYSTEM


@dataclass
class AggregatedEvent:
    """An event record with asset attribution and category tagging."""

    event_id: str = field(default_factory=lambda: str(uuid4()))
    event_type: str = ""
    category: EventCategory = EventCategory.SYSTEM
    severity: str = "info"
    asset_id: Optional[str] = None
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


class EventAggregator:
    """Collects and indexes security events across all assets.

    Maintains a bounded in-memory history (deque) and provides
    query methods by category, asset, severity, and time range.
    Can subscribe to the core event bus so all Phase 1 events
    flow through automatically.

    Args:
        max_history: Maximum events to retain in memory.
    """

    def __init__(self, max_history: int = 10_000):
        self._max_history = max_history
        self._lock = threading.RLock()
        self._events: Deque[AggregatedEvent] = deque(maxlen=max_history)
        self._subscribers: List[Callable[[AggregatedEvent], None]] = []

        # Counters
        self._total_received = 0
        self._by_category: Dict[str, int] = {}
        self._by_asset: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        event_type: str,
        severity: str = "info",
        asset_id: Optional[str] = None,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> AggregatedEvent:
        """Ingest a raw event, categorize it, and store it.

        Returns the created ``AggregatedEvent``.
        """
        category = categorize_event(event_type)
        evt = AggregatedEvent(
            event_type=event_type,
            category=category,
            severity=severity,
            asset_id=asset_id,
            message=message,
            details=details or {},
            timestamp=timestamp or datetime.utcnow().isoformat(),
        )

        with self._lock:
            self._events.append(evt)
            self._total_received += 1
            cat_key = category.value
            self._by_category[cat_key] = self._by_category.get(cat_key, 0) + 1
            if asset_id:
                self._by_asset[asset_id] = self._by_asset.get(asset_id, 0) + 1

        # Notify subscribers (outside lock to avoid deadlocks)
        for sub in self._subscribers:
            try:
                sub(evt)
            except Exception:
                pass  # best-effort

        return evt

    def ingest_bus_event(self, event_data: Dict[str, Any]) -> AggregatedEvent:
        """Ingest an event dict as produced by the core EventBus.

        Convenience adapter for subscribing to the EventBus::

            aggregator = EventAggregator()
            # subscribe to all event types on the bus:
            event_bus.subscribe("*", aggregator.ingest_bus_event)
        """
        return self.ingest(
            event_type=event_data.get("event_type", event_data.get("event", "")),
            severity=event_data.get("severity", "info"),
            asset_id=event_data.get("asset_id"),
            message=event_data.get("message", ""),
            details=event_data.get("details", {}),
            timestamp=event_data.get("timestamp"),
        )

    # ------------------------------------------------------------------
    # Subscriptions (fan-out)
    # ------------------------------------------------------------------

    def subscribe(self, callback: Callable[[AggregatedEvent], None]) -> None:
        """Register a callback invoked for every ingested event."""
        self._subscribers.append(callback)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def recent(self, limit: int = 50) -> List[AggregatedEvent]:
        """Return the most recent events (newest last)."""
        with self._lock:
            items = list(self._events)
        return items[-limit:]

    def by_category(self, category: EventCategory) -> List[AggregatedEvent]:
        """Return events matching a category."""
        with self._lock:
            return [e for e in self._events if e.category == category]

    def by_asset(self, asset_id: str) -> List[AggregatedEvent]:
        """Return events attributed to a specific asset."""
        with self._lock:
            return [e for e in self._events if e.asset_id == asset_id]

    def by_severity(self, severity: str) -> List[AggregatedEvent]:
        """Return events matching a severity level."""
        sev = severity.lower()
        with self._lock:
            return [e for e in self._events if e.severity.lower() == sev]

    def by_event_type(self, event_type: str) -> List[AggregatedEvent]:
        """Return events matching a specific event type string."""
        with self._lock:
            return [e for e in self._events if e.event_type == event_type]

    def since(self, iso_timestamp: str) -> List[AggregatedEvent]:
        """Return events with timestamp >= the given ISO 8601 string."""
        with self._lock:
            return [e for e in self._events if e.timestamp >= iso_timestamp]

    def for_asset_by_category(
        self, asset_id: str, category: EventCategory
    ) -> List[AggregatedEvent]:
        """Return events for a specific asset and category."""
        with self._lock:
            return [
                e for e in self._events
                if e.asset_id == asset_id and e.category == category
            ]

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Number of events currently in history."""
        with self._lock:
            return len(self._events)

    def clear(self) -> int:
        """Clear all events. Returns count removed."""
        with self._lock:
            count = len(self._events)
            self._events.clear()
            return count

    def stats(self) -> Dict[str, Any]:
        """Return aggregator statistics."""
        with self._lock:
            return {
                "total_received": self._total_received,
                "current_size": len(self._events),
                "max_history": self._max_history,
                "by_category": dict(self._by_category),
                "by_asset": dict(self._by_asset),
            }
