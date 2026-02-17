# PRD: Intel Module - Context Engine & Behavior Baseline
# Reference: PHASE_2_SPEC.md
#
# Builds per-asset behavioral baselines from event history using a
# configurable rolling window (default 7 days).  Tracks process spawns,
# file modifications, and network connections per asset, learning
# recurring patterns (e.g. "backup runs daily at 02:00").
#
# New events are compared against the baseline to produce a
# baseline_match (bool) and confidence score (0.0-1.0).
# Handles cold-start gracefully: days 0-6 always match with
# linearly increasing confidence.

import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .event_aggregator import AggregatedEvent, EventCategory


class BehaviorType(str, Enum):
    """Tracked behavior dimensions."""

    PROCESS_SPAWN = "process_spawn"
    FILE_MODIFICATION = "file_modification"
    NETWORK_CONNECTION = "network_connection"
    REMOTE_AUTH = "remote_auth"
    REMOTE_SENSOR = "remote_sensor"


# Map EventCategory values to BehaviorType
_CATEGORY_TO_BEHAVIOR: Dict[EventCategory, BehaviorType] = {
    EventCategory.PROCESS: BehaviorType.PROCESS_SPAWN,
    EventCategory.FILE: BehaviorType.FILE_MODIFICATION,
    EventCategory.NETWORK: BehaviorType.NETWORK_CONNECTION,
    EventCategory.REMOTE: BehaviorType.REMOTE_SENSOR,  # default for remote
}


@dataclass
class PatternEntry:
    """A single observed pattern (e.g. a process name seen at a certain hour)."""

    key: str = ""            # identifier (process name, file path, IP, etc.)
    hour: int = -1           # hour-of-day (0-23) or -1 for "any"
    occurrences: int = 0     # how many times seen in window
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineResult:
    """Output of a baseline comparison."""

    baseline_match: bool = True
    confidence: float = 1.0
    behavior_type: BehaviorType = BehaviorType.PROCESS_SPAWN
    event_key: str = ""
    reason: str = ""
    cold_start: bool = False
    days_of_data: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["behavior_type"] = self.behavior_type.value
        return d


class AssetBaseline:
    """Per-asset behavioral baseline.

    Stores observed patterns for each ``BehaviorType`` and supports
    comparison of new events against learned patterns.
    """

    def __init__(self, asset_id: str, window_days: int = 7):
        self.asset_id = asset_id
        self.window_days = window_days
        # behaviour -> key -> list[PatternEntry]
        self._patterns: Dict[BehaviorType, Dict[str, PatternEntry]] = {
            bt: {} for bt in BehaviorType
        }
        self._event_count = 0
        self._first_event_time: Optional[datetime] = None
        self._last_event_time: Optional[datetime] = None
        # hour-of-day frequency per behavior type: behavior -> hour -> count
        self._hourly: Dict[BehaviorType, Dict[int, int]] = {
            bt: defaultdict(int) for bt in BehaviorType
        }

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    def record(self, behavior: BehaviorType, key: str, timestamp: str) -> None:
        """Record an observed behavior for learning."""
        now_str = timestamp
        try:
            ts = datetime.fromisoformat(now_str)
        except (ValueError, TypeError):
            ts = datetime.utcnow()
            now_str = ts.isoformat()

        self._event_count += 1
        if self._first_event_time is None or ts < self._first_event_time:
            self._first_event_time = ts
        if self._last_event_time is None or ts > self._last_event_time:
            self._last_event_time = ts

        hour = ts.hour
        self._hourly[behavior][hour] += 1

        patterns = self._patterns[behavior]
        if key in patterns:
            entry = patterns[key]
            entry.occurrences += 1
            entry.last_seen = now_str
        else:
            patterns[key] = PatternEntry(
                key=key,
                hour=hour,
                occurrences=1,
                first_seen=now_str,
                last_seen=now_str,
            )

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    @property
    def days_of_data(self) -> int:
        """Number of full days of data collected."""
        if self._first_event_time is None or self._last_event_time is None:
            return 0
        delta = self._last_event_time - self._first_event_time
        return max(0, delta.days)

    @property
    def is_cold_start(self) -> bool:
        """True when we have fewer than ``window_days`` of data."""
        return self.days_of_data < self.window_days

    def compare(self, behavior: BehaviorType, key: str,
                timestamp: Optional[str] = None) -> BaselineResult:
        """Compare a new event against the baseline.

        Returns a ``BaselineResult`` with ``baseline_match`` and
        ``confidence`` (0.0-1.0).  During cold start (days 0 to
        ``window_days - 1``) the result always matches with linearly
        increasing confidence.
        """
        days = self.days_of_data
        cold = self.is_cold_start

        # Cold-start: always match, confidence ramps linearly
        if cold:
            conf = min(1.0, (days + 1) / self.window_days) if self.window_days > 0 else 0.0
            return BaselineResult(
                baseline_match=True,
                confidence=round(conf, 4),
                behavior_type=behavior,
                event_key=key,
                reason="cold_start" if days == 0 else "learning",
                cold_start=True,
                days_of_data=days,
            )

        patterns = self._patterns[behavior]
        entry = patterns.get(key)

        if entry is None:
            # Never seen before → anomaly
            return BaselineResult(
                baseline_match=False,
                confidence=0.9,
                behavior_type=behavior,
                event_key=key,
                reason="unseen_key",
                cold_start=False,
                days_of_data=days,
            )

        # Seen before – compute confidence from frequency
        total_in_type = sum(p.occurrences for p in patterns.values())
        if total_in_type == 0:
            freq_ratio = 0.0
        else:
            freq_ratio = entry.occurrences / total_in_type

        # Also check time-of-day alignment if timestamp provided
        hour_bonus = 0.0
        if timestamp:
            try:
                ts = datetime.fromisoformat(timestamp)
                hour = ts.hour
                hourly = self._hourly[behavior]
                total_hourly = sum(hourly.values())
                if total_hourly > 0 and hourly[hour] > 0:
                    hour_bonus = 0.1 * (hourly[hour] / total_hourly)
            except (ValueError, TypeError):
                pass

        confidence = min(1.0, round(0.5 + freq_ratio * 0.4 + hour_bonus, 4))

        return BaselineResult(
            baseline_match=True,
            confidence=confidence,
            behavior_type=behavior,
            event_key=key,
            reason="pattern_match",
            cold_start=False,
            days_of_data=days,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def known_keys(self, behavior: BehaviorType) -> List[str]:
        """Return all keys recorded for a behavior type."""
        return list(self._patterns[behavior].keys())

    def pattern_count(self, behavior: BehaviorType) -> int:
        """Number of unique patterns for a behavior type."""
        return len(self._patterns[behavior])

    def stats(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "window_days": self.window_days,
            "event_count": self._event_count,
            "days_of_data": self.days_of_data,
            "cold_start": self.is_cold_start,
            "patterns": {
                bt.value: len(self._patterns[bt]) for bt in BehaviorType
            },
        }


class ContextEngine:
    """Behavioral baseline engine across all managed assets.

    Subscribes to an ``EventAggregator`` (optional), maintains per-asset
    ``AssetBaseline`` instances, and provides comparison and querying
    APIs.

    Args:
        window_days: Rolling window size for baselines (default 7).
        max_events: Maximum events retained in the internal history
            (used for window pruning — events beyond the window are
            still reflected in pattern counts).
    """

    def __init__(self, window_days: int = 7, max_events: int = 50_000):
        self._window_days = window_days
        self._max_events = max_events
        self._lock = threading.RLock()
        self._baselines: Dict[str, AssetBaseline] = {}
        self._total_processed = 0
        self._total_anomalies = 0

    # ------------------------------------------------------------------
    # Baseline access
    # ------------------------------------------------------------------

    def _get_or_create(self, asset_id: str) -> AssetBaseline:
        """Return existing baseline or create a fresh one (must hold lock)."""
        if asset_id not in self._baselines:
            self._baselines[asset_id] = AssetBaseline(
                asset_id=asset_id,
                window_days=self._window_days,
            )
        return self._baselines[asset_id]

    def get_baseline(self, asset_id: str) -> Optional[AssetBaseline]:
        """Return baseline for an asset, or None."""
        with self._lock:
            return self._baselines.get(asset_id)

    # ------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------

    @staticmethod
    def _event_key(event: AggregatedEvent) -> str:
        """Extract a meaningful key from an event for pattern tracking."""
        details = event.details or {}

        # For remote auth events, key by detail (e.g. "failed_password")
        if event.category == EventCategory.REMOTE and "auth_log" in event.event_type:
            detail = details.get("detail") or details.get("auth_type", "")
            if detail:
                return f"auth:{detail}"

        # For other remote events, key by sensor name
        if event.category == EventCategory.REMOTE:
            sensor = details.get("sensor") or details.get("check", "")
            if sensor:
                return sensor

        # Try common detail fields in priority order
        for field_name in ("process_name", "process", "name",
                           "file_path", "path", "file",
                           "ip", "ip_address", "host", "domain",
                           "target"):
            val = details.get(field_name)
            if val:
                return str(val)
        # Fallback: use the event_type itself
        return event.event_type

    def process_event(self, event: AggregatedEvent) -> Optional[BaselineResult]:
        """Process an event: learn from it and compare to baseline.

        Only events whose category maps to a tracked ``BehaviorType``
        (PROCESS, FILE, NETWORK, REMOTE) are processed. Others are
        silently ignored (returns None).
        """
        behavior = _CATEGORY_TO_BEHAVIOR.get(event.category)
        if behavior is None:
            return None

        # Granular mapping for remote events
        if event.category == EventCategory.REMOTE:
            if "auth_log" in event.event_type:
                behavior = BehaviorType.REMOTE_AUTH
            else:
                behavior = BehaviorType.REMOTE_SENSOR

        asset_id = event.asset_id or "_global"
        key = self._event_key(event)

        with self._lock:
            baseline = self._get_or_create(asset_id)
            # Compare BEFORE recording so the new event doesn't bias
            result = baseline.compare(behavior, key, event.timestamp)
            # Then learn from it
            baseline.record(behavior, key, event.timestamp)

            self._total_processed += 1
            if not result.baseline_match:
                self._total_anomalies += 1

        return result

    def ingest_aggregated(self, event: AggregatedEvent) -> None:
        """Callback compatible with ``EventAggregator.subscribe()``.

        Processes the event for baseline learning/comparison.  The
        result is not returned (fire-and-forget for subscription use).
        """
        self.process_event(event)

    # ------------------------------------------------------------------
    # Bulk learning
    # ------------------------------------------------------------------

    def learn_from_history(
        self, events: List[AggregatedEvent]
    ) -> int:
        """Bulk-load historical events into baselines.

        Returns the number of events that were relevant (had a mapped
        BehaviorType).
        """
        count = 0
        for event in events:
            behavior = _CATEGORY_TO_BEHAVIOR.get(event.category)
            if behavior is None:
                continue
            # Granular mapping for remote events
            if event.category == EventCategory.REMOTE:
                if "auth_log" in event.event_type:
                    behavior = BehaviorType.REMOTE_AUTH
                else:
                    behavior = BehaviorType.REMOTE_SENSOR
            asset_id = event.asset_id or "_global"
            key = self._event_key(event)
            with self._lock:
                baseline = self._get_or_create(asset_id)
                baseline.record(behavior, key, event.timestamp)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def compare(
        self,
        asset_id: str,
        behavior: BehaviorType,
        key: str,
        timestamp: Optional[str] = None,
    ) -> BaselineResult:
        """Compare a hypothetical event against an asset's baseline."""
        with self._lock:
            baseline = self._get_or_create(asset_id)
            return baseline.compare(behavior, key, timestamp)

    def known_patterns(
        self, asset_id: str, behavior: BehaviorType
    ) -> List[str]:
        """Return known keys for a behavior type on an asset."""
        with self._lock:
            baseline = self._baselines.get(asset_id)
            if baseline is None:
                return []
            return baseline.known_keys(behavior)

    def asset_ids(self) -> List[str]:
        """Return list of asset IDs with baselines."""
        with self._lock:
            return list(self._baselines.keys())

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "window_days": self._window_days,
                "total_processed": self._total_processed,
                "total_anomalies": self._total_anomalies,
                "assets_tracked": len(self._baselines),
                "per_asset": {
                    aid: bl.stats()
                    for aid, bl in self._baselines.items()
                },
            }

    def reset(self, asset_id: Optional[str] = None) -> None:
        """Reset baselines. If ``asset_id`` given, reset only that asset."""
        with self._lock:
            if asset_id:
                self._baselines.pop(asset_id, None)
            else:
                self._baselines.clear()
                self._total_processed = 0
                self._total_anomalies = 0
