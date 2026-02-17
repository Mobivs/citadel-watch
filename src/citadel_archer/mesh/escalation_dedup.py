"""Escalation deduplication — correlate same-attack events from multiple agents.

v0.3.43: When a distributed attack (e.g., brute force across 5 VPS agents)
triggers threshold breaches on each agent independently, the existing
ThresholdEngine generates one escalation PER agent. This module sits at the
mesh level and merges those per-agent escalations into ONE correlated
summary before promoting to SecureChat.

How it works:
    1. Each agent's threshold breach / escalation event is submitted to the
       EscalationDeduplicator via ``submit()``.
    2. Events are grouped by **attack signature** — a fingerprint built
       from the rule_id (or event type pattern) and a configurable time
       window (default 60s).
    3. After the merge window expires, the deduplicator flushes all events
       with the same signature into a single ``MergedEscalation`` that
       lists all affected agents, total event count, and a unified summary.
    4. The merged escalation is delivered via a callback (default: no-op).

Key design:
    - Thread-safe (RLock, matches guardian_updater pattern)
    - Periodic flush via background thread (not asyncio — matches mesh/*
      modules)
    - Configurable merge window, max buffered escalations, and callbacks
    - Zero AI tokens — pure automation / correlation logic

Wiring:
    - The mesh phase-change callback in main.py calls
      ``dedup.submit()`` instead of (or in addition to) sending
      individual escalation messages.
    - ``on_merged(callback)`` subscribers receive MergedEscalation
      objects for final delivery (audit log, WebSocket broadcast, etc.).
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Tuning ──────────────────────────────────────────────────────────

DEFAULT_MERGE_WINDOW = 60       # seconds — wait for all agents to report
DEFAULT_FLUSH_INTERVAL = 15     # seconds — check for expired merge windows
MAX_PENDING_SIGNATURES = 200    # safety cap
MAX_AGENTS_PER_MERGE = 50       # safety cap per signature


# ── Data Models ─────────────────────────────────────────────────────


@dataclass
class EscalationEvent:
    """A single escalation event from one agent.

    Submitted to the deduplicator for correlation with events from
    other agents that share the same attack signature.
    """

    agent_id: str               # Node that detected the event
    rule_id: str                # Threshold rule or event pattern ID
    event_type: str             # e.g., "ssh_brute_force_volume"
    severity: str = "high"      # critical / high / medium / low
    event_count: int = 1        # How many raw events this represents
    message: str = ""           # Human-readable description
    details: Dict = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class MergedEscalation:
    """A deduplicated escalation combining events from multiple agents.

    This is what gets promoted to SecureChat / audit log — one message
    instead of N per-agent duplicates.
    """

    signature: str              # Attack fingerprint
    rule_id: str                # Common rule_id across agents
    event_type: str             # Common event type
    severity: str               # Highest severity across agents
    agents: List[str] = field(default_factory=list)
    total_event_count: int = 0
    agent_details: List[Dict] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    merged_at: str = ""
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "signature": self.signature,
            "rule_id": self.rule_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "agents": self.agents,
            "agent_count": len(self.agents),
            "total_event_count": self.total_event_count,
            "agent_details": self.agent_details,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "merged_at": self.merged_at,
            "message": self.message,
        }


# ── Pending Signature Bucket ───────────────────────────────────────


@dataclass
class _PendingBucket:
    """Internal: collects events sharing the same signature within the
    merge window."""

    signature: str
    rule_id: str
    event_type: str
    events: List[EscalationEvent] = field(default_factory=list)
    created_at: float = 0.0    # monotonic time
    first_ts: str = ""         # wall-clock ISO timestamp


# ── Attack Signature Builder ────────────────────────────────────────


def build_signature(rule_id: str, event_type: str = "") -> str:
    """Build an attack fingerprint from rule/event attributes.

    Events with the same signature from different agents are considered
    duplicates of the same distributed attack.

    Intentionally simple — rule_id already encodes the attack pattern
    (e.g., "ssh_brute_force_volume"). event_type is appended for rules
    that cover multiple event types.
    """
    parts = [rule_id]
    if event_type:
        parts.append(event_type)
    return ":".join(parts)


# ── Severity Ordering ───────────────────────────────────────────────

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_severity(a: str, b: str) -> str:
    """Return the higher severity."""
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


# ── Deduplicator ────────────────────────────────────────────────────


class EscalationDeduplicator:
    """Mesh-level escalation deduplication engine.

    Collects per-agent escalation events, groups them by attack
    signature within a configurable merge window, then flushes merged
    escalations to subscribers.

    Thread-safe — can receive events from multiple threads (mesh
    phase callbacks, autonomous escalation, etc.).

    Args:
        merge_window: Seconds to wait for additional agents to report
            the same attack before flushing. Default 60s.
        flush_interval: Seconds between periodic flush checks. Default 15s.
    """

    def __init__(
        self,
        merge_window: int = DEFAULT_MERGE_WINDOW,
        flush_interval: int = DEFAULT_FLUSH_INTERVAL,
    ):
        self._merge_window = merge_window
        self._flush_interval = flush_interval
        self._lock = threading.RLock()

        # signature → _PendingBucket
        self._pending: Dict[str, _PendingBucket] = {}

        # Subscriber callbacks: called with MergedEscalation
        self._subscribers: List[Callable[[MergedEscalation], None]] = []

        # Stats
        self._events_received = 0
        self._merges_completed = 0
        self._events_deduplicated = 0  # events that were merged (saved)

        # History (recent merged escalations for API/debug)
        self._history: List[MergedEscalation] = []
        self._max_history = 100

        # Background flush thread
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── Lifecycle ────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background flush thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._flush_loop,
            name="escalation-dedup",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "EscalationDeduplicator started (merge_window=%ds, flush=%ds)",
            self._merge_window,
            self._flush_interval,
        )

    def stop(self) -> None:
        """Stop the background thread, flush remaining."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        # Final flush
        self._flush_expired(force_all=True)
        logger.info("EscalationDeduplicator stopped")

    # ── Event Submission ─────────────────────────────────────────

    def submit(self, event: EscalationEvent) -> str:
        """Submit an escalation event for deduplication.

        Returns the attack signature the event was filed under.
        """
        sig = build_signature(event.rule_id, event.event_type)
        now = time.monotonic()

        with self._lock:
            self._events_received += 1

            if sig not in self._pending:
                if len(self._pending) >= MAX_PENDING_SIGNATURES:
                    # Safety cap — flush oldest
                    oldest_key = min(
                        self._pending, key=lambda k: self._pending[k].created_at
                    )
                    self._flush_bucket(oldest_key)

                self._pending[sig] = _PendingBucket(
                    signature=sig,
                    rule_id=event.rule_id,
                    event_type=event.event_type,
                    created_at=now,
                    first_ts=event.timestamp,
                )

            bucket = self._pending[sig]
            # Cap agents per merge
            if len(bucket.events) < MAX_AGENTS_PER_MERGE:
                bucket.events.append(event)

        return sig

    # ── Subscribers ──────────────────────────────────────────────

    def on_merged(self, callback: Callable[[MergedEscalation], None]) -> None:
        """Register a subscriber for merged escalation events."""
        with self._lock:
            self._subscribers.append(callback)

    # ── Flush Logic ──────────────────────────────────────────────

    def _flush_loop(self) -> None:
        """Background thread: periodically check for expired merge windows."""
        while not self._stop_event.wait(timeout=self._flush_interval):
            try:
                self._flush_expired()
            except Exception:
                logger.debug("Flush loop error", exc_info=True)

    def _flush_expired(self, force_all: bool = False) -> None:
        """Flush buckets whose merge window has expired."""
        now = time.monotonic()
        to_flush: List[str] = []

        with self._lock:
            for sig, bucket in self._pending.items():
                elapsed = now - bucket.created_at
                if force_all or elapsed >= self._merge_window:
                    to_flush.append(sig)

        for sig in to_flush:
            self._flush_bucket(sig)

    def _flush_bucket(self, signature: str) -> None:
        """Merge all events in a bucket and deliver to subscribers."""
        with self._lock:
            bucket = self._pending.pop(signature, None)
            if not bucket or not bucket.events:
                return
            subscribers = list(self._subscribers)

        # Build merged escalation
        agents = []
        agent_details = []
        total_count = 0
        severity = "low"
        seen_agents = set()

        for evt in bucket.events:
            if evt.agent_id not in seen_agents:
                agents.append(evt.agent_id)
                seen_agents.add(evt.agent_id)
            total_count += evt.event_count
            severity = _max_severity(severity, evt.severity)
            agent_details.append({
                "agent_id": evt.agent_id,
                "event_count": evt.event_count,
                "severity": evt.severity,
                "message": evt.message,
                "details": evt.details,
                "timestamp": evt.timestamp,
            })

        last_ts = bucket.events[-1].timestamp if bucket.events else ""

        # Build summary message
        if len(agents) > 1:
            msg = (
                f"[Distributed Attack] {bucket.rule_id} detected across "
                f"{len(agents)} agents ({', '.join(agents[:5])}"
                f"{f' +{len(agents)-5} more' if len(agents) > 5 else ''}) — "
                f"{total_count} total events, severity: {severity}"
            )
        else:
            msg = (
                f"[Escalation] {bucket.rule_id} on {agents[0] if agents else 'unknown'} — "
                f"{total_count} events, severity: {severity}"
            )

        merged = MergedEscalation(
            signature=signature,
            rule_id=bucket.rule_id,
            event_type=bucket.event_type,
            severity=severity,
            agents=agents,
            total_event_count=total_count,
            agent_details=agent_details,
            first_seen=bucket.first_ts,
            last_seen=last_ts,
            merged_at=datetime.now(timezone.utc).isoformat(),
            message=msg,
        )

        with self._lock:
            self._merges_completed += 1
            # Count deduplicated events (saved escalations)
            if len(agents) > 1:
                self._events_deduplicated += len(agents) - 1
            self._history.append(merged)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

        # Deliver to subscribers (outside lock)
        for cb in subscribers:
            try:
                cb(merged)
            except Exception:
                logger.debug("Merged escalation subscriber error", exc_info=True)

    # ── Introspection ────────────────────────────────────────────

    def get_status(self) -> dict:
        """Current deduplicator status."""
        with self._lock:
            return {
                "running": self._running,
                "merge_window_seconds": self._merge_window,
                "flush_interval_seconds": self._flush_interval,
                "pending_signatures": len(self._pending),
                "events_received": self._events_received,
                "merges_completed": self._merges_completed,
                "events_deduplicated": self._events_deduplicated,
                "history_size": len(self._history),
            }

    def get_pending(self) -> List[dict]:
        """List currently pending (not yet merged) signatures."""
        with self._lock:
            result = []
            for sig, bucket in self._pending.items():
                agents = list({e.agent_id for e in bucket.events})
                result.append({
                    "signature": sig,
                    "rule_id": bucket.rule_id,
                    "event_type": bucket.event_type,
                    "agent_count": len(agents),
                    "agents": agents,
                    "event_count": len(bucket.events),
                    "first_seen": bucket.first_ts,
                    "age_seconds": round(
                        time.monotonic() - bucket.created_at, 1
                    ),
                })
            return result

    def get_history(self, limit: int = 50) -> List[dict]:
        """Recent merged escalations (newest first)."""
        with self._lock:
            return [
                m.to_dict()
                for m in reversed(self._history[-limit:])
            ]

    @property
    def is_running(self) -> bool:
        return self._running


# ── Singleton ────────────────────────────────────────────────────────

_dedup: Optional[EscalationDeduplicator] = None


def get_escalation_deduplicator() -> Optional[EscalationDeduplicator]:
    return _dedup


def set_escalation_deduplicator(d: Optional[EscalationDeduplicator]) -> None:
    global _dedup
    _dedup = d
