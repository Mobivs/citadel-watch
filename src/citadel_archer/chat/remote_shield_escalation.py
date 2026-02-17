# PRD: Trigger 2d — Remote Shield → AI Escalation
# Reference: docs/PRD.md, Trigger Model
#
# Subscribes to EventAggregator and escalates critical/high VPS events
# (REMOTE category) to SecureChat, where AI Bridge picks them up
# for analysis.
#
# Design mirrors GuardianEscalation (Trigger 2b) with differences:
#   - Filters REMOTE category (not FILE/PROCESS)
#   - Includes "high" severity (VPS events are higher signal)
#   - Groups summaries by asset_id (which VPS is affected)
#   - Higher rate limit (15/hr vs 10/hr — VPS volume is higher)
#
# AI Bridge coupling: The summary text MUST contain the substring
# "critical" or "high" to trigger AI processing (ai_bridge.py:224-227).

import asyncio
import logging
import threading
import time
from typing import Dict, List, Optional, TYPE_CHECKING

from ..intel.event_aggregator import AggregatedEvent, EventCategory

if TYPE_CHECKING:
    from ..intel.event_aggregator import EventAggregator
    from .chat_manager import ChatManager

logger = logging.getLogger(__name__)

# Severities that warrant AI attention (includes "high" for VPS)
ESCALATION_SEVERITIES = {"alert", "critical", "high"}

# Remote-sourced event categories
REMOTE_CATEGORIES = {EventCategory.REMOTE}

# Tuning constants
BATCH_WINDOW_SECONDS = 30
DEDUP_WINDOW_SECONDS = 300  # 5 minutes
RATE_LIMIT_PER_HOUR = 15    # Higher than Guardian (10) — VPS events are higher volume
RATE_LIMIT_WINDOW = 3600    # 1 hour


class RemoteShieldEscalation:
    """Bridges VPS Remote Shield critical/high events to SecureChat for AI analysis.

    Subscribes to EventAggregator (sync callback), filters for ALERT/CRITICAL/HIGH
    severity from REMOTE category, batches events in 30-second windows,
    deduplicates within 5-minute windows, and rate-limits to 15 escalations/hour.

    Groups summaries by asset_id so the AI knows which VPS is affected.

    Args:
        aggregator: EventAggregator instance to subscribe to.
        chat_manager: ChatManager for sending escalation messages.
        loop: asyncio event loop for sync-to-async bridging.
    """

    def __init__(
        self,
        aggregator: "EventAggregator",
        chat_manager: "ChatManager",
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self._aggregator = aggregator
        self._chat = chat_manager
        self._loop = loop

        # Buffer for batching events within the flush window
        self._buffer: List[AggregatedEvent] = []
        self._buffer_lock = threading.Lock()

        # Dedup: key → monotonic timestamp of last escalation
        self._dedup_cache: Dict[str, float] = {}

        # Rate limiting
        self._escalation_count = 0
        self._hour_start = time.monotonic()

        self._running = False
        self._flush_task: Optional[asyncio.Future] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Subscribe to EventAggregator and start the batch flush loop."""
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
                    "RemoteShieldEscalation.start() requires an explicit event loop "
                    "when called outside an async context. Pass loop= to __init__."
                )

        self._flush_task = asyncio.run_coroutine_threadsafe(
            self._flush_loop(), self._loop
        )
        logger.info(
            "RemoteShieldEscalation started (batch=%ds, dedup=%ds, rate=%d/hr)",
            BATCH_WINDOW_SECONDS,
            DEDUP_WINDOW_SECONDS,
            RATE_LIMIT_PER_HOUR,
        )

    def stop(self):
        """Stop the flush loop and clean up."""
        with self._buffer_lock:
            self._running = False
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
        logger.info("RemoteShieldEscalation stopped")

    # ------------------------------------------------------------------
    # Event callback (sync — called from EventAggregator thread)
    # ------------------------------------------------------------------

    def _on_event(self, event: AggregatedEvent) -> None:
        """Sync callback from EventAggregator. Filters and buffers events."""
        # Severity filter
        if event.severity.lower() not in ESCALATION_SEVERITIES:
            return

        # Category filter (only Remote-sourced categories)
        if event.category not in REMOTE_CATEGORIES:
            return

        # Dedup check + buffer under lock for thread safety
        dedup_key = f"{event.event_type}:{event.asset_id or 'unknown'}"
        now = time.monotonic()

        with self._buffer_lock:
            self._evict_stale_dedup(now)

            last_seen = self._dedup_cache.get(dedup_key)
            if last_seen is not None and (now - last_seen) < DEDUP_WINDOW_SECONDS:
                return

            self._dedup_cache[dedup_key] = now
            self._buffer.append(event)

    def _evict_stale_dedup(self, now: float) -> None:
        """Remove dedup entries older than the dedup window."""
        cutoff = now - DEDUP_WINDOW_SECONDS
        stale = [k for k, ts in self._dedup_cache.items() if ts < cutoff]
        for k in stale:
            del self._dedup_cache[k]

    # ------------------------------------------------------------------
    # Batch flush loop (async — runs on the event loop)
    # ------------------------------------------------------------------

    async def _flush_loop(self):
        """Periodically flush buffered events as a single chat summary."""
        try:
            while self._running:
                await asyncio.sleep(BATCH_WINDOW_SECONDS)
                if self._buffer:
                    await self._flush_batch()
        except asyncio.CancelledError:
            if self._buffer and self._loop and not self._loop.is_closed():
                try:
                    await self._flush_batch()
                except Exception:
                    logger.warning("Final flush on shutdown failed", exc_info=True)

    async def _flush_batch(self):
        """Send one summary message for all buffered events."""
        # Reset rate limit counter if the hour window has elapsed
        now = time.monotonic()
        if now - self._hour_start >= RATE_LIMIT_WINDOW:
            self._escalation_count = 0
            self._hour_start = now

        # Check rate limit
        if self._escalation_count >= RATE_LIMIT_PER_HOUR:
            with self._buffer_lock:
                dropped = len(self._buffer)
                self._buffer.clear()
            if dropped:
                logger.warning(
                    "RemoteShieldEscalation rate limit reached (%d/hr), "
                    "dropped %d events",
                    RATE_LIMIT_PER_HOUR,
                    dropped,
                )
            return

        # Drain buffer
        with self._buffer_lock:
            events = self._buffer[:]
            self._buffer.clear()

        if not events:
            return

        # Group by asset_id for clearer AI context
        by_asset: Dict[str, List[AggregatedEvent]] = {}
        for e in events:
            key = e.asset_id or "unknown"
            by_asset.setdefault(key, []).append(e)

        # Build summary per asset
        parts = []
        for asset_id, asset_events in by_asset.items():
            count = len(asset_events)
            msgs = [e.message[:80] for e in asset_events[:3]]
            if count > 3:
                msgs.append(f"(+{count - 3} more)")
            parts.append(f"{asset_id}: {count} event(s) \u2014 {'; '.join(msgs)}")

        total = len(events)
        summary = (
            f"[Remote Shield] {total} critical/high VPS event(s)\n"
            + "\n".join(f"  {p}" for p in parts)
        )

        # Send to SecureChat as EVENT type (triggers AI Bridge)
        try:
            from .message import MessageType

            await self._chat.send_system(summary, MessageType.EVENT)
            self._escalation_count += 1
            logger.info("Remote Shield escalation sent: %d events", total)
        except Exception:
            logger.exception("Failed to send Remote Shield escalation to chat")
            # Re-queue events with a cap to prevent unbounded growth
            with self._buffer_lock:
                if len(self._buffer) < 500:
                    self._buffer.extend(events)
                else:
                    logger.warning(
                        "Buffer cap reached, dropping %d events", len(events)
                    )

    # ------------------------------------------------------------------
    # Introspection (for tests and debugging)
    # ------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._running

    @property
    def escalation_count(self) -> int:
        return self._escalation_count

    @property
    def buffer_size(self) -> int:
        with self._buffer_lock:
            return len(self._buffer)

    @property
    def dedup_cache_size(self) -> int:
        return len(self._dedup_cache)
