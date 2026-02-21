# PRD: Trigger 2b — Local Guardian → AI Escalation
# Reference: docs/PRD.md, Trigger Model
#
# Subscribes to EventAggregator and escalates critical local Guardian
# events (file/process) to SecureChat, where AI Bridge picks them up
# for analysis.
#
# Design mirrors Trigger 2a (agent_poller.py:184-190) with added
# batching, deduplication, and rate limiting.
#
# AI Bridge coupling: The summary text MUST contain the substring
# "critical" or "high" to trigger AI processing (ai_bridge.py:224-227).
# The "[Local Guardian] N critical/high event(s)" format satisfies this.

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

# Severities that warrant AI attention
ESCALATION_SEVERITIES = {"alert", "critical"}

# Guardian-sourced event categories
GUARDIAN_CATEGORIES = {EventCategory.FILE, EventCategory.PROCESS}

# Tuning constants
BATCH_WINDOW_SECONDS = 30
DEDUP_WINDOW_SECONDS = 300  # 5 minutes
RATE_LIMIT_PER_HOUR = 10
RATE_LIMIT_WINDOW = 3600  # 1 hour


class GuardianEscalation:
    """Bridges local Guardian critical events to SecureChat for AI analysis.

    Subscribes to EventAggregator (sync callback), filters for ALERT/CRITICAL
    severity from FILE/PROCESS categories, batches events in 30-second windows,
    deduplicates within 5-minute windows, and rate-limits to 10 escalations/hour.

    Args:
        aggregator: EventAggregator instance to subscribe to.
        chat_manager: ChatManager for sending escalation messages.
        loop: asyncio event loop for sync-to-async bridging. Required when
              calling start() outside an async context.
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
        """Subscribe to EventAggregator and start the batch flush loop.

        Raises RuntimeError if no event loop is available (pass loop= to __init__).
        """
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
                    "GuardianEscalation.start() requires an explicit event loop "
                    "when called outside an async context. Pass loop= to __init__."
                )

        # Schedule the flush loop on the event loop
        self._flush_task = asyncio.run_coroutine_threadsafe(
            self._flush_loop(), self._loop
        )
        logger.info(
            "GuardianEscalation started (batch=%ds, dedup=%ds, rate=%d/hr)",
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
        logger.info("GuardianEscalation stopped")

    # ------------------------------------------------------------------
    # Event callback (sync — called from EventAggregator thread)
    # ------------------------------------------------------------------

    def _on_event(self, event: AggregatedEvent) -> None:
        """Sync callback from EventAggregator. Filters and buffers events."""
        # Severity filter
        if event.severity.lower() not in ESCALATION_SEVERITIES:
            return

        # Category filter (only Guardian-sourced categories)
        if event.category not in GUARDIAN_CATEGORIES:
            return

        # Dedup check + buffer under lock for thread safety
        dedup_key = f"{event.event_type}:{event.asset_id or 'local'}"
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
            # Flush any remaining events on shutdown
            if self._buffer and self._loop and not self._loop.is_closed():
                try:
                    await self._flush_batch()
                except Exception:
                    logger.warning("Final flush on shutdown failed", exc_info=True)

    async def _flush_batch(self):
        """Send one summary message for all buffered events."""
        # Check if Guardian messages are muted (Do Not Disturb mode)
        try:
            from ..core.user_preferences import get_user_preferences
            if get_user_preferences().get("guardian_muted", "false") == "true":
                with self._buffer_lock:
                    self._buffer.clear()
                return
        except Exception:
            pass  # Preferences unavailable — proceed normally

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
                    "GuardianEscalation rate limit reached (%d/hr), "
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

        # Build summary (format matches AI Bridge trigger: contains "critical/high")
        # IMPORTANT: ai_bridge.py:224-227 checks for "critical" or "high" substrings
        # in EVENT messages from PARTICIPANT_CITADEL. Do not change this format
        # without updating the AI Bridge trigger logic.
        count = len(events)

        def _fmt_event(e: AggregatedEvent) -> str:
            # Extract UTC time (HH:MM:SS)
            ts_part = e.timestamp[11:19] if len(e.timestamp) >= 19 else e.timestamp
            # Pull file path from details if present
            path = (
                e.details.get("file_path")
                or e.details.get("path")
                or e.details.get("file")
                or ""
            )
            line = f"[{ts_part}] {e.severity.upper()} {e.event_type}: {e.message}"
            if path:
                line += f" | {path}"
            return line

        detail_lines = [_fmt_event(e) for e in events[:5]]
        if count > 5:
            detail_lines.append(f"(+{count - 5} more)")

        summary = (
            f"[Local Guardian] {count} critical/high event(s)\n"
            + "\n".join(detail_lines)
        )

        # Send to SecureChat as EVENT type (triggers AI Bridge)
        try:
            from .message import MessageType

            await self._chat.send_system(summary, MessageType.EVENT)
            self._escalation_count += 1
            logger.info("Guardian escalation sent: %d events", count)
        except Exception:
            logger.exception("Failed to send guardian escalation to chat")
            # Re-queue events so they aren't lost
            with self._buffer_lock:
                self._buffer.extend(events)

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
