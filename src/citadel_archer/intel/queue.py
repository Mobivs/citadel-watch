# PRD: Intel Module - Thread-Safe Ingestion Queue
# Reference: PHASE_2_SPEC.md
#
# Provides a bounded, thread-safe queue for intel items flowing from
# feed fetchers into the store.  Includes built-in deduplication so
# duplicate items are dropped before reaching the database.

import threading
from collections import OrderedDict
from typing import Dict, List, Optional

from .models import IntelItem


class IntelQueue:
    """Thread-safe ingestion queue with deduplication.

    Items are enqueued by feed fetchers and dequeued by the storage
    writer.  A sliding-window dedup set ensures that items with the
    same ``dedup_key`` are only processed once within the window.

    Args:
        maxsize: Maximum number of items the queue can hold.
                 ``put()`` drops the oldest item when full.
        dedup_window: Number of recent dedup keys to remember.
                      Older keys are evicted (LRU) to bound memory.
    """

    def __init__(self, maxsize: int = 10_000, dedup_window: int = 50_000):
        self._maxsize = maxsize
        self._dedup_window = dedup_window

        self._lock = threading.RLock()
        self._items: List[IntelItem] = []
        # OrderedDict used as an LRU set for dedup keys
        self._seen: OrderedDict[str, None] = OrderedDict()

        # Counters
        self._total_enqueued = 0
        self._total_deduped = 0
        self._total_dropped = 0  # dropped due to full queue

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def put(self, item: IntelItem) -> bool:
        """Add an item to the queue.

        Returns True if the item was enqueued, False if it was
        deduplicated (already seen).
        """
        key = item.dedup_key

        with self._lock:
            # Dedup check
            if key in self._seen:
                self._total_deduped += 1
                return False

            # Evict oldest if queue is full
            if len(self._items) >= self._maxsize:
                self._items.pop(0)
                self._total_dropped += 1

            self._items.append(item)
            self._total_enqueued += 1

            # Track in dedup window (LRU eviction)
            self._seen[key] = None
            if len(self._seen) > self._dedup_window:
                self._seen.popitem(last=False)  # evict oldest

            return True

    def put_many(self, items: List[IntelItem]) -> Dict[str, int]:
        """Enqueue multiple items. Returns counts."""
        enqueued = 0
        deduped = 0
        for item in items:
            if self.put(item):
                enqueued += 1
            else:
                deduped += 1
        return {"enqueued": enqueued, "deduped": deduped}

    # ------------------------------------------------------------------
    # Dequeue
    # ------------------------------------------------------------------

    def get(self) -> Optional[IntelItem]:
        """Remove and return the oldest item, or None if empty."""
        with self._lock:
            if not self._items:
                return None
            return self._items.pop(0)

    def get_batch(self, batch_size: int = 100) -> List[IntelItem]:
        """Remove and return up to ``batch_size`` items (FIFO)."""
        with self._lock:
            count = min(batch_size, len(self._items))
            batch = self._items[:count]
            self._items = self._items[count:]
            return batch

    def peek(self) -> Optional[IntelItem]:
        """Return the oldest item without removing it, or None."""
        with self._lock:
            return self._items[0] if self._items else None

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Current number of items in the queue."""
        with self._lock:
            return len(self._items)

    @property
    def is_empty(self) -> bool:
        with self._lock:
            return len(self._items) == 0

    @property
    def is_full(self) -> bool:
        with self._lock:
            return len(self._items) >= self._maxsize

    def clear(self) -> int:
        """Clear all items. Returns count removed."""
        with self._lock:
            count = len(self._items)
            self._items.clear()
            return count

    def clear_dedup_cache(self) -> int:
        """Clear the dedup window. Returns count of keys cleared."""
        with self._lock:
            count = len(self._seen)
            self._seen.clear()
            return count

    def stats(self) -> Dict[str, int]:
        """Return queue statistics."""
        with self._lock:
            return {
                "current_size": len(self._items),
                "maxsize": self._maxsize,
                "dedup_window_size": len(self._seen),
                "dedup_window_max": self._dedup_window,
                "total_enqueued": self._total_enqueued,
                "total_deduped": self._total_deduped,
                "total_dropped": self._total_dropped,
            }
