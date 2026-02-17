# External AI Agent Rate Limiter
# In-memory sliding window rate limiter for external agent API calls.
# Reference: PRD Trigger 1b — per-agent rate limits
#
# No persistence needed — rate windows reset on restart, which is fine
# since the agent tokens and registrations persist in SQLite.

import time
from collections import defaultdict
from typing import List, Tuple

# Window size in seconds
WINDOW_SECONDS = 60.0


class AgentRateLimiter:
    """Per-agent sliding window rate limiter.

    Tracks timestamps of recent requests per agent_id. Each call to
    check() evicts entries older than 60 seconds and compares the
    count against the agent's configured limit.

    Thread-safe under the GIL for the expected scale. No async lock
    needed since FastAPI serializes request handling per endpoint.
    """

    def __init__(self):
        self._windows: dict[str, List[float]] = defaultdict(list)

    def check(self, agent_id: str, limit_per_min: int) -> Tuple[bool, int]:
        """Check if an agent is within its rate limit.

        Args:
            agent_id: The agent's unique identifier.
            limit_per_min: Maximum requests allowed per minute.

        Returns:
            (allowed, remaining): Whether the request is allowed and
            how many requests remain in the current window.
        """
        now = time.monotonic()
        window = self._windows[agent_id]

        # Evict entries older than the window
        cutoff = now - WINDOW_SECONDS
        window[:] = [t for t in window if t > cutoff]

        if len(window) >= limit_per_min:
            return False, 0

        window.append(now)
        return True, limit_per_min - len(window)

    def reset(self, agent_id: str):
        """Reset an agent's rate window (useful for testing)."""
        self._windows.pop(agent_id, None)

    def reset_all(self):
        """Reset all rate windows."""
        self._windows.clear()
