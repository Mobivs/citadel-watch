"""
Tests for AgentRateLimiter — In-memory sliding window rate limiter.

Covers:
- Under limit → allowed
- At limit → denied
- Window slides (old entries evict after 60s)
- Independent per-agent windows
- Reset works
"""

import time
from unittest.mock import patch

import pytest

from citadel_archer.chat.agent_rate_limiter import AgentRateLimiter, WINDOW_SECONDS


@pytest.fixture
def limiter():
    return AgentRateLimiter()


class TestBasicBehavior:
    def test_under_limit_allowed(self, limiter):
        allowed, remaining = limiter.check("agent-1", limit_per_min=5)
        assert allowed is True
        assert remaining == 4

    def test_at_limit_denied(self, limiter):
        for _ in range(5):
            limiter.check("agent-1", limit_per_min=5)
        allowed, remaining = limiter.check("agent-1", limit_per_min=5)
        assert allowed is False
        assert remaining == 0

    def test_remaining_decreases(self, limiter):
        for i in range(3):
            allowed, remaining = limiter.check("agent-1", limit_per_min=5)
            assert allowed is True
            assert remaining == 5 - (i + 1)

    def test_single_request_allowed(self, limiter):
        allowed, remaining = limiter.check("agent-1", limit_per_min=1)
        assert allowed is True
        assert remaining == 0

        allowed, remaining = limiter.check("agent-1", limit_per_min=1)
        assert allowed is False


class TestSlidingWindow:
    def test_window_evicts_old_entries(self, limiter):
        """After WINDOW_SECONDS, old entries are evicted and limit resets."""
        # Fill up the limit
        for _ in range(3):
            limiter.check("agent-1", limit_per_min=3)

        # At limit
        allowed, _ = limiter.check("agent-1", limit_per_min=3)
        assert allowed is False

        # Advance time past the window
        future = time.monotonic() + WINDOW_SECONDS + 1
        with patch("citadel_archer.chat.agent_rate_limiter.time.monotonic", return_value=future):
            allowed, remaining = limiter.check("agent-1", limit_per_min=3)
            assert allowed is True
            assert remaining == 2


class TestPerAgentIsolation:
    def test_independent_windows(self, limiter):
        """Different agents have independent rate windows."""
        # Fill agent-1 to limit
        for _ in range(2):
            limiter.check("agent-1", limit_per_min=2)
        allowed, _ = limiter.check("agent-1", limit_per_min=2)
        assert allowed is False

        # agent-2 should still be allowed
        allowed, remaining = limiter.check("agent-2", limit_per_min=2)
        assert allowed is True
        assert remaining == 1


class TestReset:
    def test_reset_single_agent(self, limiter):
        for _ in range(5):
            limiter.check("agent-1", limit_per_min=5)
        allowed, _ = limiter.check("agent-1", limit_per_min=5)
        assert allowed is False

        limiter.reset("agent-1")
        allowed, remaining = limiter.check("agent-1", limit_per_min=5)
        assert allowed is True
        assert remaining == 4

    def test_reset_all(self, limiter):
        for _ in range(5):
            limiter.check("agent-1", limit_per_min=5)
            limiter.check("agent-2", limit_per_min=5)

        limiter.reset_all()

        allowed1, _ = limiter.check("agent-1", limit_per_min=5)
        allowed2, _ = limiter.check("agent-2", limit_per_min=5)
        assert allowed1 is True
        assert allowed2 is True

    def test_reset_nonexistent_agent_no_crash(self, limiter):
        limiter.reset("nonexistent")  # Should not raise
