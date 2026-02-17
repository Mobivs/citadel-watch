# PRD: SCS API Rate Limiting — Per-participant token quotas
# Reference: docs/PRD.md — "SCS API rate limiting — per-participant token quotas"
#
# Tracks cumulative token consumption per participant within a rolling
# time window. Prevents any single source from exhausting the Claude API budget.
# In-memory only — resets on restart (like AgentRateLimiter).
#
# Two-phase design:
#   1. Pre-call: estimate_tokens() + check() gates the call
#   2. Post-call: record() tracks actual token consumption

import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ── Configuration ────────────────────────────────────────────────

WINDOW_SECONDS = 3600.0  # 1-hour rolling window

# Default quotas (tokens per hour per participant type)
#   user:      200K — ~50-130 calls/hr, ~$3/hr worst case at Sonnet pricing
#   ext-agent:  50K — ~12-30 calls/hr, prevents misconfigured agent budget burn
#   citadel:   500K — security-critical, nearly impossible to hit normally
DEFAULT_QUOTAS: Dict[str, int] = {
    "user": 200_000,
    "ext-agent": 50_000,
    "citadel": 500_000,
}

# Token estimation constants for pre-call gating
TOKENS_PER_CHAR_ESTIMATE = 0.3  # conservative: ~0.25 actual for English
MIN_CALL_ESTIMATE = 2000  # system prompt + tool defs overhead
MAX_CALL_ESTIMATE = 4000  # max_tokens(1024) + typical input


# ── Data Model ───────────────────────────────────────────────────


@dataclass
class TokenEntry:
    """A single token consumption record in the sliding window."""

    timestamp: float  # time.monotonic()
    tokens: int


# ── Tracker ──────────────────────────────────────────────────────


class SCSQuotaTracker:
    """Per-participant rolling-window token quota tracker.

    Tracks token consumption per participant ID within a configurable
    time window. Each participant type (user, ext-agent, citadel) has
    a default quota that can be overridden per-type or per-ID.

    Thread-safe. In-memory only — resets on restart.

    Usage (from ai_bridge.py):
        tracker = get_scs_quota_tracker()

        # Pre-call gate:
        estimated = tracker.estimate_tokens(msg.text)
        allowed, info = tracker.check("user", estimated_tokens=estimated)
        if not allowed:
            # reject with info["reason"]

        # Post-call recording:
        tracker.record("user", actual_tokens=3500)
    """

    def __init__(
        self,
        quotas: Optional[Dict[str, int]] = None,
        window_seconds: float = WINDOW_SECONDS,
    ):
        self._quotas = dict(DEFAULT_QUOTAS)
        if quotas:
            self._quotas.update(quotas)
        self._window = window_seconds
        self._lock = threading.Lock()
        self._windows: Dict[str, List[TokenEntry]] = {}

    # ── Participant resolution ───────────────────────────────────

    @staticmethod
    def resolve_participant_type(participant_id: str) -> str:
        """Map a participant ID to its quota type.

        "user" → "user"
        "ext-agent:forge-abc123" → "ext-agent"
        "citadel" → "citadel"
        anything else → "citadel"
        """
        if participant_id == "user":
            return "user"
        if participant_id.startswith("ext-agent:"):
            return "ext-agent"
        return "citadel"

    def _get_quota(self, participant_id: str) -> int:
        """Get token quota for a participant.

        Checks for exact participant_id override first, then falls
        back to the participant type default.
        """
        if participant_id in self._quotas:
            return self._quotas[participant_id]
        ptype = self.resolve_participant_type(participant_id)
        # Fallback: if type quota was somehow removed, use user default (restrictive)
        return self._quotas.get(ptype, DEFAULT_QUOTAS["user"])

    # ── Internal helpers (must hold lock) ────────────────────────

    def _evict(self, participant_id: str, now: float) -> None:
        """Remove entries older than the window."""
        entries = self._windows.get(participant_id)
        if entries is None:
            return
        cutoff = now - self._window
        self._windows[participant_id] = [
            e for e in entries if e.timestamp > cutoff
        ]

    def _current_usage(self, participant_id: str) -> int:
        """Sum of tokens in the current window."""
        return sum(e.tokens for e in self._windows.get(participant_id, []))

    # ── Public API ───────────────────────────────────────────────

    def check(
        self, participant_id: str, estimated_tokens: int = 0
    ) -> Tuple[bool, Dict]:
        """Check if a participant has budget for a new API call.

        Args:
            participant_id: The from_id of the message trigger.
            estimated_tokens: Conservative token estimate for this call.

        Returns:
            (allowed, info): Whether the call should proceed, plus a dict
            with used, quota, remaining, participant_type, reason.
        """
        with self._lock:
            now = time.monotonic()
            self._evict(participant_id, now)
            used = self._current_usage(participant_id)
            quota = self._get_quota(participant_id)
            remaining = max(0, quota - used)
            ptype = self.resolve_participant_type(participant_id)

            info = {
                "used": used,
                "quota": quota,
                "remaining": remaining,
                "estimated": estimated_tokens,
                "participant_type": ptype,
                "participant_id": participant_id,
                "window_seconds": self._window,
            }

            if estimated_tokens > remaining:
                info["reason"] = (
                    f"Token quota exceeded for {ptype}. "
                    f"Used {used:,}/{quota:,} tokens this hour. "
                    f"Estimated call needs ~{estimated_tokens:,} tokens, "
                    f"but only {remaining:,} remain."
                )
                return False, info

            info["reason"] = "ok"
            return True, info

    def record(self, participant_id: str, tokens: int) -> None:
        """Record actual token consumption after a completed API call.

        Args:
            participant_id: The participant who triggered the call.
            tokens: Total tokens consumed (input + output).
        """
        if tokens <= 0:
            return
        with self._lock:
            now = time.monotonic()
            self._evict(participant_id, now)
            entries = self._windows.setdefault(participant_id, [])
            entries.append(TokenEntry(timestamp=now, tokens=tokens))

    def get_all_usage(self) -> Dict[str, Dict]:
        """Get current usage for all tracked participants.

        Returns dict keyed by participant_id, each with
        used, quota, remaining, participant_type.
        """
        with self._lock:
            now = time.monotonic()
            result = {}

            for pid in list(self._windows.keys()):
                self._evict(pid, now)
                used = self._current_usage(pid)
                quota = self._get_quota(pid)
                ptype = self.resolve_participant_type(pid)
                result[pid] = {
                    "used": used,
                    "quota": quota,
                    "remaining": max(0, quota - used),
                    "participant_type": ptype,
                }

            # Include default quotas for types not yet seen
            seen_types = {v["participant_type"] for v in result.values()}
            for ptype, default_quota in DEFAULT_QUOTAS.items():
                if ptype not in seen_types:
                    result[f"_default:{ptype}"] = {
                        "used": 0,
                        "quota": default_quota,
                        "remaining": default_quota,
                        "participant_type": ptype,
                    }

            return result

    def set_quota(self, key: str, tokens_per_hour: int) -> None:
        """Override quota for a participant type or specific ID."""
        with self._lock:
            self._quotas[key] = tokens_per_hour

    def reset(self, participant_id: str) -> None:
        """Reset a single participant's window."""
        with self._lock:
            self._windows.pop(participant_id, None)

    def reset_all(self) -> None:
        """Reset all windows."""
        with self._lock:
            self._windows.clear()

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate token count for a message text.

        Conservative estimate used for pre-call gating.
        Adds MIN_CALL_ESTIMATE for system prompt overhead.
        """
        char_tokens = int(len(text or "") * TOKENS_PER_CHAR_ESTIMATE)
        return max(
            MIN_CALL_ESTIMATE,
            min(char_tokens + MIN_CALL_ESTIMATE, MAX_CALL_ESTIMATE),
        )


# ── Singleton ────────────────────────────────────────────────────

_scs_quota_tracker: Optional[SCSQuotaTracker] = None
_scs_quota_lock = threading.Lock()


def get_scs_quota_tracker() -> SCSQuotaTracker:
    """Get or create the global SCS quota tracker singleton."""
    global _scs_quota_tracker
    if _scs_quota_tracker is None:
        with _scs_quota_lock:
            if _scs_quota_tracker is None:
                _scs_quota_tracker = SCSQuotaTracker()
    return _scs_quota_tracker
