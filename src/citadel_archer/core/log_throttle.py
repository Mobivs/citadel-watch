"""
Log throttling and rate limiting for Citadel Archer.

This module prevents log spam by implementing:
1. Rate limiting per agent/source
2. Deduplication of repeated messages
3. Exponential backoff for high-frequency events
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import hashlib


@dataclass
class ThrottleState:
    """Track throttling state for a specific message/agent combination."""
    last_logged: float
    suppressed_count: int
    message_hash: str
    backoff_multiplier: float = 1.0


class LogThrottler:
    """
    Rate limit and deduplicate log messages to prevent log spam.
    
    Features:
    - Per-agent rate limiting
    - Message deduplication
    - Exponential backoff for repeat offenders
    - Periodic summary of suppressed messages
    """
    
    def __init__(
        self,
        min_interval_seconds: float = 60.0,  # Min time between identical messages
        max_backoff_multiplier: float = 10.0,  # Max backoff (10x = 10 minutes max)
        summary_interval_seconds: float = 300.0,  # Emit summary every 5 minutes
    ):
        self.min_interval = min_interval_seconds
        self.max_backoff = max_backoff_multiplier
        self.summary_interval = summary_interval_seconds
        
        # Track state per agent/message combination
        self.throttle_states: Dict[str, ThrottleState] = {}
        
        # Track recent messages for deduplication
        self.recent_messages: deque = deque(maxlen=1000)
        
        # Track when we last emitted a summary
        self.last_summary_time = time.time()
        
        # Count total suppressed messages
        self.total_suppressed = 0
    
    def _get_message_hash(self, message: str) -> str:
        """Create hash of message for deduplication."""
        # Strip timestamps and variable parts for better matching
        normalized = message.lower()
        # Remove common variable parts
        for pattern in [r'\d+', r'[a-f0-9]{8,}', r'\[\d+\]']:
            import re
            normalized = re.sub(pattern, 'X', normalized)
        
        return hashlib.md5(normalized.encode()).hexdigest()[:8]
    
    def should_log(
        self,
        agent_id: str,
        message: str,
        severity: str = "info"
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a message should be logged or throttled.
        
        Args:
            agent_id: Identifier for the logging source
            message: The log message
            severity: Log severity level
            
        Returns:
            Tuple of (should_log, summary_message)
            - should_log: True if message should be logged
            - summary_message: Optional summary of suppressed messages
        """
        # Always log critical messages
        if severity.lower() in ["critical", "error"]:
            return True, None
        
        current_time = time.time()
        message_hash = self._get_message_hash(message)
        key = f"{agent_id}:{message_hash}"
        
        # Check if we've seen this exact message recently
        if key in self.throttle_states:
            state = self.throttle_states[key]
            
            # Calculate required interval with exponential backoff
            required_interval = self.min_interval * state.backoff_multiplier
            time_since_last = current_time - state.last_logged
            
            if time_since_last < required_interval:
                # Message is throttled
                state.suppressed_count += 1
                self.total_suppressed += 1
                
                # Increase backoff for persistent spam
                if state.suppressed_count % 10 == 0:
                    state.backoff_multiplier = min(
                        state.backoff_multiplier * 1.5,
                        self.max_backoff
                    )
                
                # Check if we should emit a summary
                summary = self._check_summary(current_time)
                return False, summary
            else:
                # Enough time has passed, allow logging
                # But include count of suppressed messages
                suppressed_msg = None
                if state.suppressed_count > 0:
                    suppressed_msg = f"[Previously suppressed {state.suppressed_count} similar messages from {agent_id}]"
                
                # Reset state
                state.last_logged = current_time
                state.suppressed_count = 0
                
                # Slowly decrease backoff if behavior improves
                if state.backoff_multiplier > 1.0:
                    state.backoff_multiplier = max(1.0, state.backoff_multiplier * 0.9)
                
                return True, suppressed_msg
        else:
            # First time seeing this message/agent combo
            self.throttle_states[key] = ThrottleState(
                last_logged=current_time,
                suppressed_count=0,
                message_hash=message_hash
            )
            return True, None
    
    def _check_summary(self, current_time: float) -> Optional[str]:
        """Check if we should emit a summary of suppressed messages."""
        if current_time - self.last_summary_time >= self.summary_interval:
            if self.total_suppressed > 0:
                # Build summary of top offenders
                top_offenders = sorted(
                    [(k, v.suppressed_count) for k, v in self.throttle_states.items()
                     if v.suppressed_count > 0],
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
                
                summary_parts = [f"LOG THROTTLE SUMMARY: Suppressed {self.total_suppressed} messages"]
                
                if top_offenders:
                    summary_parts.append("Top sources:")
                    for key, count in top_offenders:
                        agent_id = key.split(':')[0]
                        summary_parts.append(f"  - {agent_id}: {count} messages")
                
                self.last_summary_time = current_time
                self.total_suppressed = 0
                
                # Reset suppressed counts
                for state in self.throttle_states.values():
                    state.suppressed_count = 0
                
                return " | ".join(summary_parts)
        
        return None
    
    def reset_agent(self, agent_id: str):
        """Reset throttling state for a specific agent."""
        keys_to_remove = [k for k in self.throttle_states.keys() 
                          if k.startswith(f"{agent_id}:")]
        for key in keys_to_remove:
            del self.throttle_states[key]


# Global throttler instance
_log_throttler: Optional[LogThrottler] = None


def get_log_throttler() -> LogThrottler:
    """Get global log throttler (singleton pattern)."""
    global _log_throttler
    if _log_throttler is None:
        _log_throttler = LogThrottler()
    return _log_throttler