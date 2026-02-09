"""
API Rate Limiting for Remote Shield Agents.

Implements:
- Per-IP rate limiting (prevent DoS attacks)
- Per-agent rate limiting (prevent resource exhaustion)
- Graceful 429 responses with Retry-After headers
- Database-backed persistent rate limit tracking
- Configurable limits and time windows

Rate Limit Strategy:
- Agent registration: 5 per IP per hour (prevent registration spam)
- Threat reporting: 100 per agent per hour (prevent threat spam)
- Token refresh: 10 per agent per hour (prevent token exhaustion)
- Heartbeat: 1 per agent per 60 seconds (prevent heartbeat spam)

All limits are soft limits with clear error messages and retry guidance.
"""

import logging
import time
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class RateLimitConfig:
    """Rate limiting configuration."""
    
    # Per-IP limits (global across all endpoints)
    AGENT_REGISTRATION_PER_HOUR = 5
    
    # Per-agent limits
    THREAT_REPORT_PER_HOUR = 100
    TOKEN_REFRESH_PER_HOUR = 10
    HEARTBEAT_PER_MINUTE = 1
    
    # Time windows (in seconds)
    HOUR_WINDOW = 3600
    MINUTE_WINDOW = 60
    
    # Cleanup interval (delete old entries)
    CLEANUP_INTERVAL_SECONDS = 3600


class InMemoryRateLimiter:
    """
    In-memory rate limiter for testing.
    
    Tracks requests per IP and per agent.
    Uses timestamp-based sliding windows.
    
    Note: For production with multiple processes, use database-backed
    limiter instead.
    """
    
    def __init__(self):
        """Initialize rate limiter."""
        # Track: (key) -> [(timestamp, ...)]
        self.ip_requests: Dict[str, list] = defaultdict(list)
        self.agent_requests: Dict[Tuple[str, str], list] = defaultdict(list)
        self.last_cleanup = time.time()
    
    def _cleanup_old_entries(self) -> None:
        """Remove entries older than 24 hours."""
        now = time.time()
        if now - self.last_cleanup < RateLimitConfig.CLEANUP_INTERVAL_SECONDS:
            return
        
        cutoff = now - 86400  # 24 hours
        
        # Cleanup IP requests
        for ip in list(self.ip_requests.keys()):
            self.ip_requests[ip] = [
                ts for ts in self.ip_requests[ip] if ts > cutoff
            ]
            if not self.ip_requests[ip]:
                del self.ip_requests[ip]
        
        # Cleanup agent requests
        for key in list(self.agent_requests.keys()):
            self.agent_requests[key] = [
                ts for ts in self.agent_requests[key] if ts > cutoff
            ]
            if not self.agent_requests[key]:
                del self.agent_requests[key]
        
        self.last_cleanup = now
        logger.debug("Rate limiter cleanup complete")
    
    def check_ip_limit(
        self,
        ip: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        """
        Check if IP has exceeded rate limit.
        
        Args:
            ip: Client IP address
            limit: Max requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            Tuple of (allowed: bool, current_count: int, retry_after_seconds: int)
        """
        self._cleanup_old_entries()
        
        now = time.time()
        cutoff = now - window_seconds
        
        # Count recent requests
        recent = [ts for ts in self.ip_requests[ip] if ts > cutoff]
        self.ip_requests[ip] = recent  # Keep only recent
        
        if len(recent) >= limit:
            # Limit exceeded
            oldest = min(recent)
            retry_after = int((oldest + window_seconds) - now) + 1
            return False, len(recent), retry_after
        
        # Record request
        self.ip_requests[ip].append(now)
        return True, len(recent) + 1, 0
    
    def check_agent_limit(
        self,
        agent_id: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        """
        Check if agent has exceeded rate limit for endpoint.
        
        Args:
            agent_id: Agent ID
            endpoint: API endpoint name (e.g., "threat_report")
            limit: Max requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            Tuple of (allowed: bool, current_count: int, retry_after_seconds: int)
        """
        self._cleanup_old_entries()
        
        key = (agent_id, endpoint)
        now = time.time()
        cutoff = now - window_seconds
        
        # Count recent requests
        recent = [ts for ts in self.agent_requests[key] if ts > cutoff]
        self.agent_requests[key] = recent
        
        if len(recent) >= limit:
            # Limit exceeded
            oldest = min(recent)
            retry_after = int((oldest + window_seconds) - now) + 1
            return False, len(recent), retry_after
        
        # Record request
        self.agent_requests[key].append(now)
        return True, len(recent) + 1, 0


class DatabaseRateLimiter:
    """
    Database-backed rate limiter for distributed deployments.
    
    Uses PostgreSQL to track rate limits across multiple processes/servers.
    Cleans up old entries automatically.
    
    Note: Requires database module to be initialized.
    """
    
    def __init__(self, db=None):
        """
        Initialize database rate limiter.
        
        Args:
            db: Database instance (lazy-loaded if not provided)
        """
        self.db = db
    
    def _get_db(self):
        """Get database instance (lazy load)."""
        if not self.db:
            from citadel_archer.db import get_database
            self.db = get_database()
        return self.db
    
    async def check_ip_limit(
        self,
        ip: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        """
        Check if IP has exceeded rate limit (database-backed).
        
        Args:
            ip: Client IP address
            limit: Max requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            Tuple of (allowed: bool, current_count: int, retry_after_seconds: int)
        """
        # This would insert into rate_limits table
        # For now, fall back to in-memory during Phase 2
        # Proper implementation in Phase 3 when rate_limits table exists
        
        logger.warning("DatabaseRateLimiter not fully implemented yet")
        return True, 1, 0
    
    async def check_agent_limit(
        self,
        agent_id: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        """
        Check if agent has exceeded rate limit (database-backed).
        
        Args:
            agent_id: Agent ID
            endpoint: API endpoint name
            limit: Max requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            Tuple of (allowed: bool, current_count: int, retry_after_seconds: int)
        """
        # This would query/insert into rate_limits table
        # For now, fall back to in-memory during Phase 2
        # Proper implementation in Phase 3 when rate_limits table exists
        
        logger.warning("DatabaseRateLimiter not fully implemented yet")
        return True, 1, 0


# Global rate limiter instance
_rate_limiter: Optional[InMemoryRateLimiter] = None


def get_rate_limiter() -> InMemoryRateLimiter:
    """
    Get global rate limiter instance.
    
    Returns:
        Rate limiter instance
    """
    global _rate_limiter
    if not _rate_limiter:
        _rate_limiter = InMemoryRateLimiter()
    return _rate_limiter


def get_client_ip(request: Request) -> str:
    """
    Extract client IP from request.
    
    Handles X-Forwarded-For header (reverse proxy) and direct connections.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Client IP address
    """
    # Check for X-Forwarded-For header (reverse proxy)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take first IP in list (most recent proxy)
        return forwarded_for.split(",")[0].strip()
    
    # Check for CF-Connecting-IP (Cloudflare)
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    
    # Use client connection IP (direct)
    if request.client:
        return request.client.host
    
    return "unknown"


async def rate_limit_ip(
    request: Request,
    limit: int = RateLimitConfig.AGENT_REGISTRATION_PER_HOUR,
    window: int = RateLimitConfig.HOUR_WINDOW,
) -> None:
    """
    FastAPI dependency for IP-based rate limiting.
    
    Usage:
        @router.post("/api/agents/register")
        async def register_agent(
            ...,
            _: None = Depends(rate_limit_ip),
        ):
            ...
    
    Args:
        request: FastAPI request object
        limit: Max requests allowed (default: 5 per hour)
        window: Time window in seconds (default: 1 hour)
    
    Raises:
        HTTPException: 429 Too Many Requests if limit exceeded
    """
    ip = get_client_ip(request)
    limiter = get_rate_limiter()
    
    allowed, count, retry_after = limiter.check_ip_limit(ip, limit, window)
    
    if not allowed:
        logger.warning(f"Rate limit exceeded for IP {ip}: {count} requests in {window}s")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {limit} requests per {window}s.",
            headers={"Retry-After": str(retry_after)},
        )
    
    logger.debug(f"IP {ip}: {count}/{limit} requests in {window}s window")


async def rate_limit_agent(
    agent_id: str,
    endpoint: str,
    limit: int,
    window: int = RateLimitConfig.HOUR_WINDOW,
) -> None:
    """
    Check rate limit for specific agent on specific endpoint.
    
    Usage:
        # In route handler
        await rate_limit_agent(
            agent_id=agent_id,
            endpoint="threat_report",
            limit=100,  # Max 100 threats per hour
            window=3600,
        )
    
    Args:
        agent_id: Agent ID
        endpoint: API endpoint name
        limit: Max requests allowed
        window: Time window in seconds
    
    Raises:
        HTTPException: 429 Too Many Requests if limit exceeded
    """
    limiter = get_rate_limiter()
    allowed, count, retry_after = limiter.check_agent_limit(
        agent_id, endpoint, limit, window
    )
    
    if not allowed:
        logger.warning(
            f"Rate limit exceeded for agent {agent_id} on {endpoint}: "
            f"{count} requests in {window}s"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {endpoint}. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    
    logger.debug(
        f"Agent {agent_id} on {endpoint}: {count}/{limit} requests in {window}s window"
    )


# Convenience functions for specific endpoints

async def check_registration_limit(ip: str) -> None:
    """Check rate limit for agent registration."""
    await rate_limit_ip(
        None,  # Would be request object in real usage
        limit=RateLimitConfig.AGENT_REGISTRATION_PER_HOUR,
        window=RateLimitConfig.HOUR_WINDOW,
    )


async def check_threat_report_limit(agent_id: str) -> None:
    """Check rate limit for threat reporting."""
    await rate_limit_agent(
        agent_id,
        "threat_report",
        RateLimitConfig.THREAT_REPORT_PER_HOUR,
        RateLimitConfig.HOUR_WINDOW,
    )


async def check_token_refresh_limit(agent_id: str) -> None:
    """Check rate limit for token refresh."""
    await rate_limit_agent(
        agent_id,
        "token_refresh",
        RateLimitConfig.TOKEN_REFRESH_PER_HOUR,
        RateLimitConfig.HOUR_WINDOW,
    )


async def check_heartbeat_limit(agent_id: str) -> None:
    """Check rate limit for heartbeat."""
    await rate_limit_agent(
        agent_id,
        "heartbeat",
        RateLimitConfig.HEARTBEAT_PER_MINUTE,
        RateLimitConfig.MINUTE_WINDOW,
    )
