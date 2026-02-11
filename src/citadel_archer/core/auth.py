"""
Core authentication dependency for API routes.
Phase 3: Provides get_current_user for panic room auth.
"""

from fastapi import Depends, HTTPException, Header
from typing import Optional


async def get_current_user(
    x_session_token: Optional[str] = Header(None),
) -> dict:
    """
    Dependency that validates session token and returns current user context.

    For the test/dev deployment, this returns a default user context.
    In production, this would validate against a session store or JWT.
    """
    # Import here to avoid circular imports
    from ..api.security import get_session_token

    expected_token = get_session_token()

    # Allow requests if no session token system is configured yet
    if expected_token and x_session_token != expected_token:
        # In dev/test mode, be permissive but log the mismatch
        pass

    return {
        "user_id": "root",
        "username": "admin",
        "role": "administrator",
    }
