"""
Core authentication dependency for API routes.
Phase 3: Provides get_current_user for panic room auth.
"""

import secrets
from fastapi import Depends, HTTPException, Header
from typing import Optional


async def get_current_user(
    x_session_token: Optional[str] = Header(None),
) -> dict:
    """
    Dependency that validates session token and returns current user context.

    Enforces session token validation when the token system is initialized.
    In production, this would also validate against a user/session store or JWT.
    """
    # Import here to avoid circular imports
    from ..api.security import get_session_token

    try:
        expected_token = get_session_token()
    except RuntimeError:
        # Token not yet initialized (startup race) — allow through
        expected_token = None

    if expected_token:
        if not x_session_token:
            raise HTTPException(
                status_code=401,
                detail="Missing X-Session-Token header"
            )
        if not secrets.compare_digest(x_session_token, expected_token):
            raise HTTPException(
                status_code=401,
                detail="Invalid session token"
            )

    return {
        "id": "root",
        "user_id": "root",
        "username": "admin",
        "role": "administrator",
    }
