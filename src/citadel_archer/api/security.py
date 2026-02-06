# PRD: API Security - Session-based authentication for desktop app
# Reference: docs/PRD.md v0.2.3, Section: Security
#
# Generates a random session token on startup
# All sensitive API endpoints require this token
# Provides defense against malware accessing the API

import secrets
from typing import Optional
from fastapi import Header, HTTPException, status

# Global session token (generated once per backend instance)
# This protects against unauthorized access to the vault API
_SESSION_TOKEN: Optional[str] = None


def initialize_session_token() -> str:
    """
    Generate a new session token for this backend instance.

    Security: This creates a random 256-bit token that must be included
    in the X-Session-Token header for all protected API calls.

    This prevents:
    - Malware from accessing the API without the token
    - Unauthorized local processes from accessing passwords
    - CSRF attacks (token required, not just cookies)

    Returns:
        The generated session token (for frontend initialization)
    """
    global _SESSION_TOKEN
    # Generate cryptographically secure random token (256 bits = 32 bytes)
    _SESSION_TOKEN = secrets.token_urlsafe(32)
    return _SESSION_TOKEN


def get_session_token() -> str:
    """
    Get the current session token.

    Returns:
        Current session token

    Raises:
        RuntimeError: If session token hasn't been initialized
    """
    if _SESSION_TOKEN is None:
        raise RuntimeError("Session token not initialized. Call initialize_session_token() first.")
    return _SESSION_TOKEN


async def verify_session_token(x_session_token: str = Header(None)) -> str:
    """
    FastAPI dependency to verify session token.

    Security: This ensures the caller has the session token that was
    generated when the backend started. Without this token, API calls
    will be rejected with 401 Unauthorized.

    Usage in routes:
        @app.get("/protected", dependencies=[Depends(verify_session_token)])

    Args:
        x_session_token: Session token from X-Session-Token header

    Returns:
        The verified session token

    Raises:
        HTTPException: 401 if token is missing or invalid
    """
    if _SESSION_TOKEN is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session token not initialized"
        )

    if x_session_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Session-Token header"
        )

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(x_session_token, _SESSION_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token"
        )

    return x_session_token
