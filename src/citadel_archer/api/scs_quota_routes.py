# PRD: SCS API Rate Limiting — REST endpoint for token quota status
# Reference: docs/PRD.md — "SCS API rate limiting — per-participant token quotas"
#
#   GET /api/scs-quota  — current per-participant token usage and quotas

from fastapi import APIRouter, Depends

from ..chat.scs_quota import get_scs_quota_tracker, DEFAULT_QUOTAS, WINDOW_SECONDS
from .security import verify_session_token

router = APIRouter(prefix="/api/scs-quota", tags=["scs-quota"])


@router.get("", dependencies=[Depends(verify_session_token)])
async def get_scs_quota():
    """Return per-participant token usage, quotas, and remaining budget."""
    tracker = get_scs_quota_tracker()
    return {
        "participants": tracker.get_all_usage(),
        "defaults": DEFAULT_QUOTAS,
        "window_seconds": WINDOW_SECONDS,
    }
