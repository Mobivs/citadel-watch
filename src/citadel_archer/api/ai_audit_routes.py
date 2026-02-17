# PRD: AI Audit Log — REST API Route
# Reference: docs/PRD.md — "Append-only AI audit log (data/ai_audit.log)"
#
#   GET /api/ai-audit?limit=50  — recent AI call records + cumulative aggregates

from fastapi import APIRouter, Depends, Query

from ..chat.ai_audit import get_ai_audit_logger
from .security import verify_session_token

router = APIRouter(prefix="/api/ai-audit", tags=["ai-audit"])


@router.get("", dependencies=[Depends(verify_session_token)])
async def get_ai_audit(limit: int = Query(50, ge=1, le=500)):
    """Return recent AI call records and cumulative aggregates."""
    audit = get_ai_audit_logger()
    return {
        "records": audit.query_recent(limit=limit),
        "aggregates": audit.aggregates,
    }
