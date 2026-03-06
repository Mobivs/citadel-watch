# Event Resolution Routes — REST endpoints for marking events resolved/unresolved.
#
# POST   /api/events/{source}/{event_id}/resolve   — mark resolved (upsert)
# DELETE /api/events/{source}/{event_id}/resolve   — un-resolve
# POST   /api/events/resolutions/query             — bulk-fetch by (source, id) pairs
#
# All endpoints require the desktop session token.
# The "resolutions/query" path is a static segment that must be registered
# BEFORE /{source}/{event_id}/resolve to avoid param capture.

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .security import verify_session_token
from ..intel.resolution_store import get_resolution_store

router = APIRouter(prefix="/api/events", tags=["resolution"])

_VALID_SOURCES = {"local", "remote-shield", "correlation"}


class ResolveRequest(BaseModel):
    action_taken: str
    notes: Optional[str] = None


class ResolutionPair(BaseModel):
    source: str
    external_id: str


class QueryRequest(BaseModel):
    pairs: List[ResolutionPair]


@router.post("/resolutions/query")
async def query_resolutions(
    body: QueryRequest,
    _token: str = Depends(verify_session_token),
) -> Dict:
    """Bulk-fetch resolutions for a list of (source, external_id) pairs.

    Returns a dict keyed by 'source:external_id' for fast client-side lookup.
    """
    if len(body.pairs) > 500:
        raise HTTPException(status_code=400, detail="Too many pairs (max 500)")
    pairs = [(p.source, p.external_id) for p in body.pairs]
    return get_resolution_store().get_many(pairs)


@router.post("/{source}/{event_id}/resolve")
async def resolve_event(
    source: str,
    event_id: str,
    body: ResolveRequest,
    _token: str = Depends(verify_session_token),
) -> Dict:
    """Mark an event as resolved."""
    if source not in _VALID_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid source '{source}'. Must be one of: {sorted(_VALID_SOURCES)}",
        )
    return get_resolution_store().resolve(
        source=source,
        external_id=event_id,
        action_taken=body.action_taken,
        notes=body.notes,
    )


@router.delete("/{source}/{event_id}/resolve")
async def unresolve_event(
    source: str,
    event_id: str,
    _token: str = Depends(verify_session_token),
) -> Dict:
    """Remove a resolution record (mark event as active again)."""
    deleted = get_resolution_store().unresolve(source, event_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Resolution not found")
    return {"success": True}
