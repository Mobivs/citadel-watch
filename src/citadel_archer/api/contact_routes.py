# PRD: Contact Management API Routes
# Reference: docs/PRD.md v0.3.17, Phase 4
#
# REST endpoints for managing contacts and trusted peers.
# All endpoints require session auth (verify_session_token).
#
# Endpoints:
#   GET    /api/contacts         - List contacts (filter by trust, tag, search)
#   POST   /api/contacts         - Add a new contact
#   GET    /api/contacts/{id}    - Get contact details
#   PUT    /api/contacts/{id}    - Update contact metadata
#   DELETE /api/contacts/{id}    - Remove a contact
#   POST   /api/contacts/{id}/trust  - Set trust level
#   GET    /api/contacts/stats   - Contact registry statistics
#   GET    /api/contacts/verify/{fingerprint} - Look up by fingerprint

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from .security import verify_session_token
from ..chat.contact_registry import (
    Contact,
    ContactRegistry,
    TrustLevel,
    get_contact_registry,
    validate_public_key,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/contacts", tags=["contacts"])


# ── Request/Response Models ──────────────────────────────────────────


class AddContactRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=100)
    public_key: str = Field(
        ..., min_length=64, max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
        description="Hex-encoded Ed25519 public key",
    )
    alias: str = Field("", max_length=50)
    notes: str = Field("", max_length=500)
    tags: str = Field("", max_length=200, description="Comma-separated tags")


class UpdateContactRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=100)
    alias: Optional[str] = Field(None, max_length=50)
    notes: Optional[str] = Field(None, max_length=500)
    tags: Optional[str] = Field(None, max_length=200)


class SetTrustRequest(BaseModel):
    trust_level: TrustLevel = Field(..., description="Trust level: pending, verified, trusted, blocked")


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("")
async def list_contacts(
    trust: Optional[str] = Query(None, description="Filter by trust level"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    search: Optional[str] = Query(None, description="Search name/alias/notes"),
    _token: str = Depends(verify_session_token),
):
    """List all contacts with optional filtering."""
    registry = get_contact_registry()
    trust_level = None
    if trust:
        try:
            trust_level = TrustLevel(trust)
        except ValueError:
            raise HTTPException(400, f"Invalid trust level: {trust}")

    contacts = registry.list_contacts(
        trust_level=trust_level, tag=tag, search=search,
    )
    return {
        "contacts": [c.to_dict() for c in contacts],
        "total": len(contacts),
    }


@router.post("", status_code=201)
async def add_contact(
    req: AddContactRequest,
    _token: str = Depends(verify_session_token),
):
    """Add a new contact to the registry."""
    registry = get_contact_registry()
    try:
        contact = registry.add(
            display_name=req.display_name,
            public_key=req.public_key,
            alias=req.alias,
            notes=req.notes,
            tags=req.tags,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return contact.to_dict()


@router.get("/stats")
async def contact_stats(
    _token: str = Depends(verify_session_token),
):
    """Get contact registry statistics."""
    return get_contact_registry().stats()


@router.get("/verify/{fingerprint:path}")
async def verify_fingerprint(
    fingerprint: str = Path(..., description="Colon-separated fingerprint"),
    _token: str = Depends(verify_session_token),
):
    """Look up a contact by their public key fingerprint."""
    contact = get_contact_registry().get_by_fingerprint(fingerprint)
    if contact is None:
        raise HTTPException(404, "No contact found with this fingerprint")
    return contact.to_dict()


@router.get("/{contact_id}")
async def get_contact(
    contact_id: str,
    _token: str = Depends(verify_session_token),
):
    """Get a specific contact's details."""
    contact = get_contact_registry().get(contact_id)
    if contact is None:
        raise HTTPException(404, "Contact not found")
    return contact.to_dict()


@router.put("/{contact_id}")
async def update_contact(
    contact_id: str,
    req: UpdateContactRequest,
    _token: str = Depends(verify_session_token),
):
    """Update contact metadata (name, alias, notes, tags)."""
    registry = get_contact_registry()
    existing = registry.get(contact_id)
    if existing is None:
        raise HTTPException(404, "Contact not found")

    updated = registry.update(
        contact_id,
        display_name=req.display_name,
        alias=req.alias,
        notes=req.notes,
        tags=req.tags,
    )
    return updated.to_dict() if updated else existing.to_dict()


@router.delete("/{contact_id}")
async def delete_contact(
    contact_id: str,
    _token: str = Depends(verify_session_token),
):
    """Remove a contact permanently."""
    if not get_contact_registry().delete(contact_id):
        raise HTTPException(404, "Contact not found")
    return {"deleted": True, "contact_id": contact_id}


@router.post("/{contact_id}/trust")
async def set_trust_level(
    contact_id: str,
    req: SetTrustRequest,
    _token: str = Depends(verify_session_token),
):
    """Set a contact's trust level."""
    registry = get_contact_registry()
    contact = registry.set_trust(contact_id, req.trust_level)
    if contact is None:
        raise HTTPException(404, "Contact not found")
    return contact.to_dict()
