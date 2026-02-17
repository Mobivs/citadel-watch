# PRD: Secure File Sharing API Routes
# Reference: docs/PRD.md v0.3.19, Phase 4
#
# REST endpoints for encrypted file sharing between peers.
# All endpoints require session auth (verify_session_token).
#
# Endpoints:
#   POST   /api/files/share         - Upload & encrypt a file for sharing
#   GET    /api/files/{share_id}    - Get file share metadata
#   GET    /api/files/{share_id}/download - Download & decrypt a shared file
#   GET    /api/files               - List file shares (filter by contact)
#   DELETE /api/files/{share_id}    - Delete a file share
#   POST   /api/files/{share_id}/extend  - Extend share TTL
#   POST   /api/files/cleanup       - Remove expired file shares
#   GET    /api/files/stats/summary - File sharing statistics

import logging
import os
import re
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .security import verify_session_token
from ..chat.secure_file import (
    MAX_FILE_SIZE,
    MAX_TTL_HOURS,
    SecureFileManager,
    get_file_manager,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/files", tags=["files"])


# ── Request/Response Models ──────────────────────────────────────────


class ExtendTTLRequest(BaseModel):
    additional_hours: int = Field(
        ..., ge=1, le=MAX_TTL_HOURS,
        description="Hours to add to the share TTL",
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.post("/share", status_code=201)
async def share_file(
    file: UploadFile = File(...),
    contact_id: Optional[str] = Query(None, description="Target contact UUID"),
    ttl_hours: int = Query(24, ge=1, le=MAX_TTL_HOURS, description="Hours until expiry"),
    self_destruct: bool = Query(False, description="Delete after first download"),
    _token: str = Depends(verify_session_token),
):
    """Upload, encrypt, and share a file.

    The file is encrypted with a unique AES-256-GCM key and stored on disk.
    Returns share metadata including a share_id for retrieval.
    """
    # Validate file size via Content-Length header if available
    if file.size is not None and file.size > MAX_FILE_SIZE:
        raise HTTPException(
            413,
            f"File too large: {file.size} bytes (max {MAX_FILE_SIZE})",
        )

    # Write upload to a temp file, then pass to SecureFileManager
    try:
        content = await file.read()
    except Exception:
        raise HTTPException(400, "Failed to read uploaded file")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            413,
            f"File too large: {len(content)} bytes (max {MAX_FILE_SIZE})",
        )

    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # Write to temp file (SecureFileManager.share_file expects a path)
    # Sanitize filename for temp suffix (prevent path traversal / special chars)
    safe_suffix = re.sub(r'[^\w.\-]', '_', file.filename or 'upload')[:100]
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=f"_{safe_suffix}")
    try:
        try:
            os.write(tmp_fd, content)
        finally:
            os.close(tmp_fd)

        mgr = get_file_manager()
        share = mgr.share_file(
            source_path=tmp_path,
            contact_id=contact_id,
            ttl_hours=ttl_hours,
            self_destruct=self_destruct,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc))
    finally:
        # Always clean up the temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Override filename from the upload (temp file has a generated name)
    if file.filename:
        share.filename = file.filename
        mgr.update_filename(share.share_id, file.filename)

    return share.to_dict()


@router.get("/stats/summary")
async def file_stats(
    _token: str = Depends(verify_session_token),
):
    """Get file sharing statistics."""
    return get_file_manager().stats()


@router.get("/{share_id}")
async def get_share(
    share_id: str,
    _token: str = Depends(verify_session_token),
):
    """Get file share metadata by ID."""
    share = get_file_manager().get(share_id)
    if share is None:
        raise HTTPException(404, "File share not found")
    return share.to_dict()


@router.get("/{share_id}/download")
async def download_file(
    share_id: str,
    _token: str = Depends(verify_session_token),
):
    """Download and decrypt a shared file.

    Returns the decrypted file content with appropriate Content-Type
    and Content-Disposition headers. If the share has self_destruct=True,
    the share is deleted after this download.
    """
    mgr = get_file_manager()
    result = mgr.download(share_id)

    if result is None:
        raise HTTPException(404, "File share not found or expired")

    plaintext, share = result

    # Sanitize filename for Content-Disposition header (prevent header injection)
    safe_filename = re.sub(r'[^\w\s\-.]', '_', share.filename)
    safe_filename = safe_filename.strip('. ')
    if not safe_filename:
        safe_filename = "download"

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Content-Length": str(len(plaintext)),
            "X-Checksum-SHA256": share.checksum,
        },
    )


@router.get("")
async def list_shares(
    contact_id: Optional[str] = Query(None, description="Filter by contact UUID"),
    include_expired: bool = Query(False, description="Include expired shares"),
    _token: str = Depends(verify_session_token),
):
    """List file shares with optional filtering."""
    shares = get_file_manager().list_shares(
        contact_id=contact_id,
        include_expired=include_expired,
    )
    return {
        "shares": [s.to_dict() for s in shares],
        "total": len(shares),
    }


@router.delete("/{share_id}")
async def delete_share(
    share_id: str,
    _token: str = Depends(verify_session_token),
):
    """Delete a file share (removes encrypted file and metadata)."""
    if not get_file_manager().delete(share_id):
        raise HTTPException(404, "File share not found")
    return {"deleted": True, "share_id": share_id}


@router.post("/{share_id}/extend")
async def extend_share(
    share_id: str,
    req: ExtendTTLRequest,
    _token: str = Depends(verify_session_token),
):
    """Extend a share's TTL (capped at max TTL from now)."""
    share = get_file_manager().extend_ttl(share_id, req.additional_hours)
    if share is None:
        raise HTTPException(404, "File share not found")
    return share.to_dict()


@router.post("/cleanup")
async def cleanup_expired(
    _token: str = Depends(verify_session_token),
):
    """Remove all expired file shares from disk and database."""
    count = get_file_manager().cleanup_expired()
    return {"cleaned_up": count}
