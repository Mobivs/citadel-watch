"""Backup API routes — create, list, restore, and delete encrypted backups.

v0.3.33: Local encrypted backup + restore.  Off-site push deferred to v0.3.34.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..backup.backup_manager import BackupError, BackupManager
from .security import verify_session_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/backups", tags=["backups"])

# ── Singleton ────────────────────────────────────────────────────────

_backup_manager: Optional[BackupManager] = None


def get_backup_manager() -> BackupManager:
    """Lazy singleton — created on first use."""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager


# ── Pydantic Models ──────────────────────────────────────────────────


class CreateBackupRequest(BaseModel):
    passphrase: str = Field(..., min_length=12)
    label: str = Field("", max_length=100)


class RestoreBackupRequest(BaseModel):
    passphrase: str = Field(..., min_length=12)


# ── Routes ───────────────────────────────────────────────────────────


@router.post("")
async def create_backup(
    body: CreateBackupRequest,
    _user: dict = Depends(verify_session_token),
):
    """Create an encrypted backup of all dashboard state."""
    mgr = get_backup_manager()
    try:
        result = mgr.create_backup(body.passphrase, body.label)
    except BackupError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.get("")
async def list_backups(
    _user: dict = Depends(verify_session_token),
):
    """List all backup archives."""
    mgr = get_backup_manager()
    backups = mgr.list_backups()
    return {"backups": backups, "total": len(backups)}


@router.get("/{backup_id}")
async def get_backup_info(
    backup_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Get details for a specific backup."""
    mgr = get_backup_manager()
    info = mgr.get_backup_info(backup_id)
    if not info:
        raise HTTPException(status_code=404, detail="Backup not found.")
    return info


@router.delete("/{backup_id}")
async def delete_backup(
    backup_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Delete a backup archive and its record."""
    mgr = get_backup_manager()
    deleted = mgr.delete_backup(backup_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Backup not found.")
    return {"deleted": True}


@router.post("/{backup_id}/restore")
async def restore_backup(
    backup_id: str,
    body: RestoreBackupRequest,
    _user: dict = Depends(verify_session_token),
):
    """Restore dashboard state from an encrypted backup.

    Creates a pre-restore safety backup before overwriting databases.
    """
    mgr = get_backup_manager()
    try:
        result = mgr.restore_backup(backup_id, body.passphrase)
    except BackupError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.post("/{backup_id}/push")
async def push_to_agent(
    backup_id: str,
    _user: dict = Depends(verify_session_token),
):
    """Push backup to Remote Shield agent for off-site storage.

    Not yet implemented — deferred to v0.3.34.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Off-site backup push deferred to v0.3.34.",
    )
