# PRD: Vault API - RESTful endpoints for password management
# Reference: docs/PRD.md v0.2.3, Section: Vault
#
# API endpoints for vault operations:
# - Initialize/unlock/lock vault
# - CRUD operations for passwords
# - All operations require vault to be unlocked

from typing import Optional
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field

from ..vault import VaultManager
from .security import verify_session_token

# Global vault instance (singleton for desktop app)
vault_manager = VaultManager()

router = APIRouter(prefix="/api/vault", tags=["vault"])


# Request/Response Models
class InitializeVaultRequest(BaseModel):
    master_password: str = Field(..., min_length=12)


class UnlockVaultRequest(BaseModel):
    master_password: str


class AddPasswordRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=1)
    username: Optional[str] = None
    website: Optional[str] = None
    notes: Optional[str] = None
    category: str = "general"


class VaultStatusResponse(BaseModel):
    is_unlocked: bool
    vault_exists: bool


class PasswordResponse(BaseModel):
    id: str
    title: str
    username: Optional[str]
    website: Optional[str]
    notes: Optional[str]
    created_at: str
    updated_at: str
    category: str
    # password field only included when specifically requested


# Endpoints

@router.get("/status", response_model=VaultStatusResponse)
async def get_vault_status(token: str = Depends(verify_session_token)):
    """
    Get current vault status.

    Returns whether vault exists and is unlocked.

    Security: Requires valid session token in X-Session-Token header.
    """
    return VaultStatusResponse(
        is_unlocked=vault_manager.is_unlocked,
        vault_exists=vault_manager.vault_path.exists() and vault_manager.vault_path.stat().st_size > 0
    )


@router.post("/initialize")
async def initialize_vault(
    request: InitializeVaultRequest,
    token: str = Depends(verify_session_token)
):
    """
    Initialize new vault with master password.

    PRD: "Master password (PBKDF2 key derivation)"

    Password requirements:
    - At least 12 characters
    - Mix of uppercase, lowercase, numbers

    Security: Requires valid session token in X-Session-Token header.
    """
    success, message = vault_manager.initialize_vault(request.master_password)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    return {"success": True, "message": message}


@router.post("/unlock")
async def unlock_vault(
    request: UnlockVaultRequest,
    token: str = Depends(verify_session_token)
):
    """
    Unlock vault with master password.

    All vault operations require vault to be unlocked first.

    Security: Requires valid session token in X-Session-Token header.
    """
    success, message = vault_manager.unlock_vault(request.master_password)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=message
        )

    return {"success": True, "message": message}


@router.post("/lock")
async def lock_vault(token: str = Depends(verify_session_token)):
    """
    Lock vault (close database connection).

    Security: Requires valid session token in X-Session-Token header.
    """
    vault_manager.lock_vault()
    return {"success": True, "message": "Vault locked"}


@router.post("/passwords")
async def add_password(
    request: AddPasswordRequest,
    token: str = Depends(verify_session_token)
):
    """
    Add new password to vault.

    PRD: "Store website credentials, API keys, etc."

    Requires vault to be unlocked.

    Security: Requires valid session token in X-Session-Token header.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked. Unlock vault first."
        )

    success, result = vault_manager.add_password(
        title=request.title,
        password=request.password,
        username=request.username,
        website=request.website,
        notes=request.notes,
        category=request.category
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result
        )

    return {"success": True, "password_id": result}


@router.get("/passwords")
async def list_passwords(
    category: Optional[str] = None,
    token: str = Depends(verify_session_token)
):
    """
    List all passwords in vault.

    Does not return decrypted passwords (for security).
    Use GET /passwords/{id} to retrieve specific password.

    Requires vault to be unlocked.

    Security: Requires valid session token in X-Session-Token header.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked"
        )

    passwords = vault_manager.list_passwords(category=category)
    return {"passwords": passwords}


@router.get("/passwords/{password_id}")
async def get_password(
    password_id: str,
    token: str = Depends(verify_session_token)
):
    """
    Get password by ID (with decrypted password).

    Requires vault to be unlocked.

    Security: Requires valid session token in X-Session-Token header.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked"
        )

    password = vault_manager.get_password(password_id)

    if password is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password not found"
        )

    return password


@router.delete("/passwords/{password_id}")
async def delete_password(
    password_id: str,
    token: str = Depends(verify_session_token)
):
    """
    Delete password from vault.

    Requires vault to be unlocked.

    Security: Requires valid session token in X-Session-Token header.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked"
        )

    success, message = vault_manager.delete_password(password_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )

    return {"success": True, "message": message}
