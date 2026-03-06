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


class AddSSHCredentialRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    auth_type: str = Field("key", pattern="^(key|password)$")
    private_key: Optional[str] = None
    key_passphrase: str = ""
    password: Optional[str] = None
    default_username: str = "root"
    default_port: int = Field(22, ge=1, le=65535)


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


# ── Auto-unlock endpoints ─────────────────────────────────────────────────────

@router.get("/auto-unlock/status")
async def get_auto_unlock_status(token: str = Depends(verify_session_token)):
    """Return whether auto-unlock is configured and if the env var is set."""
    return {
        "configured": vault_manager.is_auto_unlock_configured,
        "env_var_set": bool(__import__("os").environ.get("CITADEL_VAULT_PASSWORD")),
    }


class EnableAutoUnlockRequest(BaseModel):
    master_password: str = Field(..., min_length=1)


@router.post("/auto-unlock/enable")
async def enable_auto_unlock(
    request: EnableAutoUnlockRequest,
    token: str = Depends(verify_session_token),
):
    """Save the master password for startup auto-unlock.

    The password is encrypted with a machine-specific key stored in
    data/machine.key — both files must be present to decrypt.

    Security note: This stores the vault password (encrypted) on disk.
    Anyone with filesystem access to data/ can decrypt the vault.
    Only enable this on machines you trust.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unlock the vault first before enabling auto-unlock",
        )
    # Verify the supplied password is actually correct before storing it
    success, _msg = vault_manager.unlock_vault(request.master_password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect master password — auto-unlock not saved",
        )
    ok = vault_manager.store_auto_unlock_credential(request.master_password)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to store auto-unlock credential")

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION, EventSeverity.INFO,
            "Vault auto-unlock enabled — startup credential stored"
        )
    except Exception:
        pass

    return {"success": True, "message": "Auto-unlock enabled — vault will unlock automatically on next startup"}


@router.delete("/auto-unlock")
async def disable_auto_unlock(token: str = Depends(verify_session_token)):
    """Remove the stored auto-unlock credential."""
    ok = vault_manager.clear_auto_unlock_credential()

    try:
        from ..core.audit_log import log_security_event, EventType, EventSeverity
        log_security_event(
            EventType.AI_DECISION, EventSeverity.INFO,
            "Vault auto-unlock disabled — startup credential removed"
        )
    except Exception:
        pass

    return {"success": ok, "message": "Auto-unlock disabled" if ok else "Failed to remove credential"}


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


# ── SSH Credential Endpoints ─────────────────────────────────────────

@router.post("/ssh-credentials")
async def add_ssh_credential(
    request: AddSSHCredentialRequest,
    token: str = Depends(verify_session_token),
):
    """Add an SSH credential to the vault.

    Validates key format and stores structured SSH metadata.
    Requires vault to be unlocked.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked. Unlock vault first.",
        )

    success, result = vault_manager.add_ssh_credential(
        title=request.title,
        auth_type=request.auth_type,
        private_key=request.private_key,
        key_passphrase=request.key_passphrase,
        password=request.password,
        default_username=request.default_username,
        default_port=request.default_port,
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=result)

    return {"success": True, "credential_id": result}


@router.post("/ssh-credentials/generate")
async def generate_ssh_keypair(
    token: str = Depends(verify_session_token),
):
    """Generate a new Ed25519 SSH keypair and save the private key to the vault.

    Returns the public key so the user can install it on the target server.
    Requires vault to be unlocked.
    """
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked. Unlock vault first.",
        )

    try:
        import asyncssh
        key = asyncssh.generate_private_key("ssh-ed25519")
        private_key_str = key.export_private_key().decode()
        public_key_str = key.export_public_key().decode().strip()
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="asyncssh not installed. Run: pip install asyncssh",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key generation failed: {exc}",
        )

    # Return both keys — the caller saves via POST /ssh-credentials so the
    # user's chosen name is used. Private key is shown once; user should back it up.
    return {
        "public_key": public_key_str,
        "private_key": private_key_str,
        "key_type": "ed25519",
    }


@router.get("/ssh-credentials")
async def list_ssh_credentials(
    token: str = Depends(verify_session_token),
):
    """List all SSH credentials (metadata only, no keys/passwords)."""
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked",
        )

    return {"credentials": vault_manager.list_passwords(category="ssh")}


@router.get("/ssh-credentials/{credential_id}")
async def get_ssh_credential(
    credential_id: str,
    token: str = Depends(verify_session_token),
):
    """Get a parsed SSH credential with auth details."""
    if not vault_manager.is_unlocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vault is locked",
        )

    cred = vault_manager.get_ssh_credential(credential_id)
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSH credential not found",
        )

    # Derive public key from private key so the UI can display it
    if cred.get("auth_type") == "key" and cred.get("private_key"):
        try:
            import asyncssh
            _key = asyncssh.import_private_key(cred["private_key"])
            cred["public_key"] = _key.export_public_key().decode().strip()
        except Exception:
            pass

    return cred
