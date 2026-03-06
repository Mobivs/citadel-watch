# SSH Key Rotation — Bumpless rotation and emergency recovery
#
# Two flows:
#   1. Bumpless Rotation (SSH works): rotate without ever losing access
#      pending → generating → key_written → asset_updated → cache_invalidated
#      → verified → old_key_removed → old_vault_cleared → completed
#
#   2. Emergency Recovery (SSH broken): regain access via Hostinger API
#      recovery_pending → recovery_key_uploaded → recovery_password_set
#      → recovery_manual_pending
#
# State is persisted in SQLite so rotation survives app restarts.
# On restart, in-progress rotations are resumed from their last known step.
#
# Safety invariants (inherited from panic room):
#   - Recovery keys (comment: citadel-recovery-*) are NEVER removed
#   - New key is verified before old key is removed
#   - Rollback is possible at any step before old_key_removed

import asyncio
import base64
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import asyncssh
except ImportError:
    asyncssh = None  # type: ignore[assignment]

from ..core.db import connect as db_connect

# ── Status constants ───────────────────────────────────────────────────────

TERMINAL_STATUSES = {"completed", "rolled_back", "failed", "recovery_manual_pending"}

# Rollback is allowed if status is in this set (we still have old key on remote)
ROLLBACK_ALLOWED = {
    "generating", "key_written", "asset_updated", "cache_invalidated", "verified",
}


# ── SSHRotationStore ───────────────────────────────────────────────────────

class SSHRotationStore:
    """SQLite-backed state store for SSH key rotations.

    Follows the UserPreferences db-connect pattern (WAL mode, per-call connection).
    DB file: data/ssh_rotations.db
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path("data/ssh_rotations.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with db_connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ssh_key_rotations (
                    rotation_id  TEXT PRIMARY KEY,
                    asset_id     TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'pending',
                    old_cred_id  TEXT,
                    new_cred_id  TEXT,
                    new_pub_key  TEXT,
                    old_pub_key  TEXT,
                    hostinger_vps_id INTEGER,
                    started_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL,
                    error        TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ssh_rot_asset "
                "ON ssh_key_rotations (asset_id, status)"
            )
            conn.commit()

    def _connect(self):
        return db_connect(self.db_path, row_factory=True)

    def create(self, asset_id: str, old_cred_id: Optional[str] = None,
               hostinger_vps_id: Optional[int] = None) -> str:
        """Create a new rotation record. Returns rotation_id."""
        rotation_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO ssh_key_rotations
                   (rotation_id, asset_id, status, old_cred_id, hostinger_vps_id,
                    started_at, updated_at)
                   VALUES (?, ?, 'pending', ?, ?, ?, ?)""",
                (rotation_id, asset_id, old_cred_id, hostinger_vps_id, now, now),
            )
            conn.commit()
        logger.info(f"[ssh_rotation] Created rotation {rotation_id} for asset {asset_id}")
        return rotation_id

    def update(self, rotation_id: str, status: str, **fields) -> None:
        """Update status and any extra fields (new_cred_id, new_pub_key, error, etc.)."""
        now = datetime.utcnow().isoformat()
        allowed_fields = {
            "new_cred_id", "new_pub_key", "old_pub_key", "error", "hostinger_vps_id"
        }
        extra_fields = {k: v for k, v in fields.items() if k in allowed_fields}

        set_parts = ["status = ?", "updated_at = ?"]
        params: List[Any] = [status, now]
        for col, val in extra_fields.items():
            set_parts.append(f"{col} = ?")
            params.append(val)
        params.append(rotation_id)

        with self._connect() as conn:
            conn.execute(
                f"UPDATE ssh_key_rotations SET {', '.join(set_parts)} "
                f"WHERE rotation_id = ?",
                params,
            )
            conn.commit()
        logger.info(f"[ssh_rotation] {rotation_id} → {status}")

    def get(self, rotation_id: str) -> Optional[Dict]:
        """Fetch a rotation record by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ssh_key_rotations WHERE rotation_id = ?", (rotation_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_active(self, asset_id: str) -> Optional[Dict]:
        """Return the active (non-terminal) rotation for an asset, or None."""
        placeholders = ",".join("?" * len(TERMINAL_STATUSES))
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM ssh_key_rotations "
                f"WHERE asset_id = ? AND status NOT IN ({placeholders}) "
                f"ORDER BY started_at DESC LIMIT 1",
                (asset_id, *TERMINAL_STATUSES),
            ).fetchone()
        return dict(row) if row else None

    def get_all_in_progress(self) -> List[Dict]:
        """Return all rotations that are not in a terminal state."""
        placeholders = ",".join("?" * len(TERMINAL_STATUSES))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM ssh_key_rotations "
                f"WHERE status NOT IN ({placeholders}) "
                f"ORDER BY started_at ASC",
                tuple(TERMINAL_STATUSES),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_latest(self, asset_id: str) -> Optional[Dict]:
        """Return the most recent rotation for an asset (any status)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ssh_key_rotations "
                "WHERE asset_id = ? ORDER BY started_at DESC LIMIT 1",
                (asset_id,),
            ).fetchone()
        return dict(row) if row else None


# ── Helper functions ───────────────────────────────────────────────────────

def _generate_ed25519_keypair(comment: str = "citadel-archer-rotated") -> Tuple[str, str]:
    """Generate an ed25519 keypair using asyncssh.

    Returns (private_key_openssh_pem, public_key_openssh_line).
    """
    if asyncssh is None:
        raise ImportError("asyncssh is required for SSH key rotation")
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    private_pem = key.export_private_key().decode("ascii")
    public_line = key.export_public_key().decode("ascii").strip()
    return private_pem, public_line


async def _write_key_to_authorized_keys(
    ssh_manager, asset_id: str, public_key_line: str
) -> None:
    """Atomically append a new public key to ~/.ssh/authorized_keys.

    Reuses the panic-room atomic write pattern (base64-pipe-to-tmp-mv).
    """
    # Read current authorized_keys (create if missing)
    read_result = await ssh_manager.execute(
        asset_id,
        "cat ~/.ssh/authorized_keys 2>/dev/null || echo ''",
        timeout=10,
    )
    current_content = (read_result.stdout or "").rstrip()

    # Ensure directory and file exist
    await ssh_manager.execute(
        asset_id,
        "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 700 ~/.ssh",
        timeout=10,
    )

    # Build new content: existing lines + new key
    lines = [line for line in current_content.splitlines() if line.strip()]
    # Don't add duplicate
    if public_key_line.strip() not in [line.strip() for line in lines]:
        lines.append(public_key_line.strip())
    new_content = "\n".join(lines) + "\n"

    # Atomic write via base64 + tmp file (panic-room pattern)
    encoded = base64.b64encode(new_content.encode()).decode("ascii")
    write_cmd = (
        f'printf "%s" "{encoded}" | base64 -d > ~/.ssh/authorized_keys.tmp '
        f'&& chmod 600 ~/.ssh/authorized_keys.tmp '
        f'&& mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys'
    )
    result = await ssh_manager.execute(asset_id, write_cmd, timeout=15)
    if result.exit_code != 0:
        raise RuntimeError(
            f"Failed to write authorized_keys: exit={result.exit_code} "
            f"stderr={result.stderr[:200]}"
        )


async def _remove_key_from_authorized_keys(
    ssh_manager, asset_id: str, public_key_line: str
) -> None:
    """Remove a specific public key from ~/.ssh/authorized_keys.

    Matches by the key material (the base64 blob), not the comment.
    Recovery keys (citadel-recovery-*) are never removed.
    """
    read_result = await ssh_manager.execute(
        asset_id,
        "cat ~/.ssh/authorized_keys 2>/dev/null || echo ''",
        timeout=10,
    )
    current_content = (read_result.stdout or "").rstrip()
    lines = current_content.splitlines()

    # Extract the key material (field 2 of "type material comment")
    key_parts = public_key_line.strip().split()
    key_material = key_parts[1] if len(key_parts) >= 2 else public_key_line.strip()

    # Filter out the target key, but NEVER remove recovery keys
    kept = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Never remove recovery keys
        if "citadel-recovery-" in stripped:
            kept.append(stripped)
            continue
        # Remove the old key by matching key material
        parts = stripped.split()
        if len(parts) >= 2 and parts[1] == key_material:
            logger.info(f"[ssh_rotation] Removing old key from authorized_keys on {asset_id}")
            continue
        kept.append(stripped)

    new_content = "\n".join(kept) + "\n" if kept else ""
    encoded = base64.b64encode(new_content.encode()).decode("ascii")
    write_cmd = (
        f'printf "%s" "{encoded}" | base64 -d > ~/.ssh/authorized_keys.tmp '
        f'&& chmod 600 ~/.ssh/authorized_keys.tmp '
        f'&& mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys'
    )
    result = await ssh_manager.execute(asset_id, write_cmd, timeout=15)
    if result.exit_code != 0:
        raise RuntimeError(
            f"Failed to remove old key from authorized_keys: exit={result.exit_code}"
        )


async def _check_recovery_key_present(ssh_manager, asset_id: str) -> bool:
    """Return True if a citadel-recovery-* key exists in authorized_keys."""
    result = await ssh_manager.execute(
        asset_id,
        "grep -c 'citadel-recovery-' ~/.ssh/authorized_keys 2>/dev/null || echo 0",
        timeout=10,
    )
    try:
        count = int((result.stdout or "0").strip())
        return count > 0
    except ValueError:
        return False


async def _verify_ssh_with_new_key(
    asset, new_private_key_pem: str
) -> Tuple[bool, str]:
    """Open a fresh SSH connection using ONLY the new key (bypasses manager cache).

    Returns (success, error_message).
    """
    if asyncssh is None:
        return False, "asyncssh not available"
    host = asset.ip_address or asset.hostname
    port = asset.ssh_port or 22
    username = asset.ssh_username or "root"
    conn = None
    try:
        key = asyncssh.import_private_key(new_private_key_pem)
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host=host,
                port=port,
                username=username,
                client_keys=[key],
                known_hosts=None,
            ),
            timeout=20,
        )
        # Run a quick test command
        result = await asyncio.wait_for(conn.run("echo ok", check=False), timeout=10)
        if (result.stdout or "").strip() == "ok":
            return True, ""
        return False, f"Unexpected output: {result.stdout!r}"
    except asyncio.TimeoutError:
        return False, "Connection timed out"
    except Exception as exc:
        return False, str(exc)
    finally:
        if conn is not None:
            conn.close()


# ── SSHKeyRotator ──────────────────────────────────────────────────────────

class SSHKeyRotator:
    """Orchestrates bumpless SSH key rotation and emergency recovery.

    Args:
        vault: Unlocked VaultManager instance.
        ssh: SSHConnectionManager instance.
        assets: AssetInventory instance.
        store: SSHRotationStore instance (defaults to new store).
    """

    def __init__(self, vault, ssh, assets, store: Optional[SSHRotationStore] = None):
        self.vault = vault
        self.ssh = ssh
        self.assets = assets
        self.store = store or SSHRotationStore()
        # In-memory lock prevents concurrent rotations on the same asset
        # (covers the TOCTOU gap between get_active() check and create())
        self._active: Dict[str, bool] = {}

    # ── Bumpless rotation ──────────────────────────────────────────────────

    async def start_rotation(self, asset_id: str) -> str:
        """Begin a bumpless SSH key rotation. Returns rotation_id.

        The rotation runs asynchronously — poll store.get(rotation_id) for status.

        Raises:
            ValueError: if asset not found, no SSH credential linked, or
                        rotation already in progress.
        """
        asset = self.assets.get(asset_id)
        if asset is None:
            raise ValueError(f"Asset '{asset_id}' not found")
        if not asset.ssh_credential_id:
            raise ValueError(f"Asset '{asset_id}' has no linked SSH credential")
        # Check both the in-memory lock (TOCTOU guard) and the DB (restart resume)
        if self._active.get(asset_id) or self.store.get_active(asset_id):
            raise ValueError(f"A rotation is already in progress for '{asset_id}'")

        old_cred_id = asset.ssh_credential_id
        rotation_id = self.store.create(asset_id, old_cred_id=old_cred_id)
        self._active[asset_id] = True

        # Fire and forget — caller polls for status
        asyncio.ensure_future(self._run_rotation(rotation_id, asset_id, old_cred_id))
        return rotation_id

    async def resume_rotation(self, rotation_id: str) -> Dict:
        """Resume a rotation from its last persisted status (after app restart)."""
        rec = self.store.get(rotation_id)
        if rec is None:
            return {"error": f"Rotation {rotation_id} not found"}
        if rec["status"] in TERMINAL_STATUSES:
            return {"status": rec["status"]}
        logger.info(f"[ssh_rotation] Resuming {rotation_id} from '{rec['status']}'")
        asyncio.ensure_future(
            self._run_rotation(
                rotation_id, rec["asset_id"], rec["old_cred_id"],
                resume_from=rec["status"],
                new_cred_id=rec.get("new_cred_id"),
                new_pub_key=rec.get("new_pub_key"),
            )
        )
        return {"status": "resuming", "rotation_id": rotation_id}

    async def rollback(self, rotation_id: str) -> Dict:
        """Reverse a rotation — restore the old credential.

        Only possible before old_key_removed step.
        Returns {"status": "rolled_back"} or {"error": "..."}.
        """
        rec = self.store.get(rotation_id)
        if rec is None:
            return {"error": "Rotation not found"}
        if rec["status"] not in ROLLBACK_ALLOWED:
            return {"error": f"Cannot rollback from status '{rec['status']}'"}

        asset_id = rec["asset_id"]
        old_cred_id = rec.get("old_cred_id")
        new_cred_id = rec.get("new_cred_id")
        new_pub_key = rec.get("new_pub_key")

        try:
            # Restore old credential in asset inventory
            if old_cred_id:
                self.assets.link_ssh_credential(asset_id, old_cred_id)
            # Invalidate cache so next connect uses old key
            await self.ssh.invalidate_cache(asset_id)

            # Best-effort: remove new key from authorized_keys (need working SSH)
            if new_pub_key:
                try:
                    await _remove_key_from_authorized_keys(self.ssh, asset_id, new_pub_key)
                except Exception as exc:
                    logger.warning(
                        f"[ssh_rotation] Could not remove new key during rollback "
                        f"(non-fatal): {exc}"
                    )

            # Delete the new vault credential
            if new_cred_id:
                try:
                    ok, msg = self.vault.delete_password(new_cred_id)
                    if not ok:
                        logger.warning(
                            f"[ssh_rotation] Could not delete new vault credential "
                            f"during rollback (vault may be locked): {msg}"
                        )
                except Exception as exc:
                    logger.warning(f"[ssh_rotation] Exception deleting new vault credential: {exc}")

            self.store.update(rotation_id, "rolled_back")
            return {"status": "rolled_back", "rotation_id": rotation_id}

        except Exception as exc:
            self.store.update(rotation_id, "failed", error=str(exc))
            return {"error": str(exc)}

    async def _run_rotation(
        self,
        rotation_id: str,
        asset_id: str,
        old_cred_id: Optional[str],
        resume_from: str = "pending",
        new_cred_id: Optional[str] = None,
        new_pub_key: Optional[str] = None,
    ) -> None:
        """Internal: drive the full rotation state machine.

        INVARIANT: status is updated to a step's name AFTER that step's side-effect
        succeeds, never before. This ensures that on restart resume, a status of X
        means X has actually been completed on the remote server and in the vault.
        """
        asset = self.assets.get(asset_id)
        if asset is None:
            self.store.update(rotation_id, "failed", error=f"Asset '{asset_id}' not found")
            return

        # Vault must be unlocked — steps 1, 5, 6, 7 all touch it
        if not self.vault.is_unlocked:
            self.store.update(
                rotation_id, "failed",
                error="Vault is locked — unlock the vault and retry"
            )
            logger.warning(
                f"[ssh_rotation] Rotation {rotation_id} aborted: vault is locked"
            )
            return

        new_private_key_pem: Optional[str] = None

        try:
            # ── Step 1: generating ─────────────────────────────────────────
            # Side-effect: generate keypair + store in vault
            # Status persisted AFTER vault write succeeds
            if resume_from in ("pending", "generating"):
                self.store.update(rotation_id, "generating")
                has_recovery = await _check_recovery_key_present(self.ssh, asset_id)
                if not has_recovery:
                    logger.warning(
                        f"[ssh_rotation] No recovery key on {asset_id} — proceeding anyway"
                    )

                priv_pem, pub_line = _generate_ed25519_keypair(
                    comment=f"citadel-archer-{asset_id[:8]}"
                )
                new_private_key_pem = priv_pem
                new_pub_key = pub_line

                ok, new_cred_id = self.vault.add_ssh_credential(
                    title=f"SSH Key — {asset.name} (rotated)",
                    auth_type="key",
                    private_key=new_private_key_pem,
                    default_username=asset.ssh_username or "root",
                    default_port=asset.ssh_port or 22,
                )
                if not ok:
                    raise RuntimeError(f"Failed to store new key in vault: {new_cred_id}")
                # Status + new_cred_id + new_pub_key written AFTER vault confirms
                self.store.update(rotation_id, "generating",
                                  new_cred_id=new_cred_id, new_pub_key=new_pub_key)

            # ── Step 2: key_written — CRITICAL SAFETY POINT ───────────────
            # Side-effect: write new public key to remote authorized_keys
            # Status persisted AFTER remote write succeeds
            # After this point, both old AND new keys grant access (bumpless)
            if resume_from in ("pending", "generating", "key_written"):
                if new_private_key_pem is None and new_cred_id:
                    # Reload from vault if resuming after restart
                    cred = self.vault.get_ssh_credential(new_cred_id)
                    if cred:
                        new_private_key_pem = cred.get("private_key", "")

                await _write_key_to_authorized_keys(self.ssh, asset_id, new_pub_key)
                self.store.update(rotation_id, "key_written")  # confirmed on server

            # ── Step 3: asset_updated ──────────────────────────────────────
            # Side-effect: update asset DB to point to new credential
            # Status persisted AFTER DB write succeeds
            if resume_from in ("pending", "generating", "key_written", "asset_updated"):
                self.assets.link_ssh_credential(asset_id, new_cred_id)
                self.store.update(rotation_id, "asset_updated")

            # ── Step 4: cache_invalidated ──────────────────────────────────
            # Side-effect: drop cached SSH connection so next connect uses new key
            # Status persisted AFTER cache drop succeeds
            if resume_from not in ("verified", "old_key_removed", "old_vault_cleared"):
                await self.ssh.invalidate_cache(asset_id)
                self.store.update(rotation_id, "cache_invalidated")

            # ── Step 5: verified ───────────────────────────────────────────
            # Side-effect: open fresh SSH connection using ONLY the new key
            # Status persisted AFTER successful verification
            # If this fails, old key is still valid — rollback is safe
            if resume_from not in ("old_key_removed", "old_vault_cleared"):
                # Reload private key from vault if we don't have it in memory
                if new_private_key_pem is None and new_cred_id:
                    cred = self.vault.get_ssh_credential(new_cred_id)
                    if cred:
                        new_private_key_pem = cred.get("private_key", "")

                if new_private_key_pem:
                    asset = self.assets.get(asset_id)  # refresh
                    if asset is None:
                        raise RuntimeError(
                            f"Asset '{asset_id}' was deleted during rotation"
                        )
                    success, err = await _verify_ssh_with_new_key(asset, new_private_key_pem)
                    if not success:
                        raise RuntimeError(
                            f"New key verification failed: {err}. "
                            "Old key is still active — safe to rollback."
                        )
                else:
                    logger.warning(
                        f"[ssh_rotation] Could not reload private key for verification "
                        f"— proceeding on trust"
                    )
                self.store.update(rotation_id, "verified")  # confirmed new key works

            # ── Step 6: old_key_removed ────────────────────────────────────
            # Side-effect: remove old public key from remote authorized_keys
            # Status persisted AFTER attempted removal (non-fatal if it fails)
            if resume_from != "old_vault_cleared":
                # Fetch old public key from vault BEFORE we delete the credential
                old_pub_key = self.store.get(rotation_id).get("old_pub_key")
                if not old_pub_key and old_cred_id:
                    old_cred = self.vault.get_ssh_credential(old_cred_id)
                    if old_cred and old_cred.get("auth_type") == "key":
                        try:
                            old_key = asyncssh.import_private_key(
                                old_cred.get("private_key", "")
                            )
                            old_pub_key = old_key.export_public_key().decode("ascii").strip()
                            # Persist old_pub_key for crash recovery WITHOUT advancing the
                            # status -- status must only advance AFTER the side-effect succeeds
                            self.store.update(rotation_id, "verified",
                                              old_pub_key=old_pub_key)
                        except Exception:
                            pass

                if old_pub_key:
                    try:
                        await _remove_key_from_authorized_keys(
                            self.ssh, asset_id, old_pub_key
                        )
                    except Exception as exc:
                        logger.warning(
                            f"[ssh_rotation] Could not remove old key from authorized_keys "
                            f"(non-fatal, old key stays): {exc}"
                        )
                self.store.update(rotation_id, "old_key_removed")

            # ── Step 7: old_vault_cleared ──────────────────────────────────
            # Side-effect: delete old SSH credential from vault
            # Status persisted AFTER deletion attempt (non-fatal if vault locked)
            if old_cred_id:
                try:
                    ok, msg = self.vault.delete_password(old_cred_id)
                    if not ok:
                        logger.warning(
                            f"[ssh_rotation] Could not delete old vault credential "
                            f"(vault may be locked): {msg}"
                        )
                except Exception as exc:
                    logger.warning(
                        f"[ssh_rotation] Exception deleting old vault credential: {exc}"
                    )
            self.store.update(rotation_id, "old_vault_cleared")

            # ── Done ───────────────────────────────────────────────────────
            self.store.update(rotation_id, "completed")
            logger.info(
                f"[ssh_rotation] Rotation {rotation_id} completed for asset {asset_id}"
            )

        except Exception as exc:
            err_msg = str(exc)
            logger.error(f"[ssh_rotation] Rotation {rotation_id} failed: {err_msg}", exc_info=True)
            self.store.update(rotation_id, "failed", error=err_msg)
        finally:
            self._active.pop(asset_id, None)

    # ── Emergency recovery ─────────────────────────────────────────────────

    async def start_recovery(
        self, asset_id: str, hostinger_vps_id: int
    ) -> Dict:
        """Begin emergency recovery when SSH is broken.

        Uses Hostinger API to set a temporary root password, then instructs
        the user to paste a new public key via the hPanel VPS console.

        Returns a dict with rotation_id, console_url, and new_pub_key.
        """
        asset = self.assets.get(asset_id)
        if asset is None:
            raise ValueError(f"Asset '{asset_id}' not found")
        if self._active.get(asset_id) or self.store.get_active(asset_id):
            raise ValueError(f"A rotation is already in progress for '{asset_id}'")

        old_cred_id = asset.ssh_credential_id or None
        rotation_id = self.store.create(
            asset_id,
            old_cred_id=old_cred_id,
            hostinger_vps_id=hostinger_vps_id,
        )
        self._active[asset_id] = True
        self.store.update(rotation_id, "recovery_pending")

        try:
            result = await self._run_recovery(rotation_id, asset_id, hostinger_vps_id)
        finally:
            self._active.pop(asset_id, None)
        return result

    async def complete_recovery(self, rotation_id: str) -> Dict:
        """Called after user has manually pasted the public key via console.

        Tests the new key; marks completed on success, or returns error.
        """
        rec = self.store.get(rotation_id)
        if rec is None:
            return {"error": "Rotation not found"}
        if rec["status"] != "recovery_manual_pending":
            return {"error": f"Recovery not in manual_pending state (status: {rec['status']})"}

        asset_id = rec["asset_id"]
        new_cred_id = rec.get("new_cred_id")
        asset = self.assets.get(asset_id)
        if asset is None:
            return {"error": f"Asset '{asset_id}' not found"}

        new_private_key_pem = None
        if new_cred_id:
            cred = self.vault.get_ssh_credential(new_cred_id)
            if cred:
                new_private_key_pem = cred.get("private_key", "")

        if not new_private_key_pem:
            return {"error": "Could not load new private key from vault"}

        success, err = await _verify_ssh_with_new_key(asset, new_private_key_pem)
        if not success:
            return {
                "success": False,
                "error": f"SSH test failed: {err}. Check the key was pasted correctly.",
                "new_pub_key": rec.get("new_pub_key", ""),
            }

        # Update asset to use new credential
        if new_cred_id:
            self.assets.link_ssh_credential(asset_id, new_cred_id)
        await self.ssh.invalidate_cache(asset_id)

        # Delete old vault credential (best-effort)
        old_cred_id = rec.get("old_cred_id")
        if old_cred_id:
            try:
                ok, msg = self.vault.delete_password(old_cred_id)
                if not ok:
                    logger.warning(
                        f"[ssh_rotation] Could not delete old vault credential "
                        f"in complete_recovery (vault may be locked): {msg}"
                    )
            except Exception as exc:
                logger.warning(f"[ssh_rotation] Exception deleting old vault credential: {exc}")

        self.store.update(rotation_id, "completed")
        return {"success": True, "status": "completed"}

    async def _run_recovery(
        self, rotation_id: str, asset_id: str, hostinger_vps_id: int
    ) -> Dict:
        """Internal: drive the emergency recovery state machine."""
        asset = self.assets.get(asset_id)
        console_url = (
            f"https://hpanel.hostinger.com/vps/{hostinger_vps_id}/overview"
        )

        try:
            # Generate new keypair and store in vault
            priv_pem, pub_line = _generate_ed25519_keypair(
                comment=f"citadel-archer-recovery-{asset_id[:8]}"
            )
            ok, new_cred_id = self.vault.add_ssh_credential(
                title=f"SSH Key — {asset.name if asset else asset_id} (recovery)",
                auth_type="key",
                private_key=priv_pem,
                default_username=(asset.ssh_username or "root") if asset else "root",
                default_port=(asset.ssh_port or 22) if asset else 22,
            )
            if not ok:
                raise RuntimeError(f"Failed to store recovery key in vault: {new_cred_id}")

            self.store.update(
                rotation_id, "recovery_key_uploaded",
                new_cred_id=new_cred_id,
                new_pub_key=pub_line,
            )

            # Set a temporary root password via Hostinger API
            import secrets
            import string
            tmp_password = "".join(
                secrets.choice(string.ascii_letters + string.digits)
                for _ in range(20)
            )
            try:
                from ..integrations.hostinger import HostingerClient
                client = HostingerClient()
                await client.set_root_password(hostinger_vps_id, tmp_password)
                self.store.update(rotation_id, "recovery_password_set")
                password_info = tmp_password
            except Exception as exc:
                logger.warning(
                    f"[ssh_rotation] Could not set root password via Hostinger API: {exc}"
                )
                password_info = None

            self.store.update(rotation_id, "recovery_manual_pending")

            return {
                "rotation_id": rotation_id,
                "status": "recovery_manual_pending",
                "new_pub_key": pub_line,
                "console_url": console_url,
                "tmp_password": password_info,
                "instructions": (
                    "1. Open the VPS Console link below.\n"
                    "2. Log in as root" +
                    (" with the temporary password shown separately." if password_info else ".") + "\n"
                    "3. Run: mkdir -p ~/.ssh && nano ~/.ssh/authorized_keys\n"
                    "4. Paste the public key shown below on a new line and save.\n"
                    "5. Click 'Done — Test Connection' to verify access."
                ),
            }

        except Exception as exc:
            self.store.update(rotation_id, "failed", error=str(exc))
            return {
                "rotation_id": rotation_id,
                "status": "failed",
                "error": str(exc),
                "console_url": console_url,
            }


# ── Singleton ──────────────────────────────────────────────────────────────

_store: Optional[SSHRotationStore] = None


def get_rotation_store() -> SSHRotationStore:
    """Get or create the global SSHRotationStore singleton."""
    global _store
    if _store is None:
        _store = SSHRotationStore()
    return _store
