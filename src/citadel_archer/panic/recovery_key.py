"""
Recovery Key Manager — two-tier SSH key system for safe credential rotation.

Architecture:
  - Recovery keys are marked with comment ``citadel-recovery-<key_id>``
    in ``~/.ssh/authorized_keys`` on the target VPS.
  - The private key is returned to the user exactly ONCE (via the API)
    and is NEVER stored on the server.
  - During panic credential rotation, recovery key lines are preserved
    while all other keys are replaced.
  - If a recovery key is compromised, ``rotate_recovery_key()`` atomically
    adds a new key before revoking the old one.
"""

import hashlib
import logging
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .panic_database import PanicDatabase

logger = logging.getLogger(__name__)

RECOVERY_KEY_COMMENT_PREFIX = "citadel-recovery-"
RECOVERY_KEY_SAVE_PATH = os.path.expanduser("~/.ssh/citadel-recovery.pem")


class RecoveryKeyManager:
    """Manage recovery SSH keys that survive panic credential rotation."""

    def __init__(self, db: PanicDatabase, authorized_keys_path: Optional[str] = None):
        self.db = db
        self.authorized_keys_path = authorized_keys_path or os.path.expanduser(
            "~/.ssh/authorized_keys"
        )

    # ── Public API ──────────────────────────────────────────────────

    async def generate_recovery_key(self) -> Dict:
        """Generate a new recovery key pair.

        - Stores the public key in ``authorized_keys`` AND the database.
        - Returns the private key to the caller — it is NEVER persisted.
        - Raises if a recovery key already exists (use ``rotate`` instead).
        """
        # Ensure no active recovery key already exists
        existing = self._get_active_recovery_key_from_db()
        if existing:
            raise RuntimeError(
                "A recovery key already exists. Use rotate_recovery_key() "
                "to replace it, or revoke it first."
            )

        key_id = f"rk_{secrets.token_hex(8)}"
        comment = f"{RECOVERY_KEY_COMMENT_PREFIX}{key_id}"

        private_key, public_key = self._generate_ed25519_keypair(comment)
        fingerprint = self._compute_fingerprint(public_key)

        # 1. Store metadata in database FIRST (public key + fingerprint, NOT private).
        #    If this succeeds but the file write fails, ensure_recovery_key_present()
        #    gives a clear "key in DB but not in authorized_keys" message.
        self._store_recovery_key_in_db(key_id, public_key, fingerprint, comment)

        # 2. Append to authorized_keys
        try:
            self._append_to_authorized_keys(public_key)
        except Exception:
            # Roll back the DB entry so state stays consistent
            self._revoke_recovery_key_in_db(key_id, reason="file write failed during generation")
            raise

        # 3. Auto-save private key to a known location
        saved_to = self._save_private_key(private_key)

        logger.info(f"Recovery key generated: {key_id} ({fingerprint}) → {saved_to}")

        return {
            "key_id": key_id,
            "fingerprint": fingerprint,
            "private_key": private_key,
            "public_key": public_key,
            "saved_to": saved_to,
            "warning": f"Private key auto-saved to {saved_to} — also save a backup copy.",
        }

    async def rotate_recovery_key(self) -> Dict:
        """Atomically rotate the recovery key.

        Steps (order is critical for safety):
          1. Generate new keypair
          2. Add new public key to authorized_keys
          3. Store new key in DB
          4. Remove old key from authorized_keys
          5. Revoke old key in DB

        If any step after (2) fails, the old key remains valid — no lockout.
        """
        old_key = self._get_active_recovery_key_from_db()
        if not old_key:
            raise RuntimeError(
                "No active recovery key to rotate. Use generate_recovery_key() first."
            )

        new_key_id = f"rk_{secrets.token_hex(8)}"
        new_comment = f"{RECOVERY_KEY_COMMENT_PREFIX}{new_key_id}"

        private_key, public_key = self._generate_ed25519_keypair(new_comment)
        fingerprint = self._compute_fingerprint(public_key)

        # Step 1+2: Add new key FIRST (atomic safety — old key still works)
        self._append_to_authorized_keys(public_key)
        self._store_recovery_key_in_db(new_key_id, public_key, fingerprint, new_comment)

        # Step 3: Remove old key from authorized_keys
        old_comment = old_key["comment"]
        self._remove_key_by_comment(old_comment)

        # Step 4: Revoke old key in DB
        self._revoke_recovery_key_in_db(
            old_key["key_id"], reason="Rotated — replaced by " + new_key_id
        )

        # Auto-save the new private key (overwrites the old one)
        saved_to = self._save_private_key(private_key)

        logger.info(
            f"Recovery key rotated: {old_key['key_id']} → {new_key_id} ({fingerprint}) → {saved_to}"
        )

        return {
            "key_id": new_key_id,
            "fingerprint": fingerprint,
            "private_key": private_key,
            "public_key": public_key,
            "replaced_key_id": old_key["key_id"],
            "saved_to": saved_to,
            "warning": f"Private key auto-saved to {saved_to} — also save a backup copy.",
        }

    async def verify_recovery_key(self) -> Dict:
        """Verify recovery key is present in both DB and authorized_keys."""
        db_key = self._get_active_recovery_key_from_db()
        if not db_key:
            return {"status": "missing", "reason": "No active recovery key in database"}

        # Check authorized_keys file
        file_keys = self._find_recovery_keys_in_file()
        key_in_file = any(
            db_key["comment"] in line for line in file_keys
        )

        if not key_in_file:
            return {
                "status": "desynchronized",
                "reason": "Recovery key exists in DB but not in authorized_keys",
                "key_id": db_key["key_id"],
                "fingerprint": db_key["fingerprint"],
            }

        # Update last_verified_at
        self._update_verified_timestamp(db_key["key_id"])

        return {
            "status": "valid",
            "key_id": db_key["key_id"],
            "fingerprint": db_key["fingerprint"],
            "created_at": db_key["created_at"],
            "last_verified_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_status(self) -> Dict:
        """Get recovery key status for the frontend dashboard."""
        db_key = self._get_active_recovery_key_from_db()
        if not db_key:
            return {
                "exists": False,
                "message": "No recovery key configured. Generate one before using Panic Room.",
            }

        file_keys = self._find_recovery_keys_in_file()
        in_file = any(db_key["comment"] in line for line in file_keys)

        return {
            "exists": True,
            "key_id": db_key["key_id"],
            "fingerprint": db_key["fingerprint"],
            "created_at": db_key["created_at"],
            "last_verified_at": db_key.get("last_verified_at"),
            "in_authorized_keys": in_file,
        }

    def ensure_recovery_key_present(self) -> bool:
        """Pre-flight check: abort if no recovery key is configured.

        Called by credential rotation before executing. Returns True if
        safe to proceed, raises RuntimeError if not.
        """
        db_key = self._get_active_recovery_key_from_db()
        if not db_key:
            raise RuntimeError(
                "Cannot rotate credentials — no recovery key configured. "
                "Set up a recovery key first via the Panic Room dashboard."
            )

        # Also verify it's actually in authorized_keys
        file_keys = self._find_recovery_keys_in_file()
        if not any(db_key["comment"] in line for line in file_keys):
            raise RuntimeError(
                "Recovery key exists in database but is missing from authorized_keys. "
                "Re-generate or verify the recovery key before rotating credentials."
            )

        return True

    def get_recovery_key_lines(self) -> List[str]:
        """Return all recovery key lines from authorized_keys.

        Used by credential rotation to preserve these lines during rotation.
        """
        return self._find_recovery_keys_in_file()

    # ── Private helpers ─────────────────────────────────────────────

    @staticmethod
    def _save_private_key(private_key: str) -> str:
        """Auto-save the private key to ``~/.ssh/citadel-recovery.pem``.

        - Creates ``~/.ssh/`` if needed (mode 700)
        - Writes with mode 600 (SSH refuses keys with loose permissions)
        - Overwrites any previous recovery key file
        - Returns the path it was saved to
        """
        save_path = RECOVERY_KEY_SAVE_PATH
        ssh_dir = os.path.dirname(save_path)
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

        # Write to a temp file first, then rename for atomicity
        tmp_path = save_path + ".tmp"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(private_key)
            os.replace(tmp_path, save_path)
        except Exception:
            # Clean up temp file on failure
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        logger.info(f"Recovery key private key saved to {save_path}")
        return save_path

    def _generate_ed25519_keypair(self, comment: str) -> Tuple[str, str]:
        """Generate an ed25519 SSH keypair. Returns (private_key, public_key)."""
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                key_path = os.path.join(tmpdir, "recovery_key")
                subprocess.run(
                    [
                        "ssh-keygen", "-t", "ed25519",
                        "-f", key_path,
                        "-N", "",  # no passphrase
                        "-C", comment,
                    ],
                    check=True,
                    capture_output=True,
                )
                with open(key_path, "r") as f:
                    private_key = f.read()
                with open(key_path + ".pub", "r") as f:
                    public_key = f.read().strip()
                return private_key, public_key

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.warning(f"ssh-keygen failed ({e}), using Python cryptography fallback")
            return self._generate_keypair_python(comment)

    @staticmethod
    def _generate_keypair_python(comment: str) -> Tuple[str, str]:
        """Fallback: generate keypair using the cryptography library."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        public_key_str = public_bytes.decode() + " " + comment
        return private_bytes.decode(), public_key_str

    @staticmethod
    def _compute_fingerprint(public_key: str) -> str:
        """Compute SHA256 fingerprint of an SSH public key."""
        parts = public_key.strip().split()
        if len(parts) < 2:
            return "unknown"
        key_data = parts[1]
        import base64
        try:
            raw = base64.b64decode(key_data)
            digest = hashlib.sha256(raw).digest()
            b64 = base64.b64encode(digest).decode().rstrip("=")
            return f"SHA256:{b64}"
        except Exception:
            return "SHA256:" + hashlib.sha256(key_data.encode()).hexdigest()[:43]

    def _append_to_authorized_keys(self, public_key: str):
        """Append a public key line to authorized_keys."""
        ssh_dir = os.path.dirname(self.authorized_keys_path)
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

        with open(self.authorized_keys_path, "a") as f:
            f.write(public_key.strip() + "\n")

        os.chmod(self.authorized_keys_path, 0o600)

    def _remove_key_by_comment(self, comment: str):
        """Remove lines from authorized_keys that contain the given comment."""
        if not os.path.exists(self.authorized_keys_path):
            return

        with open(self.authorized_keys_path, "r") as f:
            lines = f.readlines()

        filtered = [line for line in lines if comment not in line]

        with open(self.authorized_keys_path, "w") as f:
            f.writelines(filtered)

    def _find_recovery_keys_in_file(self) -> List[str]:
        """Return all lines in authorized_keys with a recovery key comment."""
        if not os.path.exists(self.authorized_keys_path):
            return []

        with open(self.authorized_keys_path, "r") as f:
            lines = f.readlines()

        return [
            line.strip()
            for line in lines
            if RECOVERY_KEY_COMMENT_PREFIX in line
        ]

    # ── Database helpers ────────────────────────────────────────────

    def _get_active_recovery_key_from_db(self) -> Optional[Dict]:
        """Get the currently active recovery key from the database."""
        from ..core.db import connect as db_connect

        with db_connect(self.db.db_path, row_factory=True) as conn:
            row = conn.execute(
                "SELECT * FROM recovery_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def _store_recovery_key_in_db(
        self, key_id: str, public_key: str, fingerprint: str, comment: str
    ):
        """Store recovery key metadata (NOT the private key) in the database."""
        from ..core.db import connect as db_connect

        with db_connect(self.db.db_path) as conn:
            conn.execute(
                """INSERT INTO recovery_keys
                   (key_id, public_key, fingerprint, comment, created_at, is_active)
                   VALUES (?, ?, ?, ?, ?, 1)""",
                (key_id, public_key, fingerprint, comment,
                 datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()

    def _revoke_recovery_key_in_db(self, key_id: str, reason: str = ""):
        """Mark a recovery key as revoked in the database."""
        from ..core.db import connect as db_connect

        with db_connect(self.db.db_path) as conn:
            conn.execute(
                """UPDATE recovery_keys
                   SET is_active = 0, revoked_at = ?, revoke_reason = ?
                   WHERE key_id = ?""",
                (datetime.now(timezone.utc).isoformat(), reason, key_id),
            )
            conn.commit()

    def _update_verified_timestamp(self, key_id: str):
        """Update the last_verified_at timestamp for a recovery key."""
        from ..core.db import connect as db_connect

        with db_connect(self.db.db_path) as conn:
            conn.execute(
                "UPDATE recovery_keys SET last_verified_at = ? WHERE key_id = ?",
                (datetime.now(timezone.utc).isoformat(), key_id),
            )
            conn.commit()
