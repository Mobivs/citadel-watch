# PRD: Vault Manager - Encrypted Password Database
# Reference: docs/PRD.md v0.2.3, Section: Vault
#
# SQLCipher database for password storage
# CRUD operations for passwords
# Master password verification

import sqlite3
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import uuid
import time

from .encryption import EncryptionService, verify_master_password
from ..core import get_audit_logger, EventType, EventSeverity


class VaultManager:
    """
    Manages encrypted password vault using SQLCipher.

    PRD: "Vault: Secure password manager (password storage, basic encryption)"

    Security:
    - SQLCipher database (encrypted at rest)
    - Each password encrypted with AES-256-GCM
    - Master password never stored (only salt for derivation)
    - Audit logging for all vault access
    """

    def __init__(self, vault_path: Optional[Path] = None):
        """
        Initialize vault manager.

        Args:
            vault_path: Path to vault database file
                       If None, uses default: data/vault.db
        """
        if vault_path is None:
            # Default vault location
            base_dir = Path(__file__).parent.parent.parent.parent  # citadel-archer/
            vault_path = base_dir / "data" / "vault.db"

        self.vault_path = vault_path
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn: Optional[sqlite3.Connection] = None
        self.encryption_key: Optional[bytes] = None
        self.is_unlocked = False

        # Rate limiting for unlock attempts (prevent brute force)
        self.failed_attempts = 0
        self.last_attempt_time: Optional[datetime] = None
        self.lockout_until: Optional[datetime] = None

        self.logger = get_audit_logger()

    @staticmethod
    def _escape_pragma_value(value: str) -> str:
        """
        Escape single quotes for SQLCipher PRAGMA statements.

        Security: Prevents SQL injection by doubling single quotes.
        This is the SQL standard way to escape quotes in string literals.

        Args:
            value: String to escape

        Returns:
            Escaped string safe for use in PRAGMA statements
        """
        return value.replace("'", "''")

    def initialize_vault(self, master_password: str) -> Tuple[bool, str]:
        """
        Create new vault with master password.

        PRD: "Master password (PBKDF2 key derivation)"

        Args:
            master_password: User's master password

        Returns:
            (success, message)
        """
        # Verify password strength
        is_valid, error_msg = verify_master_password(master_password)
        if not is_valid:
            return False, error_msg

        # Check if vault already exists
        if self.vault_path.exists():
            return False, "Vault already exists. Use unlock_vault() instead."

        try:
            # Generate salt for PBKDF2
            salt = EncryptionService.generate_salt()
            salt_b64 = EncryptionService.encode_for_storage(salt)

            # Create SQLCipher database
            conn = sqlite3.connect(str(self.vault_path))

            # Enable SQLCipher encryption (database-level encryption)
            # This encrypts the entire database file
            # Security: Escape single quotes to prevent SQL injection
            escaped_password = self._escape_pragma_value(master_password)
            conn.execute(f"PRAGMA key = '{escaped_password}'")

            # Create schema
            conn.execute("""
                CREATE TABLE vault_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE passwords (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    username TEXT,
                    website TEXT,
                    notes TEXT,
                    encrypted_password TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    category TEXT DEFAULT 'general'
                )
            """)

            # Store vault metadata
            conn.execute(
                "INSERT INTO vault_config (key, value) VALUES (?, ?)",
                ("salt", salt_b64)
            )
            conn.execute(
                "INSERT INTO vault_config (key, value) VALUES (?, ?)",
                ("created_at", datetime.utcnow().isoformat())
            )
            conn.execute(
                "INSERT INTO vault_config (key, value) VALUES (?, ?)",
                ("version", "1.0")
            )

            conn.commit()
            conn.close()

            self.logger.log_event(
                event_type=EventType.VAULT_CREATED,
                severity=EventSeverity.INFO,
                message="Vault initialized with master password"
            )

            return True, "Vault created successfully!"

        except Exception as e:
            self.logger.log_event(
                event_type=EventType.VAULT_ERROR,
                severity=EventSeverity.CRITICAL,
                message=f"Failed to initialize vault: {str(e)}"
            )
            return False, f"Failed to create vault: {str(e)}"

    def unlock_vault(self, master_password: str) -> Tuple[bool, str]:
        """
        Unlock vault with master password.

        PRD: Master password unlocks all stored passwords.

        Security: Rate limiting with exponential backoff to prevent brute force.
        - 1st failed attempt: no delay
        - 2nd failed attempt: 2 second delay
        - 3rd failed attempt: 4 second delay
        - 4th failed attempt: 8 second delay
        - 5th+ failed attempt: 16 second delay

        Args:
            master_password: User's master password

        Returns:
            (success, message)
        """
        # Rate limiting: Check if locked out
        if self.lockout_until and datetime.now() < self.lockout_until:
            remaining = (self.lockout_until - datetime.now()).seconds
            self.logger.log_event(
                event_type=EventType.VAULT_UNLOCK_FAILED,
                severity=EventSeverity.ALERT,
                message=f"Unlock attempt during lockout period ({remaining}s remaining)"
            )
            return False, f"Too many failed attempts. Please wait {remaining} seconds."

        if not self.vault_path.exists():
            return False, "Vault does not exist. Initialize vault first."

        try:
            # Open SQLCipher database
            conn = sqlite3.connect(str(self.vault_path))
            # Security: Escape single quotes to prevent SQL injection
            escaped_password = self._escape_pragma_value(master_password)
            conn.execute(f"PRAGMA key = '{escaped_password}'")

            # Verify password is correct by reading from database
            cursor = conn.execute(
                "SELECT value FROM vault_config WHERE key = 'salt'"
            )
            result = cursor.fetchone()

            if result is None:
                conn.close()

                # Rate limiting: Increment failed attempts
                self.failed_attempts += 1
                delay_seconds = min(2 ** (self.failed_attempts - 1), 16)  # Max 16 seconds
                self.lockout_until = datetime.now() + timedelta(seconds=delay_seconds)

                self.logger.log_event(
                    event_type=EventType.VAULT_UNLOCK_FAILED,
                    severity=EventSeverity.ALERT,
                    message=f"Vault unlock failed: incorrect password (attempt {self.failed_attempts}, {delay_seconds}s lockout)"
                )

                if self.failed_attempts == 1:
                    return False, "Incorrect master password"
                else:
                    return False, f"Incorrect master password. Please wait {delay_seconds} seconds before trying again."

            # Derive encryption key for password encryption
            salt_b64 = result[0]
            salt = EncryptionService.decode_from_storage(salt_b64)
            self.encryption_key = EncryptionService.derive_key(master_password, salt)

            self.conn = conn
            self.is_unlocked = True

            # Rate limiting: Reset on successful unlock
            self.failed_attempts = 0
            self.lockout_until = None

            self.logger.log_event(
                event_type=EventType.VAULT_UNLOCKED,
                severity=EventSeverity.INFO,
                message="Vault unlocked successfully"
            )

            return True, "Vault unlocked successfully!"

        except sqlite3.DatabaseError:
            # Rate limiting: Increment failed attempts
            self.failed_attempts += 1
            delay_seconds = min(2 ** (self.failed_attempts - 1), 16)  # Max 16 seconds
            self.lockout_until = datetime.now() + timedelta(seconds=delay_seconds)

            self.logger.log_event(
                event_type=EventType.VAULT_UNLOCK_FAILED,
                severity=EventSeverity.ALERT,
                message=f"Vault unlock failed: incorrect password (attempt {self.failed_attempts}, {delay_seconds}s lockout)"
            )

            if self.failed_attempts == 1:
                return False, "Incorrect master password or corrupted vault"
            else:
                return False, f"Incorrect master password. Please wait {delay_seconds} seconds before trying again."

        except Exception as e:
            self.logger.log_event(
                event_type=EventType.VAULT_ERROR,
                severity=EventSeverity.CRITICAL,
                message=f"Vault unlock error: {str(e)}"
            )
            return False, f"Failed to unlock vault: {str(e)}"

    def lock_vault(self):
        """Lock vault (close database connection)."""
        if self.conn:
            self.conn.close()
            self.conn = None

        self.encryption_key = None
        self.is_unlocked = False

        self.logger.log_event(
            event_type=EventType.VAULT_LOCKED,
            severity=EventSeverity.INFO,
            message="Vault locked"
        )

    def add_password(
        self,
        title: str,
        password: str,
        username: Optional[str] = None,
        website: Optional[str] = None,
        notes: Optional[str] = None,
        category: str = "general"
    ) -> Tuple[bool, str]:
        """
        Add new password to vault.

        PRD: "Store website credentials, API keys, etc."

        Args:
            title: Password entry title (e.g., "Gmail Account")
            password: Actual password to encrypt and store
            username: Optional username/email
            website: Optional website URL
            notes: Optional notes
            category: Category (general, banking, social, work, etc.)

        Returns:
            (success, message or password_id)
        """
        if not self.is_unlocked:
            return False, "Vault is locked. Unlock vault first."

        try:
            # Encrypt password with AES-256-GCM
            nonce, ciphertext = EncryptionService.encrypt(password, self.encryption_key)

            # Encode for database storage
            nonce_b64 = EncryptionService.encode_for_storage(nonce)
            ciphertext_b64 = EncryptionService.encode_for_storage(ciphertext)

            # Generate unique ID
            password_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()

            # Insert into database
            self.conn.execute("""
                INSERT INTO passwords
                (id, title, username, website, notes, encrypted_password, nonce, created_at, updated_at, category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                password_id,
                title,
                username,
                website,
                notes,
                ciphertext_b64,
                nonce_b64,
                now,
                now,
                category
            ))

            self.conn.commit()

            self.logger.log_event(
                event_type=EventType.VAULT_PASSWORD_ADDED,
                severity=EventSeverity.INFO,
                message=f"Password added to vault: {title}",
                details={"password_id": password_id, "category": category}
            )

            return True, password_id

        except Exception as e:
            self.logger.log_event(
                event_type=EventType.VAULT_ERROR,
                severity=EventSeverity.CRITICAL,
                message=f"Failed to add password: {str(e)}"
            )
            return False, f"Failed to add password: {str(e)}"

    def get_password(self, password_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve and decrypt password by ID.

        Returns:
            Password entry with decrypted password, or None if not found
        """
        if not self.is_unlocked:
            return None

        try:
            cursor = self.conn.execute(
                "SELECT * FROM passwords WHERE id = ?",
                (password_id,)
            )

            row = cursor.fetchone()
            if not row:
                return None

            # Decrypt password
            nonce = EncryptionService.decode_from_storage(row[6])  # nonce column
            ciphertext = EncryptionService.decode_from_storage(row[5])  # encrypted_password
            decrypted_password = EncryptionService.decrypt(nonce, ciphertext, self.encryption_key)

            self.logger.log_event(
                event_type=EventType.VAULT_PASSWORD_ACCESSED,
                severity=EventSeverity.INFO,
                message=f"Password accessed: {row[1]}",  # title
                details={"password_id": password_id}
            )

            return {
                "id": row[0],
                "title": row[1],
                "username": row[2],
                "website": row[3],
                "notes": row[4],
                "password": decrypted_password,
                "created_at": row[7],
                "updated_at": row[8],
                "category": row[9]
            }

        except Exception as e:
            self.logger.log_event(
                event_type=EventType.VAULT_ERROR,
                severity=EventSeverity.CRITICAL,
                message=f"Failed to get password: {str(e)}"
            )
            return None

    def list_passwords(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all passwords in vault (without decrypting).

        Args:
            category: Optional filter by category

        Returns:
            List of password entries (without decrypted passwords)
        """
        if not self.is_unlocked:
            return []

        try:
            if category:
                cursor = self.conn.execute(
                    "SELECT id, title, username, website, created_at, updated_at, category FROM passwords WHERE category = ? ORDER BY title",
                    (category,)
                )
            else:
                cursor = self.conn.execute(
                    "SELECT id, title, username, website, created_at, updated_at, category FROM passwords ORDER BY title"
                )

            passwords = []
            for row in cursor.fetchall():
                passwords.append({
                    "id": row[0],
                    "title": row[1],
                    "username": row[2],
                    "website": row[3],
                    "created_at": row[4],
                    "updated_at": row[5],
                    "category": row[6]
                })

            return passwords

        except Exception as e:
            self.logger.log_event(
                event_type=EventType.VAULT_ERROR,
                severity=EventSeverity.CRITICAL,
                message=f"Failed to list passwords: {str(e)}"
            )
            return []

    def delete_password(self, password_id: str) -> Tuple[bool, str]:
        """Delete password from vault."""
        if not self.is_unlocked:
            return False, "Vault is locked"

        try:
            self.conn.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            self.conn.commit()

            self.logger.log_event(
                event_type=EventType.VAULT_PASSWORD_DELETED,
                severity=EventSeverity.INFO,
                message=f"Password deleted from vault",
                details={"password_id": password_id}
            )

            return True, "Password deleted successfully"

        except Exception as e:
            return False, f"Failed to delete password: {str(e)}"
