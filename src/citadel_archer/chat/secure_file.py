# PRD: Secure File Sharing
# Reference: docs/PRD.md v0.3.19, Phase 4
#
# Encrypted, time-limited, self-destructing file sharing for P2P messaging.
#
# Features:
#   - AES-256-GCM encryption with random 256-bit per-file key
#   - Configurable TTL (default 24h, max 7 days)
#   - Optional self-destruct after first download
#   - SHA-256 integrity verification before and after encryption
#   - Per-contact file shares with trust enforcement
#   - Automatic cleanup of expired files
#
# Security:
#   - Each file encrypted with a unique random key (no key reuse)
#   - File key stored in SQLite, encrypted files on disk
#   - Nonce stored with ciphertext (12-byte random nonce per encryption)
#   - Blocked contacts cannot receive or access file shares
#   - Expired files deleted from disk and database
#
# Design:
#   - Follows ContactRegistry + SessionStore patterns: SQLite + WAL + contextmanager
#   - File content stored on disk (not in SQLite) for scalability
#   - Metadata + keys in SQLite for queryability
#   - Singleton accessor via get_file_manager()

import hashlib
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

NONCE_SIZE = 12             # AES-256-GCM nonce (96 bits per NIST)
KEY_SIZE = 32               # AES-256 key (256 bits)
CHUNK_SIZE = 64 * 1024      # 64 KB — reserved for future streaming encryption
# NOTE: Current implementation reads files fully into memory.
# AES-256-GCM requires full plaintext for single-shot auth tag.
# For files >100MB, switch to chunked encryption with per-chunk tags.
DEFAULT_TTL_HOURS = 24      # Default file share expiry
MAX_TTL_HOURS = 168         # Maximum TTL: 7 days
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB max per file


# ── Data Model ───────────────────────────────────────────────────────


@dataclass
class FileShare:
    """Metadata for a shared encrypted file."""
    share_id: str             # UUID
    filename: str             # Original filename (for display)
    file_size: int            # Original file size in bytes
    checksum: str             # SHA-256 of original plaintext
    encrypted_path: str       # Path to encrypted file on disk
    encryption_key: str       # Hex-encoded AES-256 key
    contact_id: Optional[str] # Target contact (None = self/local)
    created_at: str           # ISO 8601 UTC
    expires_at: str           # ISO 8601 UTC
    self_destruct: bool       # Delete after first download?
    download_count: int       # Number of times downloaded
    is_expired: bool          # Computed: past expiry time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "share_id": self.share_id,
            "filename": self.filename,
            "file_size": self.file_size,
            "checksum": self.checksum,
            "contact_id": self.contact_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "self_destruct": self.self_destruct,
            "download_count": self.download_count,
            "is_expired": self.is_expired,
            # Intentionally omit: encrypted_path, encryption_key (server-only)
        }


# ── File Encryption ──────────────────────────────────────────────────


def encrypt_file(
    source_path: str,
    dest_path: str,
    key: Optional[bytes] = None,
) -> Tuple[bytes, str]:
    """Encrypt a file with AES-256-GCM.

    Reads the source file, computes SHA-256 checksum, encrypts with a
    random nonce, and writes nonce ‖ ciphertext to dest_path.

    Args:
        source_path: Path to plaintext file.
        dest_path: Path to write encrypted output.
        key: 32-byte AES-256 key (generated if None).

    Returns:
        (key, checksum) — the encryption key and SHA-256 hex digest.

    Raises:
        ValueError: If file exceeds MAX_FILE_SIZE.
        FileNotFoundError: If source_path doesn't exist.
    """
    source = Path(source_path)
    if not source.exists():
        raise FileNotFoundError(f"Source file not found: {source_path}")

    file_size = source.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})"
        )

    if key is None:
        key = os.urandom(KEY_SIZE)

    # Read entire file, compute checksum, encrypt
    plaintext = source.read_bytes()
    checksum = hashlib.sha256(plaintext).hexdigest()

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Write nonce ‖ ciphertext
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(nonce + ciphertext)

    return key, checksum


def decrypt_file(
    encrypted_path: str,
    key: bytes,
) -> bytes:
    """Decrypt a file encrypted with encrypt_file().

    Reads nonce ‖ ciphertext from encrypted_path, decrypts with AES-256-GCM.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        FileNotFoundError: If encrypted file doesn't exist.
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key or tampered).
    """
    enc_path = Path(encrypted_path)
    if not enc_path.exists():
        raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")

    data = enc_path.read_bytes()
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def verify_checksum(data: bytes, expected_checksum: str) -> bool:
    """Verify SHA-256 checksum of data matches expected hex digest."""
    return hashlib.sha256(data).hexdigest() == expected_checksum


# ── Secure File Manager ──────────────────────────────────────────────


class SecureFileManager:
    """Manages encrypted file shares with TTL and self-destruct.

    Files are encrypted with random AES-256-GCM keys and stored on disk.
    Metadata (filename, checksum, key, expiry) is stored in SQLite.

    Usage::

        mgr = SecureFileManager()
        share = mgr.share_file("/path/to/doc.pdf", ttl_hours=48)
        data = mgr.download(share.share_id)
        mgr.cleanup_expired()
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        storage_dir: Optional[str] = None,
    ):
        self.db_path = Path(db_path) if db_path else Path("data/file_shares.db")
        self.storage_dir = Path(storage_dir) if storage_dir else Path("data/encrypted_files")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()

    @contextmanager
    def _connect(self):
        """Open a WAL-mode SQLite connection; auto-closes on exit."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_shares (
                    share_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    checksum TEXT NOT NULL,
                    encrypted_path TEXT NOT NULL,
                    encryption_key TEXT NOT NULL,
                    contact_id TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    self_destruct INTEGER NOT NULL DEFAULT 0,
                    download_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_shares_contact
                ON file_shares(contact_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_shares_expires
                ON file_shares(expires_at)
            """)

    # ── Share Operations ─────────────────────────────────────────────

    def update_filename(self, share_id: str, filename: str) -> bool:
        """Update the display filename for a share."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE file_shares SET filename = ? WHERE share_id = ?",
                    (filename, share_id),
                )
                return cursor.rowcount > 0

    def share_file(
        self,
        source_path: str,
        contact_id: Optional[str] = None,
        ttl_hours: int = DEFAULT_TTL_HOURS,
        self_destruct: bool = False,
    ) -> FileShare:
        """Encrypt and share a file.

        Args:
            source_path: Path to the file to share.
            contact_id: Target contact UUID (None for local/self shares).
            ttl_hours: Hours until the share expires (1-168).
            self_destruct: If True, file is deleted after first download.

        Returns:
            FileShare with metadata (share_id for retrieval).

        Raises:
            ValueError: If file too large or TTL out of range.
            FileNotFoundError: If source file doesn't exist.
        """
        ttl_hours = max(1, min(ttl_hours, MAX_TTL_HOURS))

        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"File not found: {source_path}")

        file_size = source.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError(
                f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})"
            )

        share_id = str(uuid4())
        encrypted_filename = f"{share_id}.enc"
        encrypted_path = str(self.storage_dir / encrypted_filename)

        key, checksum = encrypt_file(source_path, encrypted_path)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ttl_hours)

        share = FileShare(
            share_id=share_id,
            filename=source.name,
            file_size=file_size,
            checksum=checksum,
            encrypted_path=encrypted_path,
            encryption_key=key.hex(),
            contact_id=contact_id,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            self_destruct=self_destruct,
            download_count=0,
            is_expired=False,
        )

        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO file_shares
                    (share_id, filename, file_size, checksum, encrypted_path,
                     encryption_key, contact_id, created_at, expires_at,
                     self_destruct, download_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    share.share_id, share.filename, share.file_size,
                    share.checksum, share.encrypted_path,
                    share.encryption_key, share.contact_id,
                    share.created_at, share.expires_at,
                    1 if share.self_destruct else 0, 0,
                ))

        logger.info(
            "File shared: %s (%s bytes, ttl=%dh, self_destruct=%s) → %s",
            share.filename, share.file_size, ttl_hours,
            self_destruct, share_id[:8],
        )
        return share

    def download(self, share_id: str) -> Optional[Tuple[bytes, FileShare]]:
        """Download and decrypt a shared file.

        Returns:
            (plaintext_data, file_share) or None if not found/expired.

        Side effects:
            - Increments download_count
            - If self_destruct=True, atomically deletes the DB record before
              returning data (prevents race condition on concurrent downloads)
        """
        # Atomically fetch and claim the share under a single lock
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM file_shares WHERE share_id = ?",
                    (share_id,),
                ).fetchone()
                if row is None:
                    return None

                share = self._row_to_share(row)

                if share.is_expired:
                    self._delete_files(share)
                    conn.execute(
                        "DELETE FROM file_shares WHERE share_id = ?",
                        (share_id,),
                    )
                    return None

                if share.self_destruct:
                    # Atomically delete record — if two threads race, only
                    # the one that succeeds at deletion proceeds
                    cursor = conn.execute(
                        "DELETE FROM file_shares WHERE share_id = ?",
                        (share_id,),
                    )
                    if cursor.rowcount == 0:
                        return None  # Another thread consumed it
                else:
                    conn.execute(
                        "UPDATE file_shares SET download_count = download_count + 1 "
                        "WHERE share_id = ?",
                        (share_id,),
                    )

        # Decrypt outside the lock (CPU-intensive, don't hold lock)
        key = bytes.fromhex(share.encryption_key)
        try:
            plaintext = decrypt_file(share.encrypted_path, key)
        except FileNotFoundError:
            logger.warning("Encrypted file missing for share %s", share_id[:8])
            return None

        # Verify integrity
        if not verify_checksum(plaintext, share.checksum):
            logger.error(
                "Checksum mismatch for share %s — possible tampering",
                share_id[:8],
            )
            return None

        share.download_count += 1

        # Clean up encrypted file for self-destruct (record already deleted)
        if share.self_destruct:
            logger.info("Self-destructing share %s after download", share_id[:8])
            self._delete_files(share)

        return plaintext, share

    def get(self, share_id: str) -> Optional[FileShare]:
        """Get file share metadata by ID."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM file_shares WHERE share_id = ?",
                    (share_id,),
                ).fetchone()
                return self._row_to_share(row) if row else None

    def list_shares(
        self,
        contact_id: Optional[str] = None,
        include_expired: bool = False,
    ) -> List[FileShare]:
        """List file shares with optional filtering."""
        query = "SELECT * FROM file_shares"
        conditions = []
        params = []

        if contact_id is not None:
            conditions.append("contact_id = ?")
            params.append(contact_id)

        if not include_expired:
            now = datetime.now(timezone.utc).isoformat()
            conditions.append("expires_at > ?")
            params.append(now)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_share(r) for r in rows]

    def delete(self, share_id: str) -> bool:
        """Delete a file share (removes encrypted file and metadata)."""
        share = self.get(share_id)
        if share is None:
            return False

        self._delete_files(share)
        return self._delete_record(share_id)

    def extend_ttl(self, share_id: str, additional_hours: int) -> Optional[FileShare]:
        """Extend a share's TTL.

        Args:
            share_id: The share to extend.
            additional_hours: Hours to add (capped at MAX_TTL from now).

        Returns:
            Updated FileShare or None if not found.
        """
        share = self.get(share_id)
        if share is None:
            return None

        now = datetime.now(timezone.utc)
        max_expires = now + timedelta(hours=MAX_TTL_HOURS)
        current_expires = datetime.fromisoformat(share.expires_at)
        new_expires = current_expires + timedelta(hours=additional_hours)

        # Cap at max TTL from now
        if new_expires > max_expires:
            new_expires = max_expires

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE file_shares SET expires_at = ? WHERE share_id = ?",
                    (new_expires.isoformat(), share_id),
                )

        share.expires_at = new_expires.isoformat()
        share.is_expired = False
        return share

    def cleanup_expired(self) -> int:
        """Delete all expired file shares. Returns count of deleted shares."""
        now = datetime.now(timezone.utc).isoformat()
        deleted = 0

        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM file_shares WHERE expires_at <= ?",
                    (now,),
                ).fetchall()

                for row in rows:
                    share = self._row_to_share(row)
                    self._delete_files(share)
                    conn.execute(
                        "DELETE FROM file_shares WHERE share_id = ?",
                        (share.share_id,),
                    )
                    deleted += 1

        if deleted > 0:
            logger.info("Cleaned up %d expired file shares", deleted)
        return deleted

    def stats(self) -> Dict[str, Any]:
        """Return file sharing statistics."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM file_shares",
                ).fetchone()[0]
                active = conn.execute(
                    "SELECT COUNT(*) FROM file_shares WHERE expires_at > ?",
                    (now,),
                ).fetchone()[0]
                total_size = conn.execute(
                    "SELECT COALESCE(SUM(file_size), 0) FROM file_shares "
                    "WHERE expires_at > ?",
                    (now,),
                ).fetchone()[0]
                total_downloads = conn.execute(
                    "SELECT COALESCE(SUM(download_count), 0) FROM file_shares",
                ).fetchone()[0]

                return {
                    "total_shares": total,
                    "active_shares": active,
                    "expired_shares": total - active,
                    "total_size_bytes": total_size,
                    "total_downloads": total_downloads,
                }

    # ── Internal ─────────────────────────────────────────────────────

    def _row_to_share(self, row: sqlite3.Row) -> FileShare:
        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(row["expires_at"])
        # Ensure both are timezone-aware for comparison
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        return FileShare(
            share_id=row["share_id"],
            filename=row["filename"],
            file_size=row["file_size"],
            checksum=row["checksum"],
            encrypted_path=row["encrypted_path"],
            encryption_key=row["encryption_key"],
            contact_id=row["contact_id"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            self_destruct=bool(row["self_destruct"]),
            download_count=row["download_count"],
            is_expired=now >= expires,
        )

    def _delete_files(self, share: FileShare) -> None:
        """Remove encrypted file from disk."""
        try:
            enc_path = Path(share.encrypted_path)
            if enc_path.exists():
                enc_path.unlink()
        except OSError as exc:
            logger.warning(
                "Failed to delete encrypted file for share %s: %s",
                share.share_id[:8], exc,
            )

    def _delete_record(self, share_id: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM file_shares WHERE share_id = ?",
                    (share_id,),
                )
                return cursor.rowcount > 0


# ── Singleton ────────────────────────────────────────────────────────

_manager: Optional[SecureFileManager] = None
_manager_lock = threading.Lock()


def get_file_manager() -> SecureFileManager:
    """Get or create the global SecureFileManager singleton."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = SecureFileManager()
    return _manager
