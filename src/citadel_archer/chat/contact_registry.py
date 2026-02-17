# PRD: Contact Management & Trusted Peer Registry
# Reference: docs/PRD.md v0.3.17, Phase 4
#
# Manages contacts (trusted peers) for SecureChat P2P messaging.
# Each contact has:
#   - Unique contact_id (UUID)
#   - Display name and optional alias
#   - Public key (Ed25519) for message verification
#   - Fingerprint (SHA-256 of public key) for out-of-band verification
#   - Trust level: pending, verified, trusted, blocked
#   - Optional metadata: notes, tags, avatar hash
#
# Trust establishment:
#   1. User adds contact (display name + public key)
#   2. Contact starts as "pending" (key received but not verified)
#   3. User verifies fingerprint out-of-band → "verified"
#   4. User explicitly trusts → "trusted" (can send/receive messages)
#   5. User can block → "blocked" (all messages rejected)
#
# Security:
#   - Public keys stored as hex-encoded Ed25519 keys
#   - Fingerprint = SHA-256(public_key_bytes) displayed as colon-separated hex
#   - Contact DB is local-only (not synced, not shared)
#   - Blocked contacts cannot send or receive messages
#
# Design:
#   - Follows AgentRegistry pattern: SQLite + WAL + thread-safe
#   - Dataclass model (Contact) with to_dict() for API serialization
#   - Singleton accessor via get_contact_registry()

import hashlib
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────


class TrustLevel(str, Enum):
    """Trust level for a contact."""
    PENDING = "pending"       # Key received, not verified
    VERIFIED = "verified"     # Fingerprint verified out-of-band
    TRUSTED = "trusted"       # Explicitly trusted by user
    BLOCKED = "blocked"       # All messages rejected


# ── Data Model ───────────────────────────────────────────────────────


@dataclass
class Contact:
    """A trusted peer in the contact registry."""
    contact_id: str
    display_name: str
    public_key: str           # Hex-encoded Ed25519 public key
    fingerprint: str          # SHA-256 of public key bytes, colon-separated hex
    trust_level: TrustLevel = TrustLevel.PENDING
    alias: str = ""           # Optional user-defined alias
    notes: str = ""           # Free-text notes
    tags: str = ""            # Comma-separated tags
    created_at: str = ""
    updated_at: str = ""
    last_message_at: str = ""  # Last time a message was sent/received
    message_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contact_id": self.contact_id,
            "display_name": self.display_name,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint,
            "trust_level": self.trust_level.value if isinstance(self.trust_level, TrustLevel) else self.trust_level,
            "alias": self.alias,
            "notes": self.notes,
            "tags": [t.strip() for t in self.tags.split(",") if t.strip()] if self.tags else [],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_message_at": self.last_message_at,
            "message_count": self.message_count,
        }


# ── Fingerprint Helpers ──────────────────────────────────────────────


def compute_fingerprint(public_key_hex: str) -> str:
    """Compute SHA-256 fingerprint from hex-encoded public key.

    Returns colon-separated hex string for human-readable verification.
    Example: "AB:CD:EF:12:34:..."
    """
    try:
        key_bytes = bytes.fromhex(public_key_hex)
    except ValueError:
        raise ValueError("Invalid hex-encoded public key")
    digest = hashlib.sha256(key_bytes).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def validate_public_key(public_key_hex: str) -> bool:
    """Validate that a hex string is a valid Ed25519 public key (32 bytes)."""
    try:
        key_bytes = bytes.fromhex(public_key_hex)
        return len(key_bytes) == 32
    except (ValueError, TypeError):
        return False


# ── Contact Registry ─────────────────────────────────────────────────


class ContactRegistry:
    """SQLite-backed contact management and trusted peer registry.

    Thread-safe. Follows the AgentRegistry pattern with WAL journal mode.

    Usage::

        registry = ContactRegistry()
        contact = registry.add("Alice", public_key_hex="abcd...")
        registry.set_trust(contact.contact_id, TrustLevel.VERIFIED)
        all_trusted = registry.list_contacts(trust_level=TrustLevel.TRUSTED)
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/contacts.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    contact_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    public_key TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    trust_level TEXT NOT NULL DEFAULT 'pending',
                    alias TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    tags TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_message_at TEXT DEFAULT '',
                    message_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_contacts_trust
                ON contacts(trust_level)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_contacts_name
                ON contacts(display_name)
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_fingerprint
                ON contacts(fingerprint)
            """)

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

    # ── CRUD Operations ──────────────────────────────────────────────

    def add(
        self,
        display_name: str,
        public_key: str,
        alias: str = "",
        notes: str = "",
        tags: str = "",
        trust_level: TrustLevel = TrustLevel.PENDING,
    ) -> Contact:
        """Add a new contact.

        Args:
            display_name: Human-readable name.
            public_key: Hex-encoded Ed25519 public key (32 bytes = 64 hex chars).
            alias: Optional user-defined alias.
            notes: Free-text notes.
            tags: Comma-separated tags.
            trust_level: Initial trust level (default: pending).

        Returns:
            The created Contact.

        Raises:
            ValueError: If public key is invalid or already registered.
        """
        public_key = public_key.lower().strip()

        if not validate_public_key(public_key):
            raise ValueError(
                "Invalid public key: must be 32-byte Ed25519 key as 64 hex characters"
            )

        fingerprint = compute_fingerprint(public_key)
        now = datetime.now(timezone.utc).isoformat()
        contact_id = str(uuid4())

        contact = Contact(
            contact_id=contact_id,
            display_name=display_name.strip(),
            public_key=public_key,
            fingerprint=fingerprint,
            trust_level=trust_level,
            alias=alias.strip(),
            notes=notes.strip(),
            tags=tags.strip(),
            created_at=now,
            updated_at=now,
        )

        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute("""
                        INSERT INTO contacts
                        (contact_id, display_name, public_key, fingerprint,
                         trust_level, alias, notes, tags, created_at, updated_at,
                         last_message_at, message_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        contact.contact_id, contact.display_name,
                        contact.public_key, contact.fingerprint,
                        contact.trust_level.value, contact.alias,
                        contact.notes, contact.tags,
                        contact.created_at, contact.updated_at,
                        "", 0,
                    ))
                except sqlite3.IntegrityError as exc:
                    msg = str(exc)
                    if "public_key" in msg or "fingerprint" in msg:
                        raise ValueError("Public key already registered") from exc
                    raise

        logger.info(
            "Contact added: %s (%s) trust=%s",
            display_name, contact_id[:8], trust_level.value,
        )
        return contact

    def get(self, contact_id: str) -> Optional[Contact]:
        """Get a contact by ID."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM contacts WHERE contact_id = ?",
                    (contact_id,),
                ).fetchone()
                return self._row_to_contact(row) if row else None

    def get_by_fingerprint(self, fingerprint: str) -> Optional[Contact]:
        """Look up a contact by their public key fingerprint."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM contacts WHERE fingerprint = ?",
                    (fingerprint,),
                ).fetchone()
                return self._row_to_contact(row) if row else None

    def get_by_public_key(self, public_key: str) -> Optional[Contact]:
        """Look up a contact by their public key."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM contacts WHERE public_key = ?",
                    (public_key.lower().strip(),),
                ).fetchone()
                return self._row_to_contact(row) if row else None

    def list_contacts(
        self,
        trust_level: Optional[TrustLevel] = None,
        tag: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Contact]:
        """List contacts with optional filtering.

        Args:
            trust_level: Filter by trust level.
            tag: Filter by tag (substring match in comma-separated tags).
            search: Search in display_name, alias, and notes.
        """
        query = "SELECT * FROM contacts"
        conditions = []
        params = []

        if trust_level is not None:
            conditions.append("trust_level = ?")
            params.append(trust_level.value)

        if tag:
            # Match exact tag within comma-separated list using boundary checks
            # Handles: "tag", "tag,...", "...,tag", "...,tag,..."
            conditions.append(
                "(tags = ? OR tags LIKE ? OR tags LIKE ? OR tags LIKE ?)"
            )
            params.extend([tag, f"{tag},%", f"%,{tag}", f"%,{tag},%"])

        if search:
            conditions.append(
                "(display_name LIKE ? OR alias LIKE ? OR notes LIKE ?)"
            )
            term = f"%{search}%"
            params.extend([term, term, term])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY display_name ASC"

        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_contact(r) for r in rows]

    def update(
        self,
        contact_id: str,
        display_name: Optional[str] = None,
        alias: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Optional[Contact]:
        """Update contact metadata. Does NOT change trust level or public key."""
        now = datetime.now(timezone.utc).isoformat()
        updates = []
        params = []

        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name.strip())
        if alias is not None:
            updates.append("alias = ?")
            params.append(alias.strip())
        if notes is not None:
            updates.append("notes = ?")
            params.append(notes.strip())
        if tags is not None:
            updates.append("tags = ?")
            params.append(tags.strip())

        if not updates:
            return self.get(contact_id)

        updates.append("updated_at = ?")
        params.append(now)
        params.append(contact_id)

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    f"UPDATE contacts SET {', '.join(updates)} WHERE contact_id = ?",
                    params,
                )
                row = conn.execute(
                    "SELECT * FROM contacts WHERE contact_id = ?",
                    (contact_id,),
                ).fetchone()
                return self._row_to_contact(row) if row else None

    def delete(self, contact_id: str) -> bool:
        """Remove a contact permanently."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM contacts WHERE contact_id = ?",
                    (contact_id,),
                )
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info("Contact deleted: %s", contact_id[:8])
                return deleted

    # ── Trust Management ─────────────────────────────────────────────

    def set_trust(self, contact_id: str, trust_level: TrustLevel) -> Optional[Contact]:
        """Change a contact's trust level.

        Trust transitions:
          pending → verified (fingerprint confirmed)
          verified → trusted (user explicitly trusts)
          any → blocked (user blocks contact)
          blocked → pending (user unblocks, must re-verify)
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE contacts SET trust_level = ?, updated_at = ? WHERE contact_id = ?",
                    (trust_level.value, now, contact_id),
                )
                if cursor.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM contacts WHERE contact_id = ?",
                    (contact_id,),
                ).fetchone()
                logger.info(
                    "Contact trust updated: %s → %s",
                    contact_id[:8], trust_level.value,
                )
                return self._row_to_contact(row) if row else None

    def is_trusted(self, contact_id: str) -> bool:
        """Check if a contact can send/receive messages."""
        contact = self.get(contact_id)
        if contact is None:
            return False
        return contact.trust_level in (TrustLevel.VERIFIED, TrustLevel.TRUSTED)

    def is_blocked(self, contact_id: str) -> bool:
        """Check if a contact is blocked."""
        contact = self.get(contact_id)
        if contact is None:
            return False
        return contact.trust_level == TrustLevel.BLOCKED

    # ── Message Tracking ─────────────────────────────────────────────

    def record_message(self, contact_id: str) -> bool:
        """Record a message sent to/from this contact.

        Returns True if the contact was found and updated, False otherwise.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute("""
                    UPDATE contacts
                    SET message_count = message_count + 1,
                        last_message_at = ?
                    WHERE contact_id = ?
                """, (now, contact_id))
                return cursor.rowcount > 0

    # ── Statistics ───────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return contact registry statistics."""
        with self._lock:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
                by_trust = {}
                for row in conn.execute(
                    "SELECT trust_level, COUNT(*) FROM contacts GROUP BY trust_level"
                ).fetchall():
                    by_trust[row[0]] = row[1]

                return {
                    "total_contacts": total,
                    "by_trust_level": by_trust,
                }

    # ── Internal ─────────────────────────────────────────────────────

    def _row_to_contact(self, row: sqlite3.Row) -> Contact:
        """Convert a database row to a Contact dataclass."""
        trust = row["trust_level"]
        try:
            trust_level = TrustLevel(trust)
        except ValueError:
            trust_level = TrustLevel.PENDING

        return Contact(
            contact_id=row["contact_id"],
            display_name=row["display_name"],
            public_key=row["public_key"],
            fingerprint=row["fingerprint"],
            trust_level=trust_level,
            alias=row["alias"] or "",
            notes=row["notes"] or "",
            tags=row["tags"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_message_at=row["last_message_at"] or "",
            message_count=row["message_count"] or 0,
        )


# ── Singleton ────────────────────────────────────────────────────────

_registry: Optional[ContactRegistry] = None
_registry_lock = threading.Lock()


def get_contact_registry() -> ContactRegistry:
    """Get or create the global ContactRegistry singleton."""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ContactRegistry()
    return _registry
