# PRD: Secure Invitation-Based Agent Enrollment
# Reference: docs/PRD.md v0.3.22
#
# Manages one-time invitations for external AI agent enrollment.
# Flow:
#   1. Admin creates invitation → gets compact copy-paste string
#   2. User pastes string into Claude Code on remote VPS
#   3. Claude Code calls /enroll endpoint with the string
#   4. Server verifies + atomically consumes invitation
#   5. Agent registered via AgentRegistry, Bearer token returned
#
# Security:
#   - 256-bit enrollment secrets (SHA-256 hashed, never stored raw)
#   - HMAC-SHA256 binds invitation_id to secret (prevents mix-and-match)
#   - One-time use (atomic consume under lock + transaction)
#   - Short TTL (default 10 min, max 24h)
#   - Failed attempt tracking + lockout after N failures
#   - Server restart invalidates all pending invitations (HMAC key rotates)
#   - Full audit trail with IP addresses
#
# Design:
#   - Follows ContactRegistry pattern: SQLite + WAL + contextmanager + lock
#   - Singleton via get_invitation_store()

import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

COMPACT_STRING_VERSION = "CITADEL-1"
DEFAULT_TTL_SECONDS = 600       # 10 minutes
MIN_TTL_SECONDS = 60            # 1 minute
MAX_TTL_SECONDS = 86400         # 24 hours
DEFAULT_MAX_ATTEMPTS = 5
INVITATION_ID_LENGTH = 12       # hex chars (48 bits, lookup key only)
INVITATION_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
SECRET_CHAR_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


# ── Enums ────────────────────────────────────────────────────────────


class InvitationStatus(str, Enum):
    """Lifecycle states for an agent invitation."""
    PENDING = "pending"       # Created, awaiting enrollment
    REDEEMED = "redeemed"     # Successfully consumed
    REVOKED = "revoked"       # Admin manually cancelled
    EXPIRED = "expired"       # TTL exceeded
    LOCKED = "locked"         # Too many failed attempts


# ── Data Model ───────────────────────────────────────────────────────


@dataclass
class AgentInvitation:
    """A one-time invitation for external agent enrollment."""
    invitation_id: str
    secret_hash: str              # SHA-256 hex of raw enrollment secret
    hmac_tag: str                 # HMAC-SHA256 binding invitation_id + secret_hash
    agent_name: str
    agent_type: str
    status: InvitationStatus = InvitationStatus.PENDING
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    failed_attempts: int = 0
    created_at: str = ""
    expires_at: str = ""
    redeemed_at: str = ""
    redeemed_by_ip: str = ""
    created_by: str = ""
    resulting_agent_id: str = ""
    last_attempt_ip: str = ""
    last_attempt_at: str = ""
    recipient_email: str = ""
    recipient_name: str = ""
    page_visited_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API response. Never exposes secret_hash or hmac_tag."""
        return {
            "invitation_id": self.invitation_id,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "status": self.status.value if isinstance(self.status, InvitationStatus) else self.status,
            "ttl_seconds": self.ttl_seconds,
            "max_attempts": self.max_attempts,
            "failed_attempts": self.failed_attempts,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "redeemed_at": self.redeemed_at,
            "redeemed_by_ip": self.redeemed_by_ip,
            "created_by": self.created_by,
            "resulting_agent_id": self.resulting_agent_id,
            "recipient_email": self.recipient_email,
            "recipient_name": self.recipient_name,
            "page_visited_at": self.page_visited_at,
        }


# ── Invitation Store ─────────────────────────────────────────────────


class InvitationStore:
    """SQLite-backed invitation management for agent enrollment.

    Thread-safe. Follows ContactRegistry pattern: WAL journal mode,
    @contextmanager connections, threading.Lock.

    Usage::

        store = InvitationStore()
        invitation, compact = store.create_invitation("VPS-Agent", "claude_code")
        # Admin copies compact string to VPS terminal
        # Claude Code calls enroll endpoint with compact string
        ok, err, inv = store.verify_and_consume(inv_id, raw_secret, "1.2.3.4")
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/agent_invitations.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_invitations (
                    invitation_id   TEXT PRIMARY KEY,
                    secret_hash     TEXT NOT NULL,
                    hmac_tag        TEXT NOT NULL,
                    agent_name      TEXT NOT NULL,
                    agent_type      TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    ttl_seconds     INTEGER NOT NULL DEFAULT 600,
                    max_attempts    INTEGER NOT NULL DEFAULT 5,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    expires_at      TEXT NOT NULL,
                    redeemed_at     TEXT DEFAULT '',
                    redeemed_by_ip  TEXT DEFAULT '',
                    created_by      TEXT DEFAULT '',
                    resulting_agent_id TEXT DEFAULT '',
                    last_attempt_ip TEXT DEFAULT '',
                    last_attempt_at TEXT DEFAULT ''
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_status "
                "ON agent_invitations(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_expires "
                "ON agent_invitations(expires_at)"
            )
            # v0.3.32: Add recipient tracking and enrollment page visit columns
            for col, default in [
                ("recipient_email", "''"),
                ("recipient_name", "''"),
                ("page_visited_at", "''"),
            ]:
                try:
                    conn.execute(
                        f"ALTER TABLE agent_invitations ADD COLUMN {col} TEXT DEFAULT {default}"
                    )
                except sqlite3.OperationalError:
                    pass  # Column already exists

    @contextmanager
    def _connect(self):
        """Open a WAL-mode SQLite connection; auto-closes on exit."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── HMAC helpers ─────────────────────────────────────────────────

    @staticmethod
    def _get_hmac_key() -> str:
        """Get the HMAC key (server session token).

        Falls back to dev key only for ImportError (test environments
        where the security module isn't available). RuntimeError is
        re-raised — it means the session token isn't initialized yet,
        which is a real problem in production.
        """
        try:
            from ..api.security import get_session_token
            return get_session_token()
        except ImportError:
            return "dev-fallback-not-for-production"
        except RuntimeError:
            raise RuntimeError(
                "Cannot create invitations before session token is initialized"
            )

    @staticmethod
    def _compute_hmac(invitation_id: str, secret_hash: str) -> str:
        """HMAC-SHA256 binding invitation_id to secret_hash.

        Prevents mixing invitation_ids and secrets from different invitations.
        """
        key = InvitationStore._get_hmac_key()
        msg = f"enrollment:{invitation_id}:{secret_hash}"
        return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()

    # ── Creation ─────────────────────────────────────────────────────

    def create_invitation(
        self,
        agent_name: str,
        agent_type: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        created_by: str = "admin",
        recipient_email: str = "",
        recipient_name: str = "",
    ) -> Tuple[AgentInvitation, str]:
        """Create a new one-time invitation.

        Returns:
            (invitation, compact_string) — compact_string is the
            copy-paste-friendly enrollment token shown to the admin.

        Raises:
            ValueError: If agent_type is invalid or ttl out of range.
        """
        from .agent_registry import VALID_AGENT_TYPES

        if agent_type not in VALID_AGENT_TYPES:
            raise ValueError(
                f"Invalid agent_type '{agent_type}'. Must be one of: {VALID_AGENT_TYPES}"
            )
        ttl_seconds = max(MIN_TTL_SECONDS, min(ttl_seconds, MAX_TTL_SECONDS))
        max_attempts = max(1, min(max_attempts, 20))

        # Generate credentials
        invitation_id = uuid4().hex[:INVITATION_ID_LENGTH]
        raw_secret = secrets.token_urlsafe(32)  # 256-bit
        secret_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
        hmac_tag = self._compute_hmac(invitation_id, secret_hash)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        invitation = AgentInvitation(
            invitation_id=invitation_id,
            secret_hash=secret_hash,
            hmac_tag=hmac_tag,
            agent_name=agent_name,
            agent_type=agent_type,
            status=InvitationStatus.PENDING,
            ttl_seconds=ttl_seconds,
            max_attempts=max_attempts,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            created_by=created_by,
            recipient_email=recipient_email,
            recipient_name=recipient_name,
        )

        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        """INSERT INTO agent_invitations
                           (invitation_id, secret_hash, hmac_tag, agent_name, agent_type,
                            status, ttl_seconds, max_attempts, failed_attempts,
                            created_at, expires_at, created_by,
                            recipient_email, recipient_name)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)""",
                        (
                            invitation.invitation_id,
                            invitation.secret_hash,
                            invitation.hmac_tag,
                            invitation.agent_name,
                            invitation.agent_type,
                            invitation.status.value,
                            invitation.ttl_seconds,
                            invitation.max_attempts,
                            invitation.created_at,
                            invitation.expires_at,
                            invitation.created_by,
                            invitation.recipient_email,
                            invitation.recipient_name,
                        ),
                    )
                except sqlite3.IntegrityError:
                    raise ValueError(
                        "Invitation ID collision. Please retry."
                    )

        compact = f"{COMPACT_STRING_VERSION}:{invitation_id}:{raw_secret}"

        logger.info(
            "Invitation created: %s for %s (type=%s, ttl=%ds)",
            invitation_id, agent_name, agent_type, ttl_seconds,
        )
        return invitation, compact

    # ── Verification + Consumption ───────────────────────────────────

    def verify_and_consume(
        self,
        invitation_id: str,
        raw_secret: str,
        client_ip: str,
    ) -> Tuple[bool, str, Optional[AgentInvitation]]:
        """Verify and atomically consume an invitation.

        All checks happen inside a single lock + DB transaction to
        prevent race conditions (two agents redeeming simultaneously).

        Returns:
            (success, error_code, invitation)
            error_code is one of: "", "not_found", "already_redeemed",
            "revoked", "expired", "locked", "invalid_secret"
        """
        now = datetime.now(timezone.utc)

        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM agent_invitations WHERE invitation_id = ?",
                    (invitation_id,),
                ).fetchone()

                if row is None:
                    return False, "not_found", None

                inv = self._row_to_invitation(row)

                # Check status
                if inv.status == InvitationStatus.REDEEMED:
                    return False, "already_redeemed", None
                if inv.status == InvitationStatus.REVOKED:
                    return False, "revoked", None
                if inv.status == InvitationStatus.LOCKED:
                    return False, "locked", None

                # Check status is pending
                if inv.status != InvitationStatus.PENDING:
                    return False, f"status_{inv.status.value}", None

                # Check expiry
                expires = datetime.fromisoformat(inv.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if now > expires:
                    conn.execute(
                        "UPDATE agent_invitations SET status = ? WHERE invitation_id = ?",
                        (InvitationStatus.EXPIRED.value, invitation_id),
                    )
                    return False, "expired", None

                # Check lockout
                if inv.failed_attempts >= inv.max_attempts:
                    conn.execute(
                        "UPDATE agent_invitations SET status = ? WHERE invitation_id = ?",
                        (InvitationStatus.LOCKED.value, invitation_id),
                    )
                    return False, "locked", None

                # Verify secret (constant-time)
                candidate_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
                secret_ok = secrets.compare_digest(candidate_hash, inv.secret_hash)

                # Verify HMAC binding (constant-time, uses stored hash for integrity)
                expected_hmac = self._compute_hmac(invitation_id, inv.secret_hash)
                hmac_ok = secrets.compare_digest(expected_hmac, inv.hmac_tag)

                if not (secret_ok and hmac_ok):
                    # Record failed attempt
                    new_failures = inv.failed_attempts + 1
                    new_status = inv.status.value
                    if new_failures >= inv.max_attempts:
                        new_status = InvitationStatus.LOCKED.value

                    conn.execute(
                        """UPDATE agent_invitations
                           SET failed_attempts = ?, status = ?,
                               last_attempt_ip = ?, last_attempt_at = ?
                           WHERE invitation_id = ?""",
                        (new_failures, new_status, client_ip,
                         now.isoformat(), invitation_id),
                    )
                    return False, "invalid_secret", None

                # Success — atomically consume
                conn.execute(
                    """UPDATE agent_invitations
                       SET status = ?, redeemed_at = ?, redeemed_by_ip = ?
                       WHERE invitation_id = ?""",
                    (InvitationStatus.REDEEMED.value, now.isoformat(),
                     client_ip, invitation_id),
                )

                inv.status = InvitationStatus.REDEEMED
                inv.redeemed_at = now.isoformat()
                inv.redeemed_by_ip = client_ip
                return True, "", inv

    def revert_consumed(self, invitation_id: str) -> bool:
        """Revert a consumed invitation back to pending.

        Used for rollback when agent creation fails after the invitation
        was already consumed by verify_and_consume(). Without this, a
        transient DB error would permanently burn the invitation.

        Returns True if the invitation was reverted.
        """
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE agent_invitations "
                    "SET status = ?, redeemed_at = '', redeemed_by_ip = '' "
                    "WHERE invitation_id = ? AND status = ?",
                    (InvitationStatus.PENDING.value, invitation_id,
                     InvitationStatus.REDEEMED.value),
                )
                reverted = cursor.rowcount > 0
                if reverted:
                    logger.info("Reverted consumed invitation %s back to pending", invitation_id)
                return reverted

    def set_resulting_agent_id(
        self, invitation_id: str, agent_id: str
    ) -> None:
        """Update invitation with the resulting agent_id after enrollment."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE agent_invitations SET resulting_agent_id = ? "
                    "WHERE invitation_id = ?",
                    (agent_id, invitation_id),
                )

    # ── Admin Operations ─────────────────────────────────────────────

    def get_invitation(self, invitation_id: str) -> Optional[AgentInvitation]:
        """Get a single invitation by ID."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM agent_invitations WHERE invitation_id = ?",
                    (invitation_id,),
                ).fetchone()
                return self._row_to_invitation(row) if row else None

    def list_invitations(
        self, status_filter: Optional[InvitationStatus] = None,
    ) -> List[AgentInvitation]:
        """List invitations, optionally filtered by status."""
        with self._lock:
            with self._connect() as conn:
                if status_filter:
                    rows = conn.execute(
                        "SELECT * FROM agent_invitations WHERE status = ? "
                        "ORDER BY created_at DESC",
                        (status_filter.value,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM agent_invitations ORDER BY created_at DESC",
                    ).fetchall()
                return [self._row_to_invitation(r) for r in rows]

    def revoke_invitation(self, invitation_id: str) -> bool:
        """Revoke a pending invitation. Returns True if found and revoked."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE agent_invitations SET status = ? "
                    "WHERE invitation_id = ? AND status = ?",
                    (InvitationStatus.REVOKED.value, invitation_id,
                     InvitationStatus.PENDING.value),
                )
                return cursor.rowcount > 0

    def cleanup_expired(self) -> int:
        """Mark all expired pending invitations as 'expired'."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE agent_invitations SET status = ? "
                    "WHERE status = ? AND expires_at < ?",
                    (InvitationStatus.EXPIRED.value,
                     InvitationStatus.PENDING.value, now),
                )
                return cursor.rowcount

    # ── String Parsing ───────────────────────────────────────────────

    @staticmethod
    def parse_compact_string(compact: str) -> Tuple[str, str]:
        """Parse 'CITADEL-1:<invitation_id>:<secret>' into components.

        Returns:
            (invitation_id, raw_secret)

        Raises:
            ValueError: If format is invalid.
        """
        parts = compact.strip().split(":", maxsplit=2)
        if len(parts) != 3:
            raise ValueError("Invalid invitation format: expected CITADEL-1:<id>:<secret>")

        version, invitation_id, raw_secret = parts

        if version != COMPACT_STRING_VERSION:
            raise ValueError(f"Unknown invitation version: {version}")

        if not INVITATION_ID_PATTERN.match(invitation_id):
            raise ValueError("Invalid invitation ID: must be 12 hex characters")

        if not raw_secret or not SECRET_CHAR_PATTERN.match(raw_secret):
            raise ValueError("Invalid enrollment secret")

        return invitation_id, raw_secret

    # ── Easy Deployment helpers (v0.3.32) ────────────────────────────

    def verify_secret_only(
        self, invitation_id: str, raw_secret: str
    ) -> bool:
        """Verify secret WITHOUT consuming the invitation.

        Used by the public enrollment page and download endpoints
        to validate the URL token. Does NOT increment failed_attempts.

        Returns True if the invitation is pending, not expired, and
        the secret matches.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM agent_invitations WHERE invitation_id = ?",
                    (invitation_id,),
                ).fetchone()
                if row is None:
                    return False
                inv = self._row_to_invitation(row)
                if inv.status != InvitationStatus.PENDING:
                    return False
                expires = datetime.fromisoformat(inv.expires_at)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if now > expires:
                    return False
                candidate_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
                if not secrets.compare_digest(candidate_hash, inv.secret_hash):
                    return False
                expected_hmac = self._compute_hmac(invitation_id, inv.secret_hash)
                if not secrets.compare_digest(expected_hmac, inv.hmac_tag):
                    return False
                return True

    def mark_page_visited(self, invitation_id: str) -> bool:
        """Record that the enrollment page was visited.

        Only sets the timestamp if the invitation is still pending.
        Returns True if updated.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE agent_invitations SET page_visited_at = ? "
                    "WHERE invitation_id = ? AND status = ? AND page_visited_at = ''",
                    (now, invitation_id, InvitationStatus.PENDING.value),
                )
                return cursor.rowcount > 0

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _row_to_invitation(row: sqlite3.Row) -> AgentInvitation:
        """Convert a database row to an AgentInvitation."""
        try:
            status = InvitationStatus(row["status"])
        except ValueError:
            status = InvitationStatus.PENDING

        return AgentInvitation(
            invitation_id=row["invitation_id"],
            secret_hash=row["secret_hash"],
            hmac_tag=row["hmac_tag"],
            agent_name=row["agent_name"],
            agent_type=row["agent_type"],
            status=status,
            ttl_seconds=row["ttl_seconds"],
            max_attempts=row["max_attempts"],
            failed_attempts=row["failed_attempts"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            redeemed_at=row["redeemed_at"] or "",
            redeemed_by_ip=row["redeemed_by_ip"] or "",
            created_by=row["created_by"] or "",
            resulting_agent_id=row["resulting_agent_id"] or "",
            last_attempt_ip=row["last_attempt_ip"] or "",
            last_attempt_at=row["last_attempt_at"] or "",
            recipient_email=row["recipient_email"] if "recipient_email" in row.keys() else "",
            recipient_name=row["recipient_name"] if "recipient_name" in row.keys() else "",
            page_visited_at=row["page_visited_at"] if "page_visited_at" in row.keys() else "",
        )


# ── Singleton ────────────────────────────────────────────────────────

_store: Optional[InvitationStore] = None
_store_lock = threading.Lock()


def get_invitation_store() -> InvitationStore:
    """Get or create the global InvitationStore singleton."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = InvitationStore()
    return _store
