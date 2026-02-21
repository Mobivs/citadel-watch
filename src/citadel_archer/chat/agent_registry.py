# External AI Agent Registry
# Persistent SQLite storage for external AI agent registrations.
# Reference: PRD Trigger 1b — External AI agent message via REST API
#
# Follows the exact pattern of remote/shield_database.py:
# SHA-256 token hashing, WAL journal, separate data/ DB file.
#
# Token security: API tokens are SHA-256 hashed before storage. Raw tokens
# are never persisted. SHA-256 is appropriate here because the tokens are
# high-entropy (256-bit secrets.token_urlsafe), unlike passwords.

import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)

# Valid agent types (AI + Shield)
VALID_AGENT_TYPES = {"forge", "openclaw", "claude_code", "custom", "vps", "workstation", "cloud"}

# Category subsets for routing enrollment to the correct system
SHIELD_AGENT_TYPES = {"vps", "workstation", "cloud"}
AI_AGENT_TYPES = {"forge", "openclaw", "claude_code", "custom"}

# Default rate limits per agent type (messages per minute)
DEFAULT_RATE_LIMITS = {
    "forge": 60,
    "claude_code": 60,
    "openclaw": 30,
    "custom": 30,
}


def _hash_token(token: str) -> str:
    """SHA-256 hash an API token for safe storage."""
    return hashlib.sha256(token.encode()).hexdigest()


# Absolute default path — computed from this file's location so the DB is
# always found regardless of the working directory when the app starts.
_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "agent_registry.db"


class AgentRegistry:
    """SQLite persistence for external AI agent registrations.

    Stores agent credentials, rate limits, and usage stats.
    Tokens are SHA-256 hashed — raw tokens are shown once at registration
    and never stored.

    Args:
        db_path: Path to SQLite database file. Defaults to <project>/data/agent_registry.db.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Create tables if they don't exist."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS external_agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    api_token_hash TEXT NOT NULL,
                    rate_limit_per_min INTEGER DEFAULT 60,
                    status TEXT DEFAULT 'active',
                    created_at TEXT,
                    last_message_at TEXT,
                    message_count INTEGER DEFAULT 0,
                    ip_address TEXT DEFAULT '',
                    hostname TEXT DEFAULT ''
                )
            """)
            # Migration for existing databases that pre-date ip_address/hostname.
            for col in ("ip_address TEXT DEFAULT ''", "hostname TEXT DEFAULT ''"):
                col_name = col.split()[0]
                try:
                    conn.execute(f"ALTER TABLE external_agents ADD COLUMN {col}")
                    conn.commit()
                except Exception:
                    pass  # Column already exists
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ext_agents_token_hash
                ON external_agents(api_token_hash)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ext_agents_status
                ON external_agents(status)
            """)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        """Create a new connection with row_factory."""
        from ..core.db import connect as db_connect

        return db_connect(self.db_path, row_factory=True)

    # ── Registration ──────────────────────────────────────────────────

    def register_agent(
        self,
        name: str,
        agent_type: str,
        rate_limit_per_min: Optional[int] = None,
        ip_address: str = "",
        hostname: str = "",
    ) -> Tuple[str, str]:
        """Register a new external agent.

        Args:
            name: Display name for the agent.
            agent_type: One of VALID_AGENT_TYPES.
            rate_limit_per_min: Custom rate limit (default by type).
            ip_address: Agent's IP address at enrollment time (Tailscale IP preferred).
            hostname: Agent's self-reported hostname.

        Returns:
            (agent_id, raw_api_token) — token is shown once and never stored.

        Raises:
            ValueError: If agent_type is not valid.
        """
        if agent_type not in VALID_AGENT_TYPES:
            raise ValueError(
                f"Invalid agent_type '{agent_type}'. Must be one of: {VALID_AGENT_TYPES}"
            )

        agent_id = uuid4().hex
        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)

        if rate_limit_per_min is None:
            rate_limit_per_min = DEFAULT_RATE_LIMITS.get(agent_type, 30)

        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            conn.execute(
                """INSERT INTO external_agents
                   (agent_id, name, agent_type, api_token_hash,
                    rate_limit_per_min, status, created_at, ip_address, hostname)
                   VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                (agent_id, name, agent_type, token_hash, rate_limit_per_min, now,
                 ip_address, hostname),
            )
            conn.commit()

        logger.info(
            "Registered external agent: %s (%s, type=%s, ip=%s)",
            name, agent_id, agent_type, ip_address or "unknown",
        )
        return agent_id, raw_token

    # ── Token Verification ────────────────────────────────────────────

    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify an API token and return the agent dict, or None if invalid.

        Only returns agents with status='active'.
        """
        token_hash = _hash_token(token)
        with self._conn() as conn:
            row = conn.execute(
                """SELECT agent_id, name, agent_type, rate_limit_per_min, status
                   FROM external_agents
                   WHERE api_token_hash = ? AND status = 'active'""",
                (token_hash,),
            ).fetchone()

        if row is None:
            return None

        return dict(row)

    # ── CRUD ──────────────────────────────────────────────────────────

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent by ID."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT agent_id, name, agent_type, rate_limit_per_min,
                          status, created_at, last_message_at, message_count,
                          ip_address, hostname
                   FROM external_agents WHERE agent_id = ?""",
                (agent_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_agents(self) -> List[Dict]:
        """List all registered agents."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT agent_id, name, agent_type, rate_limit_per_min,
                          status, created_at, last_message_at, message_count,
                          ip_address, hostname
                   FROM external_agents ORDER BY created_at DESC"""
            ).fetchall()
        return [dict(r) for r in rows]

    def update_ip_address(self, agent_id: str, ip_address: str) -> bool:
        """Update the stored IP address for an agent.

        Called on heartbeat so the IP stays current even for agents that
        enrolled before IP capture was added (shows as 'enrolled-api' otherwise).

        Returns True if a row was updated, False if agent not found.
        """
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE external_agents SET ip_address = ? WHERE agent_id = ?",
                (ip_address, agent_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke an agent (sets status to 'revoked').

        Returns True if agent was found and revoked, False otherwise.
        """
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE external_agents SET status = 'revoked' WHERE agent_id = ?",
                (agent_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def rotate_token(self, agent_id: str) -> Optional[str]:
        """Generate a new token for an active agent, invalidating the old one.

        Returns the new raw token, or None if agent not found or not active.
        """
        new_token = secrets.token_urlsafe(32)
        new_hash = _hash_token(new_token)

        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE external_agents SET api_token_hash = ? WHERE agent_id = ? AND status = 'active'",
                (new_hash, agent_id),
            )
            conn.commit()
            if cursor.rowcount == 0:
                return None

        logger.info("Rotated token for agent %s", agent_id)
        return new_token

    # ── Stats ─────────────────────────────────────────────────────────

    def record_message(self, agent_id: str):
        """Increment message count and update last_message_at."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                """UPDATE external_agents
                   SET message_count = message_count + 1, last_message_at = ?
                   WHERE agent_id = ?""",
                (now, agent_id),
            )
            conn.commit()
