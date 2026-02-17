# Remote Shield Database
# Persistent SQLite storage for Remote Shield agents and threat reports.
# Reference: docs/ASSET_MANAGEMENT_ADDENDUM.md, Section 9
#
# Replaces the in-memory dicts (agents_db, remote_threats_db, agent_tokens)
# from remote_shield_routes.py so data survives restarts.
#
# Token security: API tokens are SHA-256 hashed before storage. Raw tokens
# are never persisted. SHA-256 is appropriate here because the tokens are
# high-entropy (256-bit secrets.token_urlsafe), unlike passwords.

import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _hash_token(token: str) -> str:
    """SHA-256 hash an API token for safe storage."""
    return hashlib.sha256(token.encode()).hexdigest()


class RemoteShieldDatabase:
    """SQLite persistence for Remote Shield agents and threats.

    Drop-in replacement for the in-memory dicts previously used in
    remote_shield_routes.py. All public methods are synchronous (SQLite
    is fast enough for the expected scale of <100 agents).

    Args:
        db_path: Path to SQLite database file. Defaults to data/remote_shield.db.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/remote_shield.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Create tables if they don't exist."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remote_shield_agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT UNIQUE NOT NULL,
                    hostname TEXT NOT NULL,
                    ip_address TEXT,
                    public_key TEXT,
                    api_token_hash TEXT NOT NULL,
                    asset_id TEXT,
                    status TEXT DEFAULT 'active',
                    last_heartbeat_at TIMESTAMP,
                    last_scan_at TIMESTAMP,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remote_shield_threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE NOT NULL,
                    agent_id TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity INTEGER DEFAULT 5,
                    title TEXT NOT NULL,
                    details TEXT DEFAULT '{}',
                    hostname TEXT,
                    detected_at TIMESTAMP,
                    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'open',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES remote_shield_agents(agent_id)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_agents_hostname
                ON remote_shield_agents(hostname)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_agents_token_hash
                ON remote_shield_agents(api_token_hash)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_agent_id
                ON remote_shield_threats(agent_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_status
                ON remote_shield_threats(status)
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ssh_hardening_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT UNIQUE NOT NULL,
                    config_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT DEFAULT 'pending',
                    applied_at TIMESTAMP,
                    backup_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hardening_asset
                ON ssh_hardening_configs(asset_id)
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT NOT NULL,
                    action TEXT NOT NULL DEFAULT 'deny',
                    source TEXT NOT NULL,
                    protocol TEXT DEFAULT 'any',
                    port TEXT DEFAULT '',
                    direction TEXT DEFAULT 'in',
                    priority INTEGER DEFAULT 100,
                    enabled INTEGER DEFAULT 1,
                    auto_generated INTEGER DEFAULT 0,
                    expires_at TIMESTAMP,
                    comment TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_fw_rules_asset
                ON firewall_rules(asset_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_fw_rules_enabled
                ON firewall_rules(enabled)
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS onboarding_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    asset_id TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    steps_json TEXT DEFAULT '{}',
                    config_json TEXT DEFAULT '{}',
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_onboard_asset
                ON onboarding_sessions(asset_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_onboard_status
                ON onboarding_sessions(status)
            """)

            # Migration: add platform column (v0.3.24)
            try:
                cursor.execute(
                    "ALTER TABLE remote_shield_agents ADD COLUMN platform TEXT DEFAULT 'linux'"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Migration: add alert_threshold column (v0.3.25)
            try:
                cursor.execute(
                    "ALTER TABLE remote_shield_agents ADD COLUMN alert_threshold INTEGER DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Migration: add patch_status_json column (v0.3.27)
            try:
                cursor.execute(
                    "ALTER TABLE remote_shield_agents ADD COLUMN patch_status_json TEXT DEFAULT '{}'"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Agent commands table (generic command queue, v0.3.27)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id TEXT UNIQUE NOT NULL,
                    agent_id TEXT NOT NULL,
                    command_type TEXT NOT NULL,
                    payload TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivered_at TIMESTAMP,
                    acknowledged_at TIMESTAMP,
                    result TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_commands_agent_status
                ON agent_commands(agent_id, status)
            """)

            # Group policies tables (v0.3.30)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policy_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    rules_json TEXT DEFAULT '{}',
                    priority INTEGER DEFAULT 100,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policy_group_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(group_id, agent_id)
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pgm_group
                ON policy_group_members(group_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pgm_agent
                ON policy_group_members(agent_id)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policy_application_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id TEXT UNIQUE NOT NULL,
                    group_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    command_id TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    applied_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pal_group
                ON policy_application_log(group_id)
            """)

            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        from ..core.db import connect as db_connect

        return db_connect(self.db_path, row_factory=True)

    # ------------------------------------------------------------------
    # Agent operations
    # ------------------------------------------------------------------

    def create_agent(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str,
        api_token: str,
        public_key: Optional[str] = None,
        platform: str = "linux",
    ) -> dict:
        """Insert a new agent. Returns the agent dict."""
        now = datetime.utcnow().isoformat()
        token_hash = _hash_token(api_token)

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO remote_shield_agents
                   (agent_id, hostname, ip_address, public_key, api_token_hash,
                    status, last_heartbeat_at, registered_at, platform)
                   VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                (agent_id, hostname, ip_address, public_key, token_hash, now, now, platform),
            )
            conn.commit()

        return {
            "id": agent_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "public_key": public_key,
            "platform": platform,
            "status": "active",
            "last_heartbeat": now,
            "registered_at": now,
            "last_scan_at": None,
        }

    def get_agent(self, agent_id: str) -> Optional[dict]:
        """Fetch agent by agent_id. Returns None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remote_shield_agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()

        if row is None:
            return None
        return self._row_to_agent(row)

    def get_agent_by_hostname(self, hostname: str) -> Optional[dict]:
        """Find agent by hostname. Returns first match or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remote_shield_agents WHERE hostname = ? LIMIT 1",
                (hostname,),
            ).fetchone()

        if row is None:
            return None
        return self._row_to_agent(row)

    def list_agents(self) -> List[dict]:
        """Return all registered agents."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM remote_shield_agents ORDER BY registered_at DESC"
            ).fetchall()

        return [self._row_to_agent(r) for r in rows]

    def update_agent_token(self, agent_id: str, new_token: str) -> bool:
        """Replace an agent's API token hash (used on re-registration)."""
        token_hash = _hash_token(new_token)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE remote_shield_agents SET api_token_hash = ? WHERE agent_id = ?",
                (token_hash, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def update_agent_heartbeat(self, agent_id: str) -> bool:
        """Update last_heartbeat_at and set status to active."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE remote_shield_agents
                   SET last_heartbeat_at = ?, status = 'active'
                   WHERE agent_id = ?""",
                (now, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def update_agent_last_scan(self, agent_id: str) -> bool:
        """Update last_scan_at timestamp."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE remote_shield_agents SET last_scan_at = ? WHERE agent_id = ?",
                (now, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def update_agent_asset_id(self, agent_id: str, asset_id: str) -> bool:
        """Link an agent to a managed asset."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE remote_shield_agents SET asset_id = ? WHERE agent_id = ?",
                (asset_id, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def set_agent_alert_threshold(self, agent_id: str, threshold: int) -> bool:
        """Set the alert severity threshold for an agent.

        Events with severity below this threshold are suppressed on the agent.
        0 = no suppression (report everything).
        """
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE remote_shield_agents SET alert_threshold = ? WHERE agent_id = ?",
                (threshold, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def get_agent_alert_threshold(self, agent_id: str) -> int:
        """Get the alert threshold for an agent. Returns 0 if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT alert_threshold FROM remote_shield_agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        if row is None:
            return 0
        return row["alert_threshold"] if "alert_threshold" in row.keys() else 0

    # ------------------------------------------------------------------
    # Patch status
    # ------------------------------------------------------------------

    def update_patch_status(self, agent_id: str, patch_data: dict) -> bool:
        """Update the patch_status_json for an agent."""
        raw = json.dumps(patch_data)
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE remote_shield_agents SET patch_status_json = ? WHERE agent_id = ?",
                (raw, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def get_patch_status(self, agent_id: str) -> Optional[dict]:
        """Get parsed patch status for an agent. Returns None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT patch_status_json FROM remote_shield_agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        raw = row["patch_status_json"] if "patch_status_json" in row.keys() else "{}"
        try:
            return json.loads(raw) if raw else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    # ------------------------------------------------------------------
    # Agent command queue
    # ------------------------------------------------------------------

    def queue_command(
        self, command_id: str, agent_id: str, command_type: str, payload: Optional[dict] = None,
    ) -> dict:
        """Queue a command for an agent. Returns the command dict."""
        now = datetime.utcnow().isoformat()
        payload_str = json.dumps(payload or {})
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO agent_commands
                   (command_id, agent_id, command_type, payload, status, created_at)
                   VALUES (?, ?, ?, ?, 'pending', ?)""",
                (command_id, agent_id, command_type, payload_str, now),
            )
            conn.commit()
        return {
            "command_id": command_id,
            "agent_id": agent_id,
            "command_type": command_type,
            "payload": payload or {},
            "status": "pending",
            "created_at": now,
        }

    def get_pending_commands(self, agent_id: str, limit: int = 5) -> List[dict]:
        """Get pending commands for an agent (oldest first).

        Atomically marks fetched commands as 'delivered' to prevent
        duplicate delivery on rapid heartbeats.
        """
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_commands WHERE agent_id = ? AND status = 'pending' "
                "ORDER BY created_at ASC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
            if rows:
                ids = [r["command_id"] for r in rows]
                placeholders = ",".join("?" for _ in ids)
                conn.execute(
                    f"UPDATE agent_commands SET status = 'delivered', delivered_at = ? "
                    f"WHERE command_id IN ({placeholders})",
                    [now] + ids,
                )
                conn.commit()
        commands = [self._row_to_command(r) for r in rows]
        for cmd in commands:
            cmd["status"] = "delivered"
            cmd["delivered_at"] = now
        return commands

    def acknowledge_command(self, command_id: str, result: str = "") -> bool:
        """Mark a command as acknowledged with optional result text."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE agent_commands SET status = 'acknowledged', acknowledged_at = ?, result = ? "
                "WHERE command_id = ? AND status IN ('pending', 'delivered')",
                (now, result, command_id),
            )
            conn.commit()
            return cur.rowcount > 0

    VALID_COMMAND_STATUSES = {"pending", "delivered", "acknowledged"}

    def list_commands(
        self, agent_id: Optional[str] = None, status: Optional[str] = None, limit: int = 50,
    ) -> List[dict]:
        """List commands with optional filtering."""
        if status and status not in self.VALID_COMMAND_STATUSES:
            raise ValueError(f"Invalid command status: {status!r}. Must be one of {self.VALID_COMMAND_STATUSES}")
        sql = "SELECT * FROM agent_commands WHERE 1=1"
        params: list = []
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_command(r) for r in rows]

    @staticmethod
    def _row_to_command(row: sqlite3.Row) -> dict:
        """Convert a command row to dict."""
        payload = row["payload"]
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                payload = {}
        return {
            "command_id": row["command_id"],
            "agent_id": row["agent_id"],
            "command_type": row["command_type"],
            "payload": payload,
            "status": row["status"],
            "created_at": row["created_at"],
            "delivered_at": row["delivered_at"],
            "acknowledged_at": row["acknowledged_at"],
            "result": row["result"] or "",
        }

    # ------------------------------------------------------------------
    # Group policy operations
    # ------------------------------------------------------------------

    def create_policy_group(
        self, group_id: str, name: str, description: str = "",
        rules: Optional[dict] = None, priority: int = 100,
    ) -> dict:
        """Create a new policy group. Returns the group dict."""
        now = datetime.utcnow().isoformat()
        rules_json = json.dumps(rules or {})
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO policy_groups
                   (group_id, name, description, rules_json, priority, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (group_id, name, description, rules_json, priority, now, now),
            )
            conn.commit()
        return {
            "group_id": group_id, "name": name, "description": description,
            "rules": rules or {}, "priority": priority,
            "created_at": now, "updated_at": now,
        }

    def get_policy_group(self, group_id: str) -> Optional[dict]:
        """Fetch a policy group by group_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM policy_groups WHERE group_id = ?", (group_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_policy_group(row)

    def list_policy_groups(self) -> List[dict]:
        """Return all policy groups ordered by priority."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM policy_groups ORDER BY priority ASC, name ASC",
            ).fetchall()
        return [self._row_to_policy_group(r) for r in rows]

    def update_policy_group(self, group_id: str, **updates) -> bool:
        """Update a policy group. Allowed keys: name, description, rules, priority."""
        allowed = {"name", "description", "priority"}
        now = datetime.utcnow().isoformat()
        sets = ["updated_at = ?"]
        params: list = [now]
        for k, v in updates.items():
            if k == "rules":
                sets.append("rules_json = ?")
                params.append(json.dumps(v))
            elif k in allowed:
                sets.append(f"{k} = ?")
                params.append(v)
        params.append(group_id)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE policy_groups SET {', '.join(sets)} WHERE group_id = ?",
                params,
            )
            conn.commit()
            return cur.rowcount > 0

    def delete_policy_group(self, group_id: str) -> bool:
        """Delete a policy group and cascade-remove its memberships."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM policy_group_members WHERE group_id = ?", (group_id,),
            )
            cur = conn.execute(
                "DELETE FROM policy_groups WHERE group_id = ?", (group_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def add_group_member(self, group_id: str, agent_id: str) -> bool:
        """Add an agent to a policy group. Returns False on duplicate."""
        now = datetime.utcnow().isoformat()
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO policy_group_members (group_id, agent_id, added_at) VALUES (?, ?, ?)",
                    (group_id, agent_id, now),
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate membership

    def remove_group_member(self, group_id: str, agent_id: str) -> bool:
        """Remove an agent from a policy group."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM policy_group_members WHERE group_id = ? AND agent_id = ?",
                (group_id, agent_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def get_group_members(self, group_id: str) -> List[str]:
        """Return agent_ids belonging to a group."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT agent_id FROM policy_group_members WHERE group_id = ? ORDER BY added_at",
                (group_id,),
            ).fetchall()
        return [r["agent_id"] for r in rows]

    def get_agent_groups(self, agent_id: str) -> List[dict]:
        """Return all policy groups an agent belongs to."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT pg.* FROM policy_groups pg
                   JOIN policy_group_members pgm ON pg.group_id = pgm.group_id
                   WHERE pgm.agent_id = ?
                   ORDER BY pg.priority ASC""",
                (agent_id,),
            ).fetchall()
        return [self._row_to_policy_group(r) for r in rows]

    def log_policy_application(
        self, application_id: str, group_id: str, agent_id: str, command_id: str,
    ) -> dict:
        """Record a policy application attempt."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO policy_application_log
                   (application_id, group_id, agent_id, command_id, status, created_at)
                   VALUES (?, ?, ?, ?, 'pending', ?)""",
                (application_id, group_id, agent_id, command_id, now),
            )
            conn.commit()
        return {
            "application_id": application_id, "group_id": group_id,
            "agent_id": agent_id, "command_id": command_id,
            "status": "pending", "created_at": now,
        }

    def update_application_status(self, command_id: str, status: str) -> bool:
        """Update policy application status by command_id."""
        now = datetime.utcnow().isoformat()
        applied_at = now if status == "applied" else None
        with self._connect() as conn:
            if applied_at:
                cur = conn.execute(
                    "UPDATE policy_application_log SET status = ?, applied_at = ? WHERE command_id = ?",
                    (status, applied_at, command_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE policy_application_log SET status = ? WHERE command_id = ?",
                    (status, command_id),
                )
            conn.commit()
            return cur.rowcount > 0

    def get_policy_compliance(self, group_id: str) -> List[dict]:
        """Get per-agent compliance status for a policy group."""
        members = self.get_group_members(group_id)
        if not members:
            return []
        # Single query: latest application log entry per agent
        placeholders = ",".join("?" for _ in members)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT agent_id, status, applied_at, created_at
                    FROM policy_application_log
                    WHERE group_id = ? AND agent_id IN ({placeholders})
                    AND id IN (
                        SELECT MAX(id) FROM policy_application_log
                        WHERE group_id = ? AND agent_id IN ({placeholders})
                        GROUP BY agent_id
                    )""",
                [group_id] + members + [group_id] + members,
            ).fetchall()
        applied_map = {
            r["agent_id"]: {
                "agent_id": r["agent_id"], "status": r["status"],
                "applied_at": r["applied_at"], "last_push": r["created_at"],
            }
            for r in rows
        }
        results = []
        for agent_id in members:
            if agent_id in applied_map:
                results.append(applied_map[agent_id])
            else:
                results.append({
                    "agent_id": agent_id, "status": "never_applied",
                    "applied_at": None, "last_push": None,
                })
        return results

    @staticmethod
    def _row_to_policy_group(row: sqlite3.Row) -> dict:
        """Convert a policy_groups row to dict."""
        rules = row["rules_json"]
        if isinstance(rules, str):
            try:
                rules = json.loads(rules)
            except (json.JSONDecodeError, TypeError):
                rules = {}
        return {
            "group_id": row["group_id"],
            "name": row["name"],
            "description": row["description"],
            "rules": rules,
            "priority": row["priority"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    # ------------------------------------------------------------------
    # Token verification
    # ------------------------------------------------------------------

    def verify_token(self, token: str) -> Optional[str]:
        """Verify an API token and return the associated agent_id, or None."""
        token_hash = _hash_token(token)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT agent_id FROM remote_shield_agents WHERE api_token_hash = ?",
                (token_hash,),
            ).fetchone()

        if row is None:
            return None
        return row["agent_id"]

    # ------------------------------------------------------------------
    # Threat operations
    # ------------------------------------------------------------------

    def create_threat(self, threat_data: dict) -> str:
        """Insert a new threat. Returns the threat_id."""
        now = datetime.utcnow().isoformat()
        threat_id = threat_data["threat_id"]
        details_json = json.dumps(threat_data.get("details") or {})
        detected_at = threat_data.get("detected_at", now)
        if isinstance(detected_at, datetime):
            detected_at = detected_at.isoformat()

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO remote_shield_threats
                   (threat_id, agent_id, threat_type, severity, title, details,
                    hostname, detected_at, reported_at, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)""",
                (
                    threat_id,
                    threat_data["agent_id"],
                    threat_data["type"],
                    threat_data["severity"],
                    threat_data["title"],
                    details_json,
                    threat_data.get("hostname", ""),
                    detected_at,
                    now,
                    now,
                ),
            )
            conn.commit()

        return threat_id

    def get_threat(self, threat_id: str) -> Optional[dict]:
        """Fetch a single threat by threat_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM remote_shield_threats WHERE threat_id = ?",
                (threat_id,),
            ).fetchone()

        if row is None:
            return None
        return self._row_to_threat(row)

    def list_threats(
        self,
        agent_id: Optional[str] = None,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[dict]:
        """List threats with optional filters, sorted newest first."""
        clauses = []
        params: list = []

        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if threat_type:
            clauses.append("threat_type = ?")
            params.append(threat_type)
        if status:
            clauses.append("status = ?")
            params.append(status)

        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)

        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM remote_shield_threats {where} "
                "ORDER BY reported_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()

        return [self._row_to_threat(r) for r in rows]

    def update_threat_status(self, threat_id: str, new_status: str) -> bool:
        """Update a threat's status. Returns True if the row was found."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE remote_shield_threats SET status = ? WHERE threat_id = ?",
                (new_status, threat_id),
            )
            conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # SSH hardening config operations
    # ------------------------------------------------------------------

    def save_hardening_config(
        self, asset_id: str, config: dict, status: str = "pending"
    ) -> dict:
        """Save or update SSH hardening config for an asset."""
        now = datetime.utcnow().isoformat()
        config_json = json.dumps(config)
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO ssh_hardening_configs
                   (asset_id, config_json, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(asset_id) DO UPDATE SET
                       config_json = excluded.config_json,
                       status = excluded.status,
                       updated_at = excluded.updated_at""",
                (asset_id, config_json, status, now, now),
            )
            conn.commit()
        return {"asset_id": asset_id, "config": config, "status": status}

    def get_hardening_config(self, asset_id: str) -> Optional[dict]:
        """Get hardening config for an asset. Returns None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ssh_hardening_configs WHERE asset_id = ?",
                (asset_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_hardening(row)

    def update_hardening_status(
        self, asset_id: str, status: str, backup_path: str = ""
    ) -> bool:
        """Update hardening status (pending, applied, rolled_back, failed)."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            updates = "status = ?, updated_at = ?"
            params: list = [status, now]
            if status == "applied":
                updates += ", applied_at = ?"
                params.append(now)
            if backup_path:
                updates += ", backup_path = ?"
                params.append(backup_path)
            params.append(asset_id)
            cur = conn.execute(
                f"UPDATE ssh_hardening_configs SET {updates} WHERE asset_id = ?",
                params,
            )
            conn.commit()
            return cur.rowcount > 0

    def list_hardening_configs(self, status: Optional[str] = None) -> List[dict]:
        """List all hardening configs, optionally filtered by status."""
        if status:
            query = "SELECT * FROM ssh_hardening_configs WHERE status = ? ORDER BY updated_at DESC"
            params: tuple = (status,)
        else:
            query = "SELECT * FROM ssh_hardening_configs ORDER BY updated_at DESC"
            params = ()
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_hardening(r) for r in rows]

    def delete_hardening_config(self, asset_id: str) -> bool:
        """Remove hardening config for an asset."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM ssh_hardening_configs WHERE asset_id = ?",
                (asset_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def _row_to_hardening(row: sqlite3.Row) -> dict:
        """Convert a hardening config row to dict."""
        config = row["config_json"]
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except (json.JSONDecodeError, TypeError):
                config = {}
        return {
            "asset_id": row["asset_id"],
            "config": config,
            "status": row["status"],
            "applied_at": row["applied_at"],
            "backup_path": row["backup_path"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    # ------------------------------------------------------------------
    # Firewall rule operations
    # ------------------------------------------------------------------

    def save_firewall_rule(self, asset_id: str, rule: dict) -> int:
        """Insert a firewall rule. Returns the new row ID."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO firewall_rules
                   (asset_id, action, source, protocol, port, direction,
                    priority, enabled, auto_generated, expires_at, comment, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset_id,
                    rule.get("action", "deny"),
                    rule["source"],
                    rule.get("protocol", "any"),
                    rule.get("port", ""),
                    rule.get("direction", "in"),
                    rule.get("priority", 100),
                    1 if rule.get("enabled", True) else 0,
                    1 if rule.get("auto_generated", False) else 0,
                    rule.get("expires_at"),
                    rule.get("comment", ""),
                    now,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def get_firewall_rules(
        self, asset_id: str, enabled_only: bool = True
    ) -> List[dict]:
        """Get firewall rules for an asset, sorted by priority."""
        clause = "WHERE asset_id = ?"
        params: list = [asset_id]
        if enabled_only:
            clause += " AND enabled = 1"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM firewall_rules {clause} ORDER BY priority ASC",
                params,
            ).fetchall()
        return [self._row_to_fw_rule(r) for r in rows]

    def update_firewall_rule(self, rule_id: int, updates: dict) -> bool:
        """Update a firewall rule by ID."""
        allowed = {
            "action", "source", "protocol", "port", "direction",
            "priority", "enabled", "expires_at", "comment",
        }
        sets = []
        params: list = []
        for k, v in updates.items():
            if k in allowed:
                if k == "enabled":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                params.append(v)
        if not sets:
            return False
        params.append(rule_id)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE firewall_rules SET {', '.join(sets)} WHERE id = ?",
                params,
            )
            conn.commit()
            return cur.rowcount > 0

    def delete_firewall_rule(self, rule_id: int) -> bool:
        """Delete a firewall rule by ID."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM firewall_rules WHERE id = ?", (rule_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def delete_expired_firewall_rules(self) -> int:
        """Delete all firewall rules whose expires_at has passed. Returns count."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM firewall_rules WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            )
            conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------
    # Onboarding session operations
    # ------------------------------------------------------------------

    def create_onboarding_session(
        self, session_id: str, asset_id: str, config: dict
    ) -> dict:
        """Create a new onboarding session."""
        now = datetime.utcnow().isoformat()
        config_json = json.dumps(config)
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO onboarding_sessions
                   (session_id, asset_id, status, steps_json, config_json, started_at, created_at)
                   VALUES (?, ?, 'pending', '{}', ?, ?, ?)""",
                (session_id, asset_id, config_json, now, now),
            )
            conn.commit()
        return {
            "session_id": session_id,
            "asset_id": asset_id,
            "status": "pending",
            "steps": {},
            "config": config,
            "started_at": now,
        }

    def get_onboarding_session(self, session_id: str) -> Optional[dict]:
        """Get an onboarding session by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM onboarding_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_onboarding(row)

    def update_onboarding_step(
        self, session_id: str, step_name: str, status: str, message: str = ""
    ) -> bool:
        """Update a single step within an onboarding session."""
        now = datetime.utcnow().isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT steps_json FROM onboarding_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if not row:
                return False
            steps = json.loads(row["steps_json"] or "{}")
            steps[step_name] = {"status": status, "message": message, "timestamp": now}
            cur = conn.execute(
                "UPDATE onboarding_sessions SET steps_json = ? WHERE session_id = ?",
                (json.dumps(steps), session_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def update_onboarding_status(self, session_id: str, status: str) -> bool:
        """Update the overall status of an onboarding session."""
        now = datetime.utcnow().isoformat()
        completed_at = now if status in ("completed", "failed") else None
        with self._connect() as conn:
            if completed_at:
                cur = conn.execute(
                    "UPDATE onboarding_sessions SET status = ?, completed_at = ? WHERE session_id = ?",
                    (status, completed_at, session_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE onboarding_sessions SET status = ? WHERE session_id = ?",
                    (status, session_id),
                )
            conn.commit()
            return cur.rowcount > 0

    def list_onboarding_sessions(
        self, asset_id: Optional[str] = None, status: Optional[str] = None
    ) -> List[dict]:
        """List onboarding sessions with optional filters."""
        clauses = []
        params: list = []
        if asset_id:
            clauses.append("asset_id = ?")
            params.append(asset_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = ""
        if clauses:
            where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM onboarding_sessions {where} ORDER BY created_at DESC",
                params,
            ).fetchall()
        return [self._row_to_onboarding(r) for r in rows]

    # ------------------------------------------------------------------
    # Row converters (sqlite3.Row → dict matching existing API contract)
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_fw_rule(row: sqlite3.Row) -> dict:
        """Convert a firewall_rules row to dict."""
        return {
            "id": row["id"],
            "asset_id": row["asset_id"],
            "action": row["action"],
            "source": row["source"],
            "protocol": row["protocol"],
            "port": row["port"],
            "direction": row["direction"],
            "priority": row["priority"],
            "enabled": bool(row["enabled"]),
            "auto_generated": bool(row["auto_generated"]),
            "expires_at": row["expires_at"],
            "comment": row["comment"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _row_to_onboarding(row: sqlite3.Row) -> dict:
        """Convert an onboarding_sessions row to dict."""
        steps = row["steps_json"]
        if isinstance(steps, str):
            try:
                steps = json.loads(steps)
            except (json.JSONDecodeError, TypeError):
                steps = {}
        config = row["config_json"]
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except (json.JSONDecodeError, TypeError):
                config = {}
        return {
            "session_id": row["session_id"],
            "asset_id": row["asset_id"],
            "status": row["status"],
            "steps": steps,
            "config": config,
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _row_to_agent(row: sqlite3.Row) -> dict:
        """Convert a DB row to the dict format expected by route handlers."""
        keys = row.keys()

        # Parse patch_status_json safely
        patch_status = {}
        if "patch_status_json" in keys:
            raw = row["patch_status_json"]
            if raw and isinstance(raw, str):
                try:
                    patch_status = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    pass

        return {
            "id": row["agent_id"],
            "hostname": row["hostname"],
            "ip_address": row["ip_address"],
            "public_key": row["public_key"],
            "platform": row["platform"] if "platform" in keys else "linux",
            "alert_threshold": row["alert_threshold"] if "alert_threshold" in keys else 0,
            "status": row["status"],
            "last_heartbeat": row["last_heartbeat_at"],
            "registered_at": row["registered_at"],
            "last_scan_at": row["last_scan_at"],
            "asset_id": row["asset_id"],
            "patch_status": patch_status,
        }

    @staticmethod
    def _row_to_threat(row: sqlite3.Row) -> dict:
        """Convert a DB row to the dict format expected by route handlers."""
        details = row["details"]
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (json.JSONDecodeError, TypeError):
                details = {}

        return {
            "id": row["threat_id"],
            "agent_id": row["agent_id"],
            "type": row["threat_type"],
            "severity": row["severity"],
            "title": row["title"],
            "details": details,
            "hostname": row["hostname"],
            "detected_at": row["detected_at"],
            "reported_at": row["reported_at"],
            "status": row["status"],
            "created_at": row["created_at"],
        }
