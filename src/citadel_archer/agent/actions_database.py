"""Action Queue and History Database for Citadel Daemon active response.

Stores commands queued for delivery to enrolled daemons, tracks their
approval state, and records execution results.

Status flow:
    queued           → sent → success | failed
    pending_approval → (approve) → queued → sent → success | failed
    pending_approval → (deny)    → denied
"""

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..core.db import connect as db_connect

_DB_PATH = Path("data/daemon_actions.db")
_LOCK = threading.Lock()


def _now() -> str:
    return datetime.utcnow().isoformat()


def init_db() -> None:
    """Create the daemon_actions table if it doesn't exist."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_connect(_DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS daemon_actions (
                action_uuid      TEXT PRIMARY KEY,
                agent_id         TEXT NOT NULL,
                action_id        TEXT NOT NULL,
                threat_id        TEXT DEFAULT '',
                parameters       TEXT NOT NULL DEFAULT '{}',
                status           TEXT NOT NULL DEFAULT 'queued',
                risk_level       TEXT NOT NULL DEFAULT 'low',
                require_approval INTEGER NOT NULL DEFAULT 0,
                description      TEXT DEFAULT '',
                requested_by     TEXT NOT NULL DEFAULT 'ai',
                created_at       TEXT NOT NULL,
                approved_at      TEXT,
                executed_at      TEXT,
                result_json      TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_da_agent_status "
            "ON daemon_actions (agent_id, status)"
        )
        conn.commit()


def queue_action(
    agent_id: str,
    action_id: str,
    parameters: Dict[str, Any],
    require_approval: bool,
    risk_level: str,
    description: str,
    threat_id: str = "",
    requested_by: str = "ai",
) -> str:
    """Queue a command for delivery to a daemon.

    Returns the action_uuid (hex UUID, no dashes).
    Status is 'pending_approval' if require_approval else 'queued'.
    """
    uuid = uuid4().hex
    status = "pending_approval" if require_approval else "queued"
    with _LOCK, db_connect(_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO daemon_actions
                (action_uuid, agent_id, action_id, threat_id, parameters,
                 status, risk_level, require_approval, description,
                 requested_by, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                uuid, agent_id, action_id, threat_id,
                json.dumps(parameters), status, risk_level,
                int(require_approval), description, requested_by, _now(),
            ),
        )
        conn.commit()
    return uuid


def get_queued_for_agent(agent_id: str) -> List[Dict]:
    """Return commands ready to deliver (status='queued') and mark them 'sent'.

    Called during heartbeat processing. Thread-safe.
    """
    with _LOCK, db_connect(_DB_PATH, row_factory=True) as conn:
        rows = conn.execute(
            "SELECT * FROM daemon_actions "
            "WHERE agent_id = ? AND status = 'queued' "
            "ORDER BY created_at",
            (agent_id,),
        ).fetchall()
        if rows:
            uuids = [r["action_uuid"] for r in rows]
            placeholders = ",".join("?" * len(uuids))
            conn.execute(
                f"UPDATE daemon_actions SET status='sent' "
                f"WHERE action_uuid IN ({placeholders})",
                uuids,
            )
            conn.commit()
        return [dict(r) for r in rows]


def approve_action(action_uuid: str) -> bool:
    """Move a pending_approval action to queued. Returns True if found."""
    with _LOCK, db_connect(_DB_PATH) as conn:
        cur = conn.execute(
            "UPDATE daemon_actions SET status='queued', approved_at=? "
            "WHERE action_uuid=? AND status='pending_approval'",
            (_now(), action_uuid),
        )
        conn.commit()
        return cur.rowcount > 0


def deny_action(action_uuid: str) -> bool:
    """Deny a pending_approval action. Returns True if found."""
    with _LOCK, db_connect(_DB_PATH) as conn:
        cur = conn.execute(
            "UPDATE daemon_actions SET status='denied' "
            "WHERE action_uuid=? AND status='pending_approval'",
            (action_uuid,),
        )
        conn.commit()
        return cur.rowcount > 0


def record_result(action_uuid: str, status: str, result: Dict) -> bool:
    """Record the execution result reported by the daemon.

    Args:
        action_uuid: The UUID of the action.
        status:      'success' or 'failed'.
        result:      Dict with execution details / forensics.

    Returns:
        True if the action was found and updated.
    """
    with _LOCK, db_connect(_DB_PATH) as conn:
        cur = conn.execute(
            "UPDATE daemon_actions "
            "SET status=?, executed_at=?, result_json=? "
            "WHERE action_uuid=? AND status='sent'",
            (status, _now(), json.dumps(result), action_uuid),
        )
        conn.commit()
        return cur.rowcount > 0


def get_action(action_uuid: str) -> Optional[Dict]:
    """Return a single action by UUID, or None if not found."""
    with _LOCK, db_connect(_DB_PATH, row_factory=True) as conn:
        row = conn.execute(
            "SELECT * FROM daemon_actions WHERE action_uuid=?",
            (action_uuid,),
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    if d.get("parameters"):
        try:
            d["parameters"] = json.loads(d["parameters"])
        except (json.JSONDecodeError, TypeError):
            pass
    if d.get("result_json"):
        try:
            d["result"] = json.loads(d["result_json"])
        except (json.JSONDecodeError, TypeError):
            d["result"] = {}
    return d


def list_actions(
    agent_id: str = "",
    action_id: str = "",
    status: str = "",
    limit: int = 50,
) -> List[Dict]:
    """Return action history with optional filters, newest first."""
    query = "SELECT * FROM daemon_actions WHERE 1=1"
    params: List[Any] = []
    if agent_id:
        query += " AND agent_id=?"
        params.append(agent_id)
    if action_id:
        query += " AND action_id=?"
        params.append(action_id)
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with _LOCK, db_connect(_DB_PATH, row_factory=True) as conn:
        rows = conn.execute(query, params).fetchall()

    results = []
    for row in rows:
        d = dict(row)
        if d.get("parameters"):
            try:
                d["parameters"] = json.loads(d["parameters"])
            except (json.JSONDecodeError, TypeError):
                pass
        if d.get("result_json"):
            try:
                d["result"] = json.loads(d["result_json"])
            except (json.JSONDecodeError, TypeError):
                d["result"] = {}
        results.append(d)
    return results
