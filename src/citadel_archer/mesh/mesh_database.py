"""Defense Mesh database — SQLite persistence for mesh peers and heartbeat log.

v0.3.35: Follows shield_database.py pattern (core.db.connect, WAL mode,
row_factory, lazy singleton).
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class MeshDatabase:
    """SQLite persistence for mesh peers and heartbeat history.

    Separate from RemoteShieldDatabase because mesh peers include the
    desktop coordinator (which is not a remote agent).

    Args:
        db_path: Path to SQLite file. Defaults to data/mesh.db.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/mesh.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mesh_peers (
                    node_id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    port INTEGER DEFAULT 9378,
                    is_desktop INTEGER DEFAULT 0,
                    label TEXT DEFAULT '',
                    last_seen_at TIMESTAMP,
                    last_escalation_phase TEXT DEFAULT 'NORMAL',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mesh_heartbeat_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT NOT NULL,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    sequence INTEGER,
                    payload_json TEXT DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hb_log_node
                ON mesh_heartbeat_log(node_id)
            """)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        from ..core.db import connect as db_connect
        return db_connect(self.db_path, row_factory=True)

    # ── Peer operations ──────────────────────────────────────────────

    def add_peer(
        self,
        node_id: str,
        ip_address: str,
        port: int = 9378,
        is_desktop: bool = False,
        label: str = "",
    ) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO mesh_peers
                   (node_id, ip_address, port, is_desktop, label, added_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(node_id) DO UPDATE SET
                       ip_address = excluded.ip_address,
                       port = excluded.port,
                       is_desktop = excluded.is_desktop,
                       label = excluded.label,
                       updated_at = excluded.updated_at""",
                (node_id, ip_address, port, 1 if is_desktop else 0, label, now, now),
            )
            conn.commit()
        return {
            "node_id": node_id,
            "ip_address": ip_address,
            "port": port,
            "is_desktop": is_desktop,
            "label": label,
        }

    def get_peer(self, node_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mesh_peers WHERE node_id = ?", (node_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_peer(row)

    def list_peers(self) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM mesh_peers ORDER BY added_at"
            ).fetchall()
        return [self._row_to_peer(r) for r in rows]

    def update_peer_heartbeat(
        self, node_id: str, escalation_phase: str = "NORMAL"
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE mesh_peers
                   SET last_seen_at = ?, last_escalation_phase = ?, updated_at = ?
                   WHERE node_id = ?""",
                (now, escalation_phase, now, node_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def remove_peer(self, node_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM mesh_peers WHERE node_id = ?", (node_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    # ── Heartbeat log (ring buffer) ──────────────────────────────────

    def log_heartbeat(
        self, node_id: str, sequence: int, payload: Optional[dict] = None
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload_json = json.dumps(payload or {})
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO mesh_heartbeat_log
                   (node_id, received_at, sequence, payload_json)
                   VALUES (?, ?, ?, ?)""",
                (node_id, now, sequence, payload_json),
            )
            # Prune to keep max 1000 entries per node
            conn.execute(
                """DELETE FROM mesh_heartbeat_log
                   WHERE node_id = ? AND id NOT IN (
                       SELECT id FROM mesh_heartbeat_log
                       WHERE node_id = ?
                       ORDER BY id DESC LIMIT 1000
                   )""",
                (node_id, node_id),
            )
            conn.commit()

    def get_heartbeat_history(
        self, node_id: str, limit: int = 50
    ) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM mesh_heartbeat_log
                   WHERE node_id = ?
                   ORDER BY id DESC LIMIT ?""",
                (node_id, limit),
            ).fetchall()
        results = []
        for r in rows:
            payload = r["payload_json"]
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except (json.JSONDecodeError, TypeError):
                    payload = {}
            results.append({
                "id": r["id"],
                "node_id": r["node_id"],
                "received_at": r["received_at"],
                "sequence": r["sequence"],
                "payload": payload,
            })
        return results

    @staticmethod
    def _row_to_peer(row: sqlite3.Row) -> dict:
        return {
            "node_id": row["node_id"],
            "ip_address": row["ip_address"],
            "port": row["port"],
            "is_desktop": bool(row["is_desktop"]),
            "label": row["label"],
            "last_seen_at": row["last_seen_at"],
            "last_escalation_phase": row["last_escalation_phase"],
            "added_at": row["added_at"],
            "updated_at": row["updated_at"],
        }


# ── Singleton ────────────────────────────────────────────────────────

_instance: Optional[MeshDatabase] = None


def get_mesh_database() -> MeshDatabase:
    global _instance
    if _instance is None:
        _instance = MeshDatabase()
    return _instance


def set_mesh_database(instance: Optional[MeshDatabase]) -> None:
    global _instance
    _instance = instance
