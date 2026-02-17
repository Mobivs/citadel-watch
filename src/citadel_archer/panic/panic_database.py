"""
Panic Room Database - Phase 3 Implementation
Handles persistence and state management for panic responses
"""

import json
import re
import sqlite3
import contextlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import hashlib
import logging

logger = logging.getLogger(__name__)


# ── asyncpg-compatible adapter ─────────────────────────────────────
# All panic action files use `async with self.db.acquire() as conn:`
# with asyncpg-style $1,$2 positional params. This adapter translates
# those calls to SQLite so we don't have to rewrite 39 call sites.

def _convert_query(query, args):
    """Convert asyncpg $1,$2 positional params to SQLite ? placeholders.

    Also handles:
    - Multiple ANY($N) → IN (?, ?, ...) with list expansion
    - CURRENT_TIMESTAMP stays as-is (supported by both)
    - ``true``/``false`` → ``1``/``0`` for SQLite boolean compat
    """
    expanded_args = list(args)

    # Handle ALL ANY($N) patterns (process in reverse to keep indices stable)
    any_matches = list(re.finditer(r'=\s*ANY\(\$(\d+)\)', query))
    for any_match in reversed(any_matches):
        param_idx = int(any_match.group(1)) - 1  # 0-based
        list_val = expanded_args[param_idx]
        if isinstance(list_val, (list, tuple)):
            placeholders = ', '.join(['?' for _ in list_val])
            query = query[:any_match.start()] + f'IN ({placeholders})' + query[any_match.end():]
            expanded_args = expanded_args[:param_idx] + list(list_val) + expanded_args[param_idx + 1:]

    # Convert $1, $2, ... to ? placeholders
    # Must go in reverse order to avoid $1 matching $10, $11, etc.
    max_param = 0
    for m in re.finditer(r'\$(\d+)', query):
        max_param = max(max_param, int(m.group(1)))
    for i in range(max_param, 0, -1):
        query = query.replace(f'${i}', '?')

    # SQLite boolean compatibility: true/false → 1/0
    query = re.sub(r'\bfalse\b', '0', query, flags=re.IGNORECASE)
    query = re.sub(r'\btrue\b', '1', query, flags=re.IGNORECASE)

    return query, expanded_args


class _ConnWrapper:
    """asyncpg-compatible wrapper around sqlite3 connection."""

    def __init__(self, db_path):
        from ..core.db import connect as db_connect

        self._conn = db_connect(db_path, row_factory=True)

    async def execute(self, query, *args):
        q, a = _convert_query(query, args)
        self._conn.execute(q, a)
        self._conn.commit()

    async def fetch(self, query, *args):
        q, a = _convert_query(query, args)
        return self._conn.execute(q, a).fetchall()

    async def fetchrow(self, query, *args):
        q, a = _convert_query(query, args)
        return self._conn.execute(q, a).fetchone()

    def close(self):
        self._conn.close()


@dataclass
class PanicSession:
    """Represents a panic room session"""
    session_id: str
    status: str  # active, completed, failed, cancelled
    playbooks: List[str]
    started_at: datetime
    completed_at: Optional[datetime] = None
    progress: int = 0
    actions: List[Dict] = None
    recovery_state: Optional[Dict] = None
    error: Optional[str] = None
    trigger_source: str = "manual"
    user_id: Optional[str] = None
    confirmation_token: Optional[str] = None
    reason: str = ""
    metadata: Dict = None

    def to_dict(self):
        """Convert to dictionary for storage"""
        data = asdict(self)
        data['started_at'] = self.started_at.isoformat() if self.started_at else None
        data['completed_at'] = self.completed_at.isoformat() if self.completed_at else None
        data['actions'] = json.dumps(self.actions) if self.actions else '[]'
        data['recovery_state'] = json.dumps(self.recovery_state) if self.recovery_state else '{}'
        data['metadata'] = json.dumps(self.metadata) if self.metadata else '{}'
        data['playbooks'] = json.dumps(self.playbooks) if self.playbooks else '[]'
        return data


class PanicDatabase:
    """Database manager for panic room sessions"""
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize database connection.

        Also exposes an asyncpg-compatible ``acquire()`` async context
        manager so that action classes (which were written for asyncpg)
        work without modification.
        """
        self.db_path = Path(db_path) if db_path else Path("/var/lib/citadel/panic/panic_sessions.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        
    @contextlib.asynccontextmanager
    async def acquire(self):
        """asyncpg-compatible acquire() — returns a _ConnWrapper.

        Reuses a single shared wrapper per PanicDatabase instance to avoid
        opening a new SQLite connection on every call. The wrapper is
        created lazily and kept alive for the lifetime of the database.
        """
        if not hasattr(self, '_shared_wrapper') or self._shared_wrapper is None:
            self._shared_wrapper = _ConnWrapper(self.db_path)
        yield self._shared_wrapper

    def _init_database(self):
        """Initialize database schema"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS panic_sessions (
                    session_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    playbooks TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    progress INTEGER DEFAULT 0,
                    actions TEXT DEFAULT '[]',
                    recovery_state TEXT DEFAULT '{}',
                    error TEXT,
                    trigger_source TEXT DEFAULT 'manual',
                    user_id TEXT,
                    confirmation_token TEXT,
                    reason TEXT,
                    metadata TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create action logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS action_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES panic_sessions(session_id)
                )
            ''')

            # Create recovery snapshots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES panic_sessions(session_id)
                )
            ''')

            # Panic manager uses these tables (asyncpg-style schema names)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_states (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    component TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL DEFAULT 'local',
                    pre_panic_state TEXT DEFAULT '{}',
                    current_state TEXT DEFAULT '{}',
                    rollback_available INTEGER DEFAULT 1,
                    rollback_attempted INTEGER DEFAULT 0,
                    rollback_succeeded INTEGER DEFAULT 0,
                    rollback_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(session_id, component, component_id, asset_id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS panic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    playbook_id TEXT,
                    playbook_name TEXT,
                    action_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT DEFAULT '{}',
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES panic_sessions(session_id)
                )
            ''')

            # Credential rotation tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credential_rotations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    credential_type TEXT NOT NULL,
                    credential_name TEXT NOT NULL,
                    old_credential_hash TEXT,
                    new_credential_hash TEXT,
                    rotation_status TEXT DEFAULT 'pending',
                    old_credential_archived INTEGER DEFAULT 0,
                    archive_path TEXT,
                    metadata TEXT DEFAULT '{}',
                    rotated_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES panic_sessions(session_id)
                )
            ''')

            # Recovery keys — never rotated during panic
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT UNIQUE NOT NULL,
                    public_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    comment TEXT DEFAULT 'citadel-recovery',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_verified_at TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    revoked_at TIMESTAMP,
                    revoke_reason TEXT
                )
            ''')

            # Create indices for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_status ON panic_sessions(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON panic_sessions(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_session ON action_logs(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_session ON recovery_snapshots(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_recovery_states_session ON recovery_states(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_panic_logs_session ON panic_logs(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cred_rotations_session ON credential_rotations(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_recovery_keys_active ON recovery_keys(is_active)')

            # Panic configuration key/value store
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS panic_config (
                    config_key TEXT PRIMARY KEY,
                    config_value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Migration: add asset_id to recovery_states if missing
            # (existing databases created before per-asset rollback)
            try:
                cursor.execute("SELECT asset_id FROM recovery_states LIMIT 0")
            except sqlite3.OperationalError:
                # Column missing — rebuild table with correct schema
                cursor.execute('ALTER TABLE recovery_states RENAME TO _recovery_states_old')
                cursor.execute('''
                    CREATE TABLE recovery_states (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        component TEXT NOT NULL,
                        component_id TEXT NOT NULL,
                        asset_id TEXT NOT NULL DEFAULT 'local',
                        pre_panic_state TEXT DEFAULT '{}',
                        current_state TEXT DEFAULT '{}',
                        rollback_available INTEGER DEFAULT 1,
                        rollback_attempted INTEGER DEFAULT 0,
                        rollback_succeeded INTEGER DEFAULT 0,
                        rollback_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(session_id, component, component_id, asset_id)
                    )
                ''')
                cursor.execute('''
                    INSERT INTO recovery_states
                        (id, session_id, component, component_id,
                         pre_panic_state, current_state, rollback_available,
                         rollback_attempted, rollback_succeeded, rollback_at, created_at)
                    SELECT id, session_id, component, component_id,
                           pre_panic_state, current_state, rollback_available,
                           rollback_attempted, rollback_succeeded, rollback_at, created_at
                    FROM _recovery_states_old
                ''')
                cursor.execute('DROP TABLE _recovery_states_old')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_recovery_states_session ON recovery_states(session_id)')
                logger.info("Migrated recovery_states table: added asset_id column")

            conn.commit()
    
    # Explicit column order for INSERT to avoid dict-ordering surprises
    _SESSION_COLUMNS = [
        'session_id', 'status', 'playbooks', 'started_at', 'completed_at',
        'progress', 'actions', 'recovery_state', 'error', 'trigger_source',
        'user_id', 'confirmation_token', 'reason', 'metadata',
    ]

    def create_session(self, session: PanicSession) -> str:
        """Create a new panic session"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()
            data = session.to_dict()

            # Use explicit column order to ensure values align correctly
            columns = ', '.join(self._SESSION_COLUMNS)
            placeholders = ', '.join(['?' for _ in self._SESSION_COLUMNS])
            values = [data.get(col) for col in self._SESSION_COLUMNS]
            query = f'INSERT INTO panic_sessions ({columns}) VALUES ({placeholders})'

            cursor.execute(query, values)
            conn.commit()

            logger.info(f"Created panic session: {session.session_id}")
            return session.session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a panic session by ID"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM panic_sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            
            if row:
                session_data = dict(row)
                # Parse JSON fields
                session_data['playbooks'] = json.loads(session_data['playbooks'])
                session_data['actions'] = json.loads(session_data['actions'])
                session_data['recovery_state'] = json.loads(session_data['recovery_state'])
                session_data['metadata'] = json.loads(session_data['metadata'])
                return session_data
                
            return None
    
    # Allowed column names for update_session (prevents SQL injection via dict keys)
    _UPDATABLE_COLUMNS = frozenset({
        'status', 'playbooks', 'completed_at', 'progress', 'actions',
        'recovery_state', 'error', 'trigger_source', 'user_id',
        'confirmation_token', 'reason', 'metadata', 'updated_at',
    })

    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update a panic session.

        Column names are validated against a whitelist to prevent
        SQL injection via dict keys.
        """
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Convert complex types to JSON
            if 'actions' in updates and isinstance(updates['actions'], list):
                updates['actions'] = json.dumps(updates['actions'])
            if 'recovery_state' in updates and isinstance(updates['recovery_state'], dict):
                updates['recovery_state'] = json.dumps(updates['recovery_state'])
            if 'metadata' in updates and isinstance(updates['metadata'], dict):
                updates['metadata'] = json.dumps(updates['metadata'])
            if 'playbooks' in updates and isinstance(updates['playbooks'], list):
                updates['playbooks'] = json.dumps(updates['playbooks'])

            # Add updated_at timestamp
            updates['updated_at'] = datetime.utcnow().isoformat()

            # Validate column names against whitelist
            invalid_keys = set(updates.keys()) - self._UPDATABLE_COLUMNS
            if invalid_keys:
                raise ValueError(f"Invalid column names: {invalid_keys}")

            set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
            query = f'UPDATE panic_sessions SET {set_clause} WHERE session_id = ?'

            cursor.execute(query, list(updates.values()) + [session_id])
            conn.commit()

            return cursor.rowcount > 0
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active panic sessions"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM panic_sessions 
                WHERE status = 'active' 
                ORDER BY started_at DESC
            ''')
            
            sessions = []
            for row in cursor.fetchall():
                session_data = dict(row)
                session_data['playbooks'] = json.loads(session_data['playbooks'])
                session_data['actions'] = json.loads(session_data['actions'])
                session_data['recovery_state'] = json.loads(session_data['recovery_state'])
                session_data['metadata'] = json.loads(session_data['metadata'])
                sessions.append(session_data)
                
            return sessions
    
    def log_action(self, session_id: str, action_name: str, action_type: str,
                   status: str, message: str = "", details: Optional[Dict] = None):
        """Log an action for a panic session"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO action_logs (session_id, action_name, action_type, status, message, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, action_name, action_type, status, message, 
                  json.dumps(details) if details else '{}'))
            
            conn.commit()
    
    def get_action_logs(self, session_id: str) -> List[Dict]:
        """Get all action logs for a session"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM action_logs 
                WHERE session_id = ? 
                ORDER BY timestamp ASC
            ''', (session_id,))
            
            logs = []
            for row in cursor.fetchall():
                log_data = dict(row)
                log_data['details'] = json.loads(log_data['details'])
                logs.append(log_data)
                
            return logs
    
    def save_recovery_state(
        self, session_id: str, component: str, component_id: str,
        asset_id: str = "local", pre_panic_state: Optional[Dict] = None,
        current_state: Optional[Dict] = None,
    ) -> None:
        """Save or update a recovery state for per-asset rollback."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO recovery_states
                    (session_id, component, component_id, asset_id,
                     pre_panic_state, current_state)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (session_id, component, component_id, asset_id)
                DO UPDATE SET current_state = excluded.current_state
            ''', (
                session_id, component, component_id, asset_id,
                json.dumps(pre_panic_state or {}),
                json.dumps(current_state or {}),
            ))
            conn.commit()

    def get_recovery_states(
        self, session_id: str,
        components: Optional[List[str]] = None,
        target_assets: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Get recovery states for rollback, optionally filtered by component and/or asset.

        Returns list of dicts with all recovery_states columns.
        """
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            clauses = ["session_id = ?", "rollback_available = 1"]
            params: list = [session_id]

            if components:
                placeholders = ','.join('?' for _ in components)
                clauses.append(f"component IN ({placeholders})")
                params.extend(components)

            if target_assets:
                placeholders = ','.join('?' for _ in target_assets)
                clauses.append(f"asset_id IN ({placeholders})")
                params.extend(target_assets)

            where = " AND ".join(clauses)
            rows = conn.execute(
                f"SELECT * FROM recovery_states WHERE {where} ORDER BY created_at ASC",
                params,
            ).fetchall()

            return [dict(r) for r in rows]

    def mark_state_rolled_back(self, state_id: int, succeeded: bool = True) -> None:
        """Mark a recovery state as rolled back."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            conn.execute('''
                UPDATE recovery_states
                SET rollback_attempted = 1,
                    rollback_succeeded = ?,
                    rollback_available = 0,
                    rollback_at = datetime('now')
                WHERE id = ?
            ''', (int(succeeded), state_id))
            conn.commit()

    def create_recovery_snapshot(self, session_id: str, snapshot_type: str, data: Dict) -> str:
        """Create a recovery snapshot"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            snapshot_id = f"snap_{session_id}_{int(datetime.utcnow().timestamp())}"
            data_json = json.dumps(data)
            integrity_hash = hashlib.sha256(data_json.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO recovery_snapshots (snapshot_id, session_id, snapshot_type, data, integrity_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (snapshot_id, session_id, snapshot_type, data_json, integrity_hash))
            
            conn.commit()
            logger.info(f"Created recovery snapshot: {snapshot_id}")
            
            return snapshot_id
    
    def get_recovery_snapshots(self, session_id: str) -> List[Dict]:
        """Get all recovery snapshots for a session"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM recovery_snapshots 
                WHERE session_id = ? 
                ORDER BY created_at DESC
            ''', (session_id,))
            
            snapshots = []
            for row in cursor.fetchall():
                snapshot_data = dict(row)
                snapshot_data['data'] = json.loads(snapshot_data['data'])
                snapshots.append(snapshot_data)
                
            return snapshots
    
    def get_session_history(self, limit: int = 50) -> List[Dict]:
        """Get panic session history"""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT session_id, status, trigger_source, reason, 
                       started_at, completed_at, progress, error
                FROM panic_sessions 
                ORDER BY started_at DESC 
                LIMIT ?
            ''', (limit,))
            
            history = []
            for row in cursor.fetchall():
                history.append(dict(row))
                
            return history
    
    def cleanup_old_sessions(self, days: int = 30) -> int:
        """Clean up old completed sessions and their dependent records."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()

            cutoff_date = datetime.utcnow().timestamp() - (days * 24 * 3600)

            # Find sessions to delete
            rows = cursor.execute('''
                SELECT session_id FROM panic_sessions
                WHERE status IN ('completed', 'cancelled')
                AND created_at < datetime(?, 'unixepoch')
            ''', (cutoff_date,)).fetchall()

            if not rows:
                return 0

            ids = [r[0] for r in rows]
            placeholders = ','.join('?' for _ in ids)

            # Delete child rows first (schema FKs have no ON DELETE CASCADE)
            for table in ('action_logs', 'recovery_snapshots', 'panic_logs',
                          'recovery_states', 'credential_rotations'):
                cursor.execute(
                    f'DELETE FROM {table} WHERE session_id IN ({placeholders})', ids
                )

            cursor.execute(
                f'DELETE FROM panic_sessions WHERE session_id IN ({placeholders})', ids
            )

            deleted_count = cursor.rowcount
            conn.commit()

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old panic sessions")

            return deleted_count

    def get_config(self) -> Dict:
        """Get all panic configuration as a dict."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path, row_factory=True) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT config_key, config_value FROM panic_config')
            rows = cursor.fetchall()
            config = {}
            for row in rows:
                try:
                    config[row['config_key']] = json.loads(row['config_value'])
                except (json.JSONDecodeError, TypeError):
                    config[row['config_key']] = row['config_value']
            return config

    def save_config(self, config: Dict) -> None:
        """Save panic configuration (key/value pairs)."""
        from ..core.db import connect as db_connect

        with db_connect(self.db_path) as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            for key, value in config.items():
                val_json = json.dumps(value) if not isinstance(value, str) else json.dumps(value)
                cursor.execute(
                    'INSERT OR REPLACE INTO panic_config (config_key, config_value, updated_at) VALUES (?, ?, ?)',
                    (key, val_json, now)
                )
            conn.commit()