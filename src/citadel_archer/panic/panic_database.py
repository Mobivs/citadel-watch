"""
Panic Room Database - Phase 3 Implementation
Handles persistence and state management for panic responses
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import hashlib
import logging

logger = logging.getLogger(__name__)


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
        """Initialize database connection"""
        self.db_path = db_path or Path("/var/lib/citadel/panic/panic_sessions.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        
    def _init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
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
            
            # Create indices for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_status ON panic_sessions(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON panic_sessions(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_session ON action_logs(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_session ON recovery_snapshots(session_id)')
            
            conn.commit()
    
    def create_session(self, session: PanicSession) -> str:
        """Create a new panic session"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            data = session.to_dict()
            
            columns = ', '.join(data.keys())
            placeholders = ', '.join(['?' for _ in data])
            query = f'INSERT INTO panic_sessions ({columns}) VALUES ({placeholders})'
            
            cursor.execute(query, list(data.values()))
            conn.commit()
            
            logger.info(f"Created panic session: {session.session_id}")
            return session.session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a panic session by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
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
    
    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update a panic session"""
        with sqlite3.connect(self.db_path) as conn:
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
            
            set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
            query = f'UPDATE panic_sessions SET {set_clause} WHERE session_id = ?'
            
            cursor.execute(query, list(updates.values()) + [session_id])
            conn.commit()
            
            return cursor.rowcount > 0
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active panic sessions"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
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
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO action_logs (session_id, action_name, action_type, status, message, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, action_name, action_type, status, message, 
                  json.dumps(details) if details else '{}'))
            
            conn.commit()
    
    def get_action_logs(self, session_id: str) -> List[Dict]:
        """Get all action logs for a session"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
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
    
    def create_recovery_snapshot(self, session_id: str, snapshot_type: str, data: Dict) -> str:
        """Create a recovery snapshot"""
        with sqlite3.connect(self.db_path) as conn:
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
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
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
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
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
        """Clean up old completed sessions"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cutoff_date = datetime.utcnow().timestamp() - (days * 24 * 3600)
            
            cursor.execute('''
                DELETE FROM panic_sessions 
                WHERE status IN ('completed', 'cancelled') 
                AND created_at < datetime(?, 'unixepoch')
            ''', (cutoff_date,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old panic sessions")
                
            return deleted_count