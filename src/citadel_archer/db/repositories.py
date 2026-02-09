"""
Data access objects (repositories) for database entities.

Provides high-level CRUD operations for:
- Agents
- API Tokens
- Threats
- Audit Logs
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)


class AgentRepository:
    """Agent data access object."""
    
    def __init__(self, db):
        """Initialize with database instance."""
        self.db = db
    
    async def create(
        self,
        hostname: str,
        ip_address: str,
        status: str = "inactive",
        public_key: Optional[str] = None,
        scan_interval_seconds: int = 300,
    ) -> str:
        """
        Create new agent.
        
        Args:
            hostname: Agent hostname
            ip_address: Agent IP address
            status: Initial status (default: inactive)
            public_key: Optional mTLS public key
            scan_interval_seconds: Scan interval in seconds
        
        Returns:
            Agent ID
        
        Raises:
            asyncpg.PostgresError: If creation fails
        """
        agent_id = str(uuid.uuid4())
        
        await self.db.execute(
            """
            INSERT INTO agents 
            (id, hostname, ip_address, status, public_key, scan_interval_seconds, registered_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            agent_id,
            hostname,
            ip_address,
            status,
            public_key,
            scan_interval_seconds,
            datetime.utcnow(),
        )
        
        logger.info(f"Agent created: {agent_id} ({hostname})")
        return agent_id
    
    async def get_by_id(self, agent_id: str) -> Optional[Dict]:
        """Get agent by ID."""
        result = await self.db.fetchrow(
            "SELECT * FROM agents WHERE id = $1",
            agent_id,
        )
        return dict(result) if result else None
    
    async def get_by_hostname(self, hostname: str) -> Optional[Dict]:
        """Get agent by hostname."""
        result = await self.db.fetchrow(
            "SELECT * FROM agents WHERE hostname = $1",
            hostname,
        )
        return dict(result) if result else None
    
    async def list_all(self, status: Optional[str] = None) -> List[Dict]:
        """
        List all agents, optionally filtered by status.
        
        Args:
            status: Optional status filter (active, inactive, offline)
        
        Returns:
            List of agent records
        """
        if status:
            results = await self.db.fetch(
                "SELECT * FROM agents WHERE status = $1 ORDER BY registered_at DESC",
                status,
            )
        else:
            results = await self.db.fetch(
                "SELECT * FROM agents ORDER BY registered_at DESC"
            )
        
        return [dict(r) for r in results]
    
    async def update_status(self, agent_id: str, status: str) -> bool:
        """Update agent status."""
        result = await self.db.execute(
            "UPDATE agents SET status = $1 WHERE id = $2",
            status,
            agent_id,
        )
        return "1" in result  # "UPDATE 1" if successful
    
    async def update_heartbeat(self, agent_id: str) -> bool:
        """Update agent last heartbeat timestamp."""
        result = await self.db.execute(
            "UPDATE agents SET last_heartbeat = $1, status = $2 WHERE id = $3",
            datetime.utcnow(),
            "active",
            agent_id,
        )
        return "1" in result
    
    async def update_last_scan(self, agent_id: str) -> bool:
        """Update agent last scan timestamp."""
        result = await self.db.execute(
            "UPDATE agents SET last_scan_at = $1 WHERE id = $2",
            datetime.utcnow(),
            agent_id,
        )
        return "1" in result
    
    async def delete(self, agent_id: str) -> bool:
        """Delete agent and all related data (cascading)."""
        result = await self.db.execute(
            "DELETE FROM agents WHERE id = $1",
            agent_id,
        )
        return "1" in result


class TokenRepository:
    """Agent token data access object."""
    
    def __init__(self, db):
        """Initialize with database instance."""
        self.db = db
    
    async def create(
        self,
        agent_id: str,
        token_hash: str,
        ttl_hours: int = 24,
    ) -> str:
        """
        Create new API token.
        
        Args:
            agent_id: Agent ID
            token_hash: Bcrypt hashed token
            ttl_hours: Time-to-live in hours (default: 24)
        
        Returns:
            Token ID
        """
        token_id = str(uuid.uuid4())
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(hours=ttl_hours)
        
        await self.db.execute(
            """
            INSERT INTO agent_tokens 
            (id, agent_id, token_hash, issued_at, expires_at, is_revoked)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            token_id,
            agent_id,
            token_hash,
            issued_at,
            expires_at,
            False,
        )
        
        logger.info(f"Token created for agent {agent_id}")
        return token_id
    
    async def get_by_hash(self, token_hash: str) -> Optional[Dict]:
        """Get token by hash."""
        result = await self.db.fetchrow(
            """
            SELECT * FROM agent_tokens 
            WHERE token_hash = $1 AND is_revoked = FALSE
            """,
            token_hash,
        )
        return dict(result) if result else None
    
    async def list_for_agent(self, agent_id: str, include_revoked: bool = False) -> List[Dict]:
        """List tokens for agent."""
        if include_revoked:
            results = await self.db.fetch(
                "SELECT * FROM agent_tokens WHERE agent_id = $1 ORDER BY issued_at DESC",
                agent_id,
            )
        else:
            results = await self.db.fetch(
                """
                SELECT * FROM agent_tokens 
                WHERE agent_id = $1 AND is_revoked = FALSE
                ORDER BY issued_at DESC
                """,
                agent_id,
            )
        
        return [dict(r) for r in results]
    
    async def revoke(self, token_hash: str) -> bool:
        """Revoke token."""
        result = await self.db.execute(
            """
            UPDATE agent_tokens 
            SET is_revoked = TRUE, revoked_at = $1
            WHERE token_hash = $2
            """,
            datetime.utcnow(),
            token_hash,
        )
        return "1" in result
    
    async def update_last_used(self, token_hash: str) -> bool:
        """Update token last used timestamp."""
        result = await self.db.execute(
            """
            UPDATE agent_tokens 
            SET last_used_at = $1
            WHERE token_hash = $2
            """,
            datetime.utcnow(),
            token_hash,
        )
        return "1" in result
    
    async def cleanup_expired(self) -> int:
        """Delete expired tokens (maintenance task)."""
        result = await self.db.execute(
            "DELETE FROM agent_tokens WHERE expires_at < $1",
            datetime.utcnow(),
        )
        # Extract count from result (e.g., "DELETE 5")
        count = int(result.split()[1]) if "DELETE" in result else 0
        if count > 0:
            logger.info(f"Cleaned up {count} expired tokens")
        return count


class ThreatRepository:
    """Threat data access object."""
    
    def __init__(self, db):
        """Initialize with database instance."""
        self.db = db
    
    async def create(
        self,
        agent_id: str,
        threat_type: str,
        severity: int,
        hostname: str,
        title: str,
        detected_at: datetime,
        description: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> str:
        """
        Create new threat record.
        
        Args:
            agent_id: Agent ID
            threat_type: Type of threat
            severity: Severity level (1-10)
            hostname: Hostname where threat detected
            title: Human-readable title
            detected_at: Detection timestamp
            description: Optional detailed description
            details: Optional threat-specific data (JSON)
        
        Returns:
            Threat ID
        """
        threat_id = str(uuid.uuid4())
        
        await self.db.execute(
            """
            INSERT INTO threats 
            (id, agent_id, threat_type, severity, hostname, title, description, details, status, detected_at, reported_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """,
            threat_id,
            agent_id,
            threat_type,
            severity,
            hostname,
            title,
            description,
            details,
            "open",
            detected_at,
            datetime.utcnow(),
        )
        
        logger.info(f"Threat created: {threat_id} ({threat_type}, severity={severity})")
        return threat_id
    
    async def get_by_id(self, threat_id: str) -> Optional[Dict]:
        """Get threat by ID."""
        result = await self.db.fetchrow(
            "SELECT * FROM threats WHERE id = $1",
            threat_id,
        )
        return dict(result) if result else None
    
    async def list_for_agent(
        self,
        agent_id: str,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict]:
        """
        List threats for agent, optionally filtered by status.
        
        Args:
            agent_id: Agent ID
            status: Optional status filter (open, acknowledged, resolved)
            limit: Result limit (default: 100)
            offset: Result offset (default: 0)
        
        Returns:
            List of threat records
        """
        if status:
            results = await self.db.fetch(
                """
                SELECT * FROM threats 
                WHERE agent_id = $1 AND status = $2
                ORDER BY detected_at DESC
                LIMIT $3 OFFSET $4
                """,
                agent_id,
                status,
                limit,
                offset,
            )
        else:
            results = await self.db.fetch(
                """
                SELECT * FROM threats 
                WHERE agent_id = $1
                ORDER BY detected_at DESC
                LIMIT $2 OFFSET $3
                """,
                agent_id,
                limit,
                offset,
            )
        
        return [dict(r) for r in results]
    
    async def list_by_severity(
        self,
        min_severity: int = 5,
        limit: int = 100,
    ) -> List[Dict]:
        """List open threats by severity level."""
        results = await self.db.fetch(
            """
            SELECT * FROM threats 
            WHERE status = 'open' AND severity >= $1
            ORDER BY severity DESC, detected_at DESC
            LIMIT $2
            """,
            min_severity,
            limit,
        )
        return [dict(r) for r in results]
    
    async def update_status(
        self,
        threat_id: str,
        status: str,
        resolution_notes: Optional[str] = None,
    ) -> bool:
        """
        Update threat status.
        
        Args:
            threat_id: Threat ID
            status: New status (open, acknowledged, resolved)
            resolution_notes: Optional notes on resolution
        
        Returns:
            True if successful
        """
        resolved_at = datetime.utcnow() if status == "resolved" else None
        
        result = await self.db.execute(
            """
            UPDATE threats 
            SET status = $1, resolved_at = $2, resolution_notes = $3
            WHERE id = $4
            """,
            status,
            resolved_at,
            resolution_notes,
            threat_id,
        )
        return "1" in result
    
    async def delete(self, threat_id: str) -> bool:
        """Delete threat record."""
        result = await self.db.execute(
            "DELETE FROM threats WHERE id = $1",
            threat_id,
        )
        return "1" in result


class AuditLogRepository:
    """Audit log data access object."""
    
    def __init__(self, db):
        """Initialize with database instance."""
        self.db = db
    
    async def log(
        self,
        event_type: str,
        severity: str,
        actor: str,
        action: str,
        result: str,
        agent_id: Optional[str] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """
        Create audit log entry.
        
        Args:
            event_type: Type of event
            severity: Severity level (info, warning, error, critical)
            actor: Who performed action
            action: What was done
            result: Result (success, failure)
            agent_id: Optional related agent ID
            details: Optional event-specific data
            ip_address: Optional source IP
        
        Returns:
            Log entry ID
        """
        log_id = str(uuid.uuid4())
        
        await self.db.execute(
            """
            INSERT INTO audit_logs 
            (id, agent_id, event_type, severity, actor, action, details, ip_address, result, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
            log_id,
            agent_id,
            event_type,
            severity,
            actor,
            action,
            details,
            ip_address,
            result,
            datetime.utcnow(),
        )
        
        return log_id
    
    async def list_recent(
        self,
        days: int = 7,
        limit: int = 1000,
        event_type: Optional[str] = None,
    ) -> List[Dict]:
        """
        List recent audit logs.
        
        Args:
            days: Number of days to look back (default: 7)
            limit: Result limit (default: 1000)
            event_type: Optional event type filter
        
        Returns:
            List of audit log records
        """
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        
        if event_type:
            results = await self.db.fetch(
                """
                SELECT * FROM audit_logs 
                WHERE timestamp >= $1 AND event_type = $2
                ORDER BY timestamp DESC
                LIMIT $3
                """,
                cutoff_time,
                event_type,
                limit,
            )
        else:
            results = await self.db.fetch(
                """
                SELECT * FROM audit_logs 
                WHERE timestamp >= $1
                ORDER BY timestamp DESC
                LIMIT $2
                """,
                cutoff_time,
                limit,
            )
        
        return [dict(r) for r in results]
    
    async def list_for_agent(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> List[Dict]:
        """List audit logs for specific agent."""
        results = await self.db.fetch(
            """
            SELECT * FROM audit_logs 
            WHERE agent_id = $1
            ORDER BY timestamp DESC
            LIMIT $2
            """,
            agent_id,
            limit,
        )
        return [dict(r) for r in results]


class RepositoryFactory:
    """Factory for creating repository instances."""
    
    def __init__(self, db):
        """Initialize with database instance."""
        self.db = db
        self._agents = None
        self._tokens = None
        self._threats = None
        self._audit_logs = None
    
    @property
    def agents(self) -> AgentRepository:
        """Get agent repository (lazy singleton)."""
        if not self._agents:
            self._agents = AgentRepository(self.db)
        return self._agents
    
    @property
    def tokens(self) -> TokenRepository:
        """Get token repository (lazy singleton)."""
        if not self._tokens:
            self._tokens = TokenRepository(self.db)
        return self._tokens
    
    @property
    def threats(self) -> ThreatRepository:
        """Get threat repository (lazy singleton)."""
        if not self._threats:
            self._threats = ThreatRepository(self.db)
        return self._threats
    
    @property
    def audit_logs(self) -> AuditLogRepository:
        """Get audit log repository (lazy singleton)."""
        if not self._audit_logs:
            self._audit_logs = AuditLogRepository(self.db)
        return self._audit_logs
