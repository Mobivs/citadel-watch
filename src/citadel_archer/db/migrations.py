"""
Database schema initialization and data migration utilities.

Handles:
- PostgreSQL schema creation from SQL file
- Migration from in-memory storage to persistent database
- Data validation and integrity checks
- Backward compatibility
"""

import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from .connection import Database, get_database
from .models import AgentModel, TokenModel, ThreatModel, AuditLogModel

logger = logging.getLogger(__name__)


async def initialize_schema(db: Database) -> bool:
    """
    Create PostgreSQL schema from schema.sql file.
    
    Reads schema.sql and executes all SQL statements to create tables,
    indexes, and constraints. Idempotent (safe to call multiple times).
    
    Args:
        db: Database instance
    
    Returns:
        True if successful, False otherwise
    
    Raises:
        FileNotFoundError: If schema.sql not found
        asyncpg.PostgresError: If schema creation fails
    """
    try:
        # Read schema file
        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            logger.error(f"Schema file not found: {schema_path}")
            raise FileNotFoundError(f"Schema file not found: {schema_path}")
        
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
        
        # Execute schema
        async with db.acquire() as conn:
            # Split by GO statement or execute all at once
            # PostgreSQL doesn't use GO, so execute entire script
            await conn.execute(schema_sql)
        
        logger.info("Database schema initialized successfully")
        return True
    
    except FileNotFoundError as e:
        logger.error(f"Schema initialization failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Schema initialization failed: {e}")
        raise


async def migrate_from_memory(
    db: Database,
    agents_data: Dict[str, Dict[str, Any]],
    tokens_data: Dict[str, Dict[str, Any]],
    threats_data: Dict[str, Dict[str, Any]],
    audit_logs_data: Optional[list] = None,
) -> Dict[str, int]:
    """
    Migrate data from in-memory storage to PostgreSQL.
    
    Handles the transition from in-memory dictionaries to persistent database.
    Validates data integrity and logs all operations.
    
    Args:
        db: Database instance
        agents_data: Dict of agent_id -> agent info (from agents_db)
        tokens_data: Dict of token_hash -> token info (from agent_tokens)
        threats_data: Dict of threat_id -> threat info (from remote_threats_db)
        audit_logs_data: List of audit log entries (optional)
    
    Returns:
        Dict with counts: {
            'agents': int,
            'tokens': int,
            'threats': int,
            'audit_logs': int,
            'errors': int
        }
    
    Raises:
        asyncpg.PostgresError: If migration fails
    """
    stats = {
        'agents': 0,
        'tokens': 0,
        'threats': 0,
        'audit_logs': 0,
        'errors': 0,
    }
    
    try:
        # Migrate agents
        logger.info(f"Migrating {len(agents_data)} agents...")
        for agent_id, agent_info in agents_data.items():
            try:
                # Validate required fields
                hostname = agent_info.get('hostname')
                ip_address = agent_info.get('ip_address') or agent_info.get('ip')
                
                if not hostname or not ip_address:
                    logger.warning(f"Skipping agent {agent_id}: missing required fields")
                    stats['errors'] += 1
                    continue
                
                # Parse timestamps safely
                registered_at = _parse_datetime(agent_info.get('registered_at'), datetime.utcnow())
                last_heartbeat = _parse_datetime(agent_info.get('last_heartbeat'))
                last_scan_at = _parse_datetime(agent_info.get('last_scan_at'))
                
                # Insert agent
                await db.execute(
                    """
                    INSERT INTO agents 
                    (id, hostname, ip_address, status, last_heartbeat, registered_at, last_scan_at, scan_interval_seconds)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (hostname) DO NOTHING
                    """,
                    agent_id,
                    hostname,
                    ip_address,
                    agent_info.get('status', 'inactive'),
                    last_heartbeat,
                    registered_at,
                    last_scan_at,
                    agent_info.get('scan_interval_seconds', 300),
                )
                stats['agents'] += 1
            except Exception as e:
                logger.error(f"Error migrating agent {agent_id}: {e}")
                stats['errors'] += 1
                continue
        
        # Migrate tokens
        logger.info(f"Migrating {len(tokens_data)} tokens...")
        for token_hash, token_info in tokens_data.items():
            try:
                agent_id = token_info.get('agent_id')
                if not agent_id:
                    logger.warning(f"Skipping token: missing agent_id")
                    stats['errors'] += 1
                    continue
                
                # Parse timestamps safely
                issued_at = _parse_datetime(token_info.get('issued_at'), datetime.utcnow())
                expires_at = _parse_datetime(token_info.get('expires_at'), datetime.utcnow() + timedelta(hours=24))
                revoked_at = _parse_datetime(token_info.get('revoked_at'))
                
                # Insert token
                await db.execute(
                    """
                    INSERT INTO agent_tokens 
                    (id, agent_id, token_hash, issued_at, expires_at, is_revoked, revoked_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    """,
                    _generate_id(),
                    agent_id,
                    token_hash,
                    issued_at,
                    expires_at,
                    token_info.get('is_revoked', False),
                    revoked_at,
                )
                stats['tokens'] += 1
            except Exception as e:
                logger.error(f"Error migrating token: {e}")
                stats['errors'] += 1
                continue
        
        # Migrate threats
        logger.info(f"Migrating {len(threats_data)} threats...")
        for threat_id, threat_info in threats_data.items():
            try:
                agent_id = threat_info.get('agent_id')
                if not agent_id:
                    logger.warning(f"Skipping threat {threat_id}: missing agent_id")
                    stats['errors'] += 1
                    continue
                
                # Parse timestamps safely
                detected_at = _parse_datetime(threat_info.get('detected_at'), datetime.utcnow())
                reported_at = _parse_datetime(threat_info.get('reported_at'), datetime.utcnow())
                resolved_at = _parse_datetime(threat_info.get('resolved_at'))
                
                # Insert threat
                await db.execute(
                    """
                    INSERT INTO threats 
                    (id, agent_id, threat_type, severity, hostname, title, description, details, status, detected_at, reported_at, resolved_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    """,
                    threat_id,
                    agent_id,
                    threat_info.get('threat_type', 'unknown'),
                    threat_info.get('severity', 5),
                    threat_info.get('hostname', 'unknown'),
                    threat_info.get('title', 'Unknown Threat'),
                    threat_info.get('description'),
                    threat_info.get('details'),
                    threat_info.get('status', 'open'),
                    detected_at,
                    reported_at,
                    resolved_at,
                )
                stats['threats'] += 1
            except Exception as e:
                logger.error(f"Error migrating threat {threat_id}: {e}")
                stats['errors'] += 1
                continue
        
        # Migrate audit logs (if provided)
        if audit_logs_data:
            logger.info(f"Migrating {len(audit_logs_data)} audit logs...")
            for log_entry in audit_logs_data:
                try:
                    # Parse timestamp safely
                    timestamp = _parse_datetime(log_entry.get('timestamp'), datetime.utcnow())
                    
                    # Insert audit log
                    await db.execute(
                        """
                        INSERT INTO audit_logs 
                        (id, agent_id, event_type, severity, actor, action, details, ip_address, result, timestamp)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        """,
                        log_entry.get('id') or _generate_id(),
                        log_entry.get('agent_id'),
                        log_entry.get('event_type', 'unknown'),
                        log_entry.get('severity', 'info'),
                        log_entry.get('actor', 'system'),
                        log_entry.get('action', 'unknown'),
                        log_entry.get('details'),
                        log_entry.get('ip_address'),
                        log_entry.get('result', 'success'),
                        timestamp,
                    )
                    stats['audit_logs'] += 1
                except Exception as e:
                    logger.error(f"Error migrating audit log: {e}")
                    stats['errors'] += 1
                    continue
        
        logger.info(f"Migration complete: {stats}")
        return stats
    
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise


def _parse_datetime(value: Any, default: Optional[datetime] = None) -> Optional[datetime]:
    """
    Parse datetime from various formats.
    
    Args:
        value: Value to parse (datetime, string, None, etc.)
        default: Default value if parsing fails
    
    Returns:
        Parsed datetime or default
    """
    if isinstance(value, datetime):
        return value
    
    if isinstance(value, str):
        try:
            # Try ISO format first
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            try:
                # Try common formats
                return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                pass
    
    return default


def _generate_id() -> str:
    """
    Generate UUID for database records.
    
    Returns:
        UUID string
    """
    import uuid
    return str(uuid.uuid4())
