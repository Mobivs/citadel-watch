"""
Database module for Citadel Archer.

Provides PostgreSQL connectivity, connection pooling, models, and migrations.
Phase 2: Database persistence for agents, tokens, threats, audit logs.

Usage:
    # Startup
    db = await create_connection_pool()
    await initialize_schema(db)
    
    # Create repository factory
    repos = RepositoryFactory(db)
    
    # Use repositories
    agent_id = await repos.agents.create("hostname", "192.168.1.1")
    agent = await repos.agents.get_by_id(agent_id)
    
    # Shutdown
    await close_connection_pool()
"""

from .connection import (
    Database,
    get_database,
    create_connection_pool,
    close_connection_pool,
)
from .models import (
    AgentModel,
    TokenModel,
    ThreatModel,
    AuditLogModel,
)
from .migrations import (
    initialize_schema,
    migrate_from_memory,
)
from .repositories import (
    AgentRepository,
    TokenRepository,
    ThreatRepository,
    AuditLogRepository,
    RepositoryFactory,
)

__all__ = [
    "Database",
    "get_database",
    "create_connection_pool",
    "close_connection_pool",
    "AgentModel",
    "TokenModel",
    "ThreatModel",
    "AuditLogModel",
    "initialize_schema",
    "migrate_from_memory",
    "AgentRepository",
    "TokenRepository",
    "ThreatRepository",
    "AuditLogRepository",
    "RepositoryFactory",
]
