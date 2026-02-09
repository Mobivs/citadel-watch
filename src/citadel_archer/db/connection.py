"""
PostgreSQL connection pooling and management.

Provides async connection pool with configurable parameters,
automatic cleanup, and connection verification.
"""

import asyncpg
import logging
from typing import Optional
from contextlib import asynccontextmanager
import os

logger = logging.getLogger(__name__)


class Database:
    """
    PostgreSQL connection pool manager.
    
    Handles connection creation, pooling, and lifecycle management.
    Implements async context manager for proper resource cleanup.
    
    Attributes:
        pool: asyncpg connection pool (None until initialize() called)
        host: PostgreSQL host
        port: PostgreSQL port
        database: Database name
        user: Database user
        password: Database password
        min_size: Minimum pool connections
        max_size: Maximum pool connections
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "citadel_archer",
        user: str = "postgres",
        password: str = "",
        min_size: int = 5,
        max_size: int = 20,
    ):
        """
        Initialize database connection parameters.
        
        Args:
            host: PostgreSQL host (default: localhost)
            port: PostgreSQL port (default: 5432)
            database: Database name (default: citadel_archer)
            user: Database user (default: postgres)
            password: Database password (default: empty)
            min_size: Minimum pool connections (default: 5)
            max_size: Maximum pool connections (default: 20)
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.min_size = min_size
        self.max_size = max_size
        self.pool: Optional[asyncpg.Pool] = None
    
    async def initialize(self) -> None:
        """
        Create connection pool.
        
        Raises:
            asyncpg.PostgresError: If connection fails
            TimeoutError: If initialization times out
        
        Note:
            Must be called before using database.
            Typically called during application startup.
        """
        try:
            self.pool = await asyncpg.create_pool(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                min_size=self.min_size,
                max_size=self.max_size,
                timeout=30.0,
                command_timeout=30.0,
            )
            logger.info(
                f"Database pool initialized: {self.user}@{self.host}:{self.port}/{self.database}"
            )
        except asyncpg.PostgresError as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error initializing database: {e}")
            raise
    
    async def close(self) -> None:
        """
        Close connection pool.
        
        Safely terminates all connections in pool.
        Should be called during application shutdown.
        """
        if self.pool:
            await self.pool.close()
            logger.info("Database pool closed")
    
    @asynccontextmanager
    async def acquire(self):
        """
        Context manager for acquiring connection from pool.
        
        Usage:
            async with db.acquire() as conn:
                result = await conn.fetch(...)
        
        Yields:
            asyncpg.Connection: Database connection
        
        Raises:
            RuntimeError: If pool not initialized
            asyncpg.PostgresError: If connection acquisition fails
        """
        if not self.pool:
            raise RuntimeError("Database pool not initialized. Call initialize() first.")
        
        conn = await self.pool.acquire()
        try:
            yield conn
        finally:
            await self.pool.release(conn)
    
    async def fetch(self, query: str, *args) -> list:
        """
        Execute SELECT query and return all rows.
        
        Args:
            query: SQL query string
            *args: Query parameters
        
        Returns:
            List of records
        
        Raises:
            asyncpg.PostgresError: If query fails
        """
        async with self.acquire() as conn:
            return await conn.fetch(query, *args)
    
    async def fetchrow(self, query: str, *args) -> Optional[dict]:
        """
        Execute SELECT query and return first row.
        
        Args:
            query: SQL query string
            *args: Query parameters
        
        Returns:
            First record or None
        
        Raises:
            asyncpg.PostgresError: If query fails
        """
        async with self.acquire() as conn:
            return await conn.fetchrow(query, *args)
    
    async def execute(self, query: str, *args) -> str:
        """
        Execute INSERT/UPDATE/DELETE query.
        
        Args:
            query: SQL query string
            *args: Query parameters
        
        Returns:
            Command status (e.g., "INSERT 0 1")
        
        Raises:
            asyncpg.PostgresError: If query fails
        """
        async with self.acquire() as conn:
            return await conn.execute(query, *args)
    
    async def executemany(self, query: str, args: list) -> None:
        """
        Execute INSERT/UPDATE/DELETE query multiple times.
        
        Args:
            query: SQL query string
            args: List of parameter tuples
        
        Raises:
            asyncpg.PostgresError: If query fails
        """
        async with self.acquire() as conn:
            await conn.executemany(query, args)
    
    async def transaction(self):
        """
        Context manager for database transaction.
        
        Usage:
            async with db.transaction() as conn:
                await conn.execute(...)
                await conn.execute(...)
                # Auto-commit on success, rollback on exception
        
        Yields:
            asyncpg.Connection: Connection in transaction
        """
        async with self.acquire() as conn:
            async with conn.transaction():
                yield conn


# Global instance
_db: Optional[Database] = None


def get_database() -> Database:
    """
    Get global database instance.
    
    Returns:
        Global Database instance
    
    Raises:
        RuntimeError: If database not initialized
    """
    if not _db:
        raise RuntimeError("Database not initialized")
    return _db


async def create_connection_pool(
    host: str = None,
    port: int = None,
    database: str = None,
    user: str = None,
    password: str = None,
    min_size: int = 5,
    max_size: int = 20,
) -> Database:
    """
    Create and initialize global database connection pool.
    
    Args:
        host: PostgreSQL host (env: DB_HOST, default: localhost)
        port: PostgreSQL port (env: DB_PORT, default: 5432)
        database: Database name (env: DB_NAME, default: citadel_archer)
        user: Database user (env: DB_USER, default: postgres)
        password: Database password (env: DB_PASSWORD, default: empty)
        min_size: Minimum pool connections (default: 5)
        max_size: Maximum pool connections (default: 20)
    
    Returns:
        Initialized Database instance
    
    Raises:
        asyncpg.PostgresError: If connection fails
    """
    global _db
    
    # Use environment variables as fallback
    host = host or os.getenv("DB_HOST", "localhost")
    port = port or int(os.getenv("DB_PORT", "5432"))
    database = database or os.getenv("DB_NAME", "citadel_archer")
    user = user or os.getenv("DB_USER", "postgres")
    password = password or os.getenv("DB_PASSWORD", "")
    
    _db = Database(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        min_size=min_size,
        max_size=max_size,
    )
    
    await _db.initialize()
    return _db


async def close_connection_pool() -> None:
    """
    Close global database connection pool.
    
    Typically called during application shutdown.
    """
    global _db
    if _db:
        await _db.close()
        _db = None
