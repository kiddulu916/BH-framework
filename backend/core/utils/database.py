"""
Database utilities for the Bug Hunting Framework.

This module contains database connection management, session handling,
and other database-related utilities.
"""

import os
from typing import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from django.conf import settings
from sqlalchemy import text
from sqlalchemy import event
from sqlalchemy.engine import Engine

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+asyncpg://postgres:postgres@localhost:5432/bug_hunting_framework')

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    poolclass=NullPool,  # Use NullPool for development
    pool_pre_ping=True,
    pool_recycle=300,
)

# Set search_path to public on each new connection
@event.listens_for(engine.sync_engine, "connect")
def set_search_path(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("SET search_path TO public")
    cursor.close()

# Create async session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class DatabaseManager:
    """Database manager for handling connections and sessions."""
    
    def __init__(self):
        self.engine = engine
        self.session_factory = async_session_factory
    
    async def get_session(self) -> AsyncSession:
        """Get a new database session."""
        return self.session_factory()
    
    async def close(self):
        """Close the database engine."""
        await self.engine.dispose()


# Global database manager instance
db_manager = DatabaseManager()


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get a database session with automatic cleanup.
    
    Usage:
        async with get_db_session() as session:
            # Use session for database operations
            result = await session.execute(query)
    """
    session = async_session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    return db_manager


async def init_database():
    """Initialize the database with tables and initial data."""
    from core.models.base import Base
    
    # Import all models to ensure they are registered with SQLAlchemy
    from core.models import (
        user,
        target,
        passive_recon,
        active_recon,
        vulnerability,
        kill_chain,
        workflow,
        report
    )
    
    async with engine.begin() as conn:
        # Set search path to public schema
        await conn.execute(text("SET search_path TO public"))
        
        # Create the public schema if it doesn't exist
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS public"))
        
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)


async def close_database():
    """Close database connections."""
    await db_manager.close()


# Health check function
async def check_database_health() -> dict:
    """
    Check database connectivity and health.
    
    Returns:
        Dictionary with health status and details
    """
    try:
        async with get_db_session() as session:
            # Simple query to test connection
            result = await session.execute(text("SELECT 1"))
            result.fetchone()
            
            return {
                "status": "healthy",
                "message": "Database connection successful",
                "details": {
                    "url": DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else "unknown",
                    "pool_size": engine.pool.size(),
                    "checked_out": engine.pool.checkedout()
                }
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}",
            "details": {
                "error": str(e),
                "url": DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else "unknown"
            }
        } 