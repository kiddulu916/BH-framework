"""
Pytest configuration and fixtures for the Bug Hunting Framework.

This module contains pytest configuration, fixtures, and test utilities
for comprehensive testing of the Bug Hunting Framework.
"""

import os
# Set testing environment variable before any other imports
os.environ['TESTING'] = 'true'

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from django.test import override_settings
from django.conf import settings

from core.utils.database import get_db_session, db_manager
from core.models.base import BaseModel
from sqlalchemy import text
import asyncio

# Global variable to track if tables have been created
_tables_created = False
_tables_creation_lock = asyncio.Lock()

@pytest_asyncio.fixture(scope="session")
async def db_manager():
    """Create a database manager for the test session."""
    from core.utils.database import db_manager
    return db_manager

@pytest_asyncio.fixture(scope="session", autouse=True)
async def create_tables_once(db_manager):
    """Create all tables once per test session."""
    global _tables_created
    
    async with _tables_creation_lock:
        if not _tables_created:
            # Import all models to ensure they're registered with metadata
            from core.models import (
                User, Target, Workflow, WorkflowExecution,
                PassiveReconResult, Subdomain, ActiveReconResult, Port, Service,
                Vulnerability, VulnerabilityFinding, KillChain, AttackPath, Report
            )
            
            # Create tables directly on the engine
            async with db_manager.engine.begin() as conn:
                await conn.run_sync(BaseModel.metadata.create_all)
                print(f"DEBUG: Created all tables in {db_manager.engine.url}")
            _tables_created = True
        yield

@pytest_asyncio.fixture
async def api_client(create_tables_once):
    """Create an async HTTP client for testing the API."""
    from api.asgi import application
    
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://localhost") as client:
        yield client

@pytest.fixture
def test_settings():
    """Test settings override."""
    return {
        "DATABASES": {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        "SECRET_KEY": "test-secret-key",
        "DEBUG": True,
        "ALLOWED_HOSTS": ["localhost", "127.0.0.1", "0.0.0.0", "testserver", "*"],
        "LOGGING_CONFIG": None,
        "LOGGING": {
            "version": 1,
            "disable_existing_loggers": False,
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                },
            },
            "root": {
                "handlers": ["console"],
                "level": "INFO",
            },
            "loggers": {
                "django": {
                    "handlers": ["console"],
                    "level": "INFO",
                    "propagate": False,
                },
            },
        },
        "INSTALLED_APPS": settings.INSTALLED_APPS,
        "MIDDLEWARE": settings.MIDDLEWARE,
        "ROOT_URLCONF": settings.ROOT_URLCONF,
        "TEMPLATES": settings.TEMPLATES,
        "STATIC_URL": settings.STATIC_URL,
        "STATIC_ROOT": settings.STATIC_ROOT,
        "MEDIA_URL": getattr(settings, "MEDIA_URL", "/media/"),
        "MEDIA_ROOT": getattr(settings, "MEDIA_ROOT", "media"),
        "DEFAULT_AUTO_FIELD": getattr(settings, "DEFAULT_AUTO_FIELD", "django.db.models.BigAutoField"),
    }

@pytest.fixture
def override_test_settings(test_settings):
    """Override Django settings for testing."""
    with override_settings(**test_settings):
        yield

@pytest_asyncio.fixture
async def db_session(db_manager, create_tables_once):
    """Create a database session for testing."""
    async with db_manager.session_factory() as session:
        yield session

@pytest_asyncio.fixture(autouse=True)
async def clean_db(db_manager, create_tables_once):
    """Clean the database between tests by deleting all data."""
    # Only clean after tables are created
    if _tables_created:
        async with db_manager.session_factory() as session:
            # Check if we're using SQLite (testing) or PostgreSQL
            engine = session.bind
            if 'sqlite' in str(engine.url):
                # SQLite: Delete all data from tables
                for table in reversed(BaseModel.metadata.sorted_tables):
                    try:
                        await session.execute(text(f'DELETE FROM "{table.name}";'))
                    except Exception as e:
                        # Ignore errors if table doesn't exist or other issues
                        print(f"Warning: Could not delete from {table.name}: {e}")
            else:
                # PostgreSQL: Use TRUNCATE
                for table in reversed(BaseModel.metadata.sorted_tables):
                    try:
                        await session.execute(text(f'TRUNCATE TABLE "{table.name}" RESTART IDENTITY CASCADE;'))
                    except Exception as e:
                        # Ignore errors if table doesn't exist or other issues
                        print(f"Warning: Could not truncate {table.name}: {e}")
            await session.commit()
    yield

@pytest_asyncio.fixture
async def sample_workflow(db_session):
    """Create a sample workflow for testing."""
    from core.models import User, Target, Workflow
    from core.models.target import TargetScope, TargetStatus
    from core.models.workflow import WorkflowStatus
    
    # Create a test user
    user = User(
        name="Test User",
        email="test@example.com",
        platform="hackerone"
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Create a test target
    target = Target(
        name="example.com",
        value="example.com",
        scope=TargetScope.DOMAIN,
        status=TargetStatus.ACTIVE,
        user_id=user.id
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    
    # Create a test workflow
    workflow = Workflow(
        name="Test Workflow",
        description="A test workflow",
        stages={
            "passive_recon": "PENDING",
            "active_recon": "PENDING",
            "vuln_scan": "PENDING",
            "vuln_test": "PENDING",
            "kill_chain": "PENDING",
            "report": "PENDING"
        },
        status=WorkflowStatus.PENDING,
        target_id=target.id,
        user_id=user.id
    )
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)
    
    return workflow

@pytest_asyncio.fixture
async def create_test_target(db_session):
    """Create a test target for testing."""
    from core.models import User, Target
    from core.models.target import TargetScope, TargetStatus
    
    # Create a test user
    user = User(
        name="Test User",
        email="test@example.com",
        platform="hackerone"
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Create a test target
    target = Target(
        name="example.com",
        value="example.com",
        scope=TargetScope.DOMAIN,
        status=TargetStatus.ACTIVE,
        user_id=user.id
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    
    return target


@pytest.fixture
def sample_target_data():
    """Create sample target data for testing."""
    return {
        "name": "Test Target",
        "value": "test.example.com",
        "scope": "DOMAIN",
        "scope_config": {"subdomains": ["*.test.example.com"]},
        "description": "Test target for API testing"
    }


@pytest_asyncio.fixture
async def sample_target(db_session):
    """Create a sample target for testing."""
    from core.models import User, Target
    from core.models.target import TargetScope, TargetStatus
    
    # Create a test user
    user = User(
        name="Test User",
        email="test@example.com",
        platform="hackerone"
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    # Create a test target
    target = Target(
        name="Test Target",
        value="test.example.com",
        scope=TargetScope.DOMAIN,
        status=TargetStatus.ACTIVE,
        scope_config={"subdomains": ["*.test.example.com"]},
        user_id=user.id
    )
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    
    return target
