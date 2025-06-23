"""
Pytest configuration and fixtures for the Bug Hunting Framework.

This module contains pytest configuration, fixtures, and test utilities
for comprehensive testing of the Bug Hunting Framework.
"""

import pytest
import asyncio
from typing import Dict, Any, Optional
from uuid import uuid4
from datetime import datetime, timezone, UTC
from unittest.mock import MagicMock, AsyncMock

import httpx
from httpx import AsyncClient, ASGITransport

from django.conf import settings
from django.test import override_settings

from core.models.target import Target, TargetScope, TargetStatus
from core.models.user import User
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.repositories.target import TargetRepository
from core.repositories.user import UserRepository
from core.repositories.workflow import WorkflowRepository
from core.utils.database import get_db_manager

import pytest_asyncio


# Pytest configuration
pytest_plugins = [
    "pytest_asyncio",
    "pytest_django",
]


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def db_manager():
    """Get database manager instance."""
    return get_db_manager()


@pytest_asyncio.fixture
async def db_session(db_manager):
    """Create a database session for testing."""
    async with db_manager.session_factory() as session:
        yield session


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "id": uuid4(),
        "name": "Test User",
        "email": "test@example.com",
        "platform": "hackerone",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }


@pytest.fixture
def sample_target_data():
    """Sample target data for testing."""
    return {
        "id": uuid4(),
        "name": "Example Target",
        "value": "example.com",
        "scope": TargetScope.DOMAIN,
        "status": TargetStatus.ACTIVE,
        "is_primary": True,
        "scope_config": {"subdomains": ["*.example.com"]},
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }


@pytest.fixture
def sample_workflow_data(sample_target_data):
    """Sample workflow data for testing."""
    return {
        "id": uuid4(),
        "target_id": sample_target_data["id"],
        "name": "Test Workflow",
        "description": "Test workflow for bug hunting",
        "status": WorkflowStatus.PENDING,
        "stages": {
            "passive_recon": StageStatus.PENDING,
            "active_recon": StageStatus.PENDING,
            "vulnerability_scan": StageStatus.PENDING,
            "vulnerability_test": StageStatus.PENDING,
            "kill_chain_analysis": StageStatus.PENDING,
            "report_generation": StageStatus.PENDING
        },
        "settings": {"test": True},
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }


@pytest_asyncio.fixture
async def sample_user(db_session, sample_user_data):
    """Create a sample user in the database."""
    user_repo = UserRepository(db_session)
    user = User(**sample_user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def sample_target(db_session, sample_target_data):
    """Create a sample target in the database."""
    target_repo = TargetRepository(db_session)
    target = Target(**sample_target_data)
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    return target


@pytest_asyncio.fixture
async def sample_workflow(db_session, sample_workflow_data, sample_target):
    """Create a sample workflow in the database."""
    workflow_repo = WorkflowRepository(db_session)
    workflow_data = {**sample_workflow_data, "target_id": sample_target.id}
    workflow = Workflow(**workflow_data)
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)
    return workflow


@pytest.fixture
def mock_repositories():
    """Create mock repositories for testing."""
    return {
        "target_repo": MagicMock(spec=TargetRepository),
        "user_repo": MagicMock(spec=UserRepository),
        "workflow_repo": MagicMock(spec=WorkflowRepository),
        "passive_recon_repo": MagicMock(),
        "active_recon_repo": MagicMock(),
        "vulnerability_repo": MagicMock(),
        "kill_chain_repo": MagicMock(),
        "report_repo": MagicMock(),
    }


@pytest_asyncio.fixture
async def api_client():
    """Create an async HTTP client for API testing."""
    from api.asgi import application
    
    transport = ASGITransport(app=application)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
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
        "ALLOWED_HOSTS": ["testserver"],
    }


@pytest.fixture
def override_test_settings(test_settings):
    """Override settings for testing."""
    with override_settings(**test_settings):
        yield


# Test utilities
class TestDataFactory:
    """Factory for creating test data."""
    
    @staticmethod
    def create_user(**kwargs) -> Dict[str, Any]:
        """Create user test data."""
        defaults = {
            "id": uuid4(),
            "name": f"Test User {uuid4().hex[:8]}",
            "email": f"test_{uuid4().hex[:8]}@example.com",
            "platform": "hackerone",
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        defaults.update(kwargs)
        return defaults
    
    @staticmethod
    def create_target(**kwargs) -> Dict[str, Any]:
        """Create target test data."""
        defaults = {
            "id": uuid4(),
            "name": f"Test Target {uuid4().hex[:8]}",
            "value": f"test{uuid4().hex[:8]}.com",
            "scope": TargetScope.DOMAIN,
            "status": TargetStatus.ACTIVE,
            "is_primary": True,
            "scope_config": {"subdomains": ["*.test.com"]},
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        defaults.update(kwargs)
        return defaults
    
    @staticmethod
    def create_workflow(target_id: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Create workflow test data."""
        defaults = {
            "id": uuid4(),
            "target_id": target_id or uuid4(),
            "name": f"Test Workflow {uuid4().hex[:8]}",
            "description": "Test workflow",
            "status": WorkflowStatus.PENDING,
            "stages": {
                "passive_recon": "pending",
                "active_recon": "pending",
                "vulnerability_scan": "pending",
                "vulnerability_test": "pending",
                "kill_chain_analysis": "pending",
                "report_generation": "pending"
            },
            "settings": {"test": True},
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        defaults.update(kwargs)
        return defaults


@pytest.fixture
def test_data_factory():
    """Get test data factory instance."""
    return TestDataFactory()


# Async test utilities
async def create_test_user(db_session, **kwargs) -> User:
    """Create a test user in the database."""
    user_data = TestDataFactory.create_user(**kwargs)
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def create_test_target(db_session, **kwargs) -> Target:
    """Create a test target in the database."""
    target_data = TestDataFactory.create_target(**kwargs)
    target = Target(**target_data)
    db_session.add(target)
    await db_session.commit()
    await db_session.refresh(target)
    return target


async def create_test_workflow(db_session, target_id: str, **kwargs) -> Workflow:
    """Create a test workflow in the database."""
    workflow_data = TestDataFactory.create_workflow(target_id=target_id, **kwargs)
    workflow = Workflow(**workflow_data)
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)
    return workflow


# Cleanup utilities
async def cleanup_test_data(db_session, *models):
    """Clean up test data from the database."""
    for model in models:
        await db_session.delete(model)
    await db_session.commit()


# Test markers
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.django_db,
] 
