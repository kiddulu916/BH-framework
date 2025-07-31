#!/usr/bin/env python
"""
Script to create the example.com target for testing.
"""
import os
import sys
import django
from django.core.management import execute_from_command_line

# Add the backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from core.models.target import Target, TargetScope, TargetStatus
from core.repositories.target import TargetRepository
from core.utils.database import get_db_session
import asyncio

async def create_example_target():
    """Create the example.com target if it doesn't exist."""
    async with get_db_session() as session:
        repo = TargetRepository(session)
        
        # Check if target already exists
        existing = await repo.get_by_value("example.com")
        if existing:
            print(f"Target example.com already exists with ID: {existing.id}")
            return existing.id
        
        # Create new target
        target_data = {
            "target": "Example Domain",
            "value": "example.com",
            "scope": TargetScope.DOMAIN,
            "status": TargetStatus.ACTIVE,
            "scope_config": {
                "subdomains": True,
                "ports": "1-1000",
                "protocols": ["http", "https"]
            }
        }
        
        target = await repo.create(**target_data)
        print(f"Created target example.com with ID: {target.id}")
        return target.id

if __name__ == "__main__":
    target_id = asyncio.run(create_example_target())
    print(f"Target ID: {target_id}") 