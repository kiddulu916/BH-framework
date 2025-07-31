#!/usr/bin/env python3
"""
Test script to test the repository layer directly.
"""

import asyncio
from core.utils.database import get_db_session
from core.models.target import Target
from core.repositories.target import TargetRepository
from sqlalchemy import select

async def test_repository():
    """Test the repository layer."""
    
    print("Testing repository layer...")
    
    try:
        async with get_db_session() as session:
            repo = TargetRepository(session)
            
            # Test 1: List targets
            print("Test 1: List targets")
            targets = await repo.list(limit=10)
            print(f"✅ Repository list successful: {len(targets)} targets")
            
            # Test 2: Count targets
            print("Test 2: Count targets")
            count = await repo.count()
            print(f"✅ Repository count successful: {count} targets")
            
            # Test 3: Direct SQLAlchemy query
            print("Test 3: Direct SQLAlchemy query")
            query = select(Target)
            result = await session.execute(query)
            targets = result.scalars().all()
            print(f"✅ Direct SQLAlchemy query successful: {len(targets)} targets")
            
    except Exception as e:
        print(f"❌ Repository test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_repository()) 