#!/usr/bin/env python3
"""
Simple test script to check database connectivity and table access.
"""

import asyncio
from core.utils.database import get_db_session
from core.models.target import Target
from sqlalchemy import text

async def test_database():
    """Test database connectivity and table access."""
    
    print("Testing database connectivity...")
    
    try:
        async with get_db_session() as session:
            # Test 1: Direct SQL query
            print("Test 1: Direct SQL query")
            result = await session.execute(text("SELECT COUNT(*) FROM public.targets"))
            count = result.scalar()
            print(f"✅ Direct SQL query successful: {count} targets")
            
            # Test 2: SQLAlchemy query
            print("Test 2: SQLAlchemy query")
            result = await session.execute(text("SELECT * FROM public.targets LIMIT 1"))
            row = result.fetchone()
            print(f"✅ SQLAlchemy query successful: {row}")
            
            # Test 3: Model query
            print("Test 3: Model query")
            result = await session.execute(text("SELECT COUNT(*) FROM targets"))
            count = result.scalar()
            print(f"✅ Model query successful: {count} targets")
            
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_database()) 