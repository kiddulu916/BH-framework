#!/usr/bin/env python3
"""
Test script to test the service layer directly.
"""

import asyncio
from core.utils.database import get_db_session
from core.tasks.target_service import TargetService
from core.schemas.base import PaginationParams

async def test_service():
    """Test the service layer."""
    
    print("Testing service layer...")
    
    try:
        async with get_db_session() as session:
            service = TargetService(session)
            
            # Test 1: List targets
            print("Test 1: List targets")
            pagination = PaginationParams(page=1, per_page=10)
            targets, total = await service.list_targets(pagination=pagination)
            print(f"✅ Service list successful: {len(targets)} targets, total: {total}")
            
    except Exception as e:
        print(f"❌ Service test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_service()) 