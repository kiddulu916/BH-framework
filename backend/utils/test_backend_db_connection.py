import os
import asyncio
from sqlalchemy import text
from core.utils.database import get_db_session

async def test_backend_db_connection():
    """Test the database connection using the same config as the backend."""
    print("Testing backend database connection...")
    
    try:
        async with get_db_session() as session:
            # Test basic connection
            result = await session.execute(text("SELECT 1"))
            print("✅ Basic connection successful")
            
            # Check if targets table exists
            result = await session.execute(
                text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'targets'")
            )
            table_exists = result.fetchone() is not None
            print(f"✅ targets table exists: {table_exists}")
            
            if table_exists:
                # Try to query the targets table
                result = await session.execute(text("SELECT COUNT(*) FROM public.targets"))
                count = result.fetchone()[0]
                print(f"✅ targets table is queryable, count: {count}")
                
                # Try to query with SQLAlchemy model
                from core.models.target import Target
                result = await session.execute(text("SELECT id FROM public.targets LIMIT 1"))
                row = result.fetchone()
                print(f"✅ SQLAlchemy query successful: {row is not None}")
            else:
                print("❌ targets table does not exist")
                
    except Exception as e:
        print(f"❌ Database connection failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_backend_db_connection()) 