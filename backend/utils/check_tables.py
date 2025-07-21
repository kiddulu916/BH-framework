import asyncio
from sqlalchemy import text
from core.utils.database import get_db_session

async def check_tables():
    async with get_db_session() as session:
        # List all tables in the database
        result = await session.execute(
            text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
        )
        tables = [row[0] for row in result.fetchall()]
        print(f"Tables in database: {tables}")
        
        # Check if targets table exists
        if 'targets' in tables:
            print("✅ targets table exists")
        else:
            print("❌ targets table does not exist")

if __name__ == "__main__":
    asyncio.run(check_tables()) 