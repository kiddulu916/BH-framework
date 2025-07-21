import asyncio
from sqlalchemy import text
from core.utils.database import get_db_session

async def check_schema():
    async with get_db_session() as session:
        # Check if attack_path_type column exists
        result = await session.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'attack_paths' AND column_name = 'attack_path_type'")
        )
        exists = result.fetchone() is not None
        print(f"attack_path_type column exists: {exists}")
        
        # List all columns in attack_paths table
        result = await session.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = 'attack_paths' ORDER BY ordinal_position")
        )
        columns = [row[0] for row in result.fetchall()]
        print(f"All columns in attack_paths: {columns}")

if __name__ == "__main__":
    asyncio.run(check_schema()) 