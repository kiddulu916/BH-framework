import asyncio
from sqlalchemy import text
from core.utils.database import get_db_session

async def check_enum_values():
    async with get_db_session() as session:
        # Check bugbountyplatform enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::bugbountyplatform))"))
        values = [row[0] for row in result.fetchall()]
        print(f"bugbountyplatform enum values: {values}")
        
        # Check targetscope enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::targetscope))"))
        values = [row[0] for row in result.fetchall()]
        print(f"targetscope enum values: {values}")
        
        # Check targetstatus enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::targetstatus))"))
        values = [row[0] for row in result.fetchall()]
        print(f"targetstatus enum values: {values}")

if __name__ == "__main__":
    asyncio.run(check_enum_values()) 