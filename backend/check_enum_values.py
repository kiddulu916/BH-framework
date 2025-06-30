import asyncio
from core.utils.database import get_db_session
from sqlalchemy import text

async def check_enum_values():
    async with get_db_session() as session:
        # Check AttackPathStatus enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::attackpathstatus)) as enum_values"))
        values = [row[0] for row in result.fetchall()]
        print('AttackPathStatus enum values:', values)
        
        # Check other enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::vulnerabilitystatus)) as enum_values"))
        values = [row[0] for row in result.fetchall()]
        print('VulnerabilityStatus enum values:', values)

if __name__ == "__main__":
    asyncio.run(check_enum_values()) 