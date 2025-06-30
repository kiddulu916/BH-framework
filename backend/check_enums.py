import asyncio
from core.utils.database import db_manager
from sqlalchemy import text

async def check_enums():
    async with db_manager.session_factory() as session:
        # Check ReportType enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::reporttype)) as enum_values"))
        print('ReportType enum values:')
        for row in result:
            print(f'  {row[0]}')
        
        # Check ReportFormat enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::reportformat)) as enum_values"))
        print('ReportFormat enum values:')
        for row in result:
            print(f'  {row[0]}')
        
        # Check ReportStatus enum values
        result = await session.execute(text("SELECT unnest(enum_range(NULL::reportstatus)) as enum_values"))
        print('ReportStatus enum values:')
        for row in result:
            print(f'  {row[0]}')

if __name__ == "__main__":
    asyncio.run(check_enums()) 