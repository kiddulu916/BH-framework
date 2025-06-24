import asyncio
from core.utils.database import get_db_session
from sqlalchemy import text

async def check_enum_values():
    async with get_db_session() as session:
        # Check workflowstatus enum
        result = await session.execute(text("SELECT unnest(enum_range(NULL::workflowstatus))"))
        workflow_status_values = [row[0] for row in result.fetchall()]
        print('WorkflowStatus enum values:', workflow_status_values)
        
        # Check workflowstage enum
        result = await session.execute(text("SELECT unnest(enum_range(NULL::workflowstage))"))
        workflow_stage_values = [row[0] for row in result.fetchall()]
        print('WorkflowStage enum values:', workflow_stage_values)
        
        # Check if stagestatus enum exists
        try:
            result = await session.execute(text("SELECT unnest(enum_range(NULL::stagestatus))"))
            stage_status_values = [row[0] for row in result.fetchall()]
            print('StageStatus enum values:', stage_status_values)
        except Exception as e:
            print('StageStatus enum does not exist or error:', str(e))

if __name__ == "__main__":
    asyncio.run(check_enum_values()) 