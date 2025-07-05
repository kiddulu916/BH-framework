"""
Report repository.

This module provides the ReportRepository class which handles
all database operations related to reports.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.report import Report, ReportStatus, ReportType
from .base import BaseRepository


class ReportRepository(BaseRepository):
    """Repository for Report model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, Report)
    
    async def get_by_target(self, target_id: UUID) -> List[Report]:
        """Get all reports for a target."""
        return await self.list(filters={'target_id': target_id}, order_by=['created_at'])
    
    async def get_by_user(self, user_id: UUID) -> List[Report]:
        """Get all reports for a user."""
        return await self.list(filters={'user_id': user_id}, order_by=['created_at'])
    
    async def get_by_type(self, report_type: ReportType) -> List[Report]:
        """Get all reports by type."""
        return await self.list(filters={'report_type': report_type}, order_by=['created_at'])
    
    async def get_by_status(self, status: ReportStatus) -> List[Report]:
        """Get all reports by status."""
        return await self.list(filters={'status': status}, order_by=['created_at'])
    
    async def get_completed_reports(self) -> List[Report]:
        """Get all completed reports."""
        return await self.list(filters={'status': ReportStatus.COMPLETED}, order_by=['created_at'])
    
    async def get_public_reports(self) -> List[Report]:
        """Get all public reports."""
        return await self.list(filters={'is_public': True}, order_by=['created_at'])
    
    async def get_by_access_token(self, access_token: str) -> Optional[Report]:
        """Get report by access token."""
        return await self.find_one({'access_token': access_token})
    
    async def get_by_workflow_id(self, workflow_id: UUID) -> Optional[Report]:
        """Get the first report for a workflow ID, or None if not found."""
        return await self.find_one({'workflow_id': workflow_id})
    
    async def count_by_workflow(self, workflow_id: UUID) -> int:
        """Count reports for a workflow."""
        return await self.count(filters={'workflow_id': workflow_id}) 