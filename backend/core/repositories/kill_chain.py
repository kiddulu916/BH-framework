"""
Kill chain repositories.

This module provides the KillChainRepository and AttackPathRepository
classes which handle all database operations related to kill chain analysis.
"""

from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from ..models.kill_chain import KillChain, AttackPath, AttackPathStatus
from .base import BaseRepository


class KillChainRepository(BaseRepository):
    """Repository for KillChain model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, KillChain)
    
    async def get_by_target(self, target_id: UUID) -> List[KillChain]:
        """Get all kill chain results for a target."""
        return await self.list(filters={'target_id': target_id}, order_by=['created_at'])
    
    async def get_by_execution_id(self, execution_id: str) -> Optional[KillChain]:
        """Get kill chain result by execution ID."""
        return await self.find_one({'execution_id': execution_id})
    
    async def count_by_target(self, target_id: UUID) -> int:
        """Count kill chain results for a target."""
        return await self.count(filters={'target_id': target_id})
    
    async def get_latest_by_target(self, target_id: UUID) -> Optional[KillChain]:
        """Get the latest kill chain result for a target."""
        query = select(self.model_class).where(
            self.model_class.target_id == target_id
        ).order_by(desc(self.model_class.created_at)).limit(1)
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def list_by_target_with_pagination(
        self, 
        target_id: UUID, 
        page: int = 1, 
        per_page: int = 10
    ) -> Tuple[List[KillChain], int]:
        """Get paginated kill chain results for a target."""
        offset = (page - 1) * per_page
        
        # Get total count
        total = await self.count(filters={'target_id': target_id})
        
        # Get paginated results
        results = await self.list(
            filters={'target_id': target_id},
            limit=per_page,
            offset=offset,
            order_by=['created_at']
        )
        
        return results, total

    async def get_by_workflow_id(self, workflow_id: UUID):
        """Get all kill chain records for a workflow ID with attack paths preloaded."""
        stmt = (
            select(KillChain)
            .options(selectinload(KillChain.attack_paths))
            .where(KillChain.execution_id == str(workflow_id))
            .order_by(KillChain.created_at)
        )
        
        result = await self.session.execute(stmt)
        return result.scalars().all()


class AttackPathRepository(BaseRepository):
    """Repository for AttackPath model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, AttackPath)
    
    async def get_by_kill_chain(self, kill_chain_id: UUID) -> List[AttackPath]:
        """Get all attack paths for a kill chain result."""
        return await self.list(filters={'kill_chain_id': kill_chain_id}, order_by=['created_at'])
    
    async def get_by_status(self, status: AttackPathStatus) -> List[AttackPath]:
        """Get all attack paths by status."""
        return await self.list(filters={'status': status}, order_by=['created_at'])
    
    async def get_verified_paths(self) -> List[AttackPath]:
        """Get all verified attack paths."""
        return await self.list(filters={'is_verified': True}, order_by=['created_at'])
    
    async def get_exploitable_paths(self) -> List[AttackPath]:
        """Get all exploitable attack paths."""
        return await self.list(filters={'is_exploitable': True}, order_by=['created_at'])
    
    async def get_high_risk_paths(self) -> List[AttackPath]:
        """Get all high risk attack paths."""
        return await self.list(filters={'risk_score': {'gte': 7.0}}, order_by=['created_at']) 