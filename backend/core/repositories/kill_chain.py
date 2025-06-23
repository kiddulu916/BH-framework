"""
Kill chain repositories.

This module provides the KillChainRepository and AttackPathRepository
classes which handle all database operations related to kill chain analysis.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

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