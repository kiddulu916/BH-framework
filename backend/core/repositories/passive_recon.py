"""
Passive reconnaissance repositories.

This module provides the PassiveReconRepository and SubdomainRepository
classes which handle all database operations related to passive reconnaissance.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.passive_recon import PassiveReconResult, Subdomain
from .base import BaseRepository


class PassiveReconRepository(BaseRepository):
    """Repository for PassiveReconResult model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, PassiveReconResult)
    
    async def get_by_target(self, target_id: UUID) -> List[PassiveReconResult]:
        """Get all passive recon results for a target."""
        return await self.list(filters={'target_id': target_id}, order_by=['created_at'])
    
    async def get_by_execution_id(self, execution_id: str) -> Optional[PassiveReconResult]:
        """Get passive recon result by execution ID."""
        return await self.find_one({'execution_id': execution_id})


class SubdomainRepository(BaseRepository):
    """Repository for Subdomain model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, Subdomain)
    
    async def get_by_passive_recon_result(self, passive_recon_result_id: UUID) -> List[Subdomain]:
        """Get all subdomains for a passive recon result."""
        return await self.list(filters={'passive_recon_result_id': passive_recon_result_id}, order_by=['name'])
    
    async def get_by_domain(self, domain: str) -> List[Subdomain]:
        """Get all subdomains for a domain."""
        return await self.list(filters={'domain': domain}, order_by=['name'])
    
    async def get_active_subdomains(self, domain: str) -> List[Subdomain]:
        """Get all active subdomains for a domain."""
        from ..models.passive_recon import SubdomainStatus
        return await self.list(filters={'domain': domain, 'status': SubdomainStatus.ACTIVE}, order_by=['name']) 