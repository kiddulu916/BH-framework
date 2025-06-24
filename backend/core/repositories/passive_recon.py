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

    async def create_with_subdomains(self, subdomains: list, **kwargs) -> PassiveReconResult:
        """
        Create a PassiveReconResult with a list of subdomain dicts.
        Normalize enum fields to uppercase for DB compatibility.
        """
        from ..models.passive_recon import Subdomain
        subdomain_objs = []
        for sd in subdomains:
            sd = dict(sd)
            sd.pop('target_id', None)
            # Map schema fields to model fields
            if 'subdomain' in sd:
                subdomain_name = sd.pop('subdomain')
                sd['name'] = subdomain_name
                # Extract subdomain part (leftmost label)
                sd['subdomain_part'] = subdomain_name.split('.')[0]
            if 'source' in sd:
                # Normalize to uppercase for DB enum
                sd['sources'] = [sd.pop('source').upper()]
            if 'status' in sd:
                sd['status'] = sd['status'].upper()
            subdomain_objs.append(Subdomain(**sd))
        kwargs['subdomains'] = subdomain_objs
        # Normalize tools_used to uppercase if present
        if 'tools_used' in kwargs:
            kwargs['tools_used'] = [t.upper() for t in kwargs['tools_used']]
        return await self.create(**kwargs)


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