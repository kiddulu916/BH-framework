"""
Passive reconnaissance repositories.

This module provides the PassiveReconRepository and SubdomainRepository
classes which handle all database operations related to passive reconnaissance.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.future import select
from sqlalchemy import func

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
        Normalize enum fields to lowercase for DB compatibility.
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
                raw_source = sd.pop('source')
                # If the source contains a dot, take the part after the last dot
                tool_name = raw_source.split('.')[-1].lower()
                sd['sources'] = [tool_name]
            if 'status' in sd:
                status_value = sd['status']
                from ..models.passive_recon import SubdomainStatus
                if isinstance(status_value, SubdomainStatus):
                    sd['status'] = status_value
                else:
                    # Convert string to SubdomainStatus enum
                    sd['status'] = SubdomainStatus(str(status_value).lower())
            subdomain_objs.append(Subdomain(**sd))
        kwargs['subdomains'] = subdomain_objs
        # Normalize tools_used to lowercase if present
        if 'tools_used' in kwargs:
            kwargs['tools_used'] = [t.lower() for t in kwargs['tools_used']]
        return await self.create(**kwargs)

    async def get_by_workflow_id(self, workflow_id: UUID):
        """Get all passive recon results for a workflow ID with subdomains preloaded."""
        stmt = (
            select(PassiveReconResult)
            .options(selectinload(PassiveReconResult.subdomains))
            .where(PassiveReconResult.execution_id == str(workflow_id))
            .order_by(PassiveReconResult.created_at)
        )
        
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_target_with_pagination(self, target_id: UUID, page: int = 1, per_page: int = 10):
        """
        Return paginated passive recon results for a target, ordered by created_at descending.
        Returns (items, total_count)
        """
        offset = (page - 1) * per_page
        stmt = (
            select(PassiveReconResult)
            .options(selectinload(PassiveReconResult.subdomains))
            .where(PassiveReconResult.target_id == target_id)
            .order_by(PassiveReconResult.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )
        result = await self.session.execute(stmt)
        items = result.scalars().all()
        # Get total count efficiently
        count_stmt = select(func.count()).where(PassiveReconResult.target_id == target_id)
        count_result = await self.session.execute(count_stmt)
        total_count = count_result.scalar_one()
        return items, total_count


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