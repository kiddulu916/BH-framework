"""
Target repository for target management operations.

This module provides the TargetRepository class which handles
all database operations related to targets.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.target import Target, TargetStatus
from .base import BaseRepository


class TargetRepository(BaseRepository):
    """
    Repository for Target model operations.
    
    This repository provides methods for managing targets,
    including domain-specific queries and operations.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize the target repository."""
        super().__init__(session, Target)
    
    async def get_by_target_and_domain(self, target: str, domain: str) -> Optional[Target]:
        """
        Get target by target and domain (target, domain).
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            Target instance or None if not found
        """
        return await self.find_one({'target': target, 'domain': domain})
    
    async def get_by_target_and_domain(self, target: str, domain: str) -> Optional[Target]:
        """
        Get target by target and domain.
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            Target instance or None if not found
        """
        return await self.find_one({
            'target': target,
            'domain': domain
        })
    
    async def get_active_targets(self, target: str, domain: str) -> List[Target]:
        """
        Get all active targets.
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            List of active targets
        """
        filters = {'status': TargetStatus.ACTIVE}
        if target:
            filters['target'] = target
        if domain:
            filters['domain'] = domain
        
        return await self.list(filters=filters, order_by=['created_at'])
    
    async def get_targets_by_target_and_domain(self, target: str, domain: str) -> List[Target]:
        """
        Get all targets for a specific user.
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            List of targets for the user
        """
        return await self.list(filters={'target': target, 'domain': domain}, order_by=['created_at'])
    
    async def get_primary_targets(self, target: str, domain: str) -> List[Target]:
        """
        Get all primary targets.
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            List of primary targets
        """
        filters = {'is_primary': True}
        if target:
            filters['target'] = target
        if domain:
            filters['domain'] = domain
        
        return await self.list(filters=filters, order_by=['created_at'])
    
    async def get_targets_by_target_and_domain(self, target: str, domain: str) -> List[Target]:
        """
        Get all targets for a specific value (domain, IP, etc.).
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            List of targets for the value
        """
        return await self.list(filters={'target': target, 'domain': domain}, order_by=['created_at'])
    
    async def search_targets(self, search_term: str, target: str, domain: str) -> List[Target]:
        """
        Search targets by name or value.
        
        Args:
            search_term: Search term
            target: Target
            domain: Domain
            
        Returns:
            List of matching targets
        """
        from sqlalchemy import or_
        
        query = select(self.model_class).where(
            or_(
                self.model_class.name.ilike(f"%{search_term}%"),
                self.model_class.value.ilike(f"%{search_term}%")
            )
        )
        
        if target:
            query = query.where(self.model_class.target == target)
        if domain:
            query = query.where(self.model_class.domain == domain)
        
        query = query.order_by(self.model_class.created_at)
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def get_targets_with_results(self, target: str, domain: str) -> List[Target]:
        """
        Get targets that have associated results from any stage.
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            List of targets with results
        """
        query = select(self.model_class).options(
            selectinload(self.model_class.passive_recon_results),
            selectinload(self.model_class.active_recon_results),
            selectinload(self.model_class.vulnerabilities),
            selectinload(self.model_class.kill_chains),
            selectinload(self.model_class.reports)
        )
        
        if target:
            query = query.where(self.model_class.target == target)
        if domain:
            query = query.where(self.model_class.domain == domain)
        
        query = query.order_by(self.model_class.created_at)
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def get_target_statistics(self, target: str, domain: str) -> dict:
        """
        Get target statistics.
        
        Args:
            target: Target
            domain: Domain
            
        Returns:
            Dictionary with target statistics
        """
        filters = {}
        if target:
            filters['target'] = target
        if domain:
            filters['domain'] = domain
        
        total_targets = await self.count(filters)
        
        active_filters = {**filters, 'status': TargetStatus.ACTIVE}
        active_targets = await self.count(active_filters)
        
        primary_filters = {**filters, 'is_primary': True}
        primary_targets = await self.count(primary_filters)
        
        return {
            'total_targets': total_targets,
            'primary_targets': primary_targets,
        }
    
    async def list_with_pagination(self, target: str = None, domain: str = None, pagination=None, filters=None, search_expr=None) -> (List[Target], int):
        """
        List targets with pagination and filtering.
        
        Args:
            pagination: Pagination object
            filters: Dictionary of field filters
            search_expr: Search expression
            
        Returns:
            Tuple of (items, total_count)
        """
        # Use the base list method for pagination
        limit = getattr(pagination, 'per_page', 10) if pagination else 10
        offset = ((getattr(pagination, 'page', 1) - 1) * limit) if pagination else 0
        
        # Get items using base repository list method
        items = await self.list(
            limit=limit,
            offset=offset,
            filters=filters,
            order_by=['created_at']
        )
        
        # Count total with same filters
        total = await self.count(filters=filters)
        
        return items, total
    
    async def get_counts_by_status(self) -> dict:
        from sqlalchemy import func
        stmt = select(self.model_class.status, func.count(self.model_class.id)).group_by(self.model_class.status)
        result = await self.session.execute(stmt)
        return {str(row[0]): row[1] for row in result.all()}
    
    async def get_recent_targets(self, limit: int = 5) -> List[Target]:
        """
        Get the most recently created targets.
        Args:
            limit: Number of recent targets to return
        Returns:
            List of recent Target instances
        """
        query = select(self.model_class).order_by(self.model_class.created_at.desc()).limit(limit)
        result = await self.session.execute(query)
        return result.scalars().all() 