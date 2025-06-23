"""
Target repository for target management operations.

This module provides the TargetRepository class which handles
all database operations related to targets.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.target import Target, TargetScope, TargetStatus
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
    
    async def get_by_value(self, value: str) -> Optional[Target]:
        """
        Get target by value (domain, IP, etc.).
        
        Args:
            value: Target value (domain, IP, etc.)
            
        Returns:
            Target instance or None if not found
        """
        return await self.find_one({'value': value})
    
    async def get_by_scope_and_value(self, scope: TargetScope, value: str) -> Optional[Target]:
        """
        Get target by scope and value.
        
        Args:
            scope: Target scope
            value: Target value (domain, IP, etc.)
            
        Returns:
            Target instance or None if not found
        """
        return await self.find_one({
            'scope': scope,
            'value': value
        })
    
    async def get_active_targets(self, user_id: Optional[UUID] = None) -> List[Target]:
        """
        Get all active targets.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            List of active targets
        """
        filters = {'status': TargetStatus.ACTIVE}
        if user_id:
            filters['user_id'] = user_id
        
        return await self.list(filters=filters, order_by=['created_at'])
    
    async def get_targets_by_user(self, user_id: UUID) -> List[Target]:
        """
        Get all targets for a specific user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of targets for the user
        """
        return await self.list(filters={'user_id': user_id}, order_by=['created_at'])
    
    async def get_primary_targets(self, user_id: Optional[UUID] = None) -> List[Target]:
        """
        Get all primary targets.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            List of primary targets
        """
        filters = {'is_primary': True}
        if user_id:
            filters['user_id'] = user_id
        
        return await self.list(filters=filters, order_by=['created_at'])
    
    async def get_targets_by_value(self, value: str) -> List[Target]:
        """
        Get all targets for a specific value (domain, IP, etc.).
        
        Args:
            value: Target value (domain, IP, etc.)
            
        Returns:
            List of targets for the value
        """
        return await self.list(filters={'value': value}, order_by=['created_at'])
    
    async def search_targets(self, search_term: str, user_id: Optional[UUID] = None) -> List[Target]:
        """
        Search targets by name or value.
        
        Args:
            search_term: Search term
            user_id: Optional user ID to filter by
            
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
        
        if user_id:
            query = query.where(self.model_class.user_id == user_id)
        
        query = query.order_by(self.model_class.created_at)
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def get_targets_with_results(self, user_id: Optional[UUID] = None) -> List[Target]:
        """
        Get targets that have associated results from any stage.
        
        Args:
            user_id: Optional user ID to filter by
            
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
        
        if user_id:
            query = query.where(self.model_class.user_id == user_id)
        
        query = query.order_by(self.model_class.created_at)
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def get_target_statistics(self, user_id: Optional[UUID] = None) -> dict:
        """
        Get target statistics.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            Dictionary with target statistics
        """
        filters = {}
        if user_id:
            filters['user_id'] = user_id
        
        total_targets = await self.count(filters)
        
        active_filters = {**filters, 'status': TargetStatus.ACTIVE}
        active_targets = await self.count(active_filters)
        
        primary_filters = {**filters, 'is_primary': True}
        primary_targets = await self.count(primary_filters)
        
        return {
            'total_targets': total_targets,
            'active_targets': active_targets,
            'primary_targets': primary_targets,
            'inactive_targets': total_targets - active_targets,
        } 