"""
Active reconnaissance repositories.

This module provides the ActiveReconRepository, PortRepository, and ServiceRepository
classes which handle all database operations related to active reconnaissance.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.active_recon import ActiveReconResult, Port, Service
from .base import BaseRepository


class ActiveReconRepository(BaseRepository):
    """Repository for ActiveReconResult model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, ActiveReconResult)
    
    async def get_by_target(self, target_id: UUID) -> List[ActiveReconResult]:
        """Get all active recon results for a target."""
        return await self.list(filters={'target_id': target_id}, order_by=['created_at'])
    
    async def get_by_execution_id(self, execution_id: str) -> Optional[ActiveReconResult]:
        """Get active recon result by execution ID."""
        return await self.find_one({'execution_id': execution_id})


class PortRepository(BaseRepository):
    """Repository for Port model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, Port)
    
    async def get_by_active_recon_result(self, active_recon_result_id: UUID) -> List[Port]:
        """Get all ports for an active recon result."""
        return await self.list(filters={'active_recon_result_id': active_recon_result_id}, order_by=['port_number'])
    
    async def get_by_host(self, host: str) -> List[Port]:
        """Get all ports for a host."""
        return await self.list(filters={'host': host}, order_by=['port_number'])
    
    async def get_open_ports(self, host: str) -> List[Port]:
        """Get all open ports for a host."""
        return await self.list(filters={'host': host, 'is_open': True}, order_by=['port_number'])


class ServiceRepository(BaseRepository):
    """Repository for Service model operations."""
    
    def __init__(self, session: AsyncSession):
        super().__init__(session, Service)
    
    async def get_by_port(self, port_id: UUID) -> List[Service]:
        """Get all services for a port."""
        return await self.list(filters={'port_id': port_id}, order_by=['name'])
    
    async def get_by_active_recon_result(self, active_recon_result_id: UUID) -> List[Service]:
        """Get all services for an active recon result."""
        return await self.list(filters={'active_recon_result_id': active_recon_result_id}, order_by=['name'])
    
    async def get_by_name(self, name: str) -> List[Service]:
        """Get all services by name."""
        return await self.list(filters={'name': name}, order_by=['created_at']) 