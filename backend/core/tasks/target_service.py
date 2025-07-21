"""
Target service for the Bug Hunting Framework.

This module contains business logic for target management operations,
including CRUD operations, validation, and target-related functionality.
"""

from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.inspection import inspect

from core.models.target import Target
from core.repositories.target import TargetRepository
from core.schemas.target import TargetCreate, TargetUpdate, TargetResponse, TargetListResponse
from core.schemas.base import PaginationParams
from core.utils.exceptions import NotFoundError, ValidationError


class TargetService:
    """Service class for target management operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the target service with a database session."""
        self.session = session
        self.repository = TargetRepository(session)
    
    async def create_target(self, payload: TargetCreate) -> TargetResponse:
        """
        Create a new target.
        
        Args:
            payload: Target creation data
            
        Returns:
            Created target response
            
        Raises:
            ValidationError: If target data is invalid
        """
        # Validate domain format
        if not self._is_valid_domain(payload.value):
            raise ValidationError(f"Invalid domain format: {payload.value}")
        
        # Check if target already exists
        existing_target = await self.repository.get_by_value(payload.value)
        if existing_target:
            raise ValidationError(f"Target with value {payload.value} already exists")
        
        # Convert scope and status to Enum if provided as strings
        create_data = payload.model_dump()
        
        if isinstance(create_data.get("scope"), str):
            from core.models.target import TargetScope
            # Find enum by value, not by name
            scope_value = create_data["scope"]
            for scope_enum in TargetScope:
                if scope_enum.value == scope_value:
                    create_data["scope"] = scope_enum
                    break
            else:
                raise ValidationError(f"Invalid scope value: {scope_value}")
        
        if "status" in create_data and isinstance(create_data["status"], str):
            from core.models.target import TargetStatus
            # Find enum by value, not by name
            status_value = create_data["status"]
            for status_enum in TargetStatus:
                if status_enum.value == status_value:
                    create_data["status"] = status_enum
                    break
            else:
                raise ValidationError(f"Invalid status value: {status_value}")
        
        # Create target
        target = await self.repository.create(**create_data)
        return TargetResponse.model_validate(target, from_attributes=True)
    
    async def get_target_by_id(self, target_id: UUID) -> Optional[TargetResponse]:
        """
        Get a target by its ID.
        
        Args:
            target_id: Target UUID
            
        Returns:
            Target response or None if not found
        """
        target = await self.repository.get_by_id(target_id)
        if not target:
            return None
        return TargetResponse.model_validate(target, from_attributes=True)
    
    async def list_targets(
        self,
        pagination: PaginationParams,
        search: Optional[str] = None,
        status: Optional[str] = None,
        value: Optional[str] = None
    ) -> Tuple[List[TargetResponse], int]:
        """
        List targets with filtering and pagination.
        
        Args:
            pagination: Pagination parameters
            search: Search term for domain or description
            status: Filter by target status
            value: Filter by target value
            
        Returns:
            Tuple of (targets, total_count)
        """
        filters = {}
        if value:
            filters["value"] = value
        if status:
            filters["status"] = status
        # For search, use SQLAlchemy or_ expression
        search_expr = None
        if search:
            search_expr = or_(Target.value.ilike(f"%{search}%"), Target.description.ilike(f"%{search}%"))
        # Get targets with pagination
        if search_expr:
            # If search, pass as a special filter (repository may need to handle this)
            targets, total = await self.repository.list_with_pagination(
                pagination=pagination,
                filters=filters,
                search_expr=search_expr
            )
        else:
            targets, total = await self.repository.list_with_pagination(
                pagination=pagination,
                filters=filters
            )
        
        # Convert to response models
        target_responses = [TargetResponse.model_validate(target, from_attributes=True) for target in targets]
        
        return target_responses, total
    
    async def update_target(self, target_id: UUID, payload: TargetUpdate) -> TargetResponse:
        """
        Update an existing target.
        
        Args:
            target_id: Target UUID
            payload: Update data
            
        Returns:
            Updated target response
            
        Raises:
            NotFoundError: If target not found
            ValidationError: If update data is invalid
        """
        # Check if target exists
        target = await self.repository.get_by_id(target_id)
        if not target:
            raise NotFoundError(f"Target with ID {target_id} not found")
        
        # Validate domain if provided
        if hasattr(payload, 'value') and payload.value and not self._is_valid_domain(payload.value):
            raise ValidationError(f"Invalid domain format: {payload.value}")
        
        # Check for domain conflicts if domain is being updated
        if hasattr(payload, 'value') and payload.value and payload.value != target.value:
            existing_target = await self.repository.get_by_value(payload.value)
            if existing_target:
                raise ValidationError(f"Target with value {payload.value} already exists")
        
        # Update target
        update_data = payload.model_dump(exclude_unset=True)
        existing_data = target.__dict__.copy()
        existing_data.update(update_data)
        model_columns = set(c.key for c in inspect(target).mapper.column_attrs)
        filtered_data = {k: v for k, v in existing_data.items() if k in model_columns}
        filtered_data["updated_at"] = datetime.now(timezone.utc)
        # Convert scope and status to Enum if provided as strings
        if isinstance(filtered_data.get("scope"), str):
            from core.models.target import TargetScope
            # Find enum by value, not by name
            scope_value = filtered_data["scope"]
            for scope_enum in TargetScope:
                if scope_enum.value == scope_value:
                    filtered_data["scope"] = scope_enum
                    break
            else:
                raise ValidationError(f"Invalid scope value: {scope_value}")
        if "status" in filtered_data and isinstance(filtered_data["status"], str):
            from core.models.target import TargetStatus
            # Find enum by value, not by name
            status_value = filtered_data["status"]
            for status_enum in TargetStatus:
                if status_enum.value == status_value:
                    filtered_data["status"] = status_enum
                    break
            else:
                raise ValidationError(f"Invalid status value: {status_value}")
        # Remove 'id' if present to avoid multiple values for 'id'
        filtered_data.pop("id", None)
        updated_target = await self.repository.update(target_id, **filtered_data)
        return TargetResponse.model_validate(updated_target, from_attributes=True)
    
    async def delete_target(self, target_id: UUID) -> bool:
        """
        Delete a target and all associated data.
        
        Args:
            target_id: Target UUID
            
        Returns:
            True if deleted successfully
            
        Raises:
            NotFoundError: If target not found
        """
        # Check if target exists
        target = await self.repository.get_by_id(target_id)
        if not target:
            raise NotFoundError(f"Target with ID {target_id} not found")
        
        # Delete target (this will cascade to related data)
        await self.repository.delete(target_id)
        return True
    
    async def get_target_summary(self, target_id: UUID) -> Dict[str, Any]:
        """
        Get a comprehensive summary of target information.
        
        Args:
            target_id: Target UUID
            
        Returns:
            Target summary data
            
        Raises:
            NotFoundError: If target not found
        """
        # Check if target exists
        target = await self.repository.get_by_id(target_id)
        if not target:
            raise NotFoundError(f"Target with ID {target_id} not found")
        
        # Get related data counts
        summary = {
            "target": TargetResponse.model_validate(target, from_attributes=True).model_dump(),
            "statistics": {
                "passive_recon_results": 0,  # TODO: Add when repositories are implemented
                "active_recon_results": 0,
                "vulnerability_findings": 0,
                "kill_chain_paths": 0,
                "reports": 0,
                "workflows": 0
            },
            "last_activity": target.updated_at,
            "status": target.status,
            "created_at": target.created_at,
            "updated_at": target.updated_at
        }
        
        return summary
    
    async def validate_target(self, target_id: UUID) -> Dict[str, Any]:
        """
        Validate target configuration and connectivity.
        
        Args:
            target_id: Target UUID
            
        Returns:
            Validation results
            
        Raises:
            NotFoundError: If target not found
        """
        # Check if target exists
        target = await self.repository.get_by_id(target_id)
        if not target:
            raise NotFoundError(f"Target with ID {target_id} not found")
        
        # Perform validation checks
        validation_results = {
            "target_id": str(target_id),
            "value": target.value,
            "checks": {
                "domain_format": self._is_valid_domain(target.value),
                "domain_resolution": await self._check_domain_resolution(target.value),
                "scope_validation": self._validate_scope(target.scope)
            },
            "overall_valid": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Determine overall validity
        validation_results["overall_valid"] = all(validation_results["checks"].values())
        
        return validation_results
    
    async def get_targets_overview(self) -> Dict[str, Any]:
        """
        Get overview statistics for all targets.
        """
        # Get basic counts
        total_targets = await self.repository.count()
        # Get targets by status
        status_counts = await self.repository.get_counts_by_status()
        # Map status keys to lowercase for explicit keys
        mapped_status = {k.lower().replace('targetstatus.', ''): v for k, v in status_counts.items()}
        active_targets = mapped_status.get('active', 0)
        inactive_targets = mapped_status.get('inactive', 0)
        primary_targets = await self.repository.count({'is_primary': True})
        overview = {
            "total_targets": total_targets,
            "active_targets": active_targets,
            "inactive_targets": inactive_targets,
            "primary_targets": primary_targets,
            "status_distribution": status_counts,
            "targets_by_status": status_counts,
            "recent_targets": [TargetResponse.model_validate(target, from_attributes=True).model_dump() for target in await self.repository.get_recent_targets(limit=5)],
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        return overview
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or '.' not in domain:
            return False
        
        # Basic domain validation
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # Check each part
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not part.replace('-', '').isalnum():
                return False
        
        return True
    
    async def _check_domain_resolution(self, domain: str) -> bool:
        """
        Check if domain resolves to IP addresses.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain resolves, False otherwise
        """
        try:
            import socket
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.herror):
            return False
    
    async def _validate_ip_addresses(self, ip_addresses: List[str]) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip_addresses: List of IP addresses to validate
            
        Returns:
            True if all IPs are valid, False otherwise
        """
        import ipaddress
        
        for ip in ip_addresses:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return False
        
        return True
    
    def _validate_scope(self, scope: Dict[str, Any]) -> bool:
        """
        Validate target scope configuration.
        
        Args:
            scope: Scope configuration to validate
            
        Returns:
            True if scope is valid, False otherwise
        """
        if not isinstance(scope, dict):
            return False
        
        # Add scope-specific validation logic here
        return True 