"""
Target schemas for target management.

This module provides Pydantic schemas for target-related operations,
including creation, updates, and responses.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict

from .base import BaseModelSchema, TimestampedSchema, IDSchema, PaginationParams, PaginatedResponse
from ..models.target import TargetScope, TargetStatus


class TargetCreate(BaseModelSchema):
    """
    Schema for creating a new target.
    
    This schema validates the data required to create a new target.
    """
    
    name: str = Field(..., min_length=1, max_length=255, description="Target name")
    scope: TargetScope = Field(..., description="Target scope type")
    value: str = Field(..., min_length=1, max_length=500, description="Target value (domain, IP, etc.)")
    description: Optional[str] = Field(None, description="Target description")
    is_primary: bool = Field(False, description="Whether this is a primary target")
    scope_config: Optional[Dict[str, Any]] = Field(None, description="Scope-specific configuration")
    user_id: Optional[UUID] = Field(None, description="User ID (optional)")


class TargetUpdate(BaseModelSchema):
    """
    Schema for updating an existing target.
    
    This schema validates the data that can be updated for a target.
    """
    
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Target name")
    value: Optional[str] = Field(None, min_length=1, max_length=500, description="Target value (domain, IP, etc.)")
    scope: Optional[TargetScope] = Field(None, description="Target scope type")
    description: Optional[str] = Field(None, description="Target description")
    status: Optional[TargetStatus] = Field(None, description="Target status")
    is_primary: Optional[bool] = Field(None, description="Whether this is a primary target")
    scope_config: Optional[Dict[str, Any]] = Field(None, description="Scope-specific configuration")
    notes: Optional[str] = Field(None, description="Additional notes")


class TargetResponse(IDSchema, TimestampedSchema):
    """
    Schema for target response data.
    
    This schema defines the structure of target data returned by API endpoints.
    """
    
    name: str = Field(..., description="Target name")
    scope: TargetScope = Field(..., description="Target scope type")
    value: str = Field(..., description="Target value")
    status: TargetStatus = Field(..., description="Target status")
    is_primary: bool = Field(..., description="Whether this is a primary target")
    description: Optional[str] = Field(None, description="Target description")
    scope_config: Optional[Dict[str, Any]] = Field(None, description="Scope-specific configuration")
    notes: Optional[str] = Field(None, description="Additional notes")
    user_id: Optional[UUID] = Field(None, description="User ID")
    
    # Computed properties
    is_active: bool = Field(..., description="Whether target is active")
    display_name: str = Field(..., description="Display name for the target")


class TargetListResponse(PaginatedResponse):
    """
    Schema for paginated target list response.
    
    This schema wraps a list of targets with pagination metadata.
    """
    
    items: List[TargetResponse] = Field(..., description="List of targets")


class TargetFilters(BaseModelSchema):
    """
    Schema for target filtering parameters.
    
    This schema defines the parameters that can be used to filter targets.
    """
    
    scope: Optional[TargetScope] = Field(None, description="Filter by scope")
    status: Optional[TargetStatus] = Field(None, description="Filter by status")
    is_primary: Optional[bool] = Field(None, description="Filter by primary status")
    user_id: Optional[UUID] = Field(None, description="Filter by user ID")
    search: Optional[str] = Field(None, description="Search term for name or value")


class TargetStatistics(BaseModelSchema):
    """
    Schema for target statistics.
    
    This schema defines the structure of target statistics data.
    """
    
    total_targets: int = Field(..., description="Total number of targets")
    active_targets: int = Field(..., description="Number of active targets")
    primary_targets: int = Field(..., description="Number of primary targets")
    inactive_targets: int = Field(..., description="Number of inactive targets")


class TargetCreateRequest(TargetCreate):
    """Alias for target creation request schema."""


class TargetUpdateRequest(TargetUpdate):
    """Alias for target update request schema.""" 