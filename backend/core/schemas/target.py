"""
Target schemas for target management.

This module provides Pydantic schemas for target-related operations,
including creation, updates, and responses.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict, field_validator

from .base import BaseModelSchema, TimestampedSchema, IDSchema, PaginationParams, PaginatedResponse
from ..models.target import TargetScope, TargetStatus, BugBountyPlatform


class RateLimitConfig(BaseModel):
    """Schema for rate limiting configuration."""
    
    requests_per_minute: Optional[int] = Field(None, ge=1, description="Maximum requests per minute")
    requests_per_hour: Optional[int] = Field(None, ge=1, description="Maximum requests per hour")
    requests_per_day: Optional[int] = Field(None, ge=1, description="Maximum requests per day")
    burst_limit: Optional[int] = Field(None, ge=1, description="Maximum concurrent requests")
    cooldown_period: Optional[int] = Field(None, ge=1, description="Cooldown period in seconds")


class CustomHeader(BaseModel):
    """Schema for custom header configuration."""
    
    name: str = Field(..., min_length=1, max_length=255, description="Header name")
    value: str = Field(..., min_length=1, max_length=1000, description="Header value")
    description: Optional[str] = Field(None, max_length=500, description="Header description")


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
    
    # Bug Bounty Program Information
    program_name: Optional[str] = Field(None, max_length=255, description="Bug bounty program name")
    platform: Optional[BugBountyPlatform] = Field(None, description="Bug bounty platform")
    program_description: Optional[str] = Field(None, description="Program description")
    contact_email: Optional[str] = Field(None, max_length=255, description="Contact email")
    contact_url: Optional[str] = Field(None, max_length=500, description="Program URL")
    
    # Scope Configuration
    approved_urls: Optional[List[str]] = Field(default=[], description="List of approved URLs")
    blacklisted_urls: Optional[List[str]] = Field(default=[], description="List of blacklisted URLs")
    scope_rules: Optional[List[str]] = Field(default=[], description="List of scope rules")
    restrictions: Optional[List[str]] = Field(default=[], description="List of restrictions")
    
    # Rate Limiting Configuration
    rate_limits: Optional[RateLimitConfig] = Field(None, description="Rate limiting configuration")
    
    # Custom Headers
    custom_headers: Optional[List[CustomHeader]] = Field(default=[], description="List of custom headers")
    
    # Additional Configuration
    special_instructions: Optional[str] = Field(None, description="Special instructions")
    notes: Optional[str] = Field(None, description="Additional notes")
    
    @field_validator('scope', mode='before')
    @classmethod
    def validate_scope(cls, v):
        """Convert scope string to proper enum value."""
        if isinstance(v, str):
            # Convert to lowercase and find the enum by value
            v_lower = v.lower()
            for scope in TargetScope:
                if scope.value == v_lower:
                    return scope
            # If not found by value, try by name (case-insensitive)
            for scope in TargetScope:
                if scope.name.lower() == v_lower:
                    return scope
        return v


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
    
    # Bug Bounty Program Information
    program_name: Optional[str] = Field(None, max_length=255, description="Bug bounty program name")
    platform: Optional[BugBountyPlatform] = Field(None, description="Bug bounty platform")
    program_description: Optional[str] = Field(None, description="Program description")
    contact_email: Optional[str] = Field(None, max_length=255, description="Contact email")
    contact_url: Optional[str] = Field(None, max_length=500, description="Program URL")
    
    # Scope Configuration
    approved_urls: Optional[List[str]] = Field(None, description="List of approved URLs")
    blacklisted_urls: Optional[List[str]] = Field(None, description="List of blacklisted URLs")
    scope_rules: Optional[List[str]] = Field(None, description="List of scope rules")
    restrictions: Optional[List[str]] = Field(None, description="List of restrictions")
    
    # Rate Limiting Configuration
    rate_limits: Optional[RateLimitConfig] = Field(None, description="Rate limiting configuration")
    
    # Custom Headers
    custom_headers: Optional[List[CustomHeader]] = Field(None, description="List of custom headers")
    
    # Additional Configuration
    special_instructions: Optional[str] = Field(None, description="Special instructions")
    
    @field_validator('scope', mode='before')
    @classmethod
    def validate_scope(cls, v):
        """Convert scope string to proper enum value."""
        if isinstance(v, str):
            # Convert to lowercase and find the enum by value
            v_lower = v.lower()
            for scope in TargetScope:
                if scope.value == v_lower:
                    return scope
            # If not found by value, try by name (case-insensitive)
            for scope in TargetScope:
                if scope.name.lower() == v_lower:
                    return scope
        return v


class TargetResponse(IDSchema, TimestampedSchema):
    """
    Schema for target response data.
    
    This schema defines the structure of target data returned by the API.
    """
    
    name: str = Field(..., description="Target name")
    scope: str = Field(..., description="Target scope type")
    value: str = Field(..., description="Target value (domain, IP, etc.)")
    status: str = Field(..., description="Target status")
    is_primary: bool = Field(..., description="Whether this is a primary target")
    scope_config: Optional[Dict[str, Any]] = Field(None, description="Scope-specific configuration")
    user_id: Optional[str] = Field(None, description="User ID")
    is_active: bool = Field(..., description="Whether the target is active")
    display_name: str = Field(..., description="Display name for the target")
    
    # Bug Bounty Program Information
    program_name: Optional[str] = Field(None, description="Bug bounty program name")
    platform: Optional[str] = Field(None, description="Bug bounty platform")
    program_description: Optional[str] = Field(None, description="Program description")
    contact_email: Optional[str] = Field(None, description="Contact email")
    contact_url: Optional[str] = Field(None, description="Program URL")
    
    # Scope Configuration
    approved_urls: Optional[List[str]] = Field(None, description="List of approved URLs")
    blacklisted_urls: Optional[List[str]] = Field(None, description="List of blacklisted URLs")
    scope_rules: Optional[List[str]] = Field(None, description="List of scope rules")
    restrictions: Optional[List[str]] = Field(None, description="List of restrictions")
    
    # Rate Limiting Configuration
    rate_limits: Optional[Dict[str, Any]] = Field(None, description="Rate limiting configuration")
    
    # Custom Headers
    custom_headers: Optional[List[Dict[str, Any]]] = Field(None, description="List of custom headers")
    
    # Additional Configuration
    special_instructions: Optional[str] = Field(None, description="Special instructions")
    notes: Optional[str] = Field(None, description="Additional notes")


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