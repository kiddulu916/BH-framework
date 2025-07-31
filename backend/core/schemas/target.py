"""
Target schemas for target management.

This module provides Pydantic schemas for target-related operations,
including creation, updates, and responses.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict, field_validator

from .base import BaseModelSchema, TimestampedSchema, IDSchema, PaginationParams, PaginatedResponse
from ..models.target import TargetStatus, BugBountyPlatform


class RateLimitConfig(BaseModel):
    """Schema for rate limiting configuration."""
    
    requests_per_second: Optional[int] = Field(None, ge=0, description="Maximum requests per second")
    requests_per_minute: Optional[int] = Field(None, ge=0, description="Maximum requests per minute")

class CustomHeader(BaseModel):
    """Schema for custom header configuration."""
    
    name: str = Field(..., min_length=1, max_length=255, description="Header name")
    value: str = Field(..., min_length=1, max_length=1000, description="Header value")
    description: Optional[str] = Field(None, max_length=500, description="Header description")


# ====================================
# Creation & update payload schemas
# ====================================

# An optional client-supplied UUID is permitted. If omitted, the DB will
# generate one via default=uuid4 on the Target model.

class TargetCreate(BaseModelSchema):
    """
    Schema for creating a new target.
    
    This schema validates the data required to create a new target.
    Updated to match frontend data structure.
    """
    
    # Basic target information
    id: UUID | None = Field(None, description="Optional client-supplied UUID for the target")
    target: str = Field(..., min_length=1, max_length=255, description="Target name")
    domain: str = Field(..., min_length=1, max_length=500, description="Target domain/IP")
    is_primary: bool = Field(False, description="Whether this is a primary target")


    # Bug Bounty Program Information
    platform: Optional[BugBountyPlatform] = Field(None, description="Bug bounty platform")
    login_email: Optional[str] = Field(None, max_length=255, description="Login email (frontend field)")
    researcher_email: Optional[str] = Field(None, max_length=255, description="Researcher email (frontend field)")
    
    # Scope Configuration
    in_scope: Optional[List[str]] = Field(default=[], description="In-scope URLs (frontend field)")
    out_of_scope: Optional[List[str]] = Field(default=[], description="Out-of-scope URLs (frontend field)")
    
    # Rate Limiting Configuration
    rate_limit_requests: Optional[int] = Field(None, ge=0, description="Rate limit requests (frontend field)")
    rate_limit_seconds: Optional[int] = Field(None, ge=0, description="Rate limit seconds (frontend field)")
    
    # Custom Headers
    custom_headers: Optional[List[CustomHeader]] = Field(default=[], description="List of custom headers")
    
    # Additional Configuration
    additional_info: Optional[List[str]] = Field(default=[], description="Additional information (frontend field)")
    notes: Optional[List[str]] = Field(default=[], description="Additional notes")

    # Legacy fields sent by old frontend builds – accepted and ignored
    name: Optional[str] = Field(None, description="(Deprecated) legacy field – ignored")
    scope: Optional[str] | None = Field(None, description="(Deprecated) legacy field – ignored")
    rate_limits: Optional[dict] = Field(None, description="(Deprecated) legacy field – ignored")


class TargetUpdate(BaseModelSchema):
    id: UUID | None = Field(None, description="Optional UUID; ignored if it does not match persisted id")
    """
    Schema for updating an existing target.
    
    This schema validates the data that can be updated for a target.
    Updated to match frontend data structure.
    """
    
    # Basic target information
    target: Optional[str] = Field(None, min_length=1, max_length=255, description="Target name (legacy field)")
    domain: Optional[str] = Field(None, min_length=1, max_length=500, description="Target domain/IP")
    is_primary: Optional[bool] = Field(None, description="Whether this is a primary target")
    status: Optional[TargetStatus] = Field(None, description="Target status")
    
    # Bug Bounty Program Information
    platform: Optional[BugBountyPlatform] = Field(None, description="Bug bounty platform")
    login_email: Optional[str] = Field(None, max_length=255, description="Login email (frontend field)")
    researcher_email: Optional[str] = Field(None, max_length=255, description="Researcher email (frontend field)")
    
    # Scope Configuration
    in_scope: Optional[List[str]] = Field(None, description="In-scope URLs (frontend field)")
    out_of_scope: Optional[List[str]] = Field(None, description="Out-of-scope URLs (frontend field)")
    
    # Rate Limiting Configuration
    rate_limit_requests: Optional[int] = Field(None, ge=0, description="Rate limit requests (frontend field)")
    rate_limit_seconds: Optional[int] = Field(None, ge=0, description="Rate limit seconds (frontend field)")
    
    # Custom Headers
    custom_headers: Optional[List[CustomHeader]] = Field(None, description="List of custom headers")
    
    # Additional Configuration
    additional_info: Optional[List[str]] = Field(None, description="Additional information (frontend field)")
    notes: Optional[List[str]] = Field(None, description="Additional notes")

    # Legacy fields – optional and ignored
    name: Optional[str] = Field(None, description="(Deprecated) legacy field – ignored")
    scope: Optional[str] | None = Field(None, description="(Deprecated) legacy field – ignored")
    rate_limits: Optional[dict] = Field(None, description="(Deprecated) legacy field – ignored")


class TargetResponse(IDSchema, TimestampedSchema):
    """
    Schema for target response data.
    
    This schema defines the structure of target data returned by the API.
    Updated to match frontend data structure.
    """
    
    target: Optional[str] = Field(None, description="Target name (legacy field)")
    domain: Optional[str] = Field(None, description="Target domain/IP")
    is_primary: bool = Field(False, description="Whether this is a primary target")
    status: str = Field(..., description="Target status")
    
    # Bug Bounty Program Information
    platform: Optional[str] = Field(None, description="Bug bounty platform")
    login_email: Optional[str] = Field(None, description="Login email (frontend field)")
    researcher_email: Optional[str] = Field(None, description="Researcher email (frontend field)")
    
    # Scope Configuration
    in_scope: Optional[List[str]] = Field(None, description="In-scope URLs (frontend field)")
    out_of_scope: Optional[List[str]] = Field(None, description="Out-of-scope URLs (frontend field)")
    
    # Rate Limiting Configuration
    rate_limit_requests: Optional[int] = Field(None, description="Rate limit requests (frontend field)")
    rate_limit_seconds: Optional[int] = Field(None, description="Rate limit seconds (frontend field)")
    
    # Custom Headers
    custom_headers: Optional[List[Dict[str, Any]]] = Field(None, description="List of custom headers")
    
    # Additional Configuration
    additional_info: Optional[List[str]] = Field(None, description="Additional information (frontend field)")
    notes: Optional[List[str]] = Field(None, description="Additional notes")

    # --- validators ---------------------------------------------------

    @field_validator("notes", mode="before")
    @classmethod
    def _coerce_notes(cls, v):
        """Allow DB to return notes as newline-separated string or JSON list."""
        if v is None:
            return None
        if isinstance(v, str):
            # split on newlines, strip blanks
            return [line.strip() for line in v.splitlines() if line.strip()]
        return v


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
    
    status: Optional[TargetStatus] = Field(None, description="Filter by status")
    is_primary: Optional[bool] = Field(None, description="Filter by primary status")
    search: Optional[str] = Field(None, description="Search term for name or value")


class TargetStatistics(BaseModelSchema):
    """
    Schema for target statistics.
    
    This schema defines the structure of target statistics data.
    """
    
    total_targets: int = Field(..., description="Total number of targets")
    primary_targets: int = Field(..., description="Number of primary targets")

class TargetCreateRequest(TargetCreate):
    """Alias for target creation request schema."""


class TargetUpdateRequest(TargetUpdate):
    """Alias for target update request schema.""" 