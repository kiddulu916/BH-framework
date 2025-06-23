"""
User schemas for user management.

This module provides Pydantic schemas for user-related operations,
including creation, updates, and responses.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict

from .base import BaseModelSchema, TimestampedSchema, IDSchema, PaginationParams, PaginatedResponse


class UserCreate(BaseModelSchema):
    """
    Schema for creating a new user.
    
    This schema validates the data required to create a new user.
    """
    
    name: str = Field(..., min_length=1, max_length=255, description="User name")
    email: Optional[str] = Field(None, description="User email address")
    platform: Optional[str] = Field(None, max_length=100, description="Bug bounty platform")
    platform_username: Optional[str] = Field(None, max_length=255, description="Username on the platform")
    preferences: Optional[Dict[str, Any]] = Field(None, description="User preferences and settings")


class UserUpdate(BaseModelSchema):
    """
    Schema for updating an existing user.
    
    This schema validates the data that can be updated for a user.
    """
    
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="User name")
    email: Optional[str] = Field(None, description="User email address")
    is_active: Optional[bool] = Field(None, description="Whether user is active")
    platform: Optional[str] = Field(None, max_length=100, description="Bug bounty platform")
    platform_username: Optional[str] = Field(None, max_length=255, description="Username on the platform")
    preferences: Optional[Dict[str, Any]] = Field(None, description="User preferences and settings")
    notes: Optional[str] = Field(None, description="Additional notes")


class UserResponse(IDSchema, TimestampedSchema):
    """
    Schema for user response data.
    
    This schema defines the structure of user data returned by API endpoints.
    """
    
    name: str = Field(..., description="User name")
    email: Optional[str] = Field(None, description="User email address")
    is_active: bool = Field(..., description="Whether user is active")
    platform: Optional[str] = Field(None, description="Bug bounty platform")
    platform_username: Optional[str] = Field(None, description="Username on the platform")
    preferences: Optional[Dict[str, Any]] = Field(None, description="User preferences and settings")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    session_data: Optional[Dict[str, Any]] = Field(None, description="Session-specific data")
    notes: Optional[str] = Field(None, description="Additional notes")
    
    # Computed properties
    display_name: str = Field(..., description="Display name for the user")


class UserListResponse(PaginatedResponse):
    """
    Schema for paginated user list response.
    
    This schema wraps a list of users with pagination metadata.
    """
    
    items: List[UserResponse] = Field(..., description="List of users")


class UserFilters(BaseModelSchema):
    """
    Schema for user filtering parameters.
    
    This schema defines the parameters that can be used to filter users.
    """
    
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    platform: Optional[str] = Field(None, description="Filter by platform")
    search: Optional[str] = Field(None, description="Search term for name or email")


class UserStatistics(BaseModelSchema):
    """
    Schema for user statistics.
    
    This schema defines the structure of user statistics data.
    """
    
    total_users: int = Field(..., description="Total number of users")
    active_users: int = Field(..., description="Number of active users")
    inactive_users: int = Field(..., description="Number of inactive users") 