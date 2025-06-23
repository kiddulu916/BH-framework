"""
Base Pydantic schemas for the Bug Hunting Framework.

This module provides base schemas used throughout the application,
including the standardized APIResponse model and common utilities.
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class APIResponse(BaseModel):
    """
    Standardized API response model for all endpoints.
    
    This model ensures consistent response structure across all API endpoints,
    following the established pattern for success and error responses.
    """
    
    success: bool = Field(..., description="Whether the request was successful")
    message: str = Field(..., description="Human-readable message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data for success cases")
    errors: Optional[List[str]] = Field(None, description="List of error messages for failure cases")

    @classmethod
    def success_response(cls, message: str, data: Optional[Dict[str, Any]] = None) -> "APIResponse":
        """Create a success response."""
        return cls(
            success=True,
            message=message,
            data=data,
            errors=None
        )
    
    @classmethod
    def error_response(cls, message: str, errors: Optional[List[str]] = None) -> "APIResponse":
        """Create an error response."""
        if errors is None:
            errors = [message]
        return cls(
            success=False,
            message=message,
            data=None,
            errors=errors
        )


class PaginationParams(BaseModel):
    """
    Pagination parameters for list endpoints.
    
    This model provides standardized pagination parameters
    that can be used across all list endpoints.
    """
    
    page: int = Field(1, ge=1, description="Page number (1-based)")
    page_size: int = Field(10, ge=1, le=100, description="Number of items per page")
    
    @property
    def offset(self) -> int:
        """Calculate the offset for database queries."""
        return (self.page - 1) * self.page_size
    
    @property
    def limit(self) -> int:
        """Get the limit for database queries."""
        return self.page_size


class PaginatedResponse(BaseModel):
    """
    Paginated response wrapper.
    
    This model wraps paginated data with metadata about
    the pagination state.
    """
    
    items: List[Dict[str, Any]] = Field(..., description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_prev: bool = Field(..., description="Whether there is a previous page")

    @classmethod
    def create(
        cls,
        items: List[Dict[str, Any]],
        total: int,
        pagination: PaginationParams
    ) -> "PaginatedResponse":
        """Create a paginated response."""
        total_pages = (total + pagination.page_size - 1) // pagination.page_size
        
        return cls(
            items=items,
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=total_pages,
            has_next=pagination.page < total_pages,
            has_prev=pagination.page > 1
        )


class BaseModelSchema(BaseModel):
    """
    Base schema with common configuration.
    
    This base class provides common configuration for all schemas,
    including JSON encoders and validation settings.
    """
    
    model_config = ConfigDict(
        from_attributes=True,
        validate_assignment=True,
        extra="forbid"
    )


class TimestampedSchema(BaseModelSchema):
    """
    Base schema for models with timestamps.
    
    This base class provides common timestamp fields
    for models that include created_at and updated_at.
    """
    
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")


class IDSchema(BaseModelSchema):
    """
    Base schema for models with ID.
    
    This base class provides common ID field
    for models that include an ID.
    """
    
    id: UUID = Field(..., description="Unique identifier") 