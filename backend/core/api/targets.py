"""
Target management API endpoints for the Bug Hunting Framework.

This module contains Django Ninja API endpoints for target management,
including CRUD operations for targets and related functionality.
"""

from typing import List, Optional
from uuid import UUID

from ninja import Router
from django.http import HttpRequest

from core.schemas.target import (
    TargetCreate, TargetUpdate, TargetResponse, TargetListResponse,
    TargetFilters, TargetStatistics
)
from core.schemas.base import APIResponse, PaginationParams
from core.tasks.target_service import TargetService
from core.utils.database import get_db_session

router = Router()


@router.post("/", response=APIResponse, summary="Create a new target")
async def create_target(request: HttpRequest, payload: TargetCreate):
    """
    Create a new target for bug hunting.
    
    This endpoint allows creating a new target with domain, IP addresses, and scope information.
    The target will be used for all subsequent bug hunting stages.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            target = await target_service.create_target(payload)
            
            return APIResponse(
                success=True,
                message="Target created successfully",
                data=target,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to create target",
            data=None,
            errors=[str(e)]
        )


@router.get("/", response=APIResponse, summary="List all targets")
async def list_targets(
    request: HttpRequest,
    page: int = 1,
    per_page: int = 10,
    search: Optional[str] = None,
    status: Optional[str] = None
):
    """
    List all targets with optional filtering and pagination.
    
    Supports filtering by search term and status, with pagination support.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            
            # Create pagination params
            pagination = PaginationParams(page=page, per_page=per_page)
            
            # Get targets with filters
            targets, total = await target_service.list_targets(
                pagination=pagination,
                search=search,
                status=status
            )
            
            # Create response
            target_list = TargetListResponse(
                targets=targets,
                total=total,
                page=page,
                per_page=per_page
            )
            
            return APIResponse(
                success=True,
                message="Targets retrieved successfully",
                data=target_list,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve targets",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}", response=APIResponse, summary="Get target by ID")
async def get_target(request: HttpRequest, target_id: UUID):
    """
    Get a specific target by its ID.
    
    Returns detailed information about the target including all associated data.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            target = await target_service.get_target_by_id(target_id)
            
            if not target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    data=None,
                    errors=[f"Target with ID {target_id} not found"]
                )
            
            return APIResponse(
                success=True,
                message="Target retrieved successfully",
                data=target,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve target",
            data=None,
            errors=[str(e)]
        )


@router.put("/{target_id}", response=APIResponse, summary="Update target")
async def update_target(request: HttpRequest, target_id: UUID, payload: TargetUpdate):
    """
    Update an existing target.
    
    Allows updating target information including domain, IP addresses, scope, and status.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            
            # Check if target exists
            existing_target = await target_service.get_target_by_id(target_id)
            if not existing_target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    data=None,
                    errors=[f"Target with ID {target_id} not found"]
                )
            
            # Update target
            updated_target = await target_service.update_target(target_id, payload)
            
            return APIResponse(
                success=True,
                message="Target updated successfully",
                data=updated_target,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to update target",
            data=None,
            errors=[str(e)]
        )


@router.delete("/{target_id}", response=APIResponse, summary="Delete target")
async def delete_target(request: HttpRequest, target_id: UUID):
    """
    Delete a target and all associated data.
    
    This will permanently delete the target and all related reconnaissance results,
    vulnerabilities, and reports. This action cannot be undone.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            
            # Check if target exists
            existing_target = await target_service.get_target_by_id(target_id)
            if not existing_target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    data=None,
                    errors=[f"Target with ID {target_id} not found"]
                )
            
            # Delete target
            await target_service.delete_target(target_id)
            
            return APIResponse(
                success=True,
                message="Target deleted successfully",
                data={"deleted_target_id": str(target_id)},
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to delete target",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/summary", response=APIResponse, summary="Get target summary")
async def get_target_summary(request: HttpRequest, target_id: UUID):
    """
    Get a summary of target information and associated data.
    
    Returns a comprehensive summary including reconnaissance results,
    vulnerability counts, and workflow status.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            
            # Check if target exists
            existing_target = await target_service.get_target_by_id(target_id)
            if not existing_target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    data=None,
                    errors=[f"Target with ID {target_id} not found"]
                )
            
            # Get target summary
            summary = await target_service.get_target_summary(target_id)
            
            return APIResponse(
                success=True,
                message="Target summary retrieved successfully",
                data=summary,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve target summary",
            data=None,
            errors=[str(e)]
        )


@router.post("/{target_id}/validate", response=APIResponse, summary="Validate target")
async def validate_target(request: HttpRequest, target_id: UUID):
    """
    Validate target configuration and connectivity.
    
    Performs validation checks on the target including domain resolution,
    IP address validation, and basic connectivity tests.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            
            # Check if target exists
            existing_target = await target_service.get_target_by_id(target_id)
            if not existing_target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    data=None,
                    errors=[f"Target with ID {target_id} not found"]
                )
            
            # Validate target
            validation_result = await target_service.validate_target(target_id)
            
            return APIResponse(
                success=True,
                message="Target validation completed",
                data=validation_result,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to validate target",
            data=None,
            errors=[str(e)]
        )


@router.get("/stats/overview", response=APIResponse, summary="Get targets overview statistics")
async def get_targets_overview(request: HttpRequest):
    """
    Get overview statistics for all targets.
    
    Returns aggregated statistics including total targets, active targets,
    targets by status, and recent activity.
    """
    try:
        async with get_db_session() as session:
            target_service = TargetService(session)
            stats = await target_service.get_targets_overview()
            
            return APIResponse(
                success=True,
                message="Targets overview retrieved successfully",
                data=stats,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve targets overview",
            data=None,
            errors=[str(e)]
        ) 