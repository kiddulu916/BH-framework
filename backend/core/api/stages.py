"""
Stage management API endpoints for the Bug Hunting Framework.

This module contains Django Ninja API endpoints for starting and managing stage containers
on-demand using Docker Compose profiles.
"""

import logging
import subprocess
import asyncio
import os
from typing import Dict, Any, Optional
from uuid import UUID
from ninja import Router
from django.http import HttpRequest
import traceback

from core.schemas.base import APIResponse
from core.utils.database import get_db_session
from core.repositories.target import TargetRepository
from core.api import api
from pydantic import BaseModel
from typing import List, Optional

logger = logging.getLogger(__name__)

router = Router()


class StageExecutionRequest(BaseModel):
    """Schema for stage execution request."""
    target_id: str
    stage_name: str
    tools: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None


@router.post("/passive-recon/start", response=APIResponse, summary="Start passive reconnaissance stage")
async def start_passive_recon(request: HttpRequest, payload: StageExecutionRequest):
    """
    Start the passive reconnaissance stage container using Docker Compose.
    
    Args:
        payload: Stage execution request containing target_id, tools, and options
        
    Returns:
        APIResponse with execution status
    """
    try:
        logger.info(f"Starting passive recon stage with payload: {payload}")
        
        # Validate target exists
        async with get_db_session() as session:
            target_repo = TargetRepository(session)
            target = await target_repo.get_by_id(UUID(payload.target_id))
            if not target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    errors=[f"Target with ID {payload.target_id} not found"]
                )
        
        # Start the passive recon container using Docker Compose
        result = await _start_stage_container("passive_recon", payload.model_dump())
        
        return APIResponse(
            success=True,
            message="Passive reconnaissance stage started successfully",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Failed to start passive recon stage: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return APIResponse(
            success=False,
            message="Failed to start passive reconnaissance stage",
            errors=[str(e)]
        )


@router.post("/active-recon/start", response=APIResponse, summary="Start active reconnaissance stage")
async def start_active_recon(request: HttpRequest, payload: StageExecutionRequest):
    """
    Start the active reconnaissance stage container using Docker Compose.
    
    Args:
        payload: Stage execution request containing target_id, tools, and options
        
    Returns:
        APIResponse with execution status
    """
    try:
        logger.info(f"Starting active recon stage with payload: {payload}")
        
        # Validate target exists
        async with get_db_session() as session:
            target_repo = TargetRepository(session)
            target = await target_repo.get_by_id(UUID(payload.target_id))
            if not target:
                return APIResponse(
                    success=False,
                    message="Target not found",
                    errors=[f"Target with ID {payload.target_id} not found"]
                )
        
        # Start the active recon container using Docker Compose
        result = await _start_stage_container("active_recon", payload.model_dump())
        
        return APIResponse(
            success=True,
            message="Active reconnaissance stage started successfully",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Failed to start active recon stage: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return APIResponse(
            success=False,
            message="Failed to start active reconnaissance stage",
            errors=[str(e)]
        )


@router.get("/passive-recon/status/{target_id}", response=APIResponse, summary="Get passive recon status")
async def get_passive_recon_status(request: HttpRequest, target_id: str):
    """
    Get the status of passive reconnaissance stage for a target.
    
    Args:
        target_id: Target ID
        
    Returns:
        APIResponse with stage status
    """
    try:
        # Check if container is running
        container_status = await _get_container_status("bug-hunting-passive-recon")
        
        return APIResponse(
            success=True,
            message="Passive recon status retrieved",
            data={
                "target_id": target_id,
                "container_status": container_status,
                "stage": "passive-recon"
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get passive recon status: {str(e)}")
        return APIResponse(
            success=False,
            message="Failed to get passive recon status",
            errors=[str(e)]
        )


@router.get("/active-recon/status/{target_id}", response=APIResponse, summary="Get active recon status")
async def get_active_recon_status(request: HttpRequest, target_id: str):
    """
    Get the status of active reconnaissance stage for a target.
    
    Args:
        target_id: Target ID
        
    Returns:
        APIResponse with stage status
    """
    try:
        # Check if container is running
        container_status = await _get_container_status("bug-hunting-active-recon")
        
        return APIResponse(
            success=True,
            message="Active recon status retrieved",
            data={
                "target_id": target_id,
                "container_status": container_status,
                "stage": "active-recon"
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get active recon status: {str(e)}")
        return APIResponse(
            success=False,
            message="Failed to get active recon status",
            errors=[str(e)]
        )


async def _start_stage_container(stage_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Start a stage container using Docker SDK.
    
    Args:
        stage_name: Name of the stage (passive_recon, active_recon, etc.)
        payload: Stage execution payload
        
    Returns:
        Dictionary with execution result
    """
    try:
        import docker
        
        # Initialize Docker client
        client = docker.from_env()
        
        # Prepare environment variables for the container
        env_vars = {
            "TARGET_ID": payload.get("target_id"),
            "STAGE_NAME": payload.get("stage_name", stage_name),
            "SELECTED_TOOLS": ",".join(payload.get("tools", [])) if payload.get("tools") else "",
            "BACKEND_API_URL": "http://backend:8000/api/",
            "BACKEND_JWT_TOKEN": os.environ.get("BACKEND_JWT_TOKEN", ""),
        }
        
        # Add options to environment variables
        options = payload.get("options", {})
        for key, value in options.items():
            env_vars[f"OPTION_{key.upper()}"] = str(value)
        
        # Container configuration
        container_name = f"bug-hunting-{stage_name}"
        
        # Check if container already exists and remove it
        try:
            existing_container = client.containers.get(container_name)
            existing_container.remove(force=True)
            logger.info(f"Removed existing container: {container_name}")
        except docker.errors.NotFound:
            pass
        
        # Start the container
        container = client.containers.run(
            image=f"bug-hunting-{stage_name}:latest",
            name=container_name,
            environment=env_vars,
            volumes={
                f"{os.getcwd()}/stages/{stage_name}": {"bind": "/app", "mode": "rw"},
                f"{os.getcwd()}/outputs": {"bind": "/app/outputs", "mode": "rw"},
            },
            network="bug-hunting_bug-hunting-network",
            detach=True,
            remove=True
        )
        
        logger.info(f"Successfully started {stage_name} container: {container.id}")
        return {
            "container_name": container_name,
            "container_id": container.id,
            "status": "started",
            "image": f"bug-hunting-{stage_name}:latest"
        }
            
    except Exception as e:
        logger.error(f"Error starting {stage_name} container: {str(e)}")
        raise


async def _get_container_status(container_name: str) -> Dict[str, Any]:
    """
    Get the status of a Docker container.
    
    Args:
        container_name: Name of the container
        
    Returns:
        Dictionary with container status
    """
    try:
        cmd = ["docker", "ps", "--filter", f"name={container_name}", "--format", "json"]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            output = stdout.decode().strip()
            if output:
                # Container is running
                return {
                    "status": "running",
                    "container_name": container_name,
                    "details": output
                }
            else:
                # Container is not running
                return {
                    "status": "stopped",
                    "container_name": container_name,
                    "details": "Container not found or not running"
                }
        else:
            error_msg = stderr.decode() if stderr else "Unknown error"
            logger.error(f"Failed to get container status: {error_msg}")
            return {
                "status": "error",
                "container_name": container_name,
                "details": error_msg
            }
            
    except Exception as e:
        logger.error(f"Error getting container status: {str(e)}")
        return {
            "status": "error",
            "container_name": container_name,
            "details": str(e)
        } 