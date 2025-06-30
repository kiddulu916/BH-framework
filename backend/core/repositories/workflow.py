"""
Workflow repositories for workflow management operations.

This module provides the WorkflowRepository and WorkflowExecutionRepository
classes which handle all database operations related to workflows.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.workflow import Workflow, WorkflowExecution, WorkflowStatus, WorkflowStage
from ..schemas.workflow import StageStatus
from .base import BaseRepository


class WorkflowRepository(BaseRepository):
    """
    Repository for Workflow model operations.
    
    This repository provides methods for managing workflows,
    including status tracking and stage management.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize the workflow repository."""
        super().__init__(session, Workflow)
    
    async def get_by_target(self, target_id: UUID) -> List[Workflow]:
        """
        Get all workflows for a target.
        
        Args:
            target_id: Target ID
            
        Returns:
            List of workflows for the target
        """
        return await self.list(filters={'target_id': target_id}, order_by=['created_at'])
    
    async def get_active_workflows(self, user_id: Optional[UUID] = None) -> List[Workflow]:
        """
        Get all active workflows.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            List of active workflows
        """
        filters = {'status': WorkflowStatus.RUNNING}
        if user_id:
            filters['user_id'] = user_id
        
        return await self.list(filters=filters, order_by=['created_at'])
    
    async def get_completed_workflows(self, user_id: Optional[UUID] = None) -> List[Workflow]:
        """
        Get all completed workflows.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            List of completed workflows
        """
        filters = {'status': WorkflowStatus.COMPLETED}
        if user_id:
            filters['user_id'] = user_id
        
        return await self.list(filters=filters, order_by=['created_at'])
    
    async def get_workflows_by_user(self, user_id: UUID) -> List[Workflow]:
        """
        Get all workflows for a specific user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of workflows for the user
        """
        return await self.list(filters={'user_id': user_id}, order_by=['created_at'])

    async def get_by_target_id(self, target_id: UUID) -> List[Workflow]:
        """
        Get all workflows for a target by target_id (alias for get_by_target).
        Args:
            target_id: Target ID
        Returns:
            List of workflows for the target
        """
        return await self.get_by_target(target_id)

    async def update_stage_status(self, workflow_id: UUID, stage_name: str, status: StageStatus) -> None:
        """
        Update the status of a specific stage in a workflow.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Stage name (e.g., "PASSIVE_RECON")
            status: New status for the stage
        """
        workflow = await self.get_by_id(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow with ID {workflow_id} not found")
        
        # Update the stages dictionary
        updated_stages = {**workflow.stages, stage_name: status}
        
        # Update the workflow
        await self.update(
            workflow_id,
            stages=updated_stages,
            updated_at=datetime.now(timezone.utc)
        )

    async def get_stage_status(self, workflow_id: UUID, stage_name: str) -> Optional[StageStatus]:
        """
        Get the status of a specific stage in a workflow.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Stage name (e.g., "PASSIVE_RECON")
            
        Returns:
            Status of the stage or None if not found
        """
        workflow = await self.get_by_id(workflow_id)
        if not workflow:
            return None
        
        return workflow.stages.get(stage_name)


class WorkflowExecutionRepository(BaseRepository):
    """
    Repository for WorkflowExecution model operations.
    
    This repository provides methods for managing workflow executions,
    including stage tracking and execution history.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize the workflow execution repository."""
        super().__init__(session, WorkflowExecution)
    
    async def get_by_workflow(self, workflow_id: UUID) -> List[WorkflowExecution]:
        """
        Get all executions for a workflow.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            List of executions for the workflow
        """
        return await self.list(filters={'workflow_id': workflow_id}, order_by=['created_at'])
    
    async def get_by_stage(self, stage: WorkflowStage) -> List[WorkflowExecution]:
        """
        Get all executions for a specific stage.
        
        Args:
            stage: Workflow stage
            
        Returns:
            List of executions for the stage
        """
        return await self.list(filters={'stage': stage}, order_by=['created_at'])
    
    async def get_by_execution_id(self, execution_id: str) -> Optional[WorkflowExecution]:
        """
        Get execution by execution ID.
        
        Args:
            execution_id: Execution ID
            
        Returns:
            WorkflowExecution instance or None if not found
        """
        return await self.find_one({'execution_id': execution_id})
    
    async def get_running_executions(self) -> List[WorkflowExecution]:
        """
        Get all running executions.
        
        Returns:
            List of running executions
        """
        return await self.list(filters={'status': WorkflowStatus.RUNNING}, order_by=['created_at'])
    
    async def get_failed_executions(self) -> List[WorkflowExecution]:
        """
        Get all failed executions.
        
        Returns:
            List of failed executions
        """
        return await self.list(filters={'status': WorkflowStatus.FAILED}, order_by=['created_at']) 