"""
Workflow service for managing bug hunting workflow execution and stage coordination.
"""

import logging
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timezone

from core.schemas.workflow import (
    WorkflowCreateRequest,
    WorkflowUpdateRequest,
    WorkflowResponse,
    WorkflowListResponse,
    WorkflowSummaryResponse,
    WorkflowExecutionRequest,
    WorkflowExecutionResponse,
    StageStatus,
    WorkflowStatus,
    StageExecutionResponse
)
from core.repositories.workflow import WorkflowRepository
from core.repositories.target import TargetRepository
from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository
from core.repositories.report import ReportRepository
from core.utils.exceptions import (
    ValidationError,
    NotFoundError,
    WorkflowError,
    StageExecutionError
)
from core.schemas.base import APIResponse

logger = logging.getLogger(__name__)


class WorkflowService:
    """
    Service for managing bug hunting workflows and stage execution.
    """
    
    def __init__(
        self,
        workflow_repository: WorkflowRepository,
        target_repository: TargetRepository,
        passive_recon_repository: PassiveReconRepository,
        active_recon_repository: ActiveReconRepository,
        vulnerability_repository: VulnerabilityRepository,
        kill_chain_repository: KillChainRepository,
        report_repository: ReportRepository
    ):
        self.workflow_repository = workflow_repository
        self.target_repository = target_repository
        self.passive_recon_repository = passive_recon_repository
        self.active_recon_repository = active_recon_repository
        self.vulnerability_repository = vulnerability_repository
        self.kill_chain_repository = kill_chain_repository
        self.report_repository = report_repository
    
    async def create_workflow(self, payload: WorkflowCreateRequest) -> APIResponse:
        """
        Create a new workflow for a target.
        
        Args:
            payload: Workflow creation data
            
        Returns:
            APIResponse with created workflow data
        """
        try:
            # Validate target exists
            target = await self.target_repository.get_by_id(payload.target_id)
            if not target:
                raise NotFoundError(f"Target with ID {payload.target_id} not found")
            
            # Check if workflow already exists for this target
            existing_workflow = await self.workflow_repository.get_by_target_id(payload.target_id)
            if existing_workflow:
                raise ValidationError(f"Workflow already exists for target {payload.target_id}")
            
            # Create workflow data
            workflow_data = {
                "name": payload.name,
                "description": payload.description,
                "target_id": payload.target_id,
                "user_id": None,  # TODO: Get from request context
                "status": WorkflowStatus.PENDING,
                "current_stage": None,
                "progress": "0%",
                "stages": {
                    "PASSIVE_RECON": StageStatus.PENDING,
                    "ACTIVE_RECON": StageStatus.PENDING,
                    "VULN_SCAN": StageStatus.PENDING,
                    "VULN_TEST": StageStatus.PENDING,
                    "KILL_CHAIN": StageStatus.PENDING,
                    "REPORT": StageStatus.PENDING
                },
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            
            workflow = await self.workflow_repository.create(**workflow_data)
            
            logger.info(f"Created workflow {workflow.id} for target {payload.target_id}")
            
            # Convert stages dict to list of stage names for response
            workflow_dict = workflow.__dict__.copy()
            if isinstance(workflow_dict.get('stages'), dict):
                workflow_dict['stages'] = list(workflow_dict['stages'].keys())
            return APIResponse(
                success=True,
                message="Workflow created successfully",
                data=WorkflowResponse.model_validate(workflow_dict).model_dump()
            )
            
        except (ValidationError, NotFoundError) as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error creating workflow: {str(e)}")
            return APIResponse(success=False, message="Failed to create workflow", errors=[str(e)])
    
    async def get_workflow(self, workflow_id: UUID) -> APIResponse:
        """
        Get workflow by ID.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            APIResponse with workflow data
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            workflow_dict = workflow.__dict__.copy()
            if isinstance(workflow_dict.get('stages'), dict):
                workflow_dict['stages'] = list(workflow_dict['stages'].keys())
            return APIResponse(
                success=True,
                message="Workflow retrieved successfully",
                data=WorkflowResponse.model_validate(workflow_dict).model_dump()
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error retrieving workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve workflow", errors=[str(e)])
    
    async def get_workflows(
        self,
        limit: int = 10,
        offset: int = 0,
        status: Optional[WorkflowStatus] = None,
        target_id: Optional[UUID] = None
    ) -> APIResponse:
        """
        Get list of workflows with optional filtering.
        
        Args:
            limit: Number of workflows to return
            offset: Number of workflows to skip
            status: Filter by workflow status
            target_id: Filter by target ID
            
        Returns:
            APIResponse with workflow list
        """
        try:
            workflows = await self.workflow_repository.list(
                limit=limit,
                offset=offset,
                status=status,
                target_id=target_id
            )
            
            total_count = await self.workflow_repository.count(
                status=status,
                target_id=target_id
            )
            
            workflow_list = []
            for w in workflows:
                w_dict = w.__dict__.copy()
                if isinstance(w_dict.get('stages'), dict):
                    w_dict['stages'] = list(w_dict['stages'].keys())
                workflow_list.append(WorkflowResponse.model_validate(w_dict).model_dump())
            
            return APIResponse(
                success=True,
                message="Workflows retrieved successfully",
                data=WorkflowListResponse(
                    workflows=workflow_list,
                    total=total_count,
                    page=offset // limit + 1 if limit > 0 else 1,
                    per_page=limit
                ).model_dump()
            )
            
        except Exception as e:
            logger.error(f"Error retrieving workflows: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve workflows", errors=[str(e)])
    
    async def update_workflow(self, workflow_id: UUID, payload: WorkflowUpdateRequest) -> APIResponse:
        """
        Update workflow.
        
        Args:
            workflow_id: Workflow ID
            payload: Update data
            
        Returns:
            APIResponse with updated workflow data
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            # Update fields
            update_data = {}
            if payload.name is not None:
                update_data["name"] = payload.name
            if payload.description is not None:
                update_data["description"] = payload.description
            if payload.status is not None:
                update_data["status"] = payload.status
            if payload.stages is not None:
                update_data["stages"] = payload.stages
            
            update_data["updated_at"] = datetime.now(timezone.utc)
            
            updated_workflow = await self.workflow_repository.update(workflow_id, **update_data)
            
            logger.info(f"Updated workflow {workflow_id}")
            
            updated_workflow_dict = updated_workflow.__dict__.copy()
            if isinstance(updated_workflow_dict.get('stages'), dict):
                updated_workflow_dict['stages'] = list(updated_workflow_dict['stages'].keys())
            return APIResponse(
                success=True,
                message="Workflow updated successfully",
                data=WorkflowResponse.model_validate(updated_workflow_dict).model_dump()
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error updating workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to update workflow", errors=[str(e)])
    
    async def delete_workflow(self, workflow_id: UUID) -> APIResponse:
        """
        Delete workflow.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            APIResponse with deletion confirmation
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            await self.workflow_repository.delete(workflow_id)
            
            logger.info(f"Deleted workflow {workflow_id}")
            
            return APIResponse(
                success=True,
                message="Workflow deleted successfully"
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error deleting workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to delete workflow", errors=[str(e)])
    
    async def get_workflow_summary(self, workflow_id: UUID) -> APIResponse:
        """
        Get workflow summary with stage status and progress.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            APIResponse with workflow summary
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            # Get stage results counts
            passive_recon_count = await self.passive_recon_repository.count_by_workflow(workflow_id)
            active_recon_count = await self.active_recon_repository.count_by_workflow(workflow_id)
            vulnerability_count = await self.vulnerability_repository.count_by_workflow(workflow_id)
            kill_chain_count = await self.kill_chain_repository.count_by_workflow(workflow_id)
            report_count = await self.report_repository.count_by_workflow(workflow_id)
            
            # Calculate progress
            total_stages = len(workflow.stages)
            completed_stages = sum(1 for status in workflow.stages.values() if status == StageStatus.COMPLETED)
            progress_percentage = (completed_stages / total_stages) * 100 if total_stages > 0 else 0
            
            summary = WorkflowSummaryResponse(
                id=workflow.id,
                name=workflow.name,
                status=workflow.status,
                stages=workflow.stages,
                progress_percentage=progress_percentage,
                stage_results={
                    "passive_recon": passive_recon_count,
                    "active_recon": active_recon_count,
                    "vulnerability_scan": vulnerability_count,
                    "kill_chain_analysis": kill_chain_count,
                    "report_generation": report_count
                },
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            
            return APIResponse(
                success=True,
                message="Workflow summary retrieved successfully",
                data=summary.model_dump()
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error retrieving workflow summary {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve workflow summary", errors=[str(e)])
    
    async def execute_stage(self, workflow_id: UUID, payload: WorkflowExecutionRequest) -> APIResponse:
        """
        Execute a specific stage of the workflow.
        
        Args:
            workflow_id: Workflow ID
            payload: Stage execution request
            
        Returns:
            APIResponse with execution status
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            stage_name = payload.stage_name
            # Normalize stage_name to uppercase string
            if hasattr(stage_name, 'value'):
                stage_name_key = stage_name.value.upper()
            else:
                stage_name_key = str(stage_name).upper()
            # Normalize workflow.stages keys to uppercase strings
            normalized_stages = {str(k).upper() if not isinstance(k, str) else k.upper(): v for k, v in workflow.stages.items()}

            # Validate stage name
            if stage_name_key not in normalized_stages:
                raise ValidationError(f"Invalid stage name: {stage_name}")
            
            # Check if stage is already running
            if normalized_stages[stage_name_key] == StageStatus.RUNNING:
                raise WorkflowError(f"Stage {stage_name} is already running")
            
            # Check dependencies
            await self._validate_stage_dependencies(workflow, stage_name_key, normalized_stages)
            
            # Update stage status to running
            await self.workflow_repository.update(workflow_id, **{
                "stages": {**workflow.stages, stage_name: StageStatus.RUNNING},
                "updated_at": datetime.now(timezone.utc)
            })
            
            # TODO: Implement actual stage execution logic
            # This would involve:
            # 1. Triggering the appropriate stage container
            # 2. Monitoring execution progress
            # 3. Updating stage status on completion
            # 4. Handling errors and retries
            
            logger.info(f"Started execution of stage {stage_name} for workflow {workflow_id}")
            
            return APIResponse(
                success=True,
                message=f"Stage {stage_name} execution started",
                data=StageExecutionResponse(
                    workflow_id=workflow_id,
                    stage_name=stage_name,
                    status=StageStatus.RUNNING,
                    message=f"Stage {stage_name} execution started"
                ).model_dump()
            )
            
        except (NotFoundError, ValidationError, WorkflowError) as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error executing stage {payload.stage_name} for workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to execute stage", errors=[str(e)])
    
    async def _validate_stage_dependencies(self, workflow, stage_name: str, normalized_stages: dict = None) -> None:
        """
        Validate that stage dependencies are met.
        
        Args:
            workflow: Workflow object
            stage_name: Name of stage to validate
            normalized_stages: Normalized stages dictionary
            
        Raises:
            WorkflowError: If dependencies are not met
        """
        dependencies = {
            "ACTIVE_RECON": ["PASSIVE_RECON"],
            "VULN_SCAN": ["ACTIVE_RECON"],
            "VULN_TEST": ["VULN_SCAN"],
            "KILL_CHAIN": ["VULN_TEST"],
            "REPORT": ["KILL_CHAIN"]
        }
        if normalized_stages is None:
            normalized_stages = {str(k).upper() if not isinstance(k, str) else k.upper(): v for k, v in workflow.stages.items()}
        if stage_name in dependencies:
            for dep_stage in dependencies[stage_name]:
                if normalized_stages.get(dep_stage) != StageStatus.COMPLETED:
                    raise WorkflowError(f"Stage {stage_name} requires {dep_stage} to be completed first")
    
    async def get_workflow_statistics(self) -> APIResponse:
        """
        Get workflow statistics.
        
        Returns:
            APIResponse with workflow statistics
        """
        try:
            total_workflows = await self.workflow_repository.count()
            pending_workflows = await self.workflow_repository.count(status=WorkflowStatus.PENDING)
            running_workflows = await self.workflow_repository.count(status=WorkflowStatus.RUNNING)
            completed_workflows = await self.workflow_repository.count(status=WorkflowStatus.COMPLETED)
            failed_workflows = await self.workflow_repository.count(status=WorkflowStatus.FAILED)
            
            statistics = {
                "total_workflows": total_workflows,
                "pending_workflows": pending_workflows,
                "running_workflows": running_workflows,
                "completed_workflows": completed_workflows,
                "failed_workflows": failed_workflows,
                "completion_rate": (completed_workflows / total_workflows * 100) if total_workflows > 0 else 0
            }
            
            return APIResponse(
                success=True,
                message="Workflow statistics retrieved successfully",
                data=statistics
            )
            
        except Exception as e:
            logger.error(f"Error retrieving workflow statistics: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve workflow statistics", errors=[str(e)]) 
