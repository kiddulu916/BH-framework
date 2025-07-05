"""
Workflow API endpoints for managing bug hunting workflows and stage execution.
"""

from typing import Optional
from uuid import UUID

from ninja import Router
from ninja.pagination import paginate, PageNumberPagination

from core.schemas.workflow import (
    WorkflowCreateRequest,
    WorkflowUpdateRequest,
    WorkflowResponse,
    WorkflowListResponse,
    WorkflowSummaryResponse,
    WorkflowExecutionRequest,
    WorkflowExecutionResponse,
    WorkflowStatus
)
from core.tasks.workflow_service import WorkflowService
from core.tasks.execution_service import ExecutionService
from core.schemas.base import APIResponse
from core.utils.database import get_db_manager, get_db_session
from core.repositories.workflow import WorkflowRepository
from core.repositories.target import TargetRepository
from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository
from core.repositories.report import ReportRepository

router = Router(tags=["Workflows"])


@router.post("", response=APIResponse, summary="Create workflow")
async def create_workflow(request, payload: WorkflowCreateRequest):
    """
    Create a new workflow for a target.
    
    Args:
        payload: Workflow creation data
        
    Returns:
        APIResponse with created workflow data
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.create_workflow(payload)


@router.get("/statistics", response=APIResponse, summary="Get workflow statistics")
async def get_workflow_statistics(request):
    """
    Get workflow statistics.
    
    Returns:
        APIResponse with workflow statistics
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.get_workflow_statistics()


@router.get("/{workflow_id}", response=APIResponse, summary="Get workflow")
async def get_workflow(request, workflow_id: UUID):
    """
    Get workflow by ID.
    
    Args:
        workflow_id: Workflow ID
        
    Returns:
        APIResponse with workflow data
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.get_workflow(workflow_id)


@router.get("", response=APIResponse, summary="List workflows")
async def list_workflows(
    request,
    limit: int = 10,
    offset: int = 0,
    status: Optional[WorkflowStatus] = None,
    target_id: Optional[UUID] = None
):
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
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.get_workflows(
            limit=limit,
            offset=offset,
            status=status,
            target_id=target_id
        )


@router.put("/workflows/{workflow_id}", response=APIResponse, summary="Update workflow")
async def update_workflow(request, workflow_id: UUID, payload: WorkflowUpdateRequest):
    """
    Update workflow.
    
    Args:
        workflow_id: Workflow ID
        payload: Update data
        
    Returns:
        APIResponse with updated workflow data
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.update_workflow(workflow_id, payload)


@router.delete("/workflows/{workflow_id}", response=APIResponse, summary="Delete workflow")
async def delete_workflow(request, workflow_id: UUID):
    """
    Delete workflow.
    
    Args:
        workflow_id: Workflow ID
        
    Returns:
        APIResponse with deletion confirmation
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.delete_workflow(workflow_id)


@router.get("/{workflow_id}/summary", response=APIResponse, summary="Get workflow summary")
async def get_workflow_summary(request, workflow_id: UUID):
    """
    Get workflow summary with stage status and progress.
    
    Args:
        workflow_id: Workflow ID
        
    Returns:
        APIResponse with workflow summary
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        return await workflow_service.get_workflow_summary(workflow_id)


@router.post("/{workflow_id}/execute", response=APIResponse, summary="Execute workflow stage")
async def execute_workflow_stage(request, workflow_id: UUID, payload: WorkflowExecutionRequest):
    """
    Execute a specific stage of the workflow.
    
    Args:
        workflow_id: Workflow ID
        payload: Stage execution request
        
    Returns:
        APIResponse with execution status
    """
    async with get_db_session() as session:
        # Initialize repositories
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        report_repo = ReportRepository(session)
        
        # Initialize services
        workflow_service = WorkflowService(
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo,
            report_repository=report_repo
        )
        
        execution_service = ExecutionService(
            workflow_repository=workflow_repo,
            target_repository=target_repo
        )
        
        # First validate and update workflow status
        workflow_result = await workflow_service.execute_stage(workflow_id, payload)
        
        if not workflow_result.success:
            return workflow_result
        
        # Then execute the actual stage container
        workflow = await workflow_repo.get_by_id(workflow_id)
        if workflow:
            return await execution_service.execute_stage_container(
                workflow_id=workflow_id,
                stage_name=payload.stage_name,
                target_id=workflow.target_id,
                execution_config=payload.config_overrides
            )
        
        return workflow_result


 