"""
Report API endpoints for managing report generation and export functionality.
"""

from typing import Optional
from uuid import UUID

from ninja import Router
from ninja.pagination import paginate, PageNumberPagination

from core.schemas.report import (
    ReportCreateRequest,
    ReportUpdateRequest,
    ReportResponse,
    ReportListResponse,
    ReportExportRequest,
    ReportTemplateResponse,
    ReportFormat
)
from core.tasks.report_service import ReportService
from core.schemas.base import APIResponse
from core.utils.database import get_db_manager, get_db_session
from core.repositories.report import ReportRepository
from core.repositories.workflow import WorkflowRepository
from core.repositories.target import TargetRepository
from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository

router = Router(tags=["Reports"])


@router.post("", response=APIResponse, summary="Create report")
async def create_report(request, payload: ReportCreateRequest):
    """
    Create a new report for a workflow.
    
    Args:
        payload: Report creation data
        
    Returns:
        APIResponse with created report data
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.create_report(payload)


@router.get("/{report_id}", response=APIResponse, summary="Get report")
async def get_report(request, report_id: UUID):
    """
    Get report by ID.
    
    Args:
        report_id: Report ID
        
    Returns:
        APIResponse with report data
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.get_report(report_id)


@router.get("", response=APIResponse, summary="List reports")
async def list_reports(
    request,
    limit: int = 10,
    offset: int = 0,
    workflow_id: Optional[UUID] = None,
    status: Optional[str] = None
):
    """
    Get list of reports with optional filtering.
    
    Args:
        limit: Number of reports to return
        offset: Number of reports to skip
        workflow_id: Filter by workflow ID
        status: Filter by report status
        
    Returns:
        APIResponse with report list
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.get_reports(
            limit=limit,
            offset=offset,
            workflow_id=workflow_id,
            status=status
        )


@router.put("/{report_id}", response=APIResponse, summary="Update report")
async def update_report(request, report_id: UUID, payload: ReportUpdateRequest):
    """
    Update report.
    
    Args:
        report_id: Report ID
        payload: Update data
        
    Returns:
        APIResponse with updated report data
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.update_report(report_id, payload)


@router.delete("/{report_id}", response=APIResponse, summary="Delete report")
async def delete_report(request, report_id: UUID):
    """
    Delete report.
    
    Args:
        report_id: Report ID
        
    Returns:
        APIResponse with deletion confirmation
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.delete_report(report_id)


@router.post("/generate/{workflow_id}", response=APIResponse, summary="Generate report")
async def generate_report(request, workflow_id: UUID, template: str = "default"):
    """
    Generate a new report for a workflow.
    
    Args:
        workflow_id: Workflow ID
        template: Report template to use
        
    Returns:
        APIResponse with generated report data
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.generate_report(workflow_id, template)


@router.post("/{report_id}/export", response=APIResponse, summary="Export report")
async def export_report(request, report_id: UUID, payload: ReportExportRequest):
    """
    Export report in specified format.
    
    Args:
        report_id: Report ID
        payload: Export configuration
        
    Returns:
        APIResponse with export data
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.export_report(report_id, payload)


@router.get("/templates", response=APIResponse, summary="Get report templates")
async def get_report_templates(request):
    """
    Get available report templates.
    
    Returns:
        APIResponse with available templates
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.get_report_templates()


# Convenience endpoints for workflow-based report operations
@router.get("/workflows/{workflow_id}/reports", response=APIResponse, summary="Get workflow reports")
async def get_workflow_reports(
    request,
    workflow_id: UUID,
    limit: int = 10,
    offset: int = 0
):
    """
    Get reports for a specific workflow.
    
    Args:
        workflow_id: Workflow ID
        limit: Number of reports to return
        offset: Number of reports to skip
        
    Returns:
        APIResponse with workflow reports
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.get_reports(
            limit=limit,
            offset=offset,
            workflow_id=workflow_id
        )


@router.post("/workflows/{workflow_id}/reports/generate", response=APIResponse, summary="Generate workflow report")
async def generate_workflow_report(request, workflow_id: UUID, template: str = "default"):
    """
    Generate a report for a specific workflow.
    
    Args:
        workflow_id: Workflow ID
        template: Report template to use
        
    Returns:
        APIResponse with generated report data
    """
    async with get_db_session() as session:
        # Initialize repositories
        report_repo = ReportRepository(session)
        workflow_repo = WorkflowRepository(session)
        target_repo = TargetRepository(session)
        passive_recon_repo = PassiveReconRepository(session)
        active_recon_repo = ActiveReconRepository(session)
        vulnerability_repo = VulnerabilityRepository(session)
        kill_chain_repo = KillChainRepository(session)
        
        # Initialize services
        report_service = ReportService(
            report_repository=report_repo,
            workflow_repository=workflow_repo,
            target_repository=target_repo,
            passive_recon_repository=passive_recon_repo,
            active_recon_repository=active_recon_repo,
            vulnerability_repository=vulnerability_repo,
            kill_chain_repository=kill_chain_repo
        )
        
        return await report_service.generate_report(workflow_id, template) 