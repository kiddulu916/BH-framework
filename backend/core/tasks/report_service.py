"""
Report service for managing report generation and export functionality.
"""

import logging
import json
import csv
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime, timezone
from pathlib import Path

from core.schemas.report import (
    ReportCreateRequest,
    ReportUpdateRequest,
    ReportResponse,
    ReportListResponse,
    ReportExportRequest,
    ReportTemplateResponse,
    ReportFormat,
    ReportType,
    ReportStatus,
    ReportSection
)
from core.repositories.report import ReportRepository
from core.repositories.workflow import WorkflowRepository
from core.repositories.target import TargetRepository
from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository
from core.utils.exceptions import (
    ValidationError,
    NotFoundError,
    ReportGenerationError,
    ExportError
)
from core.schemas.base import APIResponse
from core.models.workflow import WorkflowStatus

logger = logging.getLogger(__name__)


class ReportService:
    """
    Service for managing report generation and export functionality.
    """
    
    def __init__(
        self,
        report_repository: ReportRepository,
        workflow_repository: WorkflowRepository,
        target_repository: TargetRepository,
        passive_recon_repository: PassiveReconRepository,
        active_recon_repository: ActiveReconRepository,
        vulnerability_repository: VulnerabilityRepository,
        kill_chain_repository: KillChainRepository
    ):
        self.report_repository = report_repository
        self.workflow_repository = workflow_repository
        self.target_repository = target_repository
        self.passive_recon_repository = passive_recon_repository
        self.active_recon_repository = active_recon_repository
        self.vulnerability_repository = vulnerability_repository
        self.kill_chain_repository = kill_chain_repository
    
    async def create_report(self, payload: ReportCreateRequest) -> APIResponse:
        """
        Create a new report for a workflow.
        
        Args:
            payload: Report creation data
            
        Returns:
            APIResponse with created report data
        """
        try:
            # Validate workflow exists
            workflow = await self.workflow_repository.get_by_id(payload.workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {payload.workflow_id} not found")
            
            # Check if report already exists for this workflow
            existing_report = await self.report_repository.get_by_workflow_id(payload.workflow_id)
            if existing_report:
                raise ValidationError(f"Report already exists for workflow {payload.workflow_id}")
            
            # Generate report content
            report_content = await self._generate_report_content(workflow, payload.template)
            
            # Create report
            report_data = {
                "workflow_id": payload.workflow_id,
                "target_id": workflow.target_id,
                "name": payload.title or f"Security Assessment Report - {workflow.name}",
                "report_type": ReportType.TECHNICAL_DETAILED,
                "format": payload.format,
                "content": json.dumps(report_content),
                "status": ReportStatus.GENERATING,
                "template_used": payload.template,
                "configuration": {"template": payload.template, "format": payload.format.name if hasattr(payload.format, 'name') else str(payload.format).upper()},
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            
            report = await self.report_repository.create(**report_data)
            
            # Update workflow status to COMPLETED after report creation
            await self.workflow_repository.update(report.workflow_id, status=WorkflowStatus.COMPLETED, updated_at=datetime.now(timezone.utc))
            
            # Ensure the session is committed so the workflow status change is persisted
            await self.workflow_repository.session.commit()

            logger.info(f"Created report {report.id} for workflow {payload.workflow_id}")
            
            # Parse report content for required fields
            content = json.loads(report.content)
            sections = list(content.get("sections", {}).keys())
            # Use defaults for include_* fields
            if hasattr(report.status, 'value'):
                status_value = report.status.value
            else:
                status_value = str(report.status)
            report_response = ReportResponse(
                id=report.id,
                target_id=report.target_id,
                execution_id=report.workflow_id,
                user_id=report.user_id,
                title=report.name,
                description=report.description or "",
                report_type=ReportType.TECHNICAL_DETAILED,
                format=ReportFormat.MARKDOWN,
                status=ReportStatus(status_value),
                sections=sections,
                include_passive_recon=True,
                include_active_recon=True,
                include_vulnerabilities=True,
                include_kill_chain=True,
                include_screenshots=True,
                include_raw_data=False,
                custom_template=None,
                file_path=report.file_path,
                file_size=report.file_size,
                generation_time=None,
                error_message=None,
                metadata={},
                created_at=report.created_at,
                updated_at=report.updated_at,
                generated_at=None
            )
            return APIResponse(
                success=True,
                message="Report created successfully",
                data=report_response.model_dump()
            )
            
        except (ValidationError, NotFoundError) as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error creating report: {str(e)}")
            return APIResponse(success=False, message="Failed to create report", errors=[str(e)])
    
    async def get_report(self, report_id: UUID) -> APIResponse:
        """
        Get report by ID.
        
        Args:
            report_id: Report ID
            
        Returns:
            APIResponse with report data
        """
        try:
            report = await self.report_repository.get_by_id(report_id)
            if not report:
                raise NotFoundError(f"Report with ID {report_id} not found")
            
            # Parse content to get sections
            sections = []
            if report.content:
                try:
                    content_data = json.loads(report.content)
                    sections = list(content_data.get("sections", {}).keys())
                except (json.JSONDecodeError, KeyError):
                    sections = []
            
            # Create ReportResponse with proper field mapping
            report_response = ReportResponse(
                id=report.id,
                target_id=report.target_id,
                execution_id=report.workflow_id,
                user_id=report.user_id,
                title=report.name,  # Map name to title
                description=report.summary or "",  # Map summary to description
                report_type=ReportType(report.report_type.value) if hasattr(report.report_type, 'value') else ReportType.TECHNICAL_DETAILED,
                format=ReportFormat(report.format.value) if hasattr(report.format, 'value') else ReportFormat.PDF,
                status=ReportStatus(report.status.value) if hasattr(report.status, 'value') else ReportStatus.PENDING,
                sections=sections,
                include_passive_recon=True,  # Default values
                include_active_recon=True,
                include_vulnerabilities=True,
                include_kill_chain=True,
                include_screenshots=True,
                include_raw_data=False,
                custom_template=report.template_used,
                file_path=report.file_path,
                file_size=report.file_size,
                generation_time=report.generation_time,
                error_message=str(report.errors) if report.errors else None,
                metadata=report.configuration or {},
                created_at=report.created_at,
                updated_at=report.updated_at,
                generated_at=report.updated_at if report.status == ReportStatus.COMPLETED else None
            )
            
            return APIResponse(
                success=True,
                message="Report retrieved successfully",
                data=report_response.model_dump()
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error retrieving report {report_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve report", errors=[str(e)])
    
    async def get_reports(
        self,
        limit: int = 10,
        offset: int = 0,
        workflow_id: Optional[UUID] = None,
        status: Optional[str] = None
    ) -> APIResponse:
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
        try:
            # Build filters dictionary
            filters = {}
            if workflow_id:
                filters['workflow_id'] = workflow_id
            if status:
                # Convert status to uppercase to match database enum values
                filters['status'] = status.upper()
            
            reports = await self.report_repository.list(
                limit=limit,
                offset=offset,
                filters=filters
            )
            
            total_count = await self.report_repository.count(filters=filters)
            
            # Convert database models to schema responses
            report_list = []
            for r in reports:
                # Parse content to get sections
                sections = []
                if r.content:
                    try:
                        content_data = json.loads(r.content)
                        sections = list(content_data.get("sections", {}).keys())
                    except (json.JSONDecodeError, KeyError):
                        sections = []
                
                # Create ReportResponse with proper field mapping
                report_response = ReportResponse(
                    id=r.id,
                    target_id=r.target_id,
                    execution_id=r.workflow_id,
                    user_id=r.user_id,
                    title=r.name,  # Map name to title
                    description=r.summary or "",  # Map summary to description
                    report_type=ReportType(r.report_type.value) if hasattr(r.report_type, 'value') else ReportType.TECHNICAL_DETAILED,
                    format=ReportFormat(r.format.value) if hasattr(r.format, 'value') else ReportFormat.PDF,
                    status=ReportStatus(r.status.value) if hasattr(r.status, 'value') else ReportStatus.PENDING,
                    sections=sections,
                    include_passive_recon=True,  # Default values
                    include_active_recon=True,
                    include_vulnerabilities=True,
                    include_kill_chain=True,
                    include_screenshots=True,
                    include_raw_data=False,
                    custom_template=r.template_used,
                    file_path=r.file_path,
                    file_size=r.file_size,
                    generation_time=r.generation_time,
                    error_message=str(r.errors) if r.errors else None,
                    metadata=r.configuration or {},
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                    generated_at=r.updated_at if r.status == ReportStatus.COMPLETED else None
                )
                report_list.append(report_response.model_dump())
            
            return APIResponse(
                success=True,
                message="Reports retrieved successfully",
                data={
                    "reports": report_list,
                    "pagination": {
                        "page": offset // limit + 1 if limit > 0 else 1,
                        "per_page": limit,
                        "total": total_count
                    }
                }
            )
            
        except Exception as e:
            logger.error(f"Error retrieving reports: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve reports", errors=[str(e)])
    
    async def update_report(self, report_id: UUID, payload: ReportUpdateRequest) -> APIResponse:
        """
        Update report.
        
        Args:
            report_id: Report ID
            payload: Update data
            
        Returns:
            APIResponse with updated report data
        """
        try:
            report = await self.report_repository.get_by_id(report_id)
            if not report:
                raise NotFoundError(f"Report with ID {report_id} not found")
            
            # Update fields
            update_data = {}
            if payload.title is not None:
                update_data["name"] = payload.title  # Map title to name field
            if payload.description is not None:
                update_data["summary"] = payload.description  # Map description to summary field
            if payload.report_type is not None:
                update_data["report_type"] = payload.report_type
            if payload.format is not None:
                update_data["format"] = payload.format
            if payload.sections is not None:
                update_data["sections"] = payload.sections
            if payload.include_passive_recon is not None:
                update_data["include_passive_recon"] = payload.include_passive_recon
            if payload.include_active_recon is not None:
                update_data["include_active_recon"] = payload.include_active_recon
            if payload.include_vulnerabilities is not None:
                update_data["include_vulnerabilities"] = payload.include_vulnerabilities
            if payload.include_kill_chain is not None:
                update_data["include_kill_chain"] = payload.include_kill_chain
            if payload.include_screenshots is not None:
                update_data["include_screenshots"] = payload.include_screenshots
            if payload.include_raw_data is not None:
                update_data["include_raw_data"] = payload.include_raw_data
            if payload.custom_template is not None:
                update_data["custom_template"] = payload.custom_template
            if payload.metadata is not None:
                update_data["metadata"] = payload.metadata
            
            update_data["updated_at"] = datetime.now(timezone.utc)
            
            updated_report = await self.report_repository.update(report_id, **update_data)
            
            logger.info(f"Updated report {report_id}")
            
            # Parse content to get sections
            sections = []
            if updated_report.content:
                try:
                    content_data = json.loads(updated_report.content)
                    sections = list(content_data.get("sections", {}).keys())
                except (json.JSONDecodeError, KeyError):
                    sections = []
            
            # Create ReportResponse with proper field mapping
            report_response = ReportResponse(
                id=updated_report.id,
                target_id=updated_report.target_id,
                execution_id=updated_report.workflow_id,
                user_id=updated_report.user_id,
                title=updated_report.name,  # Map name to title
                description=updated_report.summary or "",  # Map summary to description
                report_type=ReportType(updated_report.report_type.value) if hasattr(updated_report.report_type, 'value') else ReportType.TECHNICAL_DETAILED,
                format=ReportFormat(updated_report.format.value) if hasattr(updated_report.format, 'value') else ReportFormat.PDF,
                status=ReportStatus(updated_report.status.value) if hasattr(updated_report.status, 'value') else ReportStatus.PENDING,
                sections=sections,
                include_passive_recon=getattr(updated_report, 'include_passive_recon', True),
                include_active_recon=getattr(updated_report, 'include_active_recon', True),
                include_vulnerabilities=getattr(updated_report, 'include_vulnerabilities', True),
                include_kill_chain=getattr(updated_report, 'include_kill_chain', True),
                include_screenshots=getattr(updated_report, 'include_screenshots', True),
                include_raw_data=getattr(updated_report, 'include_raw_data', False),
                custom_template=getattr(updated_report, 'custom_template', None),
                file_path=updated_report.file_path,
                file_size=updated_report.file_size,
                generation_time=getattr(updated_report, 'generation_time', None),
                error_message=getattr(updated_report, 'error_message', None),
                metadata=updated_report.configuration or {},
                created_at=updated_report.created_at,
                updated_at=updated_report.updated_at,
                generated_at=getattr(updated_report, 'generated_at', None)
            )
            
            return APIResponse(
                success=True,
                message="Report updated successfully",
                data=report_response.model_dump()
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error updating report {report_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to update report", errors=[str(e)])
    
    async def delete_report(self, report_id: UUID) -> APIResponse:
        """
        Delete report.
        
        Args:
            report_id: Report ID
            
        Returns:
            APIResponse with deletion confirmation
        """
        try:
            report = await self.report_repository.get_by_id(report_id)
            if not report:
                raise NotFoundError(f"Report with ID {report_id} not found")
            
            await self.report_repository.delete(report_id)
            
            logger.info(f"Deleted report {report_id}")
            
            return APIResponse(
                success=True,
                message="Report deleted successfully"
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error deleting report {report_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to delete report", errors=[str(e)])
    
    async def generate_report(self, workflow_id: UUID, template: str = "default") -> APIResponse:
        """
        Generate a new report for a workflow.
        
        Args:
            workflow_id: Workflow ID
            template: Report template to use
            
        Returns:
            APIResponse with generated report data
        """
        try:
            # Validate workflow exists
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            # Generate report content
            report_content = await self._generate_report_content(workflow, template)
            
            # Create or update report
            existing_report = await self.report_repository.get_by_workflow_id(workflow_id)
            
            if existing_report:
                # Update existing report
                update_data = {
                    "content": json.dumps(report_content),
                    "template_used": template,
                    "status": ReportStatus.COMPLETED.name,
                    "updated_at": datetime.now(timezone.utc)
                }
                report = await self.report_repository.update(existing_report.id, **update_data)
            else:
                # Create new report
                report_data = {
                    "workflow_id": workflow_id,
                    "target_id": workflow.target_id,
                    "name": f"Security Assessment Report - {workflow.name}",
                    "report_type": ReportType.TECHNICAL_DETAILED.name,
                    "format": ReportFormat.MARKDOWN.name,
                    "content": json.dumps(report_content),
                    "status": ReportStatus.COMPLETED.name,
                    "template_used": template,
                    "configuration": {"template": template, "format": ReportFormat.MARKDOWN.name},
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                }
                report = await self.report_repository.create(**report_data)
            
            # Update workflow status to COMPLETED after report generation
            await self.workflow_repository.update(workflow_id, status=WorkflowStatus.COMPLETED, updated_at=datetime.now(timezone.utc))
            await self.workflow_repository.session.commit()

            logger.info(f"Generated report {report.id} for workflow {workflow_id}")
            
            # Parse content to get sections
            sections = []
            if report.content:
                try:
                    content_data = json.loads(report.content)
                    sections = list(content_data.get("sections", {}).keys())
                except (json.JSONDecodeError, KeyError):
                    sections = []
            
            # Create ReportResponse with proper field mapping
            report_response = ReportResponse(
                id=report.id,
                target_id=report.target_id,
                execution_id=report.workflow_id,
                user_id=report.user_id,
                title=report.name,  # Map name to title
                description=report.summary or "",  # Map summary to description
                report_type=ReportType(report.report_type.value) if hasattr(report.report_type, 'value') else ReportType.TECHNICAL_DETAILED,
                format=ReportFormat(report.format.value) if hasattr(report.format, 'value') else ReportFormat.MARKDOWN,
                status=ReportStatus(report.status.value) if hasattr(report.status, 'value') else ReportStatus.COMPLETED,
                sections=sections,
                include_passive_recon=getattr(report, 'include_passive_recon', True),
                include_active_recon=getattr(report, 'include_active_recon', True),
                include_vulnerabilities=getattr(report, 'include_vulnerabilities', True),
                include_kill_chain=getattr(report, 'include_kill_chain', True),
                include_screenshots=getattr(report, 'include_screenshots', True),
                include_raw_data=getattr(report, 'include_raw_data', False),
                custom_template=getattr(report, 'custom_template', None),
                file_path=report.file_path,
                file_size=report.file_size,
                generation_time=getattr(report, 'generation_time', None),
                error_message=getattr(report, 'error_message', None),
                metadata=report.configuration or {},
                created_at=report.created_at,
                updated_at=report.updated_at,
                generated_at=getattr(report, 'generated_at', None)
            )
            
            return APIResponse(
                success=True,
                message="Report generation started successfully",
                data={
                    "report_id": str(report.id),
                    "status": report.status.value if hasattr(report.status, 'value') else report.status
                }
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error generating report for workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to generate report", errors=[str(e)])
    
    async def generate_workflow_report(self, workflow_id: UUID, template: str = "default") -> APIResponse:
        """
        Generate a report for a specific workflow (workflow-specific endpoint).
        
        Args:
            workflow_id: Workflow ID
            template: Report template to use
            
        Returns:
            APIResponse with generated report data
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise NotFoundError(f"Workflow with ID {workflow_id} not found")
            
            # Generate report content
            report_content = await self._generate_report_content(workflow, template)
            
            # Check if report already exists for this workflow
            existing_reports = await self.report_repository.list(
                filters={"workflow_id": workflow_id},
                limit=1
            )
            
            if existing_reports:
                existing_report = existing_reports[0]
                # Update existing report
                update_data = {
                    "content": json.dumps(report_content),
                    "template_used": template,
                    "status": ReportStatus.COMPLETED.name,
                    "updated_at": datetime.now(timezone.utc)
                }
                report = await self.report_repository.update(existing_report.id, **update_data)
            else:
                # Create new report
                report_data = {
                    "workflow_id": workflow_id,
                    "target_id": workflow.target_id,
                    "name": f"Security Assessment Report - {workflow.name}",
                    "report_type": ReportType.TECHNICAL_DETAILED.name,
                    "format": ReportFormat.MARKDOWN.name,
                    "content": json.dumps(report_content),
                    "status": ReportStatus.COMPLETED.name,
                    "template_used": template,
                    "configuration": {"template": template, "format": ReportFormat.MARKDOWN.name},
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                }
                report = await self.report_repository.create(**report_data)
            
            # Update workflow status to COMPLETED after report generation
            await self.workflow_repository.update(workflow_id, status=WorkflowStatus.COMPLETED, updated_at=datetime.now(timezone.utc))
            await self.workflow_repository.session.commit()

            logger.info(f"Generated workflow report {report.id} for workflow {workflow_id}")
            
            return APIResponse(
                success=True,
                message="Workflow report generation started successfully",
                data={
                    "report_id": str(report.id),
                    "status": report.status.value if hasattr(report.status, 'value') else report.status
                }
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error generating workflow report for workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to generate workflow report", errors=[str(e)])
    
    async def export_report(self, report_id: UUID, payload: ReportExportRequest) -> APIResponse:
        """
        Export report in specified format.
        
        Args:
            report_id: Report ID
            payload: Export configuration
            
        Returns:
            APIResponse with export data
        """
        try:
            report = await self.report_repository.get_by_id(report_id)
            if not report:
                raise NotFoundError(f"Report with ID {report_id} not found")
            
            # Export report in specified format
            export_data = await self._export_report_content(report, payload.format)
            
            return APIResponse(
                success=True,
                message="Report export started successfully",
                data={
                    "report_id": report_id,
                    "export_id": str(report_id),
                    "status": "pending",
                    "format": payload.format,
                    "content": export_data,
                    "filename": f"report_{report_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.{payload.format}"
                }
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error exporting report {report_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to export report", errors=[str(e)])
    
    async def get_report_templates(self) -> APIResponse:
        """
        Get available report templates.
        
        Returns:
            APIResponse with available templates
        """
        try:
            logger.info("Creating report templates...")
            
            # Use enum values for sections
            template1 = ReportTemplateResponse(
                id=uuid4(),
                name="default",
                description="Standard security assessment report template",
                report_type=ReportType.EXECUTIVE_SUMMARY,
                format=ReportFormat.MARKDOWN,
                sections=[
                    ReportSection.EXECUTIVE_SUMMARY,
                    ReportSection.METHODOLOGY,
                    ReportSection.FINDINGS,
                    ReportSection.RECOMMENDATIONS,
                    ReportSection.APPENDIX
                ],
                is_default=True,
                version="1.0"
            )
            logger.info(f"Created template1: {template1.model_dump()}")
            
            template2 = ReportTemplateResponse(
                id=uuid4(),
                name="executive",
                description="Executive summary focused report template",
                report_type=ReportType.EXECUTIVE_SUMMARY,
                format=ReportFormat.MARKDOWN,
                sections=[
                    ReportSection.EXECUTIVE_SUMMARY,
                    ReportSection.FINDINGS,
                    ReportSection.RECOMMENDATIONS
                ],
                version="1.0"
            )
            logger.info(f"Created template2: {template2.model_dump()}")
            
            template3 = ReportTemplateResponse(
                id=uuid4(),
                name="technical",
                description="Technical detailed report template",
                report_type=ReportType.TECHNICAL_DETAILED,
                format=ReportFormat.MARKDOWN,
                sections=[
                    ReportSection.METHODOLOGY,
                    ReportSection.FINDINGS,
                    ReportSection.VULNERABILITIES,
                    ReportSection.ATTACK_PATHS,
                    ReportSection.RECOMMENDATIONS,
                    ReportSection.APPENDIX
                ],
                version="1.0"
            )
            logger.info(f"Created template3: {template3.model_dump()}")
            
            template4 = ReportTemplateResponse(
                id=uuid4(),
                name="compliance",
                description="Compliance focused report template",
                report_type=ReportType.COMPLIANCE,
                format=ReportFormat.MARKDOWN,
                sections=[
                    ReportSection.EXECUTIVE_SUMMARY,
                    ReportSection.FINDINGS,
                    ReportSection.RECOMMENDATIONS,
                    ReportSection.APPENDIX
                ],
                version="1.0"
            )
            logger.info(f"Created template4: {template4.model_dump()}")
            
            templates = [template1, template2, template3, template4]
            
            # Convert to dict with debug logging
            template_dicts = []
            for i, template in enumerate(templates):
                try:
                    template_dict = template.model_dump()
                    template_dicts.append(template_dict)
                    logger.info(f"Successfully converted template {i+1} to dict")
                except Exception as e:
                    logger.error(f"Error converting template {i+1} to dict: {str(e)}")
                    raise
            
            response_data = {"templates": template_dicts}
            logger.info(f"Final response data: {response_data}")
            
            return APIResponse(
                success=True,
                message="Report templates retrieved successfully",
                data=response_data
            )
            
        except Exception as e:
            logger.error(f"Error retrieving report templates: {str(e)}")
            logger.error(f"Exception type: {type(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return APIResponse(success=False, message="Failed to retrieve report templates", errors=[str(e)])
    
    async def _generate_report_content(self, workflow, template: str) -> Dict[str, Any]:
        """
        Generate report content based on workflow data and template.
        
        Args:
            workflow: Workflow instance
            template: Report template name
            
        Returns:
            Report content dictionary
        """
        try:
            # Get workflow and target information
            target = await self.target_repository.get_by_id(workflow.target_id)
            
            # Collect data from all stages
            passive_recon_results = await self.passive_recon_repository.get_by_workflow_id(workflow.id)
            active_recon_results = await self.active_recon_repository.get_by_workflow_id(workflow.id)
            vulnerability_results = await self.vulnerability_repository.get_by_workflow_id(workflow.id)
            kill_chain_results = await self.kill_chain_repository.get_by_workflow_id(workflow.id)
            
            # Generate report sections based on template
            report_sections = {}
            
            if "executive_summary" in self._get_template_sections(template):
                report_sections["executive_summary"] = self._generate_executive_summary(
                    target, workflow, vulnerability_results, kill_chain_results
                )
            
            if "methodology" in self._get_template_sections(template):
                report_sections["methodology"] = self._generate_methodology_section(
                    workflow, passive_recon_results, active_recon_results
                )
            
            if "findings" in self._get_template_sections(template):
                report_sections["findings"] = self._generate_findings_section(
                    vulnerability_results, kill_chain_results
                )
            
            if "recommendations" in self._get_template_sections(template):
                report_sections["recommendations"] = self._generate_recommendations_section(
                    vulnerability_results, kill_chain_results
                )
            
            if "appendix" in self._get_template_sections(template):
                report_sections["appendix"] = self._generate_appendix_section(
                    passive_recon_results, active_recon_results, vulnerability_results
                )
            
            return {
                "workflow_id": str(workflow.id),
                "target": {
                    "id": str(target.id),
                    "domain": target.value,
                    "description": target.name
                },
                "template": template,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "sections": report_sections
            }
            
        except Exception as e:
            logger.error(f"Error generating report content: {str(e)}")
            raise ReportGenerationError(f"Failed to generate report content: {str(e)}")
    
    def _get_template_sections(self, template: str) -> List[str]:
        """Get sections for a specific template."""
        template_sections = {
            "default": ["executive_summary", "methodology", "findings", "recommendations", "appendix"],
            "executive": ["executive_summary", "findings", "recommendations"],
            "technical": ["methodology", "findings", "vulnerabilities", "attack_paths", "recommendations", "appendix"],
            "compliance": ["executive_summary", "findings", "recommendations", "appendix"]
        }
        return template_sections.get(template, template_sections["default"])
    
    def _generate_executive_summary(self, target, workflow, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate executive summary section."""
        return {
            "target_overview": f"Security assessment for {target.name} ({target.value})",
            "assessment_scope": f"Comprehensive security assessment covering {len(vulnerabilities)} vulnerabilities and {len(kill_chains)} attack paths",
            "key_findings": {
                "critical_vulnerabilities": len([v for v in vulnerabilities if getattr(v, 'severity', '').lower() == 'critical']),
                "high_vulnerabilities": len([v for v in vulnerabilities if getattr(v, 'severity', '').lower() == 'high']),
                "medium_vulnerabilities": len([v for v in vulnerabilities if getattr(v, 'severity', '').lower() == 'medium']),
                "low_vulnerabilities": len([v for v in vulnerabilities if getattr(v, 'severity', '').lower() == 'low']),
                "attack_paths": len(kill_chains)
            },
            "risk_level": "High" if len([v for v in vulnerabilities if getattr(v, 'severity', '').lower() in ['critical', 'high']]) > 0 else "Medium"
        }
    
    def _generate_executive_summary_simple(self, target, workflow, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate executive summary section (alias for compatibility)."""
        return self._generate_executive_summary(target, workflow, vulnerabilities, kill_chains)
    
    def _generate_methodology_section(self, workflow, passive_recon, active_recon) -> Dict[str, Any]:
        """Generate methodology section."""
        return {
            "approach": "Comprehensive security assessment using industry-standard tools and methodologies",
            "stages": [
                {
                    "name": "Passive Reconnaissance",
                    "description": "Information gathering without direct interaction with target systems",
                    "tools_used": ["subfinder", "amass", "assetfinder"],
                    "results_count": len(passive_recon)
                },
                {
                    "name": "Active Reconnaissance", 
                    "description": "Direct interaction with target systems to identify open ports and services",
                    "tools_used": ["nmap", "httpx"],
                    "results_count": len(active_recon)
                },
                {
                    "name": "Vulnerability Assessment",
                    "description": "Automated and manual testing for security vulnerabilities",
                    "tools_used": ["nuclei", "sqlmap", "custom scripts"],
                    "results_count": 0  # Will be updated when vulnerabilities are processed
                }
            ]
        }
    
    def _generate_findings_section(self, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate findings section."""
        return {
            "vulnerabilities": [
                {
                    "id": str(getattr(v, 'id', uuid4())),
                    "title": getattr(v, 'title', 'Unknown Vulnerability'),
                    "severity": getattr(v, 'severity', 'unknown'),
                    "description": getattr(v, 'description', 'No description available'),
                    "cvss_score": getattr(v, 'cvss_score', 0.0),
                    "status": getattr(v, 'status', 'open'),
                    "affected_components": getattr(v, 'affected_components', []),
                    "proof_of_concept": getattr(v, 'proof_of_concept', ''),
                    "remediation": getattr(v, 'remediation', '')
                }
                for v in vulnerabilities
            ],
            "attack_paths": [
                {
                    "id": str(getattr(kc, 'id', uuid4())),
                    "name": getattr(kc, 'name', 'Unknown Attack Path'),
                    "description": getattr(kc, 'description', 'No description available'),
                    "risk_level": getattr(kc, 'risk_level', 'unknown'),
                    "steps": getattr(kc, 'steps', []),
                    "status": getattr(kc, 'status', 'identified')
                }
                for kc in kill_chains
            ]
        }
    
    def _generate_findings_section_simple(self, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate findings section (alias for compatibility)."""
        return self._generate_findings_section(vulnerabilities, kill_chains)
    
    def _generate_recommendations_section(self, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate recommendations section."""
        recommendations = []
        
        # Add recommendations for critical and high vulnerabilities
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', '').lower()
            if severity in ['critical', 'high']:
                recommendations.append({
                    "title": f"Fix {getattr(vuln, 'title', 'Vulnerability')}",
                    "priority": severity,
                    "type": "vulnerability_remediation",
                    "description": f"Address the {severity} severity vulnerability: {getattr(vuln, 'description', 'No description available')}",
                    "affected_component": getattr(vuln, 'affected_component', 'Unknown'),
                    "estimated_effort": "Medium" if severity == 'high' else "High"
                })
        
        # Add recommendations for high-risk attack paths
        for kc in kill_chains:
            risk_level = getattr(kc, 'risk_level', '').lower()
            if risk_level == 'high':
                recommendations.append({
                    "title": f"Mitigate {getattr(kc, 'name', 'Attack Path')}",
                    "priority": "high",
                    "type": "attack_path_mitigation",
                    "description": f"Implement controls to prevent the high-risk attack path: {getattr(kc, 'description', 'No description available')}",
                    "affected_component": "System-wide",
                    "estimated_effort": "High"
                })
        
        return {
            "recommendations": recommendations,
            "priority_summary": {
                "critical": len([r for r in recommendations if r["priority"] == "critical"]),
                "high": len([r for r in recommendations if r["priority"] == "high"]),
                "medium": len([r for r in recommendations if r["priority"] == "medium"]),
                "low": len([r for r in recommendations if r["priority"] == "low"])
            }
        }
    
    def _generate_recommendations_section_simple(self, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate recommendations section (alias for compatibility)."""
        return self._generate_recommendations_section(vulnerabilities, kill_chains)
    
    def _generate_appendix_section(self, passive_recon, active_recon, vulnerabilities) -> Dict[str, Any]:
        """Generate appendix section with detailed results."""
        # Aggregate subdomains from passive recon
        subdomains = []
        for pr in passive_recon:
            if hasattr(pr, 'subdomains') and pr.subdomains:
                # Handle both list and dict formats
                if isinstance(pr.subdomains, list):
                    subdomains.extend([s.name if hasattr(s, 'name') else str(s) for s in pr.subdomains])
                elif isinstance(pr.subdomains, dict):
                    subdomains.extend([s.get('name', str(s)) for s in pr.subdomains.values()])
            elif hasattr(pr, 'subdomain') and pr.subdomain:
                subdomains.append(pr.subdomain)
        
        return {
            "discovered_subdomains": list(set(subdomains)),  # Remove duplicates
            "active_recon_summary": f"{len(active_recon)} active recon results",
            "vulnerability_summary": f"{len(vulnerabilities)} vulnerability scan results",
            "detailed_results": {
                "passive_reconnaissance": [
                    {
                        "id": str(getattr(pr, 'id', uuid4())),
                        "subdomain": getattr(pr, 'subdomain', 'Unknown'),
                        "ip_address": getattr(pr, 'ip_address', 'Unknown'),
                        "source": getattr(pr, 'source', 'Unknown'),
                        "discovered_at": getattr(pr, 'created_at', datetime.now(timezone.utc)).isoformat()
                    }
                    for pr in passive_recon
                ],
                "active_reconnaissance": [
                    {
                        "id": str(getattr(ar, 'id', uuid4())),
                        "host": getattr(ar, 'host', 'Unknown'),
                        "port": getattr(ar, 'port', 0),
                        "service": getattr(ar, 'service', 'Unknown'),
                        "status": getattr(ar, 'status', 'Unknown'),
                        "scanned_at": getattr(ar, 'created_at', datetime.now(timezone.utc)).isoformat()
                    }
                    for ar in active_recon
                ]
            },
            "tools_used": {
                "passive_recon": ["subfinder", "amass", "assetfinder"],
                "active_recon": ["nmap", "httpx"],
                "vulnerability_scan": ["nuclei", "custom_scripts"]
            }
        }
    
    async def _export_report_content(self, report, format_type: str) -> str:
        """
        Export report content in specified format.
        
        Args:
            report: Report object
            format_type: Export format
            
        Returns:
            Exported content as string
        """
        try:
            # Parse the JSON content if it's a string
            if isinstance(report.content, str):
                content_data = json.loads(report.content)
            else:
                content_data = report.content
            
            if format_type == "JSON":
                return json.dumps(content_data, indent=2)
            
            elif format_type == "CSV":
                # Convert report content to CSV format
                csv_data = []
                if "findings" in content_data.get("sections", {}):
                    findings = content_data["sections"]["findings"]
                    if "vulnerabilities" in findings:
                        for vuln in findings["vulnerabilities"]:
                            csv_data.append({
                                "ID": vuln["id"],
                                "Title": vuln["title"],
                                "Severity": vuln["severity"],
                                "Description": vuln["description"],
                                "CVSS Score": vuln.get("cvss_score", ""),
                                "Status": vuln["status"]
                            })
                
                if csv_data:
                    output = []
                    if csv_data:
                        fieldnames = csv_data[0].keys()
                        writer = csv.DictWriter(output, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(csv_data)
                    return "".join(output)
                else:
                    return "No data to export"
            
            elif format_type == "MARKDOWN":
                return self._convert_to_markdown(content_data)
            
            elif format_type == "PDF":
                # For now, return markdown content as PDF is not fully implemented
                # In a real implementation, you would use a library like weasyprint or reportlab
                markdown_content = self._convert_to_markdown(content_data)
                return f"PDF Export (Markdown content):\n\n{markdown_content}"
            
            else:
                raise ExportError(f"Unsupported export format: {format_type}")
                
        except Exception as e:
            logger.error(f"Error exporting report content: {str(e)}")
            raise ExportError(f"Failed to export report content: {str(e)}")
    
    def _convert_to_markdown(self, content: Dict[str, Any]) -> str:
        """Convert report content to Markdown format."""
        md_lines = []
        
        # Title
        md_lines.append(f"# {content.get('target', {}).get('domain', 'Security Assessment Report')}")
        md_lines.append("")
        
        # Generate date
        md_lines.append(f"**Generated:** {content.get('generated_at', 'Unknown')}")
        md_lines.append("")
        
        # Sections
        sections = content.get("sections", {})
        
        if "executive_summary" in sections:
            md_lines.append("## Executive Summary")
            md_lines.append("")
            summary = sections["executive_summary"]
            md_lines.append(f"**Target:** {summary.get('target_overview', 'N/A')}")
            md_lines.append(f"**Risk Level:** {summary.get('risk_level', 'N/A')}")
            md_lines.append("")
            
            key_findings = summary.get("key_findings", {})
            md_lines.append("### Key Findings")
            md_lines.append(f"- Critical Vulnerabilities: {key_findings.get('critical_vulnerabilities', 0)}")
            md_lines.append(f"- High Vulnerabilities: {key_findings.get('high_vulnerabilities', 0)}")
            md_lines.append(f"- Medium Vulnerabilities: {key_findings.get('medium_vulnerabilities', 0)}")
            md_lines.append(f"- Low Vulnerabilities: {key_findings.get('low_vulnerabilities', 0)}")
            md_lines.append(f"- Attack Paths: {key_findings.get('attack_paths', 0)}")
            md_lines.append("")
        
        if "findings" in sections:
            md_lines.append("## Findings")
            md_lines.append("")
            findings = sections["findings"]
            
            if "vulnerabilities" in findings:
                md_lines.append("### Vulnerabilities")
                md_lines.append("")
                for vuln in findings["vulnerabilities"]:
                    md_lines.append(f"#### {vuln['title']}")
                    md_lines.append(f"**Severity:** {vuln['severity'].upper()}")
                    md_lines.append(f"**CVSS Score:** {vuln.get('cvss_score', 'N/A')}")
                    md_lines.append(f"**Status:** {vuln['status']}")
                    md_lines.append("")
                    md_lines.append(f"**Description:** {vuln['description']}")
                    md_lines.append("")
        
        if "recommendations" in sections:
            md_lines.append("## Recommendations")
            md_lines.append("")
            recommendations = sections["recommendations"].get("recommendations", [])
            for i, rec in enumerate(recommendations, 1):
                md_lines.append(f"### {i}. {rec['title']}")
                md_lines.append(f"**Priority:** {rec['priority'].upper()}")
                md_lines.append(f"**Type:** {rec['type']}")
                md_lines.append("")
                md_lines.append(f"{rec['description']}")
                md_lines.append("")
        
        return "\n".join(md_lines)

    async def get_workflow_reports(
        self,
        workflow_id: UUID,
        limit: int = 10,
        offset: int = 0
    ) -> APIResponse:
        """
        Get reports for a specific workflow.
        
        Args:
            workflow_id: Workflow ID
            limit: Number of reports to return
            offset: Number of reports to skip
            
        Returns:
            APIResponse with workflow reports
        """
        try:
            # Check if workflow exists
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                return APIResponse(
                    success=False,
                    message=f"Workflow with ID {workflow_id} not found",
                    errors=[f"Workflow with ID {workflow_id} not found"]
                )
            
            # Use the existing get_reports method with workflow_id filter
            result = await self.get_reports(
                limit=limit,
                offset=offset,
                workflow_id=workflow_id
            )
            
            # Update the message to be workflow-specific
            if result.success:
                result.message = "Workflow reports retrieved successfully"
            
            return result
            
        except Exception as e:
            logger.error(f"Error retrieving workflow reports: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve workflow reports", errors=[str(e)]) 
