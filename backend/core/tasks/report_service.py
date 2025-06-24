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
    ReportType
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
                "title": payload.title or f"Security Assessment Report - {workflow.name}",
                "description": payload.description,
                "template": payload.template,
                "format": payload.format,
                "content": report_content,
                "status": "draft",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            
            report = await self.report_repository.create(report_data)
            
            logger.info(f"Created report {report.id} for workflow {payload.workflow_id}")
            
            return APIResponse(
                success=True,
                message="Report created successfully",
                data=ReportResponse.model_validate(report, from_attributes=True).model_dump()
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
            
            return APIResponse(
                success=True,
                message="Report retrieved successfully",
                data=ReportResponse.model_validate(report, from_attributes=True).model_dump()
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
            reports = await self.report_repository.list(
                limit=limit,
                offset=offset,
                workflow_id=workflow_id,
                status=status
            )
            
            total_count = await self.report_repository.count(
                workflow_id=workflow_id,
                status=status
            )
            
            report_list = [ReportResponse.model_validate(r, from_attributes=True).model_dump() for r in reports]
            
            return APIResponse(
                success=True,
                message="Reports retrieved successfully",
                data=ReportListResponse(
                    reports=report_list,
                    total=total_count,
                    page=offset // limit + 1 if limit > 0 else 1,
                    per_page=limit
                ).model_dump()
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
                update_data["title"] = payload.title
            if payload.description is not None:
                update_data["description"] = payload.description
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
            
            return APIResponse(
                success=True,
                message="Report updated successfully",
                data=ReportResponse.model_validate(updated_report, from_attributes=True).model_dump()
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
                    "content": report_content,
                    "template": template,
                    "status": "generated",
                    "updated_at": datetime.now(timezone.utc)
                }
                report = await self.report_repository.update(existing_report.id, **update_data)
            else:
                # Create new report
                report_data = {
                    "workflow_id": workflow_id,
                    "title": f"Security Assessment Report - {workflow.name}",
                    "description": f"Automated security assessment report for {workflow.name}",
                    "template": template,
                    "format": ReportFormat.MARKDOWN,
                    "content": report_content,
                    "status": "generated",
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                }
                report = await self.report_repository.create(report_data)
            
            logger.info(f"Generated report {report.id} for workflow {workflow_id}")
            
            return APIResponse(
                success=True,
                message="Report generated successfully",
                data=ReportResponse.model_validate(report, from_attributes=True).model_dump()
            )
            
        except NotFoundError as e:
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Error generating report for workflow {workflow_id}: {str(e)}")
            return APIResponse(success=False, message="Failed to generate report", errors=[str(e)])
    
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
                message="Report exported successfully",
                data={
                    "report_id": report_id,
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
            templates = [
                ReportTemplateResponse(
                    id=uuid4(),
                    name="default",
                    description="Standard security assessment report template",
                    report_type=ReportType.EXECUTIVE_SUMMARY,
                    format=ReportFormat.MARKDOWN,
                    sections=["executive_summary", "methodology", "findings", "recommendations", "appendix"],
                    is_default=True
                ),
                ReportTemplateResponse(
                    id=uuid4(),
                    name="executive",
                    description="Executive summary focused report template",
                    report_type=ReportType.EXECUTIVE_SUMMARY,
                    format=ReportFormat.MARKDOWN,
                    sections=["executive_summary", "findings", "recommendations"]
                ),
                ReportTemplateResponse(
                    id=uuid4(),
                    name="technical",
                    description="Technical detailed report template",
                    report_type=ReportType.TECHNICAL_DETAILED,
                    format=ReportFormat.MARKDOWN,
                    sections=["methodology", "findings", "vulnerabilities", "attack_paths", "recommendations", "appendix"]
                ),
                ReportTemplateResponse(
                    id=uuid4(),
                    name="compliance",
                    description="Compliance focused report template",
                    report_type=ReportType.COMPLIANCE,
                    format=ReportFormat.MARKDOWN,
                    sections=["executive_summary", "findings", "recommendations", "appendix"]
                )
            ]
            
            return APIResponse(
                success=True,
                message="Report templates retrieved successfully",
                data={"templates": [t.model_dump() for t in templates]}
            )
            
        except Exception as e:
            logger.error(f"Error retrieving report templates: {str(e)}")
            return APIResponse(success=False, message="Failed to retrieve report templates", errors=[str(e)])
    
    async def _generate_report_content(self, workflow, template: str) -> Dict[str, Any]:
        """
        Generate report content by aggregating data from all stages.
        
        Args:
            workflow: Workflow object
            template: Report template
            
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
        critical_count = sum(1 for v in vulnerabilities if v.severity == "critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "high")
        medium_count = sum(1 for v in vulnerabilities if v.severity == "medium")
        low_count = sum(1 for v in vulnerabilities if v.severity == "low")
        
        return {
            "target_overview": f"Security assessment conducted for {target.value}",
            "assessment_scope": "Comprehensive security testing including reconnaissance, vulnerability scanning, and attack path analysis",
            "key_findings": {
                "critical_vulnerabilities": critical_count,
                "high_vulnerabilities": high_count,
                "medium_vulnerabilities": medium_count,
                "low_vulnerabilities": low_count,
                "attack_paths": len(kill_chains)
            },
            "risk_level": "High" if critical_count > 0 or high_count > 5 else "Medium" if high_count > 0 else "Low"
        }
    
    def _generate_methodology_section(self, workflow, passive_recon, active_recon) -> Dict[str, Any]:
        """Generate methodology section."""
        return {
            "approach": "Automated security assessment using industry-standard tools and methodologies",
            "stages": [
                {
                    "name": "Passive Reconnaissance",
                    "description": "Information gathering without direct interaction",
                    "tools_used": ["subfinder", "amass", "assetfinder"],
                    "results_count": len(passive_recon)
                },
                {
                    "name": "Active Reconnaissance",
                    "description": "Direct interaction with target systems",
                    "tools_used": ["nmap", "httpx"],
                    "results_count": len(active_recon)
                },
                {
                    "name": "Vulnerability Assessment",
                    "description": "Automated vulnerability scanning and testing",
                    "tools_used": ["nuclei", "custom_scripts"],
                    "results_count": "See findings section"
                }
            ]
        }
    
    def _generate_findings_section(self, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate findings section."""
        return {
            "vulnerabilities": [
                {
                    "id": str(v.id),
                    "title": v.title,
                    "severity": v.severity,
                    "description": v.description,
                    "cvss_score": v.cvss_score,
                    "status": v.status
                }
                for v in vulnerabilities
            ],
            "attack_paths": [
                {
                    "id": str(kc.id),
                    "name": kc.name,
                    "description": kc.description,
                    "risk_level": kc.risk_level,
                    "steps": kc.steps
                }
                for kc in kill_chains
            ]
        }
    
    def _generate_recommendations_section(self, vulnerabilities, kill_chains) -> Dict[str, Any]:
        """Generate recommendations section."""
        recommendations = []
        
        # Add vulnerability-based recommendations
        for vuln in vulnerabilities:
            if vuln.severity in ["critical", "high"]:
                recommendations.append({
                    "type": "vulnerability_remediation",
                    "priority": "high",
                    "title": f"Fix {vuln.title}",
                    "description": f"Address {vuln.title} vulnerability with {vuln.severity} severity",
                    "affected_systems": vuln.affected_systems
                })
        
        # Add attack path-based recommendations
        for kc in kill_chains:
            if kc.risk_level in ["high", "critical"]:
                recommendations.append({
                    "type": "attack_path_mitigation",
                    "priority": "high",
                    "title": f"Mitigate {kc.name} attack path",
                    "description": f"Implement controls to prevent {kc.name} attack path",
                    "controls": ["network_segmentation", "access_controls", "monitoring"]
                })
        
        return {"recommendations": recommendations}
    
    def _generate_appendix_section(self, passive_recon, active_recon, vulnerabilities) -> Dict[str, Any]:
        """Generate appendix section."""
        return {
            "detailed_results": {
                "passive_reconnaissance": [
                    {
                        "id": str(pr.id),
                        "subdomain": pr.subdomain,
                        "ip_address": pr.ip_address,
                        "source": pr.source
                    }
                    for pr in passive_recon
                ],
                "active_reconnaissance": [
                    {
                        "id": str(ar.id),
                        "host": ar.host,
                        "port": ar.port,
                        "service": ar.service,
                        "status": ar.status
                    }
                    for ar in active_recon
                ]
            },
            "tools_used": [
                "subfinder", "amass", "assetfinder", "nmap", "httpx", "nuclei"
            ]
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
            if format_type == "json":
                return json.dumps(report.content, indent=2)
            
            elif format_type == "csv":
                # Convert report content to CSV format
                csv_data = []
                if "findings" in report.content.get("sections", {}):
                    findings = report.content["sections"]["findings"]
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
            
            elif format_type == "markdown":
                return self._convert_to_markdown(report.content)
            
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
