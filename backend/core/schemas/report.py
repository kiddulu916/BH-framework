"""
Report schemas for the Bug Hunting Framework.

This module contains Pydantic schemas for report generation,
report formats, and related data structures.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, field_validator, HttpUrl, ConfigDict

from .base import APIResponse


class ReportFormat(str, Enum):
    """Report format enumeration."""
    PDF = "PDF"
    HTML = "HTML"
    MARKDOWN = "MARKDOWN"
    JSON = "JSON"
    XML = "XML"
    CSV = "CSV"


class ReportStatus(str, Enum):
    """Report status enumeration."""
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ReportType(str, Enum):
    """Report type enumeration."""
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    TECHNICAL_DETAILED = "TECHNICAL_DETAILED"
    COMPLIANCE = "COMPLIANCE"
    REMEDIATION = "REMEDIATION"
    CUSTOM = "CUSTOM"


class ReportSection(str, Enum):
    """Report section enumeration."""
    EXECUTIVE_SUMMARY = "executive_summary"
    METHODOLOGY = "methodology"
    FINDINGS = "findings"
    VULNERABILITIES = "vulnerabilities"
    ATTACK_PATHS = "attack_paths"
    RECOMMENDATIONS = "recommendations"
    APPENDIX = "appendix"


class ReportCreate(BaseModel):
    """Schema for creating a report."""
    
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    user_id: Optional[UUID] = Field(None, description="User ID who requested the report")
    title: str = Field(..., min_length=1, max_length=255, description="Report title")
    description: Optional[str] = Field(None, max_length=1000, description="Report description")
    report_type: ReportType = Field(..., description="Type of report")
    format: ReportFormat = Field(..., description="Report format")
    sections: List[ReportSection] = Field(default_factory=list, description="Report sections to include")
    include_passive_recon: bool = Field(default=True, description="Include passive reconnaissance data")
    include_active_recon: bool = Field(default=True, description="Include active reconnaissance data")
    include_vulnerabilities: bool = Field(default=True, description="Include vulnerability findings")
    include_kill_chain: bool = Field(default=True, description="Include kill chain analysis")
    include_screenshots: bool = Field(default=True, description="Include screenshots")
    include_raw_data: bool = Field(default=False, description="Include raw tool outputs")
    custom_template: Optional[str] = Field(None, description="Custom report template")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('sections')
    def validate_sections(cls, v):
        """Validate that sections are valid report sections."""
        valid_sections = [
            'executive_summary', 'methodology', 'findings', 'vulnerabilities',
            'attack_paths', 'recommendations', 'appendix'
        ]
        for section in v:
            if section not in valid_sections:
                raise ValueError(f"Invalid report section: {section}. Valid sections: {valid_sections}")
        return v


class ReportUpdate(BaseModel):
    """Schema for updating a report."""
    
    title: Optional[str] = Field(None, min_length=1, max_length=255, description="Report title")
    description: Optional[str] = Field(None, max_length=1000, description="Report description")
    report_type: Optional[ReportType] = Field(None, description="Type of report")
    format: Optional[ReportFormat] = Field(None, description="Report format")
    sections: Optional[List[ReportSection]] = Field(None, description="Report sections to include")
    include_passive_recon: Optional[bool] = Field(None, description="Include passive reconnaissance data")
    include_active_recon: Optional[bool] = Field(None, description="Include active reconnaissance data")
    include_vulnerabilities: Optional[bool] = Field(None, description="Include vulnerability findings")
    include_kill_chain: Optional[bool] = Field(None, description="Include kill chain analysis")
    include_screenshots: Optional[bool] = Field(None, description="Include screenshots")
    include_raw_data: Optional[bool] = Field(None, description="Include raw tool outputs")
    custom_template: Optional[str] = Field(None, description="Custom report template")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    @field_validator('sections')
    def validate_sections(cls, v):
        """Validate that sections are valid report sections."""
        if v is None:
            return v
        valid_sections = [
            'executive_summary', 'methodology', 'findings', 'vulnerabilities',
            'attack_paths', 'recommendations', 'appendix'
        ]
        for section in v:
            if section not in valid_sections:
                raise ValueError(f"Invalid report section: {section}. Valid sections: {valid_sections}")
        return v


class ReportResponse(BaseModel):
    """Schema for report response."""
    
    id: UUID = Field(..., description="Report ID")
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    user_id: Optional[UUID] = Field(None, description="User ID who requested the report")
    title: str = Field(..., description="Report title")
    description: Optional[str] = Field(None, description="Report description")
    report_type: ReportType = Field(..., description="Type of report")
    format: ReportFormat = Field(..., description="Report format")
    status: ReportStatus = Field(..., description="Report status")
    sections: List[ReportSection] = Field(..., description="Report sections included")
    include_passive_recon: bool = Field(..., description="Include passive reconnaissance data")
    include_active_recon: bool = Field(..., description="Include active reconnaissance data")
    include_vulnerabilities: bool = Field(..., description="Include vulnerability findings")
    include_kill_chain: bool = Field(..., description="Include kill chain analysis")
    include_screenshots: bool = Field(..., description="Include screenshots")
    include_raw_data: bool = Field(..., description="Include raw tool outputs")
    custom_template: Optional[str] = Field(None, description="Custom report template")
    file_path: Optional[str] = Field(None, description="Generated report file path")
    file_size: Optional[int] = Field(None, ge=0, description="Report file size in bytes")
    generation_time: Optional[float] = Field(None, ge=0, description="Report generation time in seconds")
    error_message: Optional[str] = Field(None, description="Error message if generation failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    generated_at: Optional[datetime] = Field(None, description="Generation completion timestamp")
    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
    """Schema for report list response."""
    
    reports: List[ReportResponse] = Field(..., description="List of reports")
    total: int = Field(..., description="Total number of reports")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")


class ReportSummary(BaseModel):
    """Schema for report summary."""
    
    target_id: UUID = Field(..., description="Target ID")
    total_reports: int = Field(..., description="Total reports")
    completed_reports: int = Field(..., description="Completed reports count")
    failed_reports: int = Field(..., description="Failed reports count")
    pending_reports: int = Field(..., description="Pending reports count")
    formats_used: List[ReportFormat] = Field(..., description="Report formats used")
    types_used: List[ReportType] = Field(..., description="Report types used")
    last_generation: Optional[datetime] = Field(None, description="Last report generation timestamp")
    total_file_size: int = Field(default=0, description="Total file size of all reports")


class ReportFilter(BaseModel):
    """Schema for filtering reports."""
    
    target_id: Optional[UUID] = Field(None, description="Filter by target ID")
    user_id: Optional[UUID] = Field(None, description="Filter by user ID")
    report_type: Optional[ReportType] = Field(None, description="Filter by report type")
    format: Optional[ReportFormat] = Field(None, description="Filter by report format")
    status: Optional[ReportStatus] = Field(None, description="Filter by report status")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")
    generated_after: Optional[datetime] = Field(None, description="Filter by generation date (after)")
    generated_before: Optional[datetime] = Field(None, description="Filter by generation date (before)")


class ReportGenerationRequest(BaseModel):
    """Schema for report generation request."""
    
    report_id: UUID = Field(..., description="Report ID to generate")
    priority: int = Field(default=0, ge=0, le=10, description="Generation priority (0-10)")
    force_regenerate: bool = Field(default=False, description="Force regeneration if report exists")
    config_overrides: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Configuration overrides")


class ReportGenerationResponse(BaseModel):
    """Schema for report generation response."""
    
    report_id: UUID = Field(..., description="Report ID")
    status: ReportStatus = Field(..., description="Generation status")
    message: str = Field(..., description="Status message")
    estimated_time: Optional[float] = Field(None, ge=0, description="Estimated generation time in seconds")
    progress: Optional[float] = Field(None, ge=0, le=100, description="Generation progress (0-100)")


class ReportTemplate(BaseModel):
    """Schema for report template."""
    
    id: UUID = Field(..., description="Template ID")
    name: str = Field(..., description="Template name")
    description: Optional[str] = Field(None, description="Template description")
    report_type: ReportType = Field(..., description="Report type")
    format: ReportFormat = Field(..., description="Report format")
    sections: List[ReportSection] = Field(..., description="Template sections")
    template_content: str = Field(..., description="Template content")
    is_default: bool = Field(default=False, description="Is default template")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


# API Response schemas
class ReportCreateResponse(APIResponse):
    """Response schema for report creation."""
    data: Optional[ReportResponse] = Field(None, description="Created report")


class ReportUpdateResponse(APIResponse):
    """Response schema for report update."""
    data: Optional[ReportResponse] = Field(None, description="Updated report")


class ReportGetResponse(APIResponse):
    """Response schema for report retrieval."""
    data: Optional[ReportResponse] = Field(None, description="Report details")


class ReportListAPIResponse(APIResponse):
    """Response schema for report list."""
    data: Optional[ReportListResponse] = Field(None, description="List of reports")


class ReportSummaryResponse(APIResponse):
    """Response schema for report summary."""
    data: Optional[ReportSummary] = Field(None, description="Report summary")


class ReportGenerationRequestResponse(APIResponse):
    """Response schema for report generation request."""
    data: Optional[ReportGenerationResponse] = Field(None, description="Generation request response")


class ReportGenerationStatusResponse(APIResponse):
    """Response schema for report generation status."""
    data: Optional[ReportGenerationResponse] = Field(None, description="Generation status")


class ReportDownloadResponse(APIResponse):
    """Response schema for report download."""
    data: Optional[Dict[str, Any]] = Field(None, description="Download information")


# Alias classes for backward compatibility
class ReportCreateRequest(BaseModel):
    """Schema for creating a report request."""
    
    workflow_id: UUID = Field(..., description="Workflow ID")
    target_id: Optional[UUID] = Field(None, description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    user_id: Optional[UUID] = Field(None, description="User ID who requested the report")
    title: str = Field(..., min_length=1, max_length=255, description="Report title")
    description: Optional[str] = Field(None, max_length=1000, description="Report description")
    template: str = Field(..., description="Report template to use")
    report_type: Optional[ReportType] = Field(None, description="Type of report")
    format: ReportFormat = Field(..., description="Report format")
    sections: List[ReportSection] = Field(default_factory=list, description="Report sections to include")
    include_passive_recon: bool = Field(default=True, description="Include passive reconnaissance data")
    include_active_recon: bool = Field(default=True, description="Include active reconnaissance data")
    include_vulnerabilities: bool = Field(default=True, description="Include vulnerability findings")
    include_kill_chain: bool = Field(default=True, description="Include kill chain analysis")
    include_screenshots: bool = Field(default=True, description="Include screenshots")
    include_raw_data: bool = Field(default=False, description="Include raw tool outputs")
    custom_template: Optional[str] = Field(None, description="Custom report template")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('sections')
    def validate_sections(cls, v):
        """Validate that sections are valid report sections."""
        valid_sections = [
            'executive_summary', 'methodology', 'findings', 'vulnerabilities',
            'attack_paths', 'recommendations', 'appendix'
        ]
        for section in v:
            if section not in valid_sections:
                raise ValueError(f"Invalid report section: {section}. Valid sections: {valid_sections}")
        return v


class ReportUpdateRequest(ReportUpdate):
    """Alias for report update request schema."""


class ReportExportRequest(BaseModel):
    """Schema for report export request."""
    format: ReportFormat = Field(..., description="Export format")
    include_attachments: bool = Field(default=True, description="Include attachments")
    compression: bool = Field(default=False, description="Compress export file")


class ReportTemplateResponse(BaseModel):
    """Schema for report template response."""
    id: UUID = Field(..., description="Template ID")
    name: str = Field(..., description="Template name")
    description: Optional[str] = Field(None, description="Template description")
    report_type: ReportType = Field(..., description="Report type")
    format: ReportFormat = Field(..., description="Report format")
    sections: List[ReportSection] = Field(..., description="Template sections")
    is_default: bool = Field(default=False, description="Is default template")
    version: str = Field(default="1.0", description="Template version") 