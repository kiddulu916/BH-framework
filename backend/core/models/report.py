"""
Report model for storing generated reports.

This module defines the Report model which stores
generated reports and their metadata.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel, get_foreign_key, get_table_args, get_foreign_key
from sqlalchemy.dialects.postgresql import JSONB as JSONType
import enum


class ReportFormat(enum.Enum):
    """Enumeration for report formats."""
    PDF = "PDF"
    HTML = "HTML"
    MARKDOWN = "MARKDOWN"
    JSON = "JSON"
    XML = "XML"


class ReportStatus(enum.Enum):
    """Enumeration for report status."""
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ReportType(enum.Enum):
    """Enumeration for report types."""
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    TECHNICAL_DETAILED = "TECHNICAL_DETAILED"
    VULNERABILITY_REPORT = "VULNERABILITY_REPORT"
    KILL_CHAIN_ANALYSIS = "KILL_CHAIN_ANALYSIS"
    COMPLIANCE_REPORT = "COMPLIANCE_REPORT"
    CUSTOM = "CUSTOM"


class Report(BaseModel):
    """
    Report model representing generated reports.
    
    This model stores metadata about generated reports
    and their content for the bug hunting framework.
    """
    
    __tablename__ = "reports"
    
    # Report identification
    name = Column(String(255), nullable=False, index=True)  # Report name
    report_type = Column(Enum(ReportType), nullable=False, default=ReportType.TECHNICAL_DETAILED, index=True)
    format = Column(Enum(ReportFormat), nullable=False, default=ReportFormat.PDF, index=True)
    
    # Report status
    status = Column(Enum(ReportStatus), nullable=False, default=ReportStatus.GENERATING, index=True)
    is_public = Column(Boolean, default=False, nullable=False, index=True)  # Whether report is publicly accessible
    
    # Report content
    content = Column(Text, nullable=True)  # Report content (for text-based formats)
    file_path = Column(String(1000), nullable=True)  # Path to generated file
    file_size = Column(String(50), nullable=True)  # File size in bytes
    
    # Report configuration
    template_used = Column(String(255), nullable=True)  # Template used for generation
    configuration = Column(JSONType, nullable=True)  # Configuration used for report generation
    
    # Report metadata
    summary = Column(Text, nullable=True)  # Executive summary
    key_findings = Column(JSONType, nullable=True)  # Key findings summary
    statistics = Column(JSONType, nullable=True)  # Report statistics
    
    # Generation metadata
    generation_time = Column(String(50), nullable=True)  # Time taken to generate
    generated_by = Column(String(255), nullable=True)  # Who/what generated the report
    errors = Column(JSONType, nullable=True)  # Any errors during generation
    
    # Access control
    access_token = Column(String(255), nullable=True, unique=True, index=True)  # Access token for secure sharing
    expires_at = Column(String(50), nullable=True)  # When access token expires
    
    # Relationships
    target_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("targets", "id")), nullable=False)
    target = relationship("Target", back_populates="reports")
    
    workflow_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("workflows", "id")), nullable=False, index=True)
    workflow = relationship("Workflow", back_populates="reports")
    
    # Indexes
    __table_args__ = get_table_args(
        Index('idx_reports_name', 'name'),
        Index('idx_reports_type', 'report_type'),
        Index('idx_reports_format', 'format'),
        Index('idx_reports_status', 'status'),
        Index('idx_reports_target', 'target_id'),
        Index('idx_reports_workflow', 'workflow_id'),
        Index('idx_reports_created', 'created_at'),
    )
    
    def __repr__(self) -> str:
        """String representation of the report."""
        return f"<Report(name='{self.name}', type='{self.report_type.value.lower()}', status='{self.status.value.lower()}')>"
    
    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'name': self.name,
            'report_type': self.report_type.value.lower(),
            'format': self.format.value.lower(),
            'status': self.status.value.lower(),
            'is_public': self.is_public,
            'content': self.content,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'template_used': self.template_used,
            'configuration': self.configuration,
            'summary': self.summary,
            'key_findings': self.key_findings,
            'statistics': self.statistics,
            'generation_time': self.generation_time,
            'generated_by': self.generated_by,
            'errors': self.errors,
            'access_token': self.access_token,
            'expires_at': self.expires_at,
            'target_id': str(self.target_id),
        }
    
    @property
    def is_completed(self) -> bool:
        """Check if report generation is completed."""
        return self.status == ReportStatus.COMPLETED
    
    @property
    def is_failed(self) -> bool:
        """Check if report generation failed."""
        return self.status == ReportStatus.FAILED
    
    @property
    def display_name(self) -> str:
        """Get display name for the report."""
        return f"{self.name} ({self.report_type.value.replace('_', ' ').title()})"
    
    @property
    def file_extension(self) -> str:
        """Get file extension based on format."""
        format_extensions = {
            ReportFormat.PDF: "pdf",
            ReportFormat.HTML: "html",
            ReportFormat.MARKDOWN: "md",
            ReportFormat.JSON: "json",
            ReportFormat.XML: "xml",
        }
        return format_extensions.get(self.format, "txt")
    
    def mark_as_completed(self, file_path: Optional[str] = None, content: Optional[str] = None) -> None:
        """Mark report as completed."""
        self.status = ReportStatus.COMPLETED
        self.updated_at = datetime.now(timezone.utc)
        if file_path:
            self.file_path = file_path
        if content:
            self.content = content
    
    def mark_as_failed(self, errors: Optional[dict] = None) -> None:
        """Mark report as failed."""
        self.status = ReportStatus.FAILED
        self.updated_at = datetime.now(timezone.utc)
        if errors:
            self.errors = errors 