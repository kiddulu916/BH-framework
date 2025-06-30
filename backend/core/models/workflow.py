"""
Workflow models for tracking bug hunting workflow execution.

This module defines the Workflow and WorkflowExecution models
which track the overall workflow and individual executions.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index, DateTime
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel
import enum


class WorkflowStatus(enum.Enum):
    """Enumeration for workflow status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PAUSED = "PAUSED"


class WorkflowStage(enum.Enum):
    """Enumeration for workflow stages."""
    PASSIVE_RECON = "PASSIVE_RECON"
    ACTIVE_RECON = "ACTIVE_RECON"
    VULN_SCAN = "VULN_SCAN"
    VULN_TEST = "VULN_TEST"
    KILL_CHAIN = "KILL_CHAIN"
    REPORT = "REPORT"


class StageStatus(enum.Enum):
    """Enumeration for individual stage status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class Workflow(BaseModel):
    """
    Workflow model representing a bug hunting workflow.
    
    A workflow defines the sequence of stages to be executed
    for a target, along with their configuration and dependencies.
    """
    
    __tablename__ = "workflows"
    __table_args__ = {'schema': 'public'}
    
    # Workflow identification
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Workflow configuration
    stages = Column(JSONB, nullable=False)  # List of stages and their configuration
    dependencies = Column(JSONB, nullable=True)  # Stage dependencies
    settings = Column(JSONB, nullable=True)  # Workflow-specific settings
    
    # Status and tracking
    status = Column(Enum(WorkflowStatus), nullable=False, default=WorkflowStatus.PENDING, index=True)
    current_stage = Column(Enum(WorkflowStage), nullable=True)
    progress = Column(String(50), nullable=True)  # Human-readable progress
    
    # Relationships
    target_id = Column(PGUUID(as_uuid=True), ForeignKey("public.targets.id"), nullable=False)
    target = relationship("Target", backref="workflows")
    
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("public.users.id"), nullable=True)
    user = relationship("User", backref="workflows")
    
    # Executions
    executions = relationship("WorkflowExecution", back_populates="workflow", cascade="all, delete-orphan")
    
    # Reports
    reports = relationship("Report", back_populates="workflow", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_workflows_target', 'target_id'),
        Index('idx_workflows_user', 'user_id'),
        Index('idx_workflows_status', 'status'),
        Index('idx_workflows_current_stage', 'current_stage'),
        {'schema': 'public'}
    )
    
    def __repr__(self) -> str:
        """String representation of the workflow."""
        return f"<Workflow(name='{self.name}', status='{self.status.value}', target_id='{self.target_id}')>"
    
    def to_dict(self) -> dict:
        """Convert workflow to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'name': self.name,
            'stages': self.stages,
            'dependencies': self.dependencies,
            'settings': self.settings,
            'status': self.status.value,
            'current_stage': self.current_stage.value if self.current_stage else None,
            'progress': self.progress,
            'target_id': str(self.target_id),
            'user_id': str(self.user_id) if self.user_id else None,
        }
    
    @property
    def is_active(self) -> bool:
        """Check if workflow is active."""
        return self.status in [WorkflowStatus.PENDING, WorkflowStatus.RUNNING, WorkflowStatus.PAUSED]
    
    @property
    def is_completed(self) -> bool:
        """Check if workflow is completed."""
        return self.status == WorkflowStatus.COMPLETED


class WorkflowExecution(BaseModel):
    """
    WorkflowExecution model representing individual stage executions.
    
    Each execution tracks the progress and results of a specific
    stage within a workflow.
    """
    
    __tablename__ = "workflow_executions"
    __table_args__ = {'schema': 'public'}
    
    # Execution identification
    stage = Column(Enum(WorkflowStage), nullable=False, index=True)
    execution_id = Column(String(255), nullable=False, unique=True, index=True)  # Unique execution identifier
    
    # Execution status
    status = Column(Enum(WorkflowStatus), nullable=False, default=WorkflowStatus.PENDING, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Execution details
    configuration = Column(JSONB, nullable=True)  # Stage-specific configuration
    results = Column(JSONB, nullable=True)  # Execution results
    errors = Column(JSONB, nullable=True)  # Error details if failed
    
    # Progress tracking
    progress_percentage = Column(String(10), nullable=True)  # Progress as percentage
    current_step = Column(String(255), nullable=True)  # Current step being executed
    
    # Relationships
    workflow_id = Column(PGUUID(as_uuid=True), ForeignKey("public.workflows.id"), nullable=False)
    workflow = relationship("Workflow", back_populates="executions")
    
    # Indexes
    __table_args__ = (
        Index('idx_workflow_executions_workflow', 'workflow_id'),
        Index('idx_workflow_executions_stage', 'stage'),
        Index('idx_workflow_executions_status', 'status'),
        Index('idx_workflow_executions_execution_id', 'execution_id'),
        {'schema': 'public'}
    )
    
    def __repr__(self) -> str:
        """String representation of the execution."""
        return f"<WorkflowExecution(stage='{self.stage.value}', status='{self.status.value}', execution_id='{self.execution_id}')>"
    
    def to_dict(self) -> dict:
        """Convert execution to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'stage': self.stage.value,
            'execution_id': self.execution_id,
            'status': self.status.value,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'configuration': self.configuration,
            'results': self.results,
            'errors': self.errors,
            'progress_percentage': self.progress_percentage,
            'current_step': self.current_step,
            'workflow_id': str(self.workflow_id),
        }
    
    def start_execution(self) -> None:
        """Mark execution as started."""
        self.status = WorkflowStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def complete_execution(self, results: Optional[dict] = None) -> None:
        """Mark execution as completed."""
        self.status = WorkflowStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if results:
            self.results = results
    
    def fail_execution(self, errors: Optional[dict] = None) -> None:
        """Mark execution as failed."""
        self.status = WorkflowStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if errors:
            self.errors = errors 