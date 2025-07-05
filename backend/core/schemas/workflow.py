"""
Workflow schemas for the Bug Hunting Framework.

This module contains Pydantic schemas for workflow management,
execution tracking, and stage orchestration.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, field_validator, ConfigDict

from .base import APIResponse
from core.models.workflow import WorkflowStage


class WorkflowStatus(str, Enum):
    """Workflow execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PAUSED = "PAUSED"


class StageStatus(str, Enum):
    """Individual stage execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class WorkflowCreate(BaseModel):
    """Schema for creating a new workflow."""
    
    target_id: UUID = Field(..., description="Target ID for the workflow")
    name: str = Field(..., min_length=1, max_length=255, description="Workflow name")
    description: Optional[str] = Field(None, max_length=1000, description="Workflow description")
    stages: List[str] = Field(default_factory=list, description="List of stages to execute")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Workflow configuration")
    
    @field_validator('stages')
    def validate_stages(cls, v):
        """Validate that stages are valid stage names (case-insensitive) and normalize to uppercase."""
        valid_stages = [
            'PASSIVE_RECON', 'ACTIVE_RECON', 'VULN_SCAN',
            'VULN_TEST', 'KILL_CHAIN', 'REPORT'
        ]
        normalized = []
        for stage in v:
            stage_up = stage.upper()
            if stage_up not in valid_stages:
                raise ValueError(f"Invalid stage: {stage}. Valid stages: {valid_stages}")
            normalized.append(stage_up)
        return normalized


class WorkflowUpdate(BaseModel):
    """Schema for updating a workflow."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Workflow name")
    description: Optional[str] = Field(None, max_length=1000, description="Workflow description")
    status: Optional[WorkflowStatus] = Field(None, description="Workflow status")
    stages: Optional[List[str]] = Field(None, description="List of stages to execute")
    config: Optional[Dict[str, Any]] = Field(None, description="Workflow configuration")
    
    @field_validator('stages')
    def validate_stages(cls, v):
        """Validate that stages are valid stage names (case-insensitive) and normalize to uppercase."""
        if v is None:
            return v
        valid_stages = [
            'PASSIVE_RECON', 'ACTIVE_RECON', 'VULN_SCAN',
            'VULN_TEST', 'KILL_CHAIN', 'REPORT'
        ]
        normalized = []
        for stage in v:
            stage_up = stage.upper()
            if stage_up not in valid_stages:
                raise ValueError(f"Invalid stage: {stage}. Valid stages: {valid_stages}")
            normalized.append(stage_up)
        return normalized


class WorkflowResponse(BaseModel):
    """Schema for workflow response."""
    
    id: UUID = Field(..., description="Workflow ID")
    target_id: UUID = Field(..., description="Target ID")
    name: str = Field(..., description="Workflow name")
    description: Optional[str] = Field(None, description="Workflow description")
    status: WorkflowStatus = Field(..., description="Workflow status")
    stages: List[str] = Field(..., description="List of stages")
    config: Dict[str, Any] = Field(default_factory=dict, description="Workflow configuration")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    started_at: Optional[datetime] = Field(None, description="Execution start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    model_config = ConfigDict(from_attributes=True)


class WorkflowListResponse(BaseModel):
    """Schema for workflow list response."""
    
    workflows: List[WorkflowResponse] = Field(..., description="List of workflows")
    total: int = Field(..., description="Total number of workflows")
    pagination: Dict[str, Any] = Field(..., description="Pagination information")


class WorkflowExecutionCreate(BaseModel):
    """Schema for creating a workflow execution."""
    
    workflow_id: UUID = Field(..., description="Workflow ID to execute")
    user_id: Optional[UUID] = Field(None, description="User ID who initiated execution")
    priority: int = Field(default=0, ge=0, le=10, description="Execution priority (0-10)")
    config_overrides: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Configuration overrides")


class WorkflowExecutionUpdate(BaseModel):
    """Schema for updating a workflow execution."""
    
    status: Optional[WorkflowStatus] = Field(None, description="Execution status")
    started_at: Optional[datetime] = Field(None, description="Execution start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    progress: Optional[float] = Field(None, ge=0, le=100, description="Execution progress (0-100)")


class StageExecutionInfo(BaseModel):
    """Schema for stage execution information."""
    
    stage_name: str = Field(..., description="Stage name")
    status: StageStatus = Field(..., description="Stage status")
    started_at: Optional[datetime] = Field(None, description="Stage start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Stage completion timestamp")
    error_message: Optional[str] = Field(None, description="Stage error message")
    progress: float = Field(default=0, ge=0, le=100, description="Stage progress (0-100)")


class WorkflowExecutionResponse(BaseModel):
    """Schema for workflow execution response."""
    
    id: UUID = Field(..., description="Execution ID")
    workflow_id: UUID = Field(..., description="Workflow ID")
    user_id: Optional[UUID] = Field(None, description="User ID who initiated execution")
    status: WorkflowStatus = Field(..., description="Execution status")
    priority: int = Field(..., description="Execution priority")
    config_overrides: Dict[str, Any] = Field(default_factory=dict, description="Configuration overrides")
    stage_executions: List[StageExecutionInfo] = Field(default_factory=list, description="Stage execution details")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    started_at: Optional[datetime] = Field(None, description="Execution start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    progress: float = Field(default=0, ge=0, le=100, description="Overall execution progress")
    model_config = ConfigDict(from_attributes=True)


class StageExecutionResponse(BaseModel):
    """Schema for stage execution response."""
    
    workflow_id: UUID = Field(..., description="Workflow ID")
    stage_name: str = Field(..., description="Stage name")
    status: StageStatus = Field(..., description="Stage status")
    message: str = Field(..., description="Execution message")
    output: Optional[str] = Field(None, description="Execution output")
    error: Optional[str] = Field(None, description="Execution error")
    model_config = ConfigDict(from_attributes=True)


# API Response schemas
class WorkflowCreateResponse(APIResponse):
    """Response schema for workflow creation."""
    data: Optional[WorkflowResponse] = Field(None, description="Created workflow")


class WorkflowUpdateResponse(APIResponse):
    """Response schema for workflow update."""
    data: Optional[WorkflowResponse] = Field(None, description="Updated workflow")


class WorkflowGetResponse(APIResponse):
    """Response schema for workflow retrieval."""
    data: Optional[WorkflowResponse] = Field(None, description="Workflow details")


class WorkflowListAPIResponse(APIResponse):
    """Response schema for workflow list."""
    data: Optional[WorkflowListResponse] = Field(None, description="List of workflows")


class WorkflowExecutionCreateResponse(APIResponse):
    """Response schema for workflow execution creation."""
    data: Optional[WorkflowExecutionResponse] = Field(None, description="Created execution")


class WorkflowExecutionUpdateResponse(APIResponse):
    """Response schema for workflow execution update."""
    data: Optional[WorkflowExecutionResponse] = Field(None, description="Updated execution")


class WorkflowExecutionGetResponse(APIResponse):
    """Response schema for workflow execution retrieval."""
    data: Optional[WorkflowExecutionResponse] = Field(None, description="Execution details")


class WorkflowExecutionRequest(BaseModel):
    """Schema for workflow execution request."""
    # workflow_id is optional because it is provided in the URL, not the body
    workflow_id: Optional[UUID] = Field(None, description="Workflow ID to execute")
    stage_name: str = Field(..., description="Stage name to execute")
    user_id: Optional[UUID] = Field(None, description="User ID who initiated execution")
    priority: int = Field(default=0, ge=0, le=10, description="Execution priority (0-10)")
    config_overrides: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Configuration overrides")


class WorkflowCreateRequest(WorkflowCreate):
    """Alias for workflow creation request schema."""


class WorkflowUpdateRequest(WorkflowUpdate):
    """Alias for workflow update request schema."""


class WorkflowSummaryResponse(BaseModel):
    """Schema for workflow summary data."""
    
    id: UUID = Field(..., description="Workflow ID")
    name: str = Field(..., description="Workflow name")
    status: WorkflowStatus = Field(..., description="Workflow status")
    total_stages: int = Field(..., description="Total number of stages")
    completed_stages: int = Field(..., description="Number of completed stages")
    failed_stages: int = Field(..., description="Number of failed stages")
    progress: float = Field(..., ge=0, le=100, description="Overall progress percentage")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class WorkflowSummaryAPIResponse(APIResponse):
    """Response schema for workflow summary."""
    data: Optional[WorkflowSummaryResponse] = Field(None, description="Workflow summary data") 