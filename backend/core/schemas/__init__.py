"""
Pydantic schemas for the Bug Hunting Framework.

This package contains all Pydantic schemas used for request/response
validation and data serialization throughout the application.
"""

from .base import APIResponse, PaginationParams
from .target import TargetCreate, TargetUpdate, TargetResponse, TargetListResponse
from .workflow import (
    WorkflowCreate, WorkflowUpdate, WorkflowResponse, WorkflowListResponse,
    WorkflowExecutionCreate, WorkflowExecutionUpdate, WorkflowExecutionResponse
)
from .passive_recon import (
    PassiveReconResultCreate, PassiveReconResultResponse,
    SubdomainCreate, SubdomainResponse, SubdomainListResponse
)
from .active_recon import (
    ActiveReconResultCreate, ActiveReconResultResponse,
    PortCreate, PortResponse, ServiceCreate, ServiceResponse
)
from .vulnerability import (
    VulnerabilityCreate, VulnerabilityResponse,
    VulnerabilityFindingCreate, VulnerabilityFindingResponse, VulnerabilityFindingListResponse
)
from .kill_chain import (
    KillChainCreate, KillChainResponse,
    AttackPathCreate, AttackPathResponse, AttackPathListResponse
)
from .report import ReportCreate, ReportUpdate, ReportResponse, ReportListResponse

__all__ = [
    # Base
    'APIResponse',
    'PaginationParams',
    
    # Core Domain
    'TargetCreate',
    'TargetUpdate',
    'TargetResponse',
    'TargetListResponse',
    
    # Workflow
    'WorkflowCreate',
    'WorkflowUpdate',
    'WorkflowResponse',
    'WorkflowListResponse',
    'WorkflowExecutionCreate',
    'WorkflowExecutionUpdate',
    'WorkflowExecutionResponse',
    
    # Stage Results
    'PassiveReconResultCreate',
    'PassiveReconResultResponse',
    'SubdomainCreate',
    'SubdomainResponse',
    'SubdomainListResponse',
    'ActiveReconResultCreate',
    'ActiveReconResultResponse',
    'PortCreate',
    'PortResponse',
    'ServiceCreate',
    'ServiceResponse',
    'VulnerabilityCreate',
    'VulnerabilityResponse',
    'VulnerabilityFindingCreate',
    'VulnerabilityFindingResponse',
    'VulnerabilityFindingListResponse',
    'KillChainCreate',
    'KillChainResponse',
    'AttackPathCreate',
    'AttackPathResponse',
    'AttackPathListResponse',
    'ReportCreate',
    'ReportUpdate',
    'ReportResponse',
    'ReportListResponse',
] 