"""
Kill chain schemas for the Bug Hunting Framework.

This module contains Pydantic schemas for kill chain analysis,
attack paths, and related data structures.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, field_validator, HttpUrl, ConfigDict

from .base import APIResponse


class KillChainStage(str, Enum):
    """Kill chain stages enumeration."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class AttackPathStatus(str, Enum):
    """Attack path status enumeration."""
    IDENTIFIED = "identified"
    VERIFIED = "verified"
    EXPLOITED = "exploited"
    BLOCKED = "blocked"
    FALSE_POSITIVE = "false_positive"


class AttackPathSeverity(str, Enum):
    """Attack path severity enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackPathType(str, Enum):
    """Attack path type enumeration."""
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    EXECUTION = "execution"
    INITIAL_ACCESS = "initial_access"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    OTHER = "other"


class AttackPathCreate(BaseModel):
    """Schema for creating an attack path."""
    
    target_id: UUID = Field(..., description="Target ID")
    kill_chain_id: Optional[UUID] = Field(None, description="Parent kill chain ID")
    name: str = Field(..., min_length=1, max_length=255, description="Attack path name")
    description: str = Field(..., description="Attack path description")
    attack_path_type: AttackPathType = Field(..., description="Type of attack path")
    severity: AttackPathSeverity = Field(..., description="Attack path severity")
    status: AttackPathStatus = Field(default=AttackPathStatus.IDENTIFIED, description="Attack path status")
    stages: List[KillChainStage] = Field(..., description="Kill chain stages involved")
    entry_points: List[str] = Field(default_factory=list, description="Entry points for the attack")
    exit_points: List[str] = Field(default_factory=list, description="Exit points for the attack")
    prerequisites: List[str] = Field(default_factory=list, description="Prerequisites for the attack")
    techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques used")
    tools_required: List[str] = Field(default_factory=list, description="Tools required for the attack")
    evidence: Optional[str] = Field(None, description="Evidence supporting this attack path")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept for the attack")
    screenshots: Optional[List[str]] = Field(default_factory=list, description="Screenshot file paths")
    risk_score: Optional[float] = Field(None, ge=0, le=10, description="Risk score (0-10)")
    impact_assessment: Optional[str] = Field(None, description="Impact assessment")
    remediation: Optional[str] = Field(None, description="Remediation recommendations")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('stages')
    def validate_stages(cls, v):
        """Validate that stages are valid kill chain stages."""
        valid_stages = [
            'reconnaissance', 'weaponization', 'delivery', 'exploitation',
            'installation', 'command_and_control', 'actions_on_objectives'
        ]
        for stage in v:
            if stage not in valid_stages:
                raise ValueError(f"Invalid kill chain stage: {stage}. Valid stages: {valid_stages}")
        return v
    
    @field_validator('risk_score')
    def validate_risk_score(cls, v):
        """Validate risk score range."""
        if v is not None and (v < 0 or v > 10):
            raise ValueError("Risk score must be between 0 and 10")
        return v


class AttackPathResponse(BaseModel):
    """Schema for attack path response."""
    
    id: UUID = Field(..., description="Attack path ID")
    target_id: UUID = Field(..., description="Target ID")
    kill_chain_id: Optional[UUID] = Field(None, description="Parent kill chain ID")
    name: str = Field(..., description="Attack path name")
    description: str = Field(..., description="Attack path description")
    attack_path_type: AttackPathType = Field(..., description="Type of attack path")
    severity: AttackPathSeverity = Field(..., description="Attack path severity")
    status: AttackPathStatus = Field(..., description="Attack path status")
    stages: List[KillChainStage] = Field(..., description="Kill chain stages involved")
    entry_points: List[str] = Field(..., description="Entry points for the attack")
    exit_points: List[str] = Field(..., description="Exit points for the attack")
    prerequisites: List[str] = Field(..., description="Prerequisites for the attack")
    techniques: List[str] = Field(..., description="MITRE ATT&CK techniques used")
    tools_required: List[str] = Field(..., description="Tools required for the attack")
    evidence: Optional[str] = Field(None, description="Evidence supporting this attack path")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept for the attack")
    screenshots: List[str] = Field(default_factory=list, description="Screenshot file paths")
    risk_score: Optional[float] = Field(None, description="Risk score (0-10)")
    impact_assessment: Optional[str] = Field(None, description="Impact assessment")
    remediation: Optional[str] = Field(None, description="Remediation recommendations")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class AttackPathListResponse(BaseModel):
    """Schema for attack path list response."""
    
    attack_paths: List[AttackPathResponse] = Field(..., description="List of attack paths")
    total: int = Field(..., description="Total number of attack paths")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")


class KillChainCreate(BaseModel):
    """Schema for creating a kill chain analysis."""
    
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    attack_paths: List[AttackPathCreate] = Field(default_factory=list, description="Identified attack paths")
    total_attack_paths: int = Field(default=0, ge=0, description="Total number of attack paths")
    critical_paths: int = Field(default=0, ge=0, description="Number of critical attack paths")
    high_paths: int = Field(default=0, ge=0, description="Number of high severity attack paths")
    medium_paths: int = Field(default=0, ge=0, description="Number of medium severity attack paths")
    low_paths: int = Field(default=0, ge=0, description="Number of low severity attack paths")
    info_paths: int = Field(default=0, ge=0, description="Number of info attack paths")
    verified_paths: int = Field(default=0, ge=0, description="Number of verified attack paths")
    execution_time: Optional[float] = Field(None, ge=0, description="Execution time in seconds")
    analysis_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Analysis configuration")
    raw_output: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw analysis outputs")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('total_attack_paths')
    def validate_total_attack_paths(cls, v, values):
        """Validate total_attack_paths matches actual attack paths count."""
        if 'attack_paths' in values and v != len(values['attack_paths']):
            raise ValueError("total_attack_paths must match the actual number of attack paths")
        return v


class KillChainResponse(BaseModel):
    """Schema for kill chain response."""
    
    id: UUID = Field(..., description="Kill chain ID")
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    attack_paths: List[AttackPathResponse] = Field(..., description="Identified attack paths")
    total_attack_paths: int = Field(..., description="Total number of attack paths")
    critical_paths: int = Field(..., description="Number of critical attack paths")
    high_paths: int = Field(..., description="Number of high severity attack paths")
    medium_paths: int = Field(..., description="Number of medium severity attack paths")
    low_paths: int = Field(..., description="Number of low severity attack paths")
    info_paths: int = Field(..., description="Number of info attack paths")
    verified_paths: int = Field(..., description="Number of verified attack paths")
    execution_time: Optional[float] = Field(None, description="Execution time in seconds")
    analysis_config: Dict[str, Any] = Field(default_factory=dict, description="Analysis configuration")
    raw_output: Dict[str, Any] = Field(default_factory=dict, description="Raw analysis outputs")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class KillChainSummary(BaseModel):
    """Schema for kill chain summary."""
    
    target_id: UUID = Field(..., description="Target ID")
    total_attack_paths: int = Field(..., description="Total attack paths")
    critical_paths: int = Field(..., description="Critical attack paths count")
    high_paths: int = Field(..., description="High severity attack paths count")
    medium_paths: int = Field(..., description="Medium severity attack paths count")
    low_paths: int = Field(..., description="Low severity attack paths count")
    info_paths: int = Field(..., description="Info attack paths count")
    verified_paths: int = Field(..., description="Verified attack paths count")
    exploited_paths: int = Field(..., description="Exploited attack paths count")
    average_risk_score: Optional[float] = Field(None, description="Average risk score")
    last_execution: Optional[datetime] = Field(None, description="Last execution timestamp")
    execution_count: int = Field(default=0, description="Number of executions")


class KillChainFilter(BaseModel):
    """Schema for filtering kill chain results."""
    
    target_id: Optional[UUID] = Field(None, description="Filter by target ID")
    attack_path_type: Optional[AttackPathType] = Field(None, description="Filter by attack path type")
    severity: Optional[AttackPathSeverity] = Field(None, description="Filter by severity")
    status: Optional[AttackPathStatus] = Field(None, description="Filter by status")
    stages: Optional[List[KillChainStage]] = Field(None, description="Filter by kill chain stages")
    techniques: Optional[List[str]] = Field(None, description="Filter by MITRE ATT&CK techniques")
    risk_score_min: Optional[float] = Field(None, ge=0, le=10, description="Minimum risk score")
    risk_score_max: Optional[float] = Field(None, ge=0, le=10, description="Maximum risk score")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")


# API Response schemas
class KillChainCreateResponse(APIResponse):
    """Response schema for kill chain creation."""
    data: Optional[KillChainResponse] = Field(None, description="Created kill chain")


class KillChainGetResponse(APIResponse):
    """Response schema for kill chain retrieval."""
    data: Optional[KillChainResponse] = Field(None, description="Kill chain details")


class KillChainListResponse(APIResponse):
    """Response schema for kill chain list."""
    data: Optional[List[KillChainResponse]] = Field(None, description="List of kill chains")


class AttackPathCreateResponse(APIResponse):
    """Response schema for attack path creation."""
    data: Optional[AttackPathResponse] = Field(None, description="Created attack path")


class AttackPathGetResponse(APIResponse):
    """Response schema for attack path retrieval."""
    data: Optional[AttackPathResponse] = Field(None, description="Attack path details")


class AttackPathListAPIResponse(APIResponse):
    """Response schema for attack path list."""
    data: Optional[AttackPathListResponse] = Field(None, description="List of attack paths")


class KillChainSummaryResponse(APIResponse):
    """Response schema for kill chain summary."""
    data: Optional[KillChainSummary] = Field(None, description="Kill chain summary") 