"""
Passive reconnaissance schemas for the Bug Hunting Framework.

This module contains Pydantic schemas for passive reconnaissance results,
subdomain discovery, and related data structures.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, field_validator, HttpUrl, ConfigDict

from .base import APIResponse


class SubdomainStatus(str, Enum):
    """Subdomain status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class PassiveReconTool(str, Enum):
    """Passive reconnaissance tools enumeration."""
    AMASS = "amass"
    SUBFINDER = "subfinder"
    ASSETFINDER = "assetfinder"
    CRTSH = "crt.sh"
    HACKERTARGET = "hackertarget"
    SHODAN = "shodan"
    CENSYS = "censys"
    CERO = "cero"
    SUBLIST3R = "sublist3r"
    GAU = "gau"
    WAYBACKURLS = "waybackurls"
    TRUFFLEHOG = "trufflehog"
    DORKING = "dorking"
    DNS_ENUM = "dns_enum"


class SubdomainCreate(BaseModel):
    """
    Schema for creating a subdomain record.
    - metadata: Can include protocol, CIDR, or any extra info from tools like Cero.
    """
    
    target_id: UUID = Field(..., description="Target ID")
    subdomain: str = Field(..., min_length=1, max_length=255, description="Subdomain name")
    domain: str = Field(..., min_length=1, max_length=255, description="Root domain")
    ip_addresses: List[str] = Field(default_factory=list, description="Associated IP addresses")
    status: SubdomainStatus = Field(default=SubdomainStatus.UNKNOWN, description="Subdomain status")
    source: PassiveReconTool = Field(..., description="Tool that discovered this subdomain")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata (e.g., protocol, CIDR, etc.)")
    
    @field_validator('subdomain')
    def validate_subdomain(cls, v):
        """Validate subdomain format."""
        if not v or '.' not in v:
            raise ValueError("Subdomain must contain at least one dot")
        return v.lower()
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Validate domain format."""
        if not v or '.' not in v:
            raise ValueError("Domain must contain at least one dot")
        return v.lower()
    
    @field_validator('ip_addresses')
    def validate_ip_addresses(cls, v):
        """Validate IP address format."""
        import ipaddress
        for ip in v:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip}")
        return v


class SubdomainResponse(BaseModel):
    """Schema for subdomain response."""
    
    id: UUID = Field(..., description="Subdomain ID")
    target_id: UUID = Field(..., description="Target ID")
    subdomain: str = Field(..., description="Subdomain name")
    domain: str = Field(..., description="Root domain")
    ip_addresses: List[str] = Field(..., description="Associated IP addresses")
    status: SubdomainStatus = Field(..., description="Subdomain status")
    source: PassiveReconTool = Field(..., description="Tool that discovered this subdomain")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class SubdomainListResponse(BaseModel):
    """Schema for subdomain list response."""
    
    subdomains: List[SubdomainResponse] = Field(..., description="List of subdomains")
    total: int = Field(..., description="Total number of subdomains")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")


class PassiveReconResultCreate(BaseModel):
    """
    Schema for creating passive reconnaissance results.
    
    - raw_output: Should include all tool outputs, including keys like 'ipv4s', 'protocols', 'cidrs', etc.
    - metadata: Can include any extra fields from new tools (e.g., Cero).
    - subdomains: Should include all discovered subdomains, with their IPs and metadata.
    """
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[str] = Field(None, description="Workflow execution ID")
    tools_used: List[PassiveReconTool] = Field(..., description="Tools used in reconnaissance")
    subdomains: List[SubdomainCreate] = Field(default_factory=list, description="Discovered subdomains")
    total_subdomains: int = Field(default=0, ge=0, description="Total number of subdomains discovered")
    execution_time: Optional[str] = Field(None, description="Execution time in seconds")
    raw_output: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw tool outputs (e.g., {'amass': {...}, 'cero': {'ipv4s': [...], 'protocols': [...], 'cidrs': [...], ...}})")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata (e.g., summary stats, error logs, etc.)")
    
    @field_validator('total_subdomains')
    def validate_total_subdomains(cls, v, info):
        """Validate total_subdomains matches actual subdomains count."""
        if hasattr(info, 'data') and info.data is not None:
            subdomains = info.data.get('subdomains', [])
            if v != len(subdomains):
                raise ValueError("total_subdomains must match the actual number of subdomains")
        return v


class PassiveReconResultResponse(BaseModel):
    """Schema for passive reconnaissance result response."""
    
    id: UUID = Field(..., description="Result ID")
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[str] = Field(None, description="Workflow execution ID")
    tools_used: List[PassiveReconTool] = Field(..., description="Tools used in reconnaissance")
    subdomains: List[SubdomainResponse] = Field(..., description="Discovered subdomains")
    total_subdomains: int = Field(..., description="Total number of subdomains discovered")
    execution_time: Optional[str] = Field(None, description="Execution time in seconds")
    raw_output: Dict[str, Any] = Field(default_factory=dict, description="Raw tool outputs")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class PassiveReconSummary(BaseModel):
    """Schema for passive reconnaissance summary."""
    
    target_id: UUID = Field(..., description="Target ID")
    total_subdomains: int = Field(..., description="Total subdomains discovered")
    active_subdomains: int = Field(..., description="Number of active subdomains")
    inactive_subdomains: int = Field(..., description="Number of inactive subdomains")
    tools_used: List[PassiveReconTool] = Field(..., description="Tools used")
    last_execution: Optional[datetime] = Field(None, description="Last execution timestamp")
    execution_count: int = Field(default=0, description="Number of executions")


class PassiveReconFilter(BaseModel):
    """Schema for filtering passive reconnaissance results."""
    
    target_id: Optional[UUID] = Field(None, description="Filter by target ID")
    status: Optional[SubdomainStatus] = Field(None, description="Filter by subdomain status")
    source: Optional[PassiveReconTool] = Field(None, description="Filter by discovery source")
    domain: Optional[str] = Field(None, description="Filter by domain")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")


# API Response schemas
class PassiveReconResultCreateResponse(APIResponse):
    """Response schema for passive reconnaissance result creation."""
    data: Optional[PassiveReconResultResponse] = Field(None, description="Created result")


class PassiveReconResultGetResponse(APIResponse):
    """Response schema for passive reconnaissance result retrieval."""
    data: Optional[PassiveReconResultResponse] = Field(None, description="Result details")


class PassiveReconResultListResponse(APIResponse):
    """Response schema for passive reconnaissance result list."""
    data: Optional[List[PassiveReconResultResponse]] = Field(None, description="List of results")


class SubdomainCreateResponse(APIResponse):
    """Response schema for subdomain creation."""
    data: Optional[SubdomainResponse] = Field(None, description="Created subdomain")


class SubdomainGetResponse(APIResponse):
    """Response schema for subdomain retrieval."""
    data: Optional[SubdomainResponse] = Field(None, description="Subdomain details")


class SubdomainListAPIResponse(APIResponse):
    """Response schema for subdomain list."""
    data: Optional[SubdomainListResponse] = Field(None, description="List of subdomains")


class PassiveReconSummaryResponse(APIResponse):
    """Response schema for passive reconnaissance summary."""
    data: Optional[PassiveReconSummary] = Field(None, description="Reconnaissance summary") 