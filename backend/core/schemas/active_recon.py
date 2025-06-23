"""
Active reconnaissance schemas for the Bug Hunting Framework.

This module contains Pydantic schemas for active reconnaissance results,
port scanning, service detection, and related data structures.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, field_validator, HttpUrl, ConfigDict

from .base import APIResponse


class PortStatus(str, Enum):
    """Port status enumeration."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class ServiceState(str, Enum):
    """Service state enumeration."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ActiveReconTool(str, Enum):
    """Active reconnaissance tools enumeration."""
    NMAP = "nmap"
    MASSCAN = "masscan"
    RUSTSCAN = "rustscan"
    HTTPX = "httpx"
    NUCLEI = "nuclei"
    WHATWEB = "whatweb"
    WAFW00F = "wafw00f"


class PortCreate(BaseModel):
    """Schema for creating a port record."""
    
    target_id: UUID = Field(..., description="Target ID")
    host: str = Field(..., description="Host IP address or domain")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(..., description="Protocol (tcp/udp)")
    status: PortStatus = Field(..., description="Port status")
    service_name: Optional[str] = Field(None, description="Service name")
    service_version: Optional[str] = Field(None, description="Service version")
    service_product: Optional[str] = Field(None, description="Service product")
    service_extra_info: Optional[str] = Field(None, description="Additional service information")
    banner: Optional[str] = Field(None, description="Service banner")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('host')
    def validate_host(cls, v):
        """Validate host format."""
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            # If not a valid IP, check if it's a valid domain
            if not v or '.' not in v:
                raise ValueError("Host must be a valid IP address or domain")
        return v
    
    @field_validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol."""
        if v.lower() not in ['tcp', 'udp']:
            raise ValueError("Protocol must be 'tcp' or 'udp'")
        return v.lower()


class PortResponse(BaseModel):
    """Schema for port response."""
    
    id: UUID = Field(..., description="Port ID")
    target_id: UUID = Field(..., description="Target ID")
    host: str = Field(..., description="Host IP address or domain")
    port: int = Field(..., description="Port number")
    protocol: str = Field(..., description="Protocol")
    status: PortStatus = Field(..., description="Port status")
    service_name: Optional[str] = Field(None, description="Service name")
    service_version: Optional[str] = Field(None, description="Service version")
    service_product: Optional[str] = Field(None, description="Service product")
    service_extra_info: Optional[str] = Field(None, description="Additional service information")
    banner: Optional[str] = Field(None, description="Service banner")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class ServiceCreate(BaseModel):
    """Schema for creating a service record."""
    
    target_id: UUID = Field(..., description="Target ID")
    host: str = Field(..., description="Host IP address or domain")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(..., description="Protocol")
    service_name: str = Field(..., description="Service name")
    service_version: Optional[str] = Field(None, description="Service version")
    service_product: Optional[str] = Field(None, description="Service product")
    service_extra_info: Optional[str] = Field(None, description="Additional service information")
    state: ServiceState = Field(..., description="Service state")
    banner: Optional[str] = Field(None, description="Service banner")
    http_title: Optional[str] = Field(None, description="HTTP page title")
    http_status: Optional[int] = Field(None, description="HTTP status code")
    http_headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="HTTP headers")
    technologies: Optional[List[str]] = Field(default_factory=list, description="Detected technologies")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('host')
    def validate_host(cls, v):
        """Validate host format."""
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            # If not a valid IP, check if it's a valid domain
            if not v or '.' not in v:
                raise ValueError("Host must be a valid IP address or domain")
        return v
    
    @field_validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol."""
        if v.lower() not in ['tcp', 'udp']:
            raise ValueError("Protocol must be 'tcp' or 'udp'")
        return v.lower()


class ServiceResponse(BaseModel):
    """Schema for service response."""
    
    id: UUID = Field(..., description="Service ID")
    target_id: UUID = Field(..., description="Target ID")
    host: str = Field(..., description="Host IP address or domain")
    port: int = Field(..., description="Port number")
    protocol: str = Field(..., description="Protocol")
    service_name: str = Field(..., description="Service name")
    service_version: Optional[str] = Field(None, description="Service version")
    service_product: Optional[str] = Field(None, description="Service product")
    service_extra_info: Optional[str] = Field(None, description="Additional service information")
    state: ServiceState = Field(..., description="Service state")
    banner: Optional[str] = Field(None, description="Service banner")
    http_title: Optional[str] = Field(None, description="HTTP page title")
    http_status: Optional[int] = Field(None, description="HTTP status code")
    http_headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    technologies: List[str] = Field(default_factory=list, description="Detected technologies")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class ActiveReconResultCreate(BaseModel):
    """Schema for creating active reconnaissance results."""
    
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    tools_used: List[ActiveReconTool] = Field(..., description="Tools used in reconnaissance")
    hosts_scanned: List[str] = Field(..., description="List of hosts scanned")
    ports: List[PortCreate] = Field(default_factory=list, description="Discovered ports")
    services: List[ServiceCreate] = Field(default_factory=list, description="Discovered services")
    total_ports: int = Field(default=0, ge=0, description="Total number of ports discovered")
    total_services: int = Field(default=0, ge=0, description="Total number of services discovered")
    execution_time: Optional[float] = Field(None, ge=0, description="Execution time in seconds")
    scan_range: Optional[str] = Field(None, description="Port scan range used")
    raw_output: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw tool outputs")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('total_ports')
    def validate_total_ports(cls, v, values):
        """Validate total_ports matches actual ports count."""
        if 'ports' in values and v != len(values['ports']):
            raise ValueError("total_ports must match the actual number of ports")
        return v
    
    @field_validator('total_services')
    def validate_total_services(cls, v, values):
        """Validate total_services matches actual services count."""
        if 'services' in values and v != len(values['services']):
            raise ValueError("total_services must match the actual number of services")
        return v


class ActiveReconResultResponse(BaseModel):
    """Schema for active reconnaissance result response."""
    
    id: UUID = Field(..., description="Result ID")
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[UUID] = Field(None, description="Workflow execution ID")
    tools_used: List[ActiveReconTool] = Field(..., description="Tools used in reconnaissance")
    hosts_scanned: List[str] = Field(..., description="List of hosts scanned")
    ports: List[PortResponse] = Field(..., description="Discovered ports")
    services: List[ServiceResponse] = Field(..., description="Discovered services")
    total_ports: int = Field(..., description="Total number of ports discovered")
    total_services: int = Field(..., description="Total number of services discovered")
    execution_time: Optional[float] = Field(None, description="Execution time in seconds")
    scan_range: Optional[str] = Field(None, description="Port scan range used")
    raw_output: Dict[str, Any] = Field(default_factory=dict, description="Raw tool outputs")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class ActiveReconSummary(BaseModel):
    """Schema for active reconnaissance summary."""
    
    target_id: UUID = Field(..., description="Target ID")
    total_hosts: int = Field(..., description="Total hosts scanned")
    total_ports: int = Field(..., description="Total ports discovered")
    total_services: int = Field(..., description="Total services discovered")
    open_ports: int = Field(..., description="Number of open ports")
    web_services: int = Field(..., description="Number of web services")
    tools_used: List[ActiveReconTool] = Field(..., description="Tools used")
    last_execution: Optional[datetime] = Field(None, description="Last execution timestamp")
    execution_count: int = Field(default=0, description="Number of executions")


class ActiveReconFilter(BaseModel):
    """Schema for filtering active reconnaissance results."""
    
    target_id: Optional[UUID] = Field(None, description="Filter by target ID")
    host: Optional[str] = Field(None, description="Filter by host")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Filter by port")
    protocol: Optional[str] = Field(None, description="Filter by protocol")
    status: Optional[PortStatus] = Field(None, description="Filter by port status")
    service_name: Optional[str] = Field(None, description="Filter by service name")
    state: Optional[ServiceState] = Field(None, description="Filter by service state")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")


# API Response schemas
class ActiveReconResultCreateResponse(APIResponse):
    """Response schema for active reconnaissance result creation."""
    data: Optional[ActiveReconResultResponse] = Field(None, description="Created result")


class ActiveReconResultGetResponse(APIResponse):
    """Response schema for active reconnaissance result retrieval."""
    data: Optional[ActiveReconResultResponse] = Field(None, description="Result details")


class ActiveReconResultListResponse(APIResponse):
    """Response schema for active reconnaissance result list."""
    data: Optional[List[ActiveReconResultResponse]] = Field(None, description="List of results")


class PortCreateResponse(APIResponse):
    """Response schema for port creation."""
    data: Optional[PortResponse] = Field(None, description="Created port")


class PortGetResponse(APIResponse):
    """Response schema for port retrieval."""
    data: Optional[PortResponse] = Field(None, description="Port details")


class ServiceCreateResponse(APIResponse):
    """Response schema for service creation."""
    data: Optional[ServiceResponse] = Field(None, description="Created service")


class ServiceGetResponse(APIResponse):
    """Response schema for service retrieval."""
    data: Optional[ServiceResponse] = Field(None, description="Service details")


class ActiveReconSummaryResponse(APIResponse):
    """Response schema for active reconnaissance summary."""
    data: Optional[ActiveReconSummary] = Field(None, description="Reconnaissance summary") 