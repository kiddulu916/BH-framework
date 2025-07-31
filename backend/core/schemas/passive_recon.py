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


class ReconCategory(str, Enum):
    """Reconnaissance categories enumeration."""
    DOMAIN_WHOIS = "DOMAIN_WHOIS"
    SUBDOMAIN_ENUMERATION = "SUBDOMAIN_ENUMERATION"
    CERTIFICATE_TRANSPARENCY = "CERTIFICATE_TRANSPARENCY"
    PUBLIC_REPOSITORIES = "PUBLIC_REPOSITORIES"
    SEARCH_ENGINE_DORKING = "SEARCH_ENGINE_DORKING"
    DATA_BREACHES = "DATA_BREACHES"
    INFRASTRUCTURE_EXPOSURE = "INFRASTRUCTURE_EXPOSURE"
    ARCHIVE_HISTORICAL = "ARCHIVE_HISTORICAL"
    SOCIAL_MEDIA_OSINT = "SOCIAL_MEDIA_OSINT"
    CLOUD_ASSETS = "CLOUD_ASSETS"


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
    # Enhanced OSINT tools
    WHOIS = "whois"
    SECURITYTRAILS = "securitytrails"
    VIRUSTOTAL = "virustotal"
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    GOOGLE_DORKS = "google_dorks"
    BING_DORKS = "bing_dorks"
    HIBP = "hibp"
    DEHASHED = "dehashed"
    INTELX = "intelx"
    BINARYEDGE = "binaryedge"
    ZOOMEYE = "zoomeye"
    WAYBACK_MACHINE = "wayback_machine"
    GOOGLE_CACHE = "google_cache"
    LINKEDIN = "linkedin"
    TWITTER = "twitter"
    AWS_S3 = "aws_s3"
    GCP_STORAGE = "gcp_storage"
    AZURE_BLOB = "azure_blob"


# Enhanced OSINT Data Schemas
class WHOISRecordCreate(BaseModel):
    """Schema for creating WHOIS record data."""
    target_id: UUID = Field(..., description="Target ID")
    domain: str = Field(..., description="Domain name")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    registrant_name: Optional[str] = Field(None, description="Registrant name")
    registrant_email: Optional[str] = Field(None, description="Registrant email")
    registrant_organization: Optional[str] = Field(None, description="Registrant organization")
    creation_date: Optional[datetime] = Field(None, description="Domain creation date")
    expiration_date: Optional[datetime] = Field(None, description="Domain expiration date")
    updated_date: Optional[datetime] = Field(None, description="Domain last updated date")
    name_servers: List[str] = Field(default_factory=list, description="Name servers")
    status: List[str] = Field(default_factory=list, description="Domain status")
    dns_records: Optional[Dict[str, Any]] = Field(default_factory=dict, description="DNS records")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class CertificateLogCreate(BaseModel):
    """Schema for creating certificate transparency log data."""
    target_id: UUID = Field(..., description="Target ID")
    domain: str = Field(..., description="Domain name")
    certificate_id: Optional[str] = Field(None, description="Certificate ID")
    issuer: Optional[str] = Field(None, description="Certificate issuer")
    subject: Optional[str] = Field(None, description="Certificate subject")
    not_before: Optional[datetime] = Field(None, description="Certificate valid from")
    not_after: Optional[datetime] = Field(None, description="Certificate valid until")
    serial_number: Optional[str] = Field(None, description="Certificate serial number")
    fingerprint: Optional[str] = Field(None, description="Certificate fingerprint")
    log_index: Optional[int] = Field(None, description="CT log index")
    log_url: Optional[str] = Field(None, description="CT log URL")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class RepositoryFindingCreate(BaseModel):
    """Schema for creating repository finding data."""
    target_id: UUID = Field(..., description="Target ID")
    repository_url: str = Field(..., description="Repository URL")
    platform: str = Field(..., description="Repository platform (GitHub, GitLab, etc.)")
    repository_name: Optional[str] = Field(None, description="Repository name")
    owner: Optional[str] = Field(None, description="Repository owner")
    description: Optional[str] = Field(None, description="Repository description")
    language: Optional[str] = Field(None, description="Primary programming language")
    stars: Optional[int] = Field(None, description="Number of stars")
    forks: Optional[int] = Field(None, description="Number of forks")
    last_updated: Optional[datetime] = Field(None, description="Last update date")
    secrets_found: List[str] = Field(default_factory=list, description="Secrets found in repository")
    files_analyzed: List[str] = Field(default_factory=list, description="Files analyzed")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class SearchDorkResultCreate(BaseModel):
    """Schema for creating search engine dorking results."""
    target_id: UUID = Field(..., description="Target ID")
    search_engine: str = Field(..., description="Search engine used")
    dork_query: str = Field(..., description="Dork query used")
    results_count: int = Field(default=0, description="Number of results found")
    urls_found: List[str] = Field(default_factory=list, description="URLs found")
    file_types: List[str] = Field(default_factory=list, description="File types discovered")
    parameters: List[str] = Field(default_factory=list, description="URL parameters found")
    error_messages: List[str] = Field(default_factory=list, description="Error messages found")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class BreachRecordCreate(BaseModel):
    """Schema for creating data breach record data."""
    target_id: UUID = Field(..., description="Target ID")
    breach_name: str = Field(..., description="Name of the breach")
    breach_date: Optional[datetime] = Field(None, description="Date of the breach")
    breach_description: Optional[str] = Field(None, description="Description of the breach")
    data_classes: List[str] = Field(default_factory=list, description="Types of data exposed")
    records_count: Optional[int] = Field(None, description="Number of records exposed")
    source: str = Field(..., description="Source of breach information")
    verification_status: Optional[str] = Field(None, description="Verification status")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class InfrastructureExposureCreate(BaseModel):
    """Schema for creating infrastructure exposure data."""
    target_id: UUID = Field(..., description="Target ID")
    ip_address: str = Field(..., description="IP address")
    port: Optional[int] = Field(None, description="Port number")
    service: Optional[str] = Field(None, description="Service name")
    banner: Optional[str] = Field(None, description="Service banner")
    ssl_info: Optional[Dict[str, Any]] = Field(default_factory=dict, description="SSL certificate information")
    vulnerabilities: List[str] = Field(default_factory=list, description="Vulnerabilities found")
    source: str = Field(..., description="Source of information (Shodan, Censys, etc.)")
    last_seen: Optional[datetime] = Field(None, description="Last seen timestamp")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class ArchiveFindingCreate(BaseModel):
    """Schema for creating archive and historical data findings."""
    target_id: UUID = Field(..., description="Target ID")
    url: str = Field(..., description="Original URL")
    archived_url: str = Field(..., description="Archived URL")
    archive_date: Optional[datetime] = Field(None, description="Archive date")
    archive_source: str = Field(..., description="Archive source (Wayback Machine, Google Cache, etc.)")
    content_type: Optional[str] = Field(None, description="Content type")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    title: Optional[str] = Field(None, description="Page title")
    parameters: List[str] = Field(default_factory=list, description="URL parameters found")
    secrets_found: List[str] = Field(default_factory=list, description="Secrets found in content")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class SocialMediaIntelCreate(BaseModel):
    """Schema for creating social media intelligence data."""
    target_id: UUID = Field(..., description="Target ID")
    platform: str = Field(..., description="Social media platform")
    username: Optional[str] = Field(None, description="Username or handle")
    profile_url: Optional[str] = Field(None, description="Profile URL")
    display_name: Optional[str] = Field(None, description="Display name")
    bio: Optional[str] = Field(None, description="Profile bio")
    location: Optional[str] = Field(None, description="Location")
    company: Optional[str] = Field(None, description="Company")
    job_title: Optional[str] = Field(None, description="Job title")
    followers_count: Optional[int] = Field(None, description="Number of followers")
    following_count: Optional[int] = Field(None, description="Number of following")
    posts_count: Optional[int] = Field(None, description="Number of posts")
    last_active: Optional[datetime] = Field(None, description="Last active date")
    intel_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional intelligence metadata")


class CloudAssetCreate(BaseModel):
    """Schema for creating cloud asset discovery data."""
    target_id: UUID = Field(..., description="Target ID")
    asset_type: str = Field(..., description="Type of cloud asset")
    provider: str = Field(..., description="Cloud provider (AWS, GCP, Azure, etc.)")
    asset_name: str = Field(..., description="Asset name")
    asset_url: Optional[str] = Field(None, description="Asset URL")
    region: Optional[str] = Field(None, description="Cloud region")
    status: Optional[str] = Field(None, description="Asset status")
    permissions: Optional[str] = Field(None, description="Asset permissions")
    last_modified: Optional[datetime] = Field(None, description="Last modified date")
    size: Optional[int] = Field(None, description="Asset size in bytes")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


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
    Enhanced schema for creating passive reconnaissance results.
    
    Now supports comprehensive OSINT data from all enhanced tool runners.
    """
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[str] = Field(None, description="Workflow execution ID")
    tools_used: List[PassiveReconTool] = Field(..., description="Tools used in reconnaissance")
    subdomains: List[SubdomainCreate] = Field(default_factory=list, description="Discovered subdomains")
    total_subdomains: int = Field(default=0, ge=0, description="Total number of subdomains discovered")
    execution_time: Optional[str] = Field(None, description="Execution time in seconds")
    raw_output: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw tool outputs")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    # Enhanced OSINT data
    whois_records: List[WHOISRecordCreate] = Field(default_factory=list, description="WHOIS records")
    certificate_logs: List[CertificateLogCreate] = Field(default_factory=list, description="Certificate transparency logs")
    repository_findings: List[RepositoryFindingCreate] = Field(default_factory=list, description="Repository findings")
    search_dork_results: List[SearchDorkResultCreate] = Field(default_factory=list, description="Search engine dorking results")
    breach_records: List[BreachRecordCreate] = Field(default_factory=list, description="Data breach records")
    infrastructure_exposures: List[InfrastructureExposureCreate] = Field(default_factory=list, description="Infrastructure exposure data")
    archive_findings: List[ArchiveFindingCreate] = Field(default_factory=list, description="Archive and historical findings")
    social_media_intel: List[SocialMediaIntelCreate] = Field(default_factory=list, description="Social media intelligence")
    cloud_assets: List[CloudAssetCreate] = Field(default_factory=list, description="Cloud asset discoveries")
    
    # Correlation data
    correlation_data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Cross-tool correlation data")
    
    @field_validator('total_subdomains')
    def validate_total_subdomains(cls, v, info):
        """Validate total_subdomains matches actual subdomains count."""
        if hasattr(info, 'data') and info.data is not None:
            subdomains = info.data.get('subdomains', [])
            if v != len(subdomains):
                raise ValueError("total_subdomains must match the actual number of subdomains")
        return v


class PassiveReconResultResponse(BaseModel):
    """Enhanced schema for passive reconnaissance result response."""
    
    id: UUID = Field(..., description="Result ID")
    target_id: UUID = Field(..., description="Target ID")
    execution_id: Optional[str] = Field(None, description="Workflow execution ID")
    tools_used: List[PassiveReconTool] = Field(..., description="Tools used in reconnaissance")
    subdomains: List[SubdomainResponse] = Field(..., description="Discovered subdomains")
    total_subdomains: int = Field(..., description="Total number of subdomains discovered")
    execution_time: Optional[str] = Field(None, description="Execution time in seconds")
    raw_output: Dict[str, Any] = Field(default_factory=dict, description="Raw tool outputs")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    # Enhanced OSINT data counts
    whois_records_count: int = Field(default=0, description="Number of WHOIS records")
    certificate_logs_count: int = Field(default=0, description="Number of certificate logs")
    repository_findings_count: int = Field(default=0, description="Number of repository findings")
    search_dork_results_count: int = Field(default=0, description="Number of search dork results")
    breach_records_count: int = Field(default=0, description="Number of breach records")
    infrastructure_exposures_count: int = Field(default=0, description="Number of infrastructure exposures")
    archive_findings_count: int = Field(default=0, description="Number of archive findings")
    social_media_intel_count: int = Field(default=0, description="Number of social media intelligence records")
    cloud_assets_count: int = Field(default=0, description="Number of cloud assets")
    
    # Correlation data
    correlation_data: Dict[str, Any] = Field(default_factory=dict, description="Cross-tool correlation data")
    
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class PassiveReconSummary(BaseModel):
    """Enhanced schema for passive reconnaissance summary."""
    
    target_id: UUID = Field(..., description="Target ID")
    total_subdomains: int = Field(..., description="Total subdomains discovered")
    active_subdomains: int = Field(..., description="Number of active subdomains")
    inactive_subdomains: int = Field(..., description="Number of inactive subdomains")
    tools_used: List[PassiveReconTool] = Field(..., description="Tools used")
    last_execution: Optional[datetime] = Field(None, description="Last execution timestamp")
    execution_count: int = Field(default=0, description="Number of executions")
    
    # Enhanced OSINT summary
    whois_records_count: int = Field(default=0, description="Total WHOIS records")
    certificate_logs_count: int = Field(default=0, description="Total certificate logs")
    repository_findings_count: int = Field(default=0, description="Total repository findings")
    search_dork_results_count: int = Field(default=0, description="Total search dork results")
    breach_records_count: int = Field(default=0, description="Total breach records")
    infrastructure_exposures_count: int = Field(default=0, description="Total infrastructure exposures")
    archive_findings_count: int = Field(default=0, description="Total archive findings")
    social_media_intel_count: int = Field(default=0, description="Total social media intelligence records")
    cloud_assets_count: int = Field(default=0, description="Total cloud assets")


class PassiveReconFilter(BaseModel):
    """Schema for filtering passive reconnaissance results."""
    
    target_id: Optional[UUID] = Field(None, description="Filter by target ID")
    status: Optional[SubdomainStatus] = Field(None, description="Filter by subdomain status")
    source: Optional[PassiveReconTool] = Field(None, description="Filter by discovery source")
    domain: Optional[str] = Field(None, description="Filter by domain")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")
    category: Optional[ReconCategory] = Field(None, description="Filter by reconnaissance category")


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


# Enhanced OSINT Response schemas
class WHOISRecordResponse(BaseModel):
    """Response schema for WHOIS record."""
    id: UUID = Field(..., description="WHOIS record ID")
    target_id: UUID = Field(..., description="Target ID")
    domain: str = Field(..., description="Domain name")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    registrant_name: Optional[str] = Field(None, description="Registrant name")
    registrant_email: Optional[str] = Field(None, description="Registrant email")
    registrant_organization: Optional[str] = Field(None, description="Registrant organization")
    creation_date: Optional[datetime] = Field(None, description="Domain creation date")
    expiration_date: Optional[datetime] = Field(None, description="Domain expiration date")
    updated_date: Optional[datetime] = Field(None, description="Domain last updated date")
    name_servers: List[str] = Field(default_factory=list, description="Name servers")
    status: List[str] = Field(default_factory=list, description="Domain status")
    dns_records: Dict[str, Any] = Field(default_factory=dict, description="DNS records")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class CertificateLogResponse(BaseModel):
    """Response schema for certificate log."""
    id: UUID = Field(..., description="Certificate log ID")
    target_id: UUID = Field(..., description="Target ID")
    domain: str = Field(..., description="Domain name")
    certificate_id: Optional[str] = Field(None, description="Certificate ID")
    issuer: Optional[str] = Field(None, description="Certificate issuer")
    subject: Optional[str] = Field(None, description="Certificate subject")
    not_before: Optional[datetime] = Field(None, description="Certificate valid from")
    not_after: Optional[datetime] = Field(None, description="Certificate valid until")
    serial_number: Optional[str] = Field(None, description="Certificate serial number")
    fingerprint: Optional[str] = Field(None, description="Certificate fingerprint")
    log_index: Optional[int] = Field(None, description="CT log index")
    log_url: Optional[str] = Field(None, description="CT log URL")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class RepositoryFindingResponse(BaseModel):
    """Response schema for repository finding."""
    id: UUID = Field(..., description="Repository finding ID")
    target_id: UUID = Field(..., description="Target ID")
    repository_url: str = Field(..., description="Repository URL")
    platform: str = Field(..., description="Repository platform")
    repository_name: Optional[str] = Field(None, description="Repository name")
    owner: Optional[str] = Field(None, description="Repository owner")
    description: Optional[str] = Field(None, description="Repository description")
    language: Optional[str] = Field(None, description="Primary programming language")
    stars: Optional[int] = Field(None, description="Number of stars")
    forks: Optional[int] = Field(None, description="Number of forks")
    last_updated: Optional[datetime] = Field(None, description="Last update date")
    secrets_found: List[str] = Field(default_factory=list, description="Secrets found in repository")
    files_analyzed: List[str] = Field(default_factory=list, description="Files analyzed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class SearchDorkResultResponse(BaseModel):
    """Response schema for search dork result."""
    id: UUID = Field(..., description="Search dork result ID")
    target_id: UUID = Field(..., description="Target ID")
    search_engine: str = Field(..., description="Search engine used")
    dork_query: str = Field(..., description="Dork query used")
    results_count: int = Field(default=0, description="Number of results found")
    urls_found: List[str] = Field(default_factory=list, description="URLs found")
    file_types: List[str] = Field(default_factory=list, description="File types discovered")
    parameters: List[str] = Field(default_factory=list, description="URL parameters found")
    error_messages: List[str] = Field(default_factory=list, description="Error messages found")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class BreachRecordResponse(BaseModel):
    """Response schema for breach record."""
    id: UUID = Field(..., description="Breach record ID")
    target_id: UUID = Field(..., description="Target ID")
    breach_name: str = Field(..., description="Name of the breach")
    breach_date: Optional[datetime] = Field(None, description="Date of the breach")
    breach_description: Optional[str] = Field(None, description="Description of the breach")
    data_classes: List[str] = Field(default_factory=list, description="Types of data exposed")
    records_count: Optional[int] = Field(None, description="Number of records exposed")
    source: str = Field(..., description="Source of breach information")
    verification_status: Optional[str] = Field(None, description="Verification status")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class InfrastructureExposureResponse(BaseModel):
    """Response schema for infrastructure exposure."""
    id: UUID = Field(..., description="Infrastructure exposure ID")
    target_id: UUID = Field(..., description="Target ID")
    ip_address: str = Field(..., description="IP address")
    port: Optional[int] = Field(None, description="Port number")
    service: Optional[str] = Field(None, description="Service name")
    banner: Optional[str] = Field(None, description="Service banner")
    ssl_info: Dict[str, Any] = Field(default_factory=dict, description="SSL certificate information")
    vulnerabilities: List[str] = Field(default_factory=list, description="Vulnerabilities found")
    source: str = Field(..., description="Source of information")
    last_seen: Optional[datetime] = Field(None, description="Last seen timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class ArchiveFindingResponse(BaseModel):
    """Response schema for archive finding."""
    id: UUID = Field(..., description="Archive finding ID")
    target_id: UUID = Field(..., description="Target ID")
    url: str = Field(..., description="Original URL")
    archived_url: str = Field(..., description="Archived URL")
    archive_date: Optional[datetime] = Field(None, description="Archive date")
    archive_source: str = Field(..., description="Archive source")
    content_type: Optional[str] = Field(None, description="Content type")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    title: Optional[str] = Field(None, description="Page title")
    parameters: List[str] = Field(default_factory=list, description="URL parameters found")
    secrets_found: List[str] = Field(default_factory=list, description="Secrets found in content")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class SocialMediaIntelResponse(BaseModel):
    """Response schema for social media intelligence."""
    id: UUID = Field(..., description="Social media intelligence ID")
    target_id: UUID = Field(..., description="Target ID")
    platform: str = Field(..., description="Social media platform")
    username: Optional[str] = Field(None, description="Username or handle")
    profile_url: Optional[str] = Field(None, description="Profile URL")
    display_name: Optional[str] = Field(None, description="Display name")
    bio: Optional[str] = Field(None, description="Profile bio")
    location: Optional[str] = Field(None, description="Location")
    company: Optional[str] = Field(None, description="Company")
    job_title: Optional[str] = Field(None, description="Job title")
    followers_count: Optional[int] = Field(None, description="Number of followers")
    following_count: Optional[int] = Field(None, description="Number of following")
    posts_count: Optional[int] = Field(None, description="Number of posts")
    last_active: Optional[datetime] = Field(None, description="Last active date")
    intel_metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional intelligence metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True)


class CloudAssetResponse(BaseModel):
    """Response schema for cloud asset."""
    id: UUID = Field(..., description="Cloud asset ID")
    target_id: UUID = Field(..., description="Target ID")
    asset_type: str = Field(..., description="Type of cloud asset")
    provider: str = Field(..., description="Cloud provider")
    asset_name: str = Field(..., description="Asset name")
    asset_url: Optional[str] = Field(None, description="Asset URL")
    region: Optional[str] = Field(None, description="Cloud region")
    status: Optional[str] = Field(None, description="Asset status")
    permissions: Optional[str] = Field(None, description="Asset permissions")
    last_modified: Optional[datetime] = Field(None, description="Last modified date")
    size: Optional[int] = Field(None, description="Asset size in bytes")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    model_config = ConfigDict(from_attributes=True) 