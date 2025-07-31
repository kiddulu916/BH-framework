"""
Passive reconnaissance models for storing passive recon results.

This module defines the PassiveReconResult and Subdomain models
which store the results of passive reconnaissance activities.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index, Integer
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel, get_foreign_key, get_table_args, get_foreign_key
from sqlalchemy.dialects.postgresql import JSONB as JSONType
import enum


class ReconStatus(enum.Enum):
    """Enumeration for reconnaissance status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SubdomainStatus(enum.Enum):
    """Enumeration for subdomain status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class ReconCategory(enum.Enum):
    """Enumeration for reconnaissance categories."""
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


class PassiveReconResult(BaseModel):
    """
    PassiveReconResult model representing passive reconnaissance results.
    
    This model stores the overall results of passive reconnaissance
    activities performed against a target.
    """
    
    __tablename__ = "passive_recon_results"
    __table_args__ = get_table_args(
        Index('idx_passive_recon_target', 'target_id'),
        Index('idx_passive_recon_execution', 'execution_id'),
        Index('idx_passive_recon_created', 'created_at'),
    )
    
    # Recon identification
    execution_id = Column(String(255), nullable=False, index=True)  # Link to workflow execution
    
    # Recon details
    tools_used = Column(JSONType, nullable=True)  # List of tools used and their versions
    configuration = Column(JSONType, nullable=True)  # Configuration used for the recon
    
    # Results summary
    total_subdomains = Column(Integer, default=0, nullable=False)
    unique_subdomains = Column(Integer, default=0, nullable=False)
    total_ips = Column(Integer, default=0, nullable=False)
    unique_ips = Column(Integer, default=0, nullable=False)
    
    # Raw results
    raw_output = Column(JSONType, nullable=True)  # Raw tool outputs
    processed_data = Column(JSONType, nullable=True)  # Processed and normalized data
    
    # Execution metadata
    execution_time = Column(String(50), nullable=True)  # Total execution time
    errors = Column(JSONType, nullable=True)  # Any errors encountered
    
    # Additional metadata
    extra_metadata = Column(JSONType, nullable=True)  # Arbitrary metadata storage
    
    # Relationships
    target_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("targets", "id")), nullable=False)
    target = relationship("Target", back_populates="passive_recon_results")
    
    # Subdomains
    subdomains = relationship("Subdomain", back_populates="passive_recon_result", cascade="all, delete-orphan")
    
    # Enhanced OSINT relationships
    whois_records = relationship("WHOISRecord", back_populates="passive_recon_result", cascade="all, delete-orphan")
    certificate_logs = relationship("CertificateLog", back_populates="passive_recon_result", cascade="all, delete-orphan")
    repository_findings = relationship("RepositoryFinding", back_populates="passive_recon_result", cascade="all, delete-orphan")
    search_dork_results = relationship("SearchDorkResult", back_populates="passive_recon_result", cascade="all, delete-orphan")
    breach_records = relationship("BreachRecord", back_populates="passive_recon_result", cascade="all, delete-orphan")
    infrastructure_exposures = relationship("InfrastructureExposure", back_populates="passive_recon_result", cascade="all, delete-orphan")
    archive_findings = relationship("ArchiveFinding", back_populates="passive_recon_result", cascade="all, delete-orphan")
    social_media_intel = relationship("SocialMediaIntel", back_populates="passive_recon_result", cascade="all, delete-orphan")
    cloud_assets = relationship("CloudAsset", back_populates="passive_recon_result", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation of the passive recon result."""
        return f"<PassiveReconResult(target_id='{self.target_id}', total_subdomains={self.total_subdomains})>"
    
    def to_dict(self) -> dict:
        """Convert passive recon result to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'execution_id': self.execution_id,
            'tools_used': self.tools_used,
            'total_subdomains': self.total_subdomains,
            'execution_time': self.execution_time,
            'raw_output': self.raw_output,
            'extra_metadata': self.extra_metadata,
            'target_id': str(self.target_id),
            'subdomains': [s.to_dict() for s in self.subdomains],
            'whois_records': [w.to_dict() for w in self.whois_records],
            'certificate_logs': [c.to_dict() for c in self.certificate_logs],
            'repository_findings': [r.to_dict() for r in self.repository_findings],
            'search_dork_results': [s.to_dict() for s in self.search_dork_results],
            'breach_records': [b.to_dict() for b in self.breach_records],
            'infrastructure_exposures': [i.to_dict() for i in self.infrastructure_exposures],
            'archive_findings': [a.to_dict() for a in self.archive_findings],
            'social_media_intel': [s.to_dict() for s in self.social_media_intel],
            'cloud_assets': [c.to_dict() for c in self.cloud_assets],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Subdomain(BaseModel):
    """
    Subdomain model representing discovered subdomains.
    
    This model stores individual subdomain information discovered
    during passive reconnaissance.
    """
    
    __tablename__ = "subdomains"
    __table_args__ = get_table_args(
        Index('idx_subdomains_name', 'name'),
        Index('idx_subdomains_domain', 'domain'),
        Index('idx_subdomains_status', 'status'),
        Index('idx_subdomains_verified', 'is_verified'),
        Index('idx_subdomains_passive_recon', 'passive_recon_result_id'),
    )
    
    # Subdomain identification
    name = Column(String(500), nullable=False, index=True)  # Full subdomain name
    domain = Column(String(255), nullable=False, index=True)  # Base domain
    subdomain_part = Column(String(255), nullable=False, index=True)  # Subdomain part only
    
    # Status and verification
    status = Column(Enum(SubdomainStatus), nullable=False, default=SubdomainStatus.UNKNOWN, index=True)
    is_verified = Column(Boolean, default=False, nullable=False, index=True)
    
    # DNS information
    ip_addresses = Column(JSONType, nullable=True)  # List of IP addresses
    cname = Column(String(500), nullable=True)  # CNAME record if exists
    mx_records = Column(JSONType, nullable=True)  # MX records
    txt_records = Column(JSONType, nullable=True)  # TXT records
    ns_records = Column(JSONType, nullable=True)  # NS records
    
    # Discovery metadata
    sources = Column(JSONType, nullable=True)  # List of sources that discovered this subdomain
    first_seen = Column(String(50), nullable=True)  # When first discovered
    last_seen = Column(String(50), nullable=True)  # When last seen
    
    # Additional information
    tags = Column(JSONType, nullable=True)  # Tags for categorization
    notes = Column(Text, nullable=True)  # Additional notes
    
    # Extra metadata
    extra_metadata = Column(JSONType, nullable=True)  # Arbitrary metadata storage
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="subdomains")
    
    def __repr__(self) -> str:
        """String representation of the subdomain."""
        return f"<Subdomain(name='{self.name}', status='{self.status}')>"
    
    def to_dict(self) -> dict:
        """Convert subdomain to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'name': self.name,
            'domain': self.domain,
            'subdomain_part': self.subdomain_part,
            'status': self.status.value if self.status else None,
            'is_verified': self.is_verified,
            'ip_addresses': self.ip_addresses,
            'cname': self.cname,
            'mx_records': self.mx_records,
            'txt_records': self.txt_records,
            'ns_records': self.ns_records,
            'sources': self.sources,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'tags': self.tags,
            'notes': self.notes,
            'extra_metadata': self.extra_metadata,
            'passive_recon_result_id': str(self.passive_recon_result_id),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @property
    def is_active(self) -> bool:
        """Check if subdomain is active."""
        return self.status == SubdomainStatus.ACTIVE
    
    @property
    def has_ip(self) -> bool:
        """Check if subdomain has IP addresses."""
        return bool(self.ip_addresses and len(self.ip_addresses) > 0)


# Enhanced OSINT Models

class WHOISRecord(BaseModel):
    """WHOIS record model for domain registration information."""
    
    __tablename__ = "whois_records"
    __table_args__ = get_table_args(
        Index('idx_whois_domain', 'domain'),
        Index('idx_whois_registrar', 'registrar'),
        Index('idx_whois_passive_recon', 'passive_recon_result_id'),
    )
    
    domain = Column(String(500), nullable=False, index=True)
    registrar = Column(String(255), nullable=True)
    registrant_name = Column(String(255), nullable=True)
    registrant_email = Column(String(255), nullable=True)
    registrant_organization = Column(String(255), nullable=True)
    creation_date = Column(String(50), nullable=True)
    expiration_date = Column(String(50), nullable=True)
    updated_date = Column(String(50), nullable=True)
    name_servers = Column(JSONType, nullable=True)
    status = Column(JSONType, nullable=True)
    raw_data = Column(Text, nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="whois_records")
    
    def to_dict(self) -> dict:
        """Convert WHOIS record to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'domain': self.domain,
            'registrar': self.registrar,
            'registrant_name': self.registrant_name,
            'registrant_email': self.registrant_email,
            'registrant_organization': self.registrant_organization,
            'creation_date': self.creation_date,
            'expiration_date': self.expiration_date,
            'updated_date': self.updated_date,
            'name_servers': self.name_servers,
            'status': self.status,
            'raw_data': self.raw_data,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class CertificateLog(BaseModel):
    """Certificate transparency log model."""
    
    __tablename__ = "certificate_logs"
    __table_args__ = get_table_args(
        Index('idx_cert_domain', 'domain'),
        Index('idx_cert_issuer', 'issuer'),
        Index('idx_cert_passive_recon', 'passive_recon_result_id'),
    )
    
    domain = Column(String(500), nullable=False, index=True)
    certificate_id = Column(String(255), nullable=True)
    issuer = Column(String(255), nullable=True)
    subject_alt_names = Column(JSONType, nullable=True)
    not_before = Column(String(50), nullable=True)
    not_after = Column(String(50), nullable=True)
    serial_number = Column(String(255), nullable=True)
    fingerprint = Column(String(255), nullable=True)
    log_index = Column(String(255), nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="certificate_logs")
    
    def to_dict(self) -> dict:
        """Convert certificate log to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'domain': self.domain,
            'certificate_id': self.certificate_id,
            'issuer': self.issuer,
            'subject_alt_names': self.subject_alt_names,
            'not_before': self.not_before,
            'not_after': self.not_after,
            'serial_number': self.serial_number,
            'fingerprint': self.fingerprint,
            'log_index': self.log_index,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class RepositoryFinding(BaseModel):
    """Public repository finding model."""
    
    __tablename__ = "repository_findings"
    __table_args__ = get_table_args(
        Index('idx_repo_platform', 'platform'),
        Index('idx_repo_type', 'finding_type'),
        Index('idx_repo_passive_recon', 'passive_recon_result_id'),
    )
    
    platform = Column(String(50), nullable=False, index=True)  # GitHub, GitLab, etc.
    repository_url = Column(String(500), nullable=True)
    file_path = Column(String(500), nullable=True)
    finding_type = Column(String(100), nullable=False, index=True)  # API_KEY, PASSWORD, etc.
    content = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    commit_hash = Column(String(255), nullable=True)
    severity = Column(String(50), nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="repository_findings")
    
    def to_dict(self) -> dict:
        """Convert repository finding to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'platform': self.platform,
            'repository_url': self.repository_url,
            'file_path': self.file_path,
            'finding_type': self.finding_type,
            'content': self.content,
            'line_number': self.line_number,
            'commit_hash': self.commit_hash,
            'severity': self.severity,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class SearchDorkResult(BaseModel):
    """Search engine dorking result model."""
    
    __tablename__ = "search_dork_results"
    __table_args__ = get_table_args(
        Index('idx_dork_query', 'search_query'),
        Index('idx_dork_type', 'result_type'),
        Index('idx_dork_passive_recon', 'passive_recon_result_id'),
    )
    
    search_query = Column(String(500), nullable=False, index=True)
    result_type = Column(String(100), nullable=False, index=True)  # FILE, DIRECTORY, ERROR, etc.
    url = Column(String(500), nullable=True)
    title = Column(String(500), nullable=True)
    snippet = Column(Text, nullable=True)
    file_type = Column(String(50), nullable=True)
    file_size = Column(String(50), nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="search_dork_results")
    
    def to_dict(self) -> dict:
        """Convert search dork result to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'search_query': self.search_query,
            'result_type': self.result_type,
            'url': self.url,
            'title': self.title,
            'snippet': self.snippet,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class BreachRecord(BaseModel):
    """Data breach record model."""
    
    __tablename__ = "breach_records"
    __table_args__ = get_table_args(
        Index('idx_breach_source', 'breach_source'),
        Index('idx_breach_type', 'breach_type'),
        Index('idx_breach_passive_recon', 'passive_recon_result_id'),
    )
    
    breach_source = Column(String(255), nullable=False, index=True)  # HaveIBeenPwned, DeHashed, etc.
    breach_type = Column(String(100), nullable=False, index=True)  # EMAIL, PASSWORD, PERSONAL_INFO, etc.
    email = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=True)
    personal_info = Column(JSONType, nullable=True)
    breach_date = Column(String(50), nullable=True)
    breach_name = Column(String(255), nullable=True)
    severity = Column(String(50), nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="breach_records")
    
    def to_dict(self) -> dict:
        """Convert breach record to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'breach_source': self.breach_source,
            'breach_type': self.breach_type,
            'email': self.email,
            'username': self.username,
            'password_hash': self.password_hash,
            'personal_info': self.personal_info,
            'breach_date': self.breach_date,
            'breach_name': self.breach_name,
            'severity': self.severity,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class InfrastructureExposure(BaseModel):
    """Infrastructure exposure model (Shodan, Censys, etc.)."""
    
    __tablename__ = "infrastructure_exposures"
    __table_args__ = get_table_args(
        Index('idx_infra_source', 'source'),
        Index('idx_infra_service', 'service'),
        Index('idx_infra_passive_recon', 'passive_recon_result_id'),
    )
    
    source = Column(String(50), nullable=False, index=True)  # Shodan, Censys, etc.
    ip_address = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)
    service = Column(String(100), nullable=True, index=True)
    banner = Column(Text, nullable=True)
    ssl_info = Column(JSONType, nullable=True)
    vulnerabilities = Column(JSONType, nullable=True)
    location = Column(JSONType, nullable=True)
    organization = Column(String(255), nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="infrastructure_exposures")
    
    def to_dict(self) -> dict:
        """Convert infrastructure exposure to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'source': self.source,
            'ip_address': self.ip_address,
            'port': self.port,
            'service': self.service,
            'banner': self.banner,
            'ssl_info': self.ssl_info,
            'vulnerabilities': self.vulnerabilities,
            'location': self.location,
            'organization': self.organization,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class ArchiveFinding(BaseModel):
    """Archive and historical data finding model."""
    
    __tablename__ = "archive_findings"
    __table_args__ = get_table_args(
        Index('idx_archive_source', 'archive_source'),
        Index('idx_archive_type', 'finding_type'),
        Index('idx_archive_passive_recon', 'passive_recon_result_id'),
    )
    
    archive_source = Column(String(50), nullable=False, index=True)  # Wayback Machine, Google Cache, etc.
    finding_type = Column(String(100), nullable=False, index=True)  # URL, PARAMETER, SECRET, etc.
    original_url = Column(String(500), nullable=True)
    archived_url = Column(String(500), nullable=True)
    archive_date = Column(String(50), nullable=True)
    content = Column(Text, nullable=True)
    parameters = Column(JSONType, nullable=True)
    secrets_found = Column(JSONType, nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="archive_findings")
    
    def to_dict(self) -> dict:
        """Convert archive finding to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'archive_source': self.archive_source,
            'finding_type': self.finding_type,
            'original_url': self.original_url,
            'archived_url': self.archived_url,
            'archive_date': self.archive_date,
            'content': self.content,
            'parameters': self.parameters,
            'secrets_found': self.secrets_found,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class SocialMediaIntel(BaseModel):
    """Social media and public information intelligence model."""
    
    __tablename__ = "social_media_intel"
    __table_args__ = get_table_args(
        Index('idx_social_platform', 'platform'),
        Index('idx_social_type', 'intel_type'),
        Index('idx_social_passive_recon', 'passive_recon_result_id'),
    )
    
    platform = Column(String(50), nullable=False, index=True)  # LinkedIn, Twitter, etc.
    intel_type = Column(String(100), nullable=False, index=True)  # EMPLOYEE, TECH_STACK, PROJECT, etc.
    username = Column(String(255), nullable=True)
    profile_url = Column(String(500), nullable=True)
    content = Column(Text, nullable=True)
    intel_metadata = Column(JSONType, nullable=True)  # Renamed from metadata to avoid SQLAlchemy conflict
    relevance_score = Column(Integer, nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="social_media_intel")
    
    def to_dict(self) -> dict:
        """Convert social media intel to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'platform': self.platform,
            'intel_type': self.intel_type,
            'username': self.username,
            'profile_url': self.profile_url,
            'content': self.content,
            'intel_metadata': self.intel_metadata,
            'relevance_score': self.relevance_score,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        }


class CloudAsset(BaseModel):
    """Cloud asset discovery model."""
    
    __tablename__ = "cloud_assets"
    __table_args__ = get_table_args(
        Index('idx_cloud_provider', 'provider'),
        Index('idx_cloud_type', 'asset_type'),
        Index('idx_cloud_passive_recon', 'passive_recon_result_id'),
    )
    
    provider = Column(String(50), nullable=False, index=True)  # AWS, GCP, Azure, etc.
    asset_type = Column(String(100), nullable=False, index=True)  # S3_BUCKET, STORAGE_ACCOUNT, etc.
    asset_name = Column(String(255), nullable=True)
    asset_url = Column(String(500), nullable=True)
    is_public = Column(Boolean, default=False, nullable=False)
    permissions = Column(JSONType, nullable=True)
    contents = Column(JSONType, nullable=True)
    misconfiguration = Column(Text, nullable=True)
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("passive_recon_results", "id")), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="cloud_assets")
    
    def to_dict(self) -> dict:
        """Convert cloud asset to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'provider': self.provider,
            'asset_type': self.asset_type,
            'asset_name': self.asset_name,
            'asset_url': self.asset_url,
            'is_public': self.is_public,
            'permissions': self.permissions,
            'contents': self.contents,
            'misconfiguration': self.misconfiguration,
            'passive_recon_result_id': str(self.passive_recon_result_id),
        } 