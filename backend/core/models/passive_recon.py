"""
Passive reconnaissance result models.

This module defines the PassiveReconResult and Subdomain models
which store the results of passive reconnaissance activities.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index, Integer
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel
import enum


class ReconSource(enum.Enum):
    """Enumeration for reconnaissance sources."""
    SUBFINDER = "subfinder"
    AMASS = "amass"
    ASSETFINDER = "assetfinder"
    CRTSH = "crt.sh"
    HACKERTARGET = "hackertarget"
    SHODAN = "shodan"
    CENSYS = "censys"
    MANUAL = "manual"


class SubdomainStatus(enum.Enum):
    """Enumeration for subdomain status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class PassiveReconResult(BaseModel):
    """
    PassiveReconResult model representing passive reconnaissance results.
    
    This model stores the overall results of passive reconnaissance
    activities performed against a target.
    """
    
    __tablename__ = "passive_recon_results"
    __table_args__ = (
        Index('idx_passive_recon_target', 'target_id'),
        Index('idx_passive_recon_execution', 'execution_id'),
        Index('idx_passive_recon_created', 'created_at'),
        {'schema': 'public'}
    )
    
    # Result identification
    execution_id = Column(String(255), nullable=False, index=True)  # Link to workflow execution
    
    # Reconnaissance details
    tools_used = Column(JSONB, nullable=True)  # List of tools used and their versions
    configuration = Column(JSONB, nullable=True)  # Configuration used for the recon
    
    # Results summary
    total_subdomains = Column(Integer, default=0, nullable=False)
    unique_subdomains = Column(Integer, default=0, nullable=False)
    active_subdomains = Column(Integer, default=0, nullable=False)
    
    # Raw results
    raw_output = Column(JSONB, nullable=True)  # Raw tool outputs
    processed_data = Column(JSONB, nullable=True)  # Processed and normalized data
    
    # Execution metadata
    execution_time = Column(String(50), nullable=True)  # Total execution time
    errors = Column(JSONB, nullable=True)  # Any errors encountered
    
    # Extra metadata
    extra_metadata = Column(JSONB, nullable=True)  # Arbitrary metadata storage
    
    # Relationships
    target_id = Column(PGUUID(as_uuid=True), ForeignKey("public.targets.id"), nullable=False)
    target = relationship("Target", back_populates="passive_recon_results")
    
    # Subdomains
    subdomains = relationship("Subdomain", back_populates="passive_recon_result", cascade="all, delete-orphan")
    
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
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'id': str(self.id),
        }


class Subdomain(BaseModel):
    """
    Subdomain model representing discovered subdomains.
    
    This model stores individual subdomain information discovered
    during passive reconnaissance.
    """
    
    __tablename__ = "subdomains"
    __table_args__ = (
        Index('idx_subdomains_name', 'name'),
        Index('idx_subdomains_domain', 'domain'),
        Index('idx_subdomains_status', 'status'),
        Index('idx_subdomains_verified', 'is_verified'),
        Index('idx_subdomains_passive_recon', 'passive_recon_result_id'),
        {'schema': 'public'}
    )
    
    # Subdomain identification
    name = Column(String(500), nullable=False, index=True)  # Full subdomain name
    domain = Column(String(255), nullable=False, index=True)  # Base domain
    subdomain_part = Column(String(255), nullable=False, index=True)  # Subdomain part only
    
    # Status and verification
    status = Column(Enum(SubdomainStatus), nullable=False, default=SubdomainStatus.UNKNOWN, index=True)
    is_verified = Column(Boolean, default=False, nullable=False, index=True)
    
    # DNS information
    ip_addresses = Column(JSONB, nullable=True)  # List of IP addresses
    cname = Column(String(500), nullable=True)  # CNAME record if exists
    mx_records = Column(JSONB, nullable=True)  # MX records
    txt_records = Column(JSONB, nullable=True)  # TXT records
    ns_records = Column(JSONB, nullable=True)  # NS records
    
    # Discovery metadata
    sources = Column(JSONB, nullable=True)  # List of sources that discovered this subdomain
    first_seen = Column(String(50), nullable=True)  # When first discovered
    last_seen = Column(String(50), nullable=True)  # When last seen
    
    # Additional information
    tags = Column(JSONB, nullable=True)  # Tags for categorization
    notes = Column(Text, nullable=True)  # Additional notes
    
    # Extra metadata
    extra_metadata = Column(JSONB, nullable=True)  # Arbitrary metadata storage
    
    # Relationships
    passive_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey("public.passive_recon_results.id"), nullable=False)
    passive_recon_result = relationship("PassiveReconResult", back_populates="subdomains")
    
    def __repr__(self) -> str:
        """String representation of the subdomain."""
        return f"<Subdomain(name='{self.name}', status='{self.status.value}')>"
    
    def to_dict(self) -> dict:
        """Convert subdomain to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'id': str(self.id),
            'target_id': str(self.passive_recon_result.target_id) if self.passive_recon_result else None,
            'subdomain': self.name,
            'domain': self.domain,
            'ip_addresses': self.ip_addresses,
            'status': self.status.value if hasattr(self.status, 'value') else self.status,
            'source': self.sources[0] if self.sources and isinstance(self.sources, list) else (self.sources or None),
            'extra_metadata': self.extra_metadata,
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