"""
Target model for managing bug hunting targets.

This module defines the Target model which represents the main
entities that bug hunting operations are performed against.
"""

import re
from typing import List, Optional
from uuid import UUID

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index, Integer
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship, validates

from .base import BaseModel, get_table_args, get_foreign_key
from sqlalchemy.dialects.postgresql import JSONB as JSONType
import enum

class TargetStatus(enum.Enum):
    """Enumeration for target status."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class BugBountyPlatform(enum.Enum):
    """Enumeration for bug bounty platforms."""
    HACKERONE = "HACKERONE"
    BUGCROWD = "BUGCROWD"
    INTIGRITI = "INTIGRITI"
    YESWEHACK = "YESWEHACK"
    CUSTOM = "CUSTOM"


class Target(BaseModel):
    """
    Target model representing bug hunting targets.
    
    A target can be a domain, IP range, subnet, or wildcard scope
    that bug hunting operations are performed against.
    """
    
    __tablename__ = "targets"
    
    # Target identification
    target = Column(String(255), nullable=True, index=True)  # Legacy field for frontend compatibility
    domain = Column(String(500), nullable=True, index=True)  # Frontend field for domain/IP
    is_primary = Column(Boolean, nullable=False, default=False)
    
    # Target status
    status = Column(Enum(TargetStatus, values_callable=lambda obj: [e.value for e in obj]), nullable=False, default=TargetStatus.ACTIVE)
       
    # Bug Bounty Program Information
    platform = Column(Enum(BugBountyPlatform, values_callable=lambda obj: [e.value for e in obj]), nullable=True)
    login_email = Column(String(255), nullable=True)  # Frontend field
    researcher_email = Column(String(255), nullable=True)  # Frontend field
    
    # Scope Configuration
    in_scope = Column(JSONType, nullable=True)  # Frontend field - List of in-scope URLs
    out_of_scope = Column(JSONType, nullable=True)  # Frontend field - List of out-of-scope URLs
    
    # Rate Limiting Configuration
    rate_limit_requests = Column(Integer, nullable=True)  # Frontend field
    rate_limit_seconds = Column(Integer, nullable=True)  # Frontend field
    
    # Custom Headers
    custom_headers = Column(JSONType, nullable=True)  # List of custom headers
    
    # Additional Configuration
    additional_info = Column(JSONType, nullable=True)  # Frontend field - List of additional info
    notes = Column(Text, nullable=True)
    
    # Stage results relationships
    passive_recon_results = relationship("PassiveReconResult", back_populates="target", cascade="all, delete-orphan")
    active_recon_results = relationship("ActiveReconResult", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
    kill_chains = relationship("KillChain", back_populates="target", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="target", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = get_table_args(
        Index('idx_targets_domain', 'domain'),
        Index('idx_targets_status', 'status'),
    )
    
    def __init__(self, **kwargs):
        """Initialize target with defaults."""
        # Set defaults if not provided
        if 'status' not in kwargs:
            kwargs['status'] = TargetStatus.ACTIVE
        if 'is_primary' not in kwargs:
            kwargs['is_primary'] = False

        
        super().__init__(**kwargs)
        
        # Validate the value after all fields are set
        if hasattr(self, 'target') and self.target:
            self._validate_target()
    
    @validates('target')
    def validate_target(self, key, value):
        """Validate target name."""
        if not value or not value.strip():
            raise ValueError("Target name cannot be empty")
        
        value = value.strip()
        if len(value) > 255:
            raise ValueError("Target name cannot exceed 255 characters")
        
        return value
    
    @validates('domain')
    def validate_domain(self, key, value):
        """Validate target domain."""
        if value and len(value.strip()) > 500:
            raise ValueError("Target domain cannot exceed 500 characters")
        return value.strip() if value else value
    
    @validates('status')
    def validate_status(self, key, value):
        """Validate and serialize status enum."""
        if isinstance(value, TargetStatus):
            return value
        elif isinstance(value, str):
            try:
                return TargetStatus(value.lower())
            except ValueError:
                return value
        else:
            return value
    
    @validates('platform')
    def validate_platform(self, key, value):
        """Validate and serialize platform enum."""
        if isinstance(value, BugBountyPlatform):
            return value
        elif isinstance(value, str):
            try:
                return BugBountyPlatform(value.lower())
            except ValueError:
                return value
        else:
            return value
    
    def _validate_target(self):
        """Validate target field."""
        if self.target and len(self.target.strip()) > 255:
            raise ValueError("Target field cannot exceed 255 characters")
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        if not domain:
            return False
        
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        if (domain.startswith('.') or 
            domain.endswith('.') or 
            '..' in domain or
            not re.match(domain_pattern, domain)):
            return False
        
        return True
    
    def _is_valid_ip_range(self, ip_range: str) -> bool:
        """Validate IP range format using ipaddress module for strict IPv4 validation."""
        import ipaddress
        try:
            ipaddress.IPv4Address(ip_range)
            return True
        except Exception:
            try:
                ipaddress.IPv4Network(ip_range, strict=False)
                return True
            except Exception:
                return False
    
    def _is_valid_subnet(self, subnet: str) -> bool:
        """Validate subnet format."""
        import ipaddress
        try:
            ipaddress.IPv4Network(subnet, strict=False)
            return True
        except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
            return False
    
    def _is_valid_wildcard(self, wildcard: str) -> bool:
        """Validate wildcard format."""
        wildcard_pattern = r'^\*\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(wildcard_pattern, wildcard))
    
    def _matches_wildcard_pattern(self, domain: str, wildcard_pattern: str) -> bool:
        """Check if a domain matches a wildcard pattern."""
        if not wildcard_pattern.startswith('*.'):
            return domain == wildcard_pattern
        
        base_domain = wildcard_pattern[2:]  # Remove '*.' prefix
        
        if domain == base_domain:
            return True
        
        if domain.endswith('.' + base_domain):
            return True
        
        return False
    
    def __repr__(self) -> str:
        """String representation of the target."""
        return f"<Target(target='{self.target}', domain='{self.domain}', status='{self.status.value}')>"
    
    def to_dict(self) -> dict:
        """Convert target to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'target': self.target,
            'domain': self.domain,
            'is_primary': self.is_primary,
            'status': self.status.value.lower(),
            'platform': self.platform.value.lower() if self.platform else None,
            'login_email': self.login_email,
            'researcher_email': self.researcher_email,
            'in_scope': self.in_scope,
            'out_of_scope': self.out_of_scope,
            'rate_limit_requests': self.rate_limit_requests,
            'rate_limit_seconds': self.rate_limit_seconds,
            'custom_headers': self.custom_headers,
            'additional_info': self.additional_info,
            'notes': self.notes,
        }
    
    @property
    def is_active(self) -> bool:
        """Check if target is active."""
        return self.status == TargetStatus.ACTIVE
    
    @property
    def display_name(self) -> str:
        """Get display name for the target."""
        return f"{self.target} ({self.domain})" 