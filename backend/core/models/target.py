"""
Target model for managing bug hunting targets.

This module defines the Target model which represents the main
entities that bug hunting operations are performed against.
"""

import re
from typing import List, Optional
from uuid import UUID

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship, validates

from .base import BaseModel
import enum


class TargetScope(enum.Enum):
    """Enumeration for target scope types."""
    DOMAIN = "DOMAIN"
    IP_RANGE = "IP_RANGE"
    SUBNET = "SUBNET"
    WILDCARD = "WILDCARD"


class TargetStatus(enum.Enum):
    """Enumeration for target status."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ARCHIVED = "ARCHIVED"
    BLACKLISTED = "BLACKLISTED"


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
    name = Column(String(255), nullable=False, index=True)
    scope = Column(Enum(TargetScope, values_callable=lambda obj: [e.value for e in obj]), nullable=False, default=TargetScope.DOMAIN)
    value = Column(String(500), nullable=False, index=True)  # Domain, IP, or range
    
    # Target configuration
    status = Column(Enum(TargetStatus, values_callable=lambda obj: [e.value for e in obj]), nullable=False, default=TargetStatus.ACTIVE)
    is_primary = Column(Boolean, default=False, index=True)  # Primary target for the scope
    
    # Scope configuration
    scope_config = Column(JSONB, nullable=True)  # Additional scope-specific configuration
    
    # Bug Bounty Program Information
    program_name = Column(String(255), nullable=True, index=True)
    platform = Column(Enum(BugBountyPlatform, values_callable=lambda obj: [e.value for e in obj]), nullable=True)
    program_description = Column(Text, nullable=True)
    contact_email = Column(String(255), nullable=True)
    contact_url = Column(String(500), nullable=True)
    
    # Scope Configuration
    approved_urls = Column(JSONB, nullable=True)  # List of approved URLs
    blacklisted_urls = Column(JSONB, nullable=True)  # List of blacklisted URLs
    scope_rules = Column(JSONB, nullable=True)  # List of scope rules
    restrictions = Column(JSONB, nullable=True)  # List of restrictions
    
    # Rate Limiting Configuration
    rate_limits = Column(JSONB, nullable=True)  # Rate limiting configuration
    
    # Custom Headers
    custom_headers = Column(JSONB, nullable=True)  # List of custom headers
    
    # Additional Configuration
    special_instructions = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    
    # Relationships
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("public.users.id"), nullable=True)
    user = relationship("User", back_populates="targets")
    
    # Stage results relationships
    passive_recon_results = relationship("PassiveReconResult", back_populates="target", cascade="all, delete-orphan")
    active_recon_results = relationship("ActiveReconResult", back_populates="target", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="target", cascade="all, delete-orphan")
    kill_chains = relationship("KillChain", back_populates="target", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="target", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_targets_scope_value', 'scope', 'value'),
        Index('idx_targets_status', 'status'),
        Index('idx_targets_user', 'user_id'),
        {'schema': 'public'}
    )
    
    def __init__(self, **kwargs):
        """Initialize target with defaults."""
        # Set defaults if not provided
        if 'scope' not in kwargs:
            kwargs['scope'] = TargetScope.DOMAIN
        if 'status' not in kwargs:
            kwargs['status'] = TargetStatus.ACTIVE
        if 'is_primary' not in kwargs:
            kwargs['is_primary'] = False
        
        super().__init__(**kwargs)
        
        # Validate the value after all fields are set
        if hasattr(self, 'value') and self.value:
            self._validate_value_with_scope()
    
    def _validate_value_with_scope(self):
        """Validate value based on the current scope."""
        if not self.value or not self.value.strip():
            raise ValueError("Target value cannot be empty")
        
        value = self.value.strip()
        
        if self.scope == TargetScope.DOMAIN:
            if not self._is_valid_domain(value):
                raise ValueError(f"Invalid domain format: {value}")
        elif self.scope == TargetScope.IP_RANGE:
            if not self._is_valid_ip_range(value):
                raise ValueError(f"Invalid IP range format: {value}")
        elif self.scope == TargetScope.SUBNET:
            if not self._is_valid_subnet(value):
                raise ValueError(f"Invalid subnet format: {value}")
        elif self.scope == TargetScope.WILDCARD:
            if not self._is_valid_wildcard(value):
                raise ValueError(f"Invalid wildcard format: {value}")
    
    @validates('name')
    def validate_name(self, key, value):
        """Validate target name."""
        if not value or not value.strip():
            raise ValueError("Target name cannot be empty")
        
        value = value.strip()
        if len(value) > 255:
            raise ValueError("Target name cannot exceed 255 characters")
        
        return value
    
    @validates('value')
    def validate_value(self, key, value):
        """Validate target value based on scope."""
        if not value or not value.strip():
            raise ValueError("Target value cannot be empty")
        
        # Only do basic validation here - scope-specific validation should be done separately
        # or in the application layer
        return value.strip()
    
    @validates('scope')
    def validate_scope(self, key, value):
        """Validate and serialize scope enum."""
        if isinstance(value, TargetScope):
            return value
        elif isinstance(value, str):
            try:
                return TargetScope(value.lower())
            except ValueError:
                # Let SQLAlchemy handle database-level validation for invalid values
                return value
        else:
            # Let SQLAlchemy handle database-level validation for invalid types
            return value
    
    @validates('status')
    def validate_status(self, key, value):
        """Validate and serialize status enum."""
        if isinstance(value, TargetStatus):
            return value
        elif isinstance(value, str):
            try:
                return TargetStatus(value.lower())
            except ValueError:
                # Let SQLAlchemy handle database-level validation for invalid values
                return value
        else:
            # Let SQLAlchemy handle database-level validation for invalid types
            return value
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        if not domain:
            return False
        
        # Basic domain regex pattern
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        # Check for common invalid patterns
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
            # Check if it's a single IP address
            ipaddress.IPv4Address(ip_range)
            return True
        except Exception:
            # Check if it's a valid IP range (CIDR notation)
            try:
                ipaddress.IPv4Network(ip_range, strict=False)
                return True
            except Exception:
                return False
    
    def _is_valid_subnet(self, subnet: str) -> bool:
        """Validate subnet format."""
        import ipaddress
        try:
            # Validate both IP and CIDR parts
            ipaddress.IPv4Network(subnet, strict=False)
            return True
        except (ipaddress.NetmaskValueError, ipaddress.AddressValueError, ValueError):
            return False
    
    def _is_valid_wildcard(self, wildcard: str) -> bool:
        """Validate wildcard format."""
        # Basic wildcard validation - can be expanded
        wildcard_pattern = r'^\*\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(wildcard_pattern, wildcard))
    
    def _matches_wildcard_pattern(self, domain: str, wildcard_pattern: str) -> bool:
        """Check if a domain matches a wildcard pattern."""
        if not wildcard_pattern.startswith('*.'):
            return domain == wildcard_pattern
        
        # Extract the base domain from the wildcard pattern
        base_domain = wildcard_pattern[2:]  # Remove '*.' prefix
        
        # Check if the domain ends with the base domain
        if domain == base_domain:
            return True
        
        # Check if the domain is a subdomain of the base domain
        if domain.endswith('.' + base_domain):
            return True
        
        return False
    
    def __repr__(self) -> str:
        """String representation of the target."""
        return f"<Target(name='{self.name}', scope='{self.scope.value}', value='{self.value}')>"
    
    def to_dict(self) -> dict:
        """Convert target to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'name': self.name,
            'scope': self.scope.value,
            'value': self.value,
            'status': self.status.value,
            'is_primary': self.is_primary,
            'scope_config': self.scope_config,
            'user_id': str(self.user_id) if self.user_id else None,
            # Bug Bounty Program Information
            'program_name': self.program_name,
            'platform': self.platform.value if self.platform else None,
            'program_description': self.program_description,
            'contact_email': self.contact_email,
            'contact_url': self.contact_url,
            # Scope Configuration
            'approved_urls': self.approved_urls,
            'blacklisted_urls': self.blacklisted_urls,
            'scope_rules': self.scope_rules,
            'restrictions': self.restrictions,
            # Rate Limiting Configuration
            'rate_limits': self.rate_limits,
            # Custom Headers
            'custom_headers': self.custom_headers,
            # Additional Configuration
            'special_instructions': self.special_instructions,
            'notes': self.notes,
        }
    
    @property
    def is_active(self) -> bool:
        """Check if target is active."""
        return self.status == TargetStatus.ACTIVE
    
    @property
    def display_name(self) -> str:
        """Get display name for the target."""
        return f"{self.name} ({self.value})" 