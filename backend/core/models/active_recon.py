"""
Active reconnaissance result models.

This module defines the ActiveReconResult, Port, and Service models
which store the results of active reconnaissance activities.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index, Integer, Float
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel, get_foreign_key, get_table_args, get_foreign_key
from sqlalchemy.dialects.postgresql import JSONB as JSONType
import enum
import json


class PortStatus(enum.Enum):
    """Enumeration for port status."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open_filtered"
    CLOSED_FILTERED = "closed_filtered"
    UNKNOWN = "unknown"


class ServiceStatus(enum.Enum):
    """Enumeration for service status."""
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


class ActiveReconResult(BaseModel):
    """
    ActiveReconResult model representing active reconnaissance results.
    
    This model stores the overall results of active reconnaissance
    activities performed against discovered subdomains.
    """
    
    __tablename__ = "active_recon_results"
    __table_args__ = get_table_args(
        Index('idx_active_recon_target', 'target_id'),
        Index('idx_active_recon_execution', 'execution_id'),
        Index('idx_active_recon_created', 'created_at'),
    )
    
    # Result identification
    execution_id = Column(String(255), nullable=False, index=True)  # Link to workflow execution
    
    # Reconnaissance details
    tools_used = Column(JSONType, nullable=True)  # List of tools used and their versions
    configuration = Column(JSONType, nullable=True)  # Configuration used for the recon
    scan_type = Column(String(100), nullable=True)  # Type of scan performed
    hosts_scanned = Column(JSONType, nullable=False, default=list)  # List of hosts scanned
    
    # Results summary
    total_hosts_scanned = Column(Integer, default=0, nullable=False)
    hosts_with_open_ports = Column(Integer, default=0, nullable=False)
    total_open_ports = Column(Integer, default=0, nullable=False)
    total_services_detected = Column(Integer, default=0, nullable=False)
    
    # Raw results
    raw_output = Column(JSONType, nullable=True)  # Raw tool outputs
    processed_data = Column(JSONType, nullable=True)  # Processed and normalized data
    
    # Execution metadata
    execution_time = Column(Float, nullable=True)  # Total execution time in seconds
    errors = Column(JSONType, nullable=True)  # Any errors encountered
    
    # Relationships
    target_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("targets", "id")), nullable=False)
    target = relationship("Target", back_populates="active_recon_results")
    
    # Ports and services
    ports = relationship("Port", back_populates="active_recon_result", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="active_recon_result", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation of the active recon result."""
        return f"<ActiveReconResult(target_id='{self.target_id}', total_open_ports={self.total_open_ports})>"
    
    def to_dict(self) -> dict:
        """Convert active recon result to dictionary."""
        # Parse JSONB fields back to Python objects
        def parse_jsonb_field(value):
            if value is None:
                return value
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return value
            return value
        
        base_dict = super().to_dict()
        return {
            **base_dict,
            'execution_id': self.execution_id,
            'tools_used': parse_jsonb_field(self.tools_used),
            'configuration': parse_jsonb_field(self.configuration),
            'scan_type': self.scan_type,
            'hosts_scanned': parse_jsonb_field(self.hosts_scanned),
            'total_hosts_scanned': self.total_hosts_scanned,
            'hosts_with_open_ports': self.hosts_with_open_ports,
            'total_open_ports': self.total_open_ports,
            'total_services_detected': self.total_services_detected,
            'raw_output': parse_jsonb_field(self.raw_output),
            'processed_data': parse_jsonb_field(self.processed_data),
            'execution_time': self.execution_time,
            'errors': parse_jsonb_field(self.errors),
            'target_id': str(self.target_id),
        }


class Port(BaseModel):
    """
    Port model representing discovered ports.
    
    This model stores individual port information discovered
    during active reconnaissance.
    """
    
    __tablename__ = "ports"
    __table_args__ = get_table_args(
        Index('idx_ports_host', 'host'),
        Index('idx_ports_number', 'port_number'),
        Index('idx_ports_protocol', 'protocol'),
        Index('idx_ports_status', 'status'),
        Index('idx_ports_open', 'is_open'),
        Index('idx_ports_service', 'service_name'),
        Index('idx_ports_active_recon', 'active_recon_result_id'),
        Index('idx_ports_host_port', 'host', 'port_number', 'protocol'),
    )
    
    # Port identification
    host = Column(String(255), nullable=False, index=True)  # Host (IP or domain)
    port_number = Column(Integer, nullable=False, index=True)  # Port number
    protocol = Column(String(10), nullable=False, default="tcp", index=True)  # Protocol (tcp/udp)
    
    # Port status
    status = Column(Enum(PortStatus), nullable=False, default=PortStatus.UNKNOWN, index=True)
    is_open = Column(Boolean, default=False, nullable=False, index=True)
    
    # Service information
    service_name = Column(String(255), nullable=True, index=True)  # Detected service name
    service_version = Column(String(255), nullable=True)  # Service version if detected
    service_product = Column(String(255), nullable=True)  # Product name if detected
    
    # Additional information
    banner = Column(Text, nullable=True)  # Service banner
    script_output = Column(JSONType, nullable=True)  # Nmap script output
    notes = Column(Text, nullable=True)  # Additional notes
    
    # Relationships
    active_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("active_recon_results", "id")), nullable=False)
    active_recon_result = relationship("ActiveReconResult", back_populates="ports")
    
    # Services
    services = relationship("Service", back_populates="port", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation of the port."""
        return f"<Port(host='{self.host}', port={self.port_number}/{self.protocol}, status='{self.status.value}')>"
    
    def to_dict(self) -> dict:
        """Convert port to dictionary."""
        base_dict = super().to_dict()
        
        # Parse JSONB fields back to Python objects
        def parse_jsonb_field(value):
            if value is None:
                return value
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return value
            return value
        
        return {
            **base_dict,
            'host': self.host,
            'port_number': self.port_number,
            'port': self.port_number,  # alias for schema compatibility
            'protocol': self.protocol,
            'status': self.status.value,
            'is_open': self.is_open,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'service_product': self.service_product,
            'banner': self.banner,
            'script_output': parse_jsonb_field(self.script_output),
            'active_recon_result_id': str(self.active_recon_result_id),
            'target_id': str(self.active_recon_result.target_id) if self.active_recon_result else None,
            'metadata': {},  # default empty dict for compatibility
        }
    
    @property
    def port_string(self) -> str:
        """Get port string representation."""
        return f"{self.port_number}/{self.protocol}"
    
    @property
    def has_service(self) -> bool:
        """Check if port has service information."""
        return bool(self.service_name or self.service_product)


class Service(BaseModel):
    """
    Service model representing detected services.
    
    This model stores detailed service information discovered
    during active reconnaissance.
    """
    
    __tablename__ = "services"
    __table_args__ = get_table_args(
        Index('idx_services_name', 'name'),
        Index('idx_services_product', 'product'),
        Index('idx_services_status', 'status'),
        Index('idx_services_confirmed', 'is_confirmed'),
        Index('idx_services_port', 'port_id'),
        Index('idx_services_active_recon', 'active_recon_result_id'),
    )
    
    # Service identification
    name = Column(String(255), nullable=False, index=True)  # Service name
    version = Column(String(255), nullable=True)  # Service version
    product = Column(String(255), nullable=True)  # Product name
    extrainfo = Column(String(500), nullable=True)  # Extra information
    
    # Service status
    status = Column(Enum(ServiceStatus), nullable=False, default=ServiceStatus.UNKNOWN, index=True)
    is_confirmed = Column(Boolean, default=False, nullable=False, index=True)
    
    # Service details
    banner = Column(Text, nullable=True)  # Service banner
    fingerprint = Column(JSONType, nullable=True)  # Service fingerprint
    cpe = Column(String(500), nullable=True)  # Common Platform Enumeration
    
    # Additional information
    tags = Column(JSONType, nullable=True)  # Tags for categorization
    notes = Column(Text, nullable=True)  # Additional notes
    
    # Relationships
    port_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("ports", "id")), nullable=False)
    port = relationship("Port", back_populates="services")
    
    active_recon_result_id = Column(PGUUID(as_uuid=True), ForeignKey(get_foreign_key("active_recon_results", "id")), nullable=False)
    active_recon_result = relationship("ActiveReconResult", back_populates="services")
    
    def __repr__(self) -> str:
        """String representation of the service."""
        return f"<Service(name='{self.name}', product='{self.product}', status='{self.status.value}')>"
    
    def to_dict(self) -> dict:
        """Convert service to dictionary."""
        base_dict = super().to_dict()
        
        # Parse JSONB fields back to Python objects
        def parse_jsonb_field(value):
            if value is None:
                return value
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return value
            return value
        
        return {
            **base_dict,
            'name': self.name,
            'version': self.version,
            'product': self.product,
            'extrainfo': self.extrainfo,
            'status': self.status.value,
            'is_confirmed': self.is_confirmed,
            'banner': self.banner,
            'fingerprint': parse_jsonb_field(self.fingerprint),
            'cpe': self.cpe,
            'tags': parse_jsonb_field(self.tags),
            'port_id': str(self.port_id),
            'active_recon_result_id': str(self.active_recon_result_id),
        }
    
    @property
    def display_name(self) -> str:
        """Get display name for the service."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        elif self.product:
            return self.product
        elif self.name:
            return self.name
        return "Unknown Service" 