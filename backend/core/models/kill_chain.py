"""
Kill chain analysis models.

This module defines the KillChain and AttackPath models
which store the results of kill chain analysis activities.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import Column, String, Text, Boolean, Enum, ForeignKey, Index, Integer, Float
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel
import enum


class KillChainPhase(enum.Enum):
    """Enumeration for MITRE ATT&CK kill chain phases."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class AttackPathStatus(enum.Enum):
    """Enumeration for attack path status."""
    IDENTIFIED = "identified"
    VERIFIED = "verified"
    EXPLOITED = "exploited"
    BLOCKED = "blocked"
    FALSE_POSITIVE = "false_positive"


class KillChain(BaseModel):
    """
    KillChain model representing kill chain analysis results.
    
    This model stores the overall results of kill chain analysis
    activities performed against the target environment.
    """
    
    __tablename__ = "kill_chains"
    __table_args__ = (
        Index('idx_kill_chains_target', 'target_id'),
        Index('idx_kill_chains_execution', 'execution_id'),
        Index('idx_kill_chains_created', 'created_at'),
        {'schema': 'public'}
    )
    
    # Analysis identification
    execution_id = Column(String(255), nullable=False, index=True)  # Link to workflow execution
    
    # Analysis details
    analysis_type = Column(String(100), nullable=True)  # Type of kill chain analysis
    methodology = Column(String(255), nullable=True)  # Analysis methodology used
    configuration = Column(JSONB, nullable=True)  # Configuration used for the analysis
    
    # Results summary
    total_paths_identified = Column(Integer, default=0, nullable=False)
    verified_paths = Column(Integer, default=0, nullable=False)
    exploitable_paths = Column(Integer, default=0, nullable=False)
    blocked_paths = Column(Integer, default=0, nullable=False)
    
    # Analysis results
    raw_analysis = Column(JSONB, nullable=True)  # Raw analysis data
    processed_paths = Column(JSONB, nullable=True)  # Processed attack paths
    
    # Execution metadata
    execution_time = Column(String(50), nullable=True)  # Total execution time
    errors = Column(JSONB, nullable=True)  # Any errors encountered
    
    # Relationships
    target_id = Column(PGUUID(as_uuid=True), ForeignKey("public.targets.id"), nullable=False)
    target = relationship("Target", back_populates="kill_chains")
    
    # Attack paths
    attack_paths = relationship("AttackPath", back_populates="kill_chain", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        """String representation of the kill chain analysis result."""
        return f"<KillChain(target_id='{self.target_id}', total_paths={self.total_paths_identified})>"
    
    def to_dict(self) -> dict:
        """Convert kill chain analysis result to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'execution_id': self.execution_id,
            'analysis_type': self.analysis_type,
            'methodology': self.methodology,
            'configuration': self.configuration,
            'total_paths_identified': self.total_paths_identified,
            'verified_paths': self.verified_paths,
            'exploitable_paths': self.exploitable_paths,
            'blocked_paths': self.blocked_paths,
            'raw_analysis': self.raw_analysis,
            'processed_paths': self.processed_paths,
            'execution_time': self.execution_time,
            'errors': self.errors,
            'target_id': str(self.target_id),
        }


class AttackPath(BaseModel):
    """
    AttackPath model representing individual attack paths.
    
    This model stores detailed information about individual attack paths
    identified during kill chain analysis.
    """
    
    __tablename__ = "attack_paths"
    __table_args__ = (
        Index('idx_attack_paths_name', 'name'),
        Index('idx_attack_paths_status', 'status'),
        Index('idx_attack_paths_verified', 'is_verified'),
        Index('idx_attack_paths_exploitable', 'is_exploitable'),
        Index('idx_attack_paths_kill_chain', 'kill_chain_id'),
        {'schema': 'public'}
    )
    
    # Path identification
    name = Column(String(500), nullable=False, index=True)  # Attack path name
    description = Column(Text, nullable=True)  # Detailed description
    status = Column(Enum(AttackPathStatus), nullable=False, default=AttackPathStatus.IDENTIFIED, index=True)
    
    # Path details
    phases = Column(JSONB, nullable=True)  # Kill chain phases involved
    techniques = Column(JSONB, nullable=True)  # MITRE ATT&CK techniques
    tactics = Column(JSONB, nullable=True)  # MITRE ATT&CK tactics
    
    # Path components
    entry_points = Column(JSONB, nullable=True)  # Entry points for the attack
    exit_points = Column(JSONB, nullable=True)  # Exit points for the attack
    intermediate_nodes = Column(JSONB, nullable=True)  # Intermediate nodes in the path
    
    # Risk assessment
    risk_score = Column(Float, nullable=True)  # Overall risk score
    likelihood = Column(String(50), nullable=True)  # Likelihood of success
    impact = Column(String(50), nullable=True)  # Potential impact
    
    # Verification
    is_verified = Column(Boolean, default=False, nullable=False, index=True)  # Whether manually verified
    verification_evidence = Column(JSONB, nullable=True)  # Evidence from verification
    verification_notes = Column(Text, nullable=True)  # Notes from verification
    
    # Exploitation
    is_exploitable = Column(Boolean, default=False, nullable=False, index=True)  # Whether path is exploitable
    exploitation_evidence = Column(JSONB, nullable=True)  # Evidence from exploitation attempts
    exploitation_notes = Column(Text, nullable=True)  # Notes from exploitation
    
    # Mitigation
    mitigation_controls = Column(JSONB, nullable=True)  # Existing mitigation controls
    recommended_controls = Column(JSONB, nullable=True)  # Recommended additional controls
    
    # Additional information
    tags = Column(JSONB, nullable=True)  # Tags for categorization
    notes = Column(Text, nullable=True)  # Additional notes
    
    # Relationships
    kill_chain_id = Column(PGUUID(as_uuid=True), ForeignKey("public.kill_chains.id"), nullable=False)
    kill_chain = relationship("KillChain", back_populates="attack_paths")
    
    def __repr__(self) -> str:
        """String representation of the attack path."""
        return f"<AttackPath(name='{self.name}', status='{self.status.value}', risk_score={self.risk_score})>"
    
    def to_dict(self) -> dict:
        """Convert attack path to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'name': self.name,
            'description': self.description,
            'status': self.status.value,
            'phases': self.phases,
            'techniques': self.techniques,
            'tactics': self.tactics,
            'entry_points': self.entry_points,
            'exit_points': self.exit_points,
            'intermediate_nodes': self.intermediate_nodes,
            'risk_score': self.risk_score,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'is_verified': self.is_verified,
            'verification_evidence': self.verification_evidence,
            'verification_notes': self.verification_notes,
            'is_exploitable': self.is_exploitable,
            'exploitation_evidence': self.exploitation_evidence,
            'exploitation_notes': self.exploitation_notes,
            'mitigation_controls': self.mitigation_controls,
            'recommended_controls': self.recommended_controls,
            'tags': self.tags,
            'kill_chain_id': str(self.kill_chain_id),
        }
    
    @property
    def is_high_risk(self) -> bool:
        """Check if attack path is high risk."""
        return self.risk_score is not None and self.risk_score >= 7.0
    
    @property
    def is_verified_and_exploitable(self) -> bool:
        """Check if attack path is both verified and exploitable."""
        return self.is_verified and self.is_exploitable
    
    @property
    def display_risk(self) -> str:
        """Get display risk level with color coding."""
        if self.risk_score is None:
            return "⚪ UNKNOWN"
        
        if self.risk_score >= 8.0:
            return "🔴 CRITICAL"
        elif self.risk_score >= 6.0:
            return "🟠 HIGH"
        elif self.risk_score >= 4.0:
            return "🟡 MEDIUM"
        elif self.risk_score >= 2.0:
            return "🟢 LOW"
        else:
            return "🔵 MINIMAL" 