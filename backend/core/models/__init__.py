"""
Database models for the Bug Hunting Framework.

This package contains all SQLAlchemy models for the application,
organized by domain and functionality.
"""

from .base import BaseModel
from .target import Target
from .user import User
from .workflow import Workflow, WorkflowExecution
from .passive_recon import PassiveReconResult, Subdomain
from .active_recon import ActiveReconResult, Port, Service
from .vulnerability import Vulnerability, VulnerabilityFinding
from .kill_chain import KillChain, AttackPath
from .report import Report

__all__ = [
    # Base
    'BaseModel',
    
    # Core Domain
    'Target',
    'User',
    'Workflow',
    'WorkflowExecution',
    
    # Stage Results
    'PassiveReconResult',
    'Subdomain',
    'ActiveReconResult',
    'Port',
    'Service',
    'Vulnerability',
    'VulnerabilityFinding',
    'KillChain',
    'AttackPath',
    'Report',
] 