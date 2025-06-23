"""
User model for user management.

This module defines the User model which represents users
who can create targets and generate reports.
"""

from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, Boolean, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import relationship

from .base import BaseModel


class User(BaseModel):
    """
    User model representing application users.
    
    Users can create targets, manage workflows, and generate reports.
    This is a simplified user model focused on bug hunting operations.
    """
    
    __tablename__ = "users"
    
    # User identification
    name = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=True, unique=True, index=True)
    
    # User configuration
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    platform = Column(String(100), nullable=True)  # Bug bounty platform (e.g., HackerOne, Bugcrowd)
    platform_username = Column(String(255), nullable=True)  # Username on the platform
    
    # User preferences and settings
    preferences = Column(JSONB, nullable=True)  # User preferences and settings
    
    # Session management
    last_login = Column(DateTime, nullable=True)
    session_data = Column(JSONB, nullable=True)  # Session-specific data
    
    # Relationships
    targets = relationship("Target", back_populates="user", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_users_email', 'email'),
        Index('idx_users_platform', 'platform'),
        Index('idx_users_active', 'is_active'),
        {'schema': 'public'}
    )
    
    def __repr__(self) -> str:
        """String representation of the user."""
        return f"<User(name='{self.name}', email='{self.email}')>"
    
    def to_dict(self) -> dict:
        """Convert user to dictionary."""
        base_dict = super().to_dict()
        return {
            **base_dict,
            'name': self.name,
            'email': self.email,
            'is_active': self.is_active,
            'platform': self.platform,
            'platform_username': self.platform_username,
            'preferences': self.preferences,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'session_data': self.session_data,
        }
    
    @property
    def display_name(self) -> str:
        """Get display name for the user."""
        if self.platform and self.platform_username:
            return f"{self.name} ({self.platform}:{self.platform_username})"
        return self.name
    
    def update_last_login(self) -> None:
        """Update the last login timestamp."""
        self.last_login = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc) 