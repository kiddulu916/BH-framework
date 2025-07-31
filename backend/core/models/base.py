"""
Base model with shared fields and functionality for all database models.

This module provides a base class that all models inherit from,
ensuring consistent behavior and common fields across the application.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import DeclarativeBase
import os


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


def get_table_args(*indexes, **kwargs):
    """
    Helper function to create table arguments with conditional schema.
    
    In test mode (SQLite), no schema is used.
    In production mode (PostgreSQL), the 'public' schema is used.
    """
    TESTING = os.getenv('TESTING', 'false').lower() == 'true' or 'test' in os.getenv('DJANGO_SETTINGS_MODULE', '').lower()
    
    if TESTING:
        return indexes
    else:
        return indexes + ({'schema': 'public'},)


def get_foreign_key(table_name, column_name="id"):
    """
    Helper function to create foreign key references with conditional schema.
    
    In test mode (SQLite), no schema is used.
    In production mode (PostgreSQL), the 'public' schema is used.
    """
    TESTING = os.getenv('TESTING', 'false').lower() == 'true' or 'test' in os.getenv('DJANGO_SETTINGS_MODULE', '').lower()
    
    if TESTING:
        return f"{table_name}.{column_name}"
    else:
        return f"public.{table_name}.{column_name}"


class BaseModel(Base):
    """
    Base model with common fields and functionality.
    
    All models should inherit from this class to ensure consistent
    behavior and common fields across the application.
    """
    
    __abstract__ = True
    
    # Primary key - UUID for better distribution and security
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    
    # Timestamps - using timezone-aware datetimes
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Metadata
    notes = Column(Text, nullable=True)
    
    def __repr__(self) -> str:
        """String representation of the model."""
        return f"<{self.__class__.__name__}(id={self.id})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model instance to dictionary."""
        return {
            'id': str(self.id),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'notes': self.notes,
        }
    
    def update(self, **kwargs: Any) -> None:
        """Update model attributes."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = datetime.now(timezone.utc) 