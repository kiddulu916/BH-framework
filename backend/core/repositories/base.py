"""
Base repository class with common CRUD operations.

This module provides a base repository class that implements
common database operations for all models in the application.
"""

from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from uuid import UUID

from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import Select

from ..models.base import BaseModel
from ..utils.exceptions import NotFoundError, DatabaseError

T = TypeVar('T', bound=BaseModel)


class BaseRepository:
    """
    Base repository class with common CRUD operations.
    
    This class provides a foundation for all repository classes,
    implementing common database operations and patterns.
    """
    
    def __init__(self, session: AsyncSession, model_class: Type[T]):
        """
        Initialize the repository.
        
        Args:
            session: Database session
            model_class: SQLAlchemy model class
        """
        self.session = session
        self.model_class = model_class
    
    async def create(self, **kwargs) -> T:
        """
        Create a new record.
        
        Args:
            **kwargs: Model attributes
            
        Returns:
            Created model instance
            
        Raises:
            DatabaseError: If creation fails
        """
        try:
            # Debug: Print the kwargs being passed to create
            print(f"Debug: BaseRepository.create() called with kwargs: {kwargs}")
            for k, v in kwargs.items():
                print(f"  {k}: type={type(v)}, value={v}")
            
            instance = self.model_class(**kwargs)
            self.session.add(instance)
            await self.session.flush()
            await self.session.refresh(instance)
            return instance
        except Exception as e:
            await self.session.rollback()
            print(f"Debug: Exception in BaseRepository.create(): {e}")
            print(f"Debug: Exception type: {type(e)}")
            raise DatabaseError(f"Failed to create {self.model_class.__name__}: {str(e)}")
    
    async def get_by_id(self, id: Union[str, UUID], include_relationships: Optional[List[str]] = None) -> Optional[T]:
        """
        Get a record by ID.
        
        Args:
            id: Record ID
            include_relationships: List of relationship names to include
            
        Returns:
            Model instance or None if not found
        """
        query = select(self.model_class).where(self.model_class.id == id)
        
        if include_relationships:
            for relationship in include_relationships:
                query = query.options(selectinload(getattr(self.model_class, relationship)))
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def get_by_id_or_raise(self, id: Union[str, UUID], include_relationships: Optional[List[str]] = None) -> T:
        """
        Get a record by ID or raise NotFoundError.
        
        Args:
            id: Record ID
            include_relationships: List of relationship names to include
            
        Returns:
            Model instance
            
        Raises:
            NotFoundError: If record not found
        """
        instance = await self.get_by_id(id, include_relationships)
        if not instance:
            raise NotFoundError(self.model_class.__name__, str(id))
        return instance
    
    async def list(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[List[str]] = None,
        include_relationships: Optional[List[str]] = None
    ) -> List[T]:
        """
        List records with optional filtering and pagination.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            filters: Dictionary of field filters
            order_by: List of fields to order by
            include_relationships: List of relationship names to include
            
        Returns:
            List of model instances
        """
        query = select(self.model_class)
        
        # Apply filters
        if filters:
            filter_conditions = []
            for field, value in filters.items():
                if hasattr(self.model_class, field):
                    if isinstance(value, (list, tuple)):
                        filter_conditions.append(getattr(self.model_class, field).in_(value))
                    else:
                        filter_conditions.append(getattr(self.model_class, field) == value)
            
            if filter_conditions:
                query = query.where(and_(*filter_conditions))
        
        # Apply ordering
        if order_by:
            order_conditions = []
            for field in order_by:
                if hasattr(self.model_class, field):
                    order_conditions.append(getattr(self.model_class, field))
            if order_conditions:
                query = query.order_by(*order_conditions)
        
        # Apply pagination
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)
        
        # Include relationships
        if include_relationships:
            for relationship in include_relationships:
                query = query.options(selectinload(getattr(self.model_class, relationship)))
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Count records with optional filtering.
        
        Args:
            filters: Dictionary of field filters
            
        Returns:
            Number of records
        """
        query = select(self.model_class)
        
        if filters:
            filter_conditions = []
            for field, value in filters.items():
                if hasattr(self.model_class, field):
                    if isinstance(value, (list, tuple)):
                        filter_conditions.append(getattr(self.model_class, field).in_(value))
                    else:
                        filter_conditions.append(getattr(self.model_class, field) == value)
            
            if filter_conditions:
                query = query.where(and_(*filter_conditions))
        
        result = await self.session.execute(query)
        return len(result.scalars().all())
    
    async def update(self, id: Union[str, UUID], **kwargs) -> Optional[T]:
        """
        Update a record by ID.
        
        Args:
            id: Record ID
            **kwargs: Fields to update
            
        Returns:
            Updated model instance or None if not found
            
        Raises:
            DatabaseError: If update fails
        """
        try:
            query = update(self.model_class).where(self.model_class.id == id).values(**kwargs)
            result = await self.session.execute(query)
            
            if result.rowcount == 0:
                return None
            
            await self.session.flush()
            return await self.get_by_id(id)
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to update {self.model_class.__name__}: {str(e)}")
    
    async def update_or_raise(self, id: Union[str, UUID], **kwargs) -> T:
        """
        Update a record by ID or raise NotFoundError.
        
        Args:
            id: Record ID
            **kwargs: Fields to update
            
        Returns:
            Updated model instance
            
        Raises:
            NotFoundError: If record not found
            DatabaseError: If update fails
        """
        instance = await self.update(id, **kwargs)
        if not instance:
            raise NotFoundError(self.model_class.__name__, str(id))
        return instance
    
    async def delete(self, id: Union[str, UUID]) -> bool:
        """
        Delete a record by ID.
        
        Args:
            id: Record ID
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            DatabaseError: If deletion fails
        """
        try:
            query = delete(self.model_class).where(self.model_class.id == id)
            result = await self.session.execute(query)
            return result.rowcount > 0
        except Exception as e:
            await self.session.rollback()
            raise DatabaseError(f"Failed to delete {self.model_class.__name__}: {str(e)}")
    
    async def delete_or_raise(self, id: Union[str, UUID]) -> bool:
        """
        Delete a record by ID or raise NotFoundError.
        
        Args:
            id: Record ID
            
        Returns:
            True if deleted
            
        Raises:
            NotFoundError: If record not found
            DatabaseError: If deletion fails
        """
        deleted = await self.delete(id)
        if not deleted:
            raise NotFoundError(self.model_class.__name__, str(id))
        return deleted
    
    async def exists(self, id: Union[str, UUID]) -> bool:
        """
        Check if a record exists by ID.
        
        Args:
            id: Record ID
            
        Returns:
            True if record exists, False otherwise
        """
        query = select(self.model_class.id).where(self.model_class.id == id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none() is not None
    
    async def find_one(self, filters: Dict[str, Any], include_relationships: Optional[List[str]] = None) -> Optional[T]:
        """
        Find a single record matching filters.
        
        Args:
            filters: Dictionary of field filters
            include_relationships: List of relationship names to include
            
        Returns:
            Model instance or None if not found
        """
        query = select(self.model_class)
        
        filter_conditions = []
        for field, value in filters.items():
            if hasattr(self.model_class, field):
                if isinstance(value, (list, tuple)):
                    filter_conditions.append(getattr(self.model_class, field).in_(value))
                else:
                    filter_conditions.append(getattr(self.model_class, field) == value)
        
        if filter_conditions:
            query = query.where(and_(*filter_conditions))
        
        if include_relationships:
            for relationship in include_relationships:
                query = query.options(selectinload(getattr(self.model_class, relationship)))
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def find_one_or_raise(self, filters: Dict[str, Any], include_relationships: Optional[List[str]] = None) -> T:
        """
        Find a single record matching filters or raise NotFoundError.
        
        Args:
            filters: Dictionary of field filters
            include_relationships: List of relationship names to include
            
        Returns:
            Model instance
            
        Raises:
            NotFoundError: If record not found
        """
        instance = await self.find_one(filters, include_relationships)
        if not instance:
            filter_str = ", ".join([f"{k}={v}" for k, v in filters.items()])
            raise NotFoundError(self.model_class.__name__, f"with filters: {filter_str}")
        return instance 