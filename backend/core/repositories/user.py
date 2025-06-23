"""
User repository for user management operations.

This module provides the UserRepository class which handles
all database operations related to users.
"""

from typing import List, Optional
from uuid import UUID

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.user import User
from .base import BaseRepository


class UserRepository(BaseRepository):
    """
    Repository for User model operations.
    
    This repository provides methods for managing users,
    including authentication and profile operations.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize the user repository."""
        super().__init__(session, User)
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address.
        
        Args:
            email: User email address
            
        Returns:
            User instance or None if not found
        """
        return await self.find_one({'email': email})
    
    async def get_by_platform_username(self, platform: str, username: str) -> Optional[User]:
        """
        Get user by platform and username.
        
        Args:
            platform: Bug bounty platform
            username: Username on the platform
            
        Returns:
            User instance or None if not found
        """
        return await self.find_one({
            'platform': platform,
            'platform_username': username
        })
    
    async def get_active_users(self) -> List[User]:
        """
        Get all active users.
        
        Returns:
            List of active users
        """
        return await self.list(filters={'is_active': True}, order_by=['created_at'])
    
    async def search_users(self, search_term: str) -> List[User]:
        """
        Search users by name or email.
        
        Args:
            search_term: Search term
            
        Returns:
            List of matching users
        """
        from sqlalchemy import or_
        
        query = select(self.model_class).where(
            or_(
                self.model_class.name.ilike(f"%{search_term}%"),
                self.model_class.email.ilike(f"%{search_term}%")
            )
        )
        
        query = query.order_by(self.model_class.created_at)
        
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def get_users_by_platform(self, platform: str) -> List[User]:
        """
        Get all users for a specific platform.
        
        Args:
            platform: Bug bounty platform
            
        Returns:
            List of users for the platform
        """
        return await self.list(filters={'platform': platform}, order_by=['created_at'])
    
    async def update_last_login(self, user_id: UUID) -> User:
        """
        Update user's last login timestamp.
        
        Args:
            user_id: User ID
            
        Returns:
            Updated user instance
            
        Raises:
            NotFoundError: If user not found
        """
        from datetime import datetime
        
        user = await self.update_or_raise(user_id, last_login=datetime.utcnow())
        return user
    
    async def get_user_statistics(self) -> dict:
        """
        Get user statistics.
        
        Returns:
            Dictionary with user statistics
        """
        total_users = await self.count()
        active_users = await self.count({'is_active': True})
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': total_users - active_users,
        }
    
    async def get_users_with_targets(self) -> List[User]:
        """
        Get users that have created targets.
        
        Returns:
            List of users with targets
        """
        query = select(self.model_class).options(
            selectinload(self.model_class.targets)
        ).order_by(self.model_class.created_at)
        
        result = await self.session.execute(query)
        return result.scalars().all() 