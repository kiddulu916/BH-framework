#!/usr/bin/env python3
"""
Simple database connection test script.
"""

import asyncio
import os
from core.utils.database import init_database, check_database_health

async def check_db_connection():
    """Test database connection and initialization."""
    print("Testing database connection...")
    
    # Check health
    health = await check_database_health()
    print(f"Health check: {health}")
    
    if health['status'] == 'healthy':
        print("Database connection is healthy!")
        
        # Try to initialize database
        print("Initializing database...")
        try:
            await init_database()
            print("Database initialization successful!")
        except Exception as e:
            print(f"Database initialization failed: {e}")
    else:
        print(f"Database connection failed: {health['message']}")

if __name__ == "__main__":
    asyncio.run(check_db_connection()) 