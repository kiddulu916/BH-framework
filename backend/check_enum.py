#!/usr/bin/env python
"""
Temporary script to check database enum values for reportstatus.
"""
import asyncio
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from sqlalchemy import text
from core.utils.database import db_manager

async def check_enum_values():
    """Check the actual enum values in the database."""
    async with db_manager.session_factory() as session:
        try:
            # Check reportstatus enum values
            result = await session.execute(text("SELECT unnest(enum_range(NULL::reportstatus))"))
            report_status_values = [row[0] for row in result.fetchall()]
            print(f"Database reportstatus enum values: {report_status_values}")
            
            # Check reportformat enum values
            result = await session.execute(text("SELECT unnest(enum_range(NULL::reportformat))"))
            report_format_values = [row[0] for row in result.fetchall()]
            print(f"Database reportformat enum values: {report_format_values}")
            
            # Check reporttype enum values
            result = await session.execute(text("SELECT unnest(enum_range(NULL::reporttype))"))
            report_type_values = [row[0] for row in result.fetchall()]
            print(f"Database reporttype enum values: {report_type_values}")
            
        except Exception as e:
            print(f"Error checking enum values: {e}")

if __name__ == "__main__":
    asyncio.run(check_enum_values()) 