#!/usr/bin/env python3
"""Check database schema for active_recon_results table."""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')
django.setup()

from sqlalchemy import create_engine, text
from api.settings import DATABASES

def check_schema():
    """Check the schema of active_recon_results table."""
    try:
        # Get database config
        db_config = DATABASES['default']
        
        # Build connection URL
        if 'URL' in db_config:
            db_url = db_config['URL']
        else:
            # Build URL from individual components
            db_url = f"postgresql://{db_config['USER']}:{db_config['PASSWORD']}@{db_config['HOST']}:{db_config['PORT']}/{db_config['NAME']}"
        
        print(f"Connecting to database: {db_url}")
        
        # Create engine
        engine = create_engine(db_url)
        
        # Query schema information
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = 'active_recon_results' 
                ORDER BY ordinal_position;
            """))
            
            print("ActiveReconResults table schema:")
            print("-" * 50)
            for row in result:
                print(f"{row[0]}: {row[1]} (nullable: {row[2]}, default: {row[3]})")
                
    except Exception as e:
        print(f"Error checking schema: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_schema() 