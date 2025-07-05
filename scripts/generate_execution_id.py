#!/usr/bin/env python3
"""
Script to generate a valid execution_id for testing the active recon API.
Since the actual workflow execution has Docker container issues, we'll generate a test UUID.
"""

import uuid

# Generate a valid execution_id for testing
execution_id = str(uuid.uuid4())
print(f"Generated Execution ID for testing: {execution_id}")
print(f"\nYou can use this execution_id in your active recon API tests.")
print(f"Note: This is a test UUID - in production, this would come from the workflow execution system.") 