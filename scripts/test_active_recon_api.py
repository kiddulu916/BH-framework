#!/usr/bin/env python3
"""
Test script to debug active recon API payload validation.
"""

import requests
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv("backend/.env")

# API configuration
BACKEND_URL = "http://localhost:8000"
JWT_TOKEN = os.environ.get("JWT_SECRET", "dev-secret")

def test_active_recon_api():
    """Test the active recon API with a sample payload."""
    
    # First, get a target ID
    targets_response = requests.get(f"{BACKEND_URL}/api/targets/?value=example.com")
    print(f"Targets API response: {targets_response.status_code}")
    
    if targets_response.status_code == 200:
        targets_data = targets_response.json()
        print(f"Targets data: {json.dumps(targets_data, indent=2)}")
        
        if targets_data.get("success") and targets_data.get("data", {}).get("targets"):
            target_id = targets_data["data"]["targets"][0]["id"]
            print(f"Target ID: {target_id}")
            
            # Create a test payload
            test_payload = {
                "target_id": target_id,
                "tools_used": ["naabu"],  # Use lowercase
                "hosts_scanned": ["example.com"],
                "ports": [],
                "services": [],
                "total_ports": 0,
                "total_services": 0,
                "raw_output": {
                    "tool": "naabu",
                    "targets": ["example.com"],
                    "hosts": []
                },
                "metadata": {
                    "tool": "naabu",
                    "target": "example.com"
                }
            }
            
            print(f"Test payload: {json.dumps(test_payload, indent=2)}")
            
            # Test the API
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                f"{BACKEND_URL}/api/results/active-recon",
                headers=headers,
                json=test_payload
            )
            
            print(f"Active recon API response: {response.status_code}")
            print(f"Response body: {response.text}")
            
            if response.status_code == 422:
                try:
                    error_data = response.json()
                    print(f"Validation errors: {json.dumps(error_data, indent=2)}")
                except:
                    print(f"Raw error response: {response.text}")
        else:
            print("No targets found")
    else:
        print(f"Failed to get targets: {targets_response.text}")

if __name__ == "__main__":
    test_active_recon_api() 