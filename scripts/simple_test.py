#!/usr/bin/env python3
"""
Simple test script to debug API issues.
"""

import requests
import json

def test_api():
    """Simple API test."""
    
    print("🧪 Simple API Test")
    print("=" * 30)
    
    # Test 1: Health check
    print("1️⃣ Testing health endpoint...")
    try:
        health_response = requests.get("http://localhost:8000/api/health", timeout=5)
        print(f"Health status: {health_response.status_code}")
        if health_response.status_code == 200:
            print("✅ Health check passed")
        else:
            print(f"❌ Health check failed: {health_response.text}")
            return
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return
    
    # Test 2: Simple target creation
    print("\n2️⃣ Testing target creation...")
    
    simple_data = {
        "name": "Simple Test Target",
        "scope": "DOMAIN",
        "value": "test.com"
    }
    
    try:
        response = requests.post(
            "http://localhost:8000/api/targets/",
            json=simple_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success: {json.dumps(data, indent=2)}")
        else:
            print(f"❌ Failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_api() 