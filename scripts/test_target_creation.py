#!/usr/bin/env python3
"""
Test script to verify target creation API endpoint with new frontend fields.
"""

import requests
import json

def test_target_creation():
    """Test the target creation API endpoint."""
    
    # Test data matching the frontend form structure
    test_target_data = {
        "target": "Test Company",
        "domain": "test-company.com",
        "login_email": "test@test-company.com",
        "researcher_email": "researcher@example.com",
        "in_scope": ["*.test-company.com", "api.test-company.com"],
        "out_of_scope": ["blog.test-company.com"],
        "rate_limit_requests": 10,
        "rate_limit_seconds": 60,
        "additional_info": ["Important note 1", "Important note 2"],
        "notes": ["General note 1", "General note 2"],
        "custom_headers": {
            "X-API-Key": "test-key",
            "Authorization": "Bearer test-token"
        },
        "status": "active",
        "is_primary": True,
        "platform": "hackerone"
    }
    
    try:
        # Test the target creation endpoint
        response = requests.post(
            "http://localhost:8000/api/targets",
            json=test_target_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Success! Response: {json.dumps(result, indent=2)}")
            
            if result.get("success"):
                print("🎉 Target creation API is working correctly!")
                return True
            else:
                print(f"❌ API returned success=False: {result.get('errors', [])}")
                return False
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
        print(f"Response text: {response.text}")
        return False

def test_targets_list():
    """Test the targets list endpoint."""
    
    try:
        response = requests.get("http://localhost:8000/api/targets")
        
        print(f"\n--- Testing Targets List ---")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Targets list response: {json.dumps(result, indent=2)}")
            return True
        else:
            print(f"❌ HTTP Error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Target Creation API...")
    print("=" * 50)
    
    # Test target creation
    creation_success = test_target_creation()
    
    # Test targets list
    list_success = test_targets_list()
    
    print("\n" + "=" * 50)
    if creation_success and list_success:
        print("🎉 All tests passed! The API is working correctly.")
    else:
        print("❌ Some tests failed. Check the output above for details.") 