#!/usr/bin/env python3
"""
Automated test script to simulate frontend target profile submission.
Tests the complete flow from frontend form data to backend API response.
"""

import requests
import json
import time
from typing import Dict, Any

def test_frontend_submission():
    """Test the complete frontend to backend target creation flow."""
    
    print("🧪 Testing Frontend Target Profile Submission")
    print("=" * 50)
    
    # Test data that matches the backend schema requirements
    import time
    timestamp = int(time.time())
    frontend_form_data = {
        "target": f"test-company-inc-{timestamp}",
        "domain": f"test-company-inc-{timestamp}.com",
        "is_primary": False,
        "login_email": "admin@test-company-inc.com",
        "researcher_email": "researcher@example.com",
        "in_scope": [
            "*.test-company-inc.com",
            "api.test-company-inc.com",
            "admin.test-company-inc.com"
        ],
        "out_of_scope": [
            "blog.test-company-inc.com",
            "status.test-company-inc.com"
        ],
        "rate_limit_requests": 15,
        "rate_limit_seconds": 60,
        "additional_info": [
            "Important: This is a test environment",
            "Note: API endpoints are rate limited",
            "Security: All endpoints require authentication"
        ],
        "notes": "This is a comprehensive test target. Multiple subdomains should be scanned. Focus on API security testing.",
        "custom_headers": [
            {
                "name": "X-API-Key",
                "value": "test-api-key-12345",
                "description": "API authentication key"
            },
            {
                "name": "Authorization",
                "value": "Bearer test-token-67890",
                "description": "Bearer token for authentication"
            },
            {
                "name": "User-Agent",
                "value": "BugHuntingFramework/1.0",
                "description": "Custom user agent"
            }
        ]
    }
    
    # Backend API endpoint
    api_url = "http://localhost:8000/api/targets/"
    
    print(f"📡 API Endpoint: {api_url}")
    print(f"📝 Test Data: {json.dumps(frontend_form_data, indent=2)}")
    print()
    
    try:
        # Step 1: Test API connectivity
        print("1️⃣ Testing API connectivity...")
        health_response = requests.get("http://localhost:8000/api/health", timeout=10)
        if health_response.status_code == 200:
            print("✅ Backend API is accessible")
        else:
            print(f"❌ Backend API health check failed: {health_response.status_code}")
            return False
        
        # Step 2: Submit target creation request
        print("\n2️⃣ Submitting target creation request...")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        response = requests.post(
            api_url,
            json=frontend_form_data,
            headers=headers,
            timeout=30
        )
        
        print(f"📊 Response Status: {response.status_code}")
        print(f"📋 Response Headers: {dict(response.headers)}")
        
        # Step 3: Analyze response
        print("\n3️⃣ Analyzing response...")
        
        if response.status_code == 200:
            try:
                response_data = response.json()
                print(f"📄 Response Body: {json.dumps(response_data, indent=2)}")
                
                if response_data.get("success") is True:
                    print("✅ Target creation successful!")
                    
                    # Extract target data
                    target_data = response_data.get("data", {})
                    target_id = target_data.get("id")
                    
                    if target_id:
                        print(f"🆔 Target ID: {target_id}")
                        
                        # Step 4: Verify target was created by fetching it
                        print("\n4️⃣ Verifying target creation...")
                        verify_url = f"{api_url.rstrip('/')}/{target_id}"
                        print(f"🔍 Verification URL: {verify_url}")
                        verify_response = requests.get(verify_url, timeout=10)
                        
                        if verify_response.status_code == 200:
                            verify_data = verify_response.json()
                            if verify_data.get("success") is True:
                                print("✅ Target verification successful!")
                                
                                # Step 5: Verify all fields were saved correctly
                                print("\n5️⃣ Verifying all fields were saved correctly...")
                                saved_target = verify_data.get("data", {})
                                
                                field_verifications = [
                                    ("target", frontend_form_data["target"]),
                                    ("domain", frontend_form_data["domain"]),
                                    ("is_primary", frontend_form_data["is_primary"]),
                                    ("login_email", frontend_form_data["login_email"]),
                                    ("researcher_email", frontend_form_data["researcher_email"]),
                                    ("in_scope", frontend_form_data["in_scope"]),
                                    ("out_of_scope", frontend_form_data["out_of_scope"]),
                                    ("rate_limit_requests", frontend_form_data["rate_limit_requests"]),
                                    ("rate_limit_seconds", frontend_form_data["rate_limit_seconds"]),
                                    ("additional_info", frontend_form_data["additional_info"]),
                                    ("notes", frontend_form_data["notes"]),
                                    ("custom_headers", frontend_form_data["custom_headers"])
                                ]
                                
                                all_fields_correct = True
                                for field_name, expected_value in field_verifications:
                                    actual_value = saved_target.get(field_name)
                                    if actual_value == expected_value:
                                        print(f"✅ {field_name}: {actual_value}")
                                    else:
                                        print(f"❌ {field_name}: expected {expected_value}, got {actual_value}")
                                        all_fields_correct = False
                                
                                if all_fields_correct:
                                    print("\n🎉 All fields verified successfully!")
                                    return True
                                else:
                                    print("\n⚠️ Some fields were not saved correctly")
                                    return False
                            else:
                                print(f"❌ Target verification failed: {verify_data}")
                                return False
                        else:
                            print(f"❌ Target verification request failed: {verify_response.status_code}")
                            return False
                    else:
                        print("❌ No target ID returned in response")
                        return False
                else:
                    print(f"❌ Target creation failed: {response_data.get('message', 'Unknown error')}")
                    if response_data.get("errors"):
                        print(f"🔍 Errors: {response_data['errors']}")
                    return False
                    
            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON response: {e}")
                print(f"📄 Raw response: {response.text}")
                return False
        else:
            print(f"❌ HTTP request failed with status {response.status_code}")
            print(f"📄 Response body: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to backend API. Is the backend running?")
        return False
    except requests.exceptions.Timeout:
        print("❌ Request timed out. Backend may be overloaded.")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_target_listing():
    """Test the target listing endpoint to ensure it works with the new schema."""
    
    print("\n" + "=" * 50)
    print("📋 Testing Target Listing Endpoint")
    print("=" * 50)
    
    try:
        response = requests.get("http://localhost:8000/api/targets/", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success") is True:
                response_data = data.get("data", {})
                targets = response_data.get("items", [])
                print(f"✅ Target listing successful: {len(targets)} targets found")
                
                if targets:
                    print("📋 Sample target data:")
                    sample_target = targets[0]
                    for key, value in sample_target.items():
                        if isinstance(value, (list, dict)):
                            print(f"  {key}: {type(value).__name__} with {len(value)} items")
                        else:
                            print(f"  {key}: {value}")
                
                return True
            else:
                print(f"❌ Target listing failed: {data.get('message', 'Unknown error')}")
                return False
        else:
            print(f"❌ Target listing request failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Target listing test failed: {e}")
        return False

def main():
    """Main test function."""
    
    print("🚀 Starting Frontend Submission Test Suite")
    print("=" * 60)
    
    # Wait a moment for services to be ready
    print("⏳ Waiting for services to be ready...")
    time.sleep(2)
    
    # Run tests
    submission_success = test_frontend_submission()
    listing_success = test_target_listing()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    print(f"🎯 Frontend Submission Test: {'✅ PASSED' if submission_success else '❌ FAILED'}")
    print(f"📋 Target Listing Test: {'✅ PASSED' if listing_success else '❌ FAILED'}")
    
    if submission_success and listing_success:
        print("\n🎉 All tests passed! The frontend-backend integration is working correctly.")
        print("✅ Target profile creation is ready for frontend testing.")
        return True
    else:
        print("\n⚠️ Some tests failed. Please check the backend configuration and try again.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 