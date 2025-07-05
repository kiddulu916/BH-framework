#!/usr/bin/env python
"""
Test script to debug the targets API 400 error.
"""
import requests
import json

def test_targets_api():
    """Test different targets API calls to identify the issue."""
    base_url = "http://localhost:8000/api/targets"
    
    # Test 1: Basic list without parameters
    print("=== Test 1: Basic list without parameters ===")
    try:
        response = requests.get(base_url)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Message: {data.get('message')}")
            if data.get('data', {}).get('targets'):
                print(f"Found {len(data['data']['targets'])} targets")
                for target in data['data']['targets']:
                    print(f"  - {target.get('value')} (ID: {target.get('id')})")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Exception: {e}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 2: With value parameter
    print("=== Test 2: With value parameter ===")
    try:
        response = requests.get(f"{base_url}?value=example.com")
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Message: {data.get('message')}")
            if data.get('data', {}).get('targets'):
                print(f"Found {len(data['data']['targets'])} targets")
                for target in data['data']['targets']:
                    print(f"  - {target.get('value')} (ID: {target.get('id')})")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Exception: {e}")
    
    print("\n" + "="*50 + "\n")
    
    # Test 3: With different parameter format
    print("=== Test 3: With search parameter ===")
    try:
        response = requests.get(f"{base_url}?search=example.com")
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Message: {data.get('message')}")
            if data.get('data', {}).get('targets'):
                print(f"Found {len(data['data']['targets'])} targets")
                for target in data['data']['targets']:
                    print(f"  - {target.get('value')} (ID: {target.get('id')})")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    test_targets_api() 