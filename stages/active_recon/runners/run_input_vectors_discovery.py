#!/usr/bin/env python3
"""
Input Vectors Discovery Runner

This module provides comprehensive input vectors discovery capabilities for
mapping all points where user-supplied data enters the application.

Features:
- HTTP header analysis and enumeration
- Cookie and local storage analysis
- JSON/XML data input mapping
- File upload endpoint discovery
- Client-side input analysis
- Parameter discovery and mapping
"""

import os
import json
import subprocess
import requests
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

def analyze_http_headers_as_inputs(target: str) -> Dict[str, Any]:
    """
    Analyze HTTP headers that might be used as input vectors.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing HTTP header analysis results
    """
    try:
        print(f"[INFO] Analyzing HTTP headers as input vectors for {target}")
        
        # Common headers that might be used as inputs
        input_headers = [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Forwarded-Host",
            "X-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Custom-IP-Authorization",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "X-Original-Remote-Addr",
            "X-Forwarded-By",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "X-Original-Remote-Addr",
            "X-Forwarded-By",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "X-Original-Remote-Addr",
            "X-Forwarded-By",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "X-Original-Remote-Addr",
            "X-Forwarded-By"
        ]
        
        # Custom application headers that might be inputs
        custom_headers = [
            "X-App-Token",
            "X-API-Key",
            "X-Auth-Token",
            "X-Session-ID",
            "X-User-ID",
            "X-Role",
            "X-Permission",
            "X-Feature-Flag",
            "X-Debug",
            "X-Test-Mode"
        ]
        
        all_headers = input_headers + custom_headers
        headers_found = {}
        potential_inputs = []
        
        # Test both HTTP and HTTPS
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                
                # Test with various header values to see if they're reflected
                test_headers = {
                    "User-Agent": "TestUserAgent-InputVector",
                    "X-Forwarded-For": "192.168.1.100",
                    "X-Custom-Header": "TestCustomHeader"
                }
                
                response = requests.get(url, headers=test_headers, timeout=10, allow_redirects=False)
                
                # Check if any test headers are reflected in the response
                response_text = response.text.lower()
                for header_name, header_value in test_headers.items():
                    if header_value.lower() in response_text:
                        potential_inputs.append({
                            "header": header_name,
                            "value": header_value,
                            "reflected": True,
                            "location": "response_body"
                        })
                
                # Check response headers for potential input processing
                for header_name in all_headers:
                    if header_name in response.headers:
                        headers_found[header_name] = response.headers[header_name]
                        
                        # Check if it might be processed as input
                        if any(indicator in response.headers[header_name].lower() for indicator in ["processed", "validated", "sanitized"]):
                            potential_inputs.append({
                                "header": header_name,
                                "value": response.headers[header_name],
                                "reflected": False,
                                "processed": True
                            })
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "headers_found": headers_found,
            "potential_inputs": potential_inputs,
            "total_headers": len(headers_found),
            "total_potential_inputs": len(potential_inputs)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "headers_found": {},
            "potential_inputs": []
        }

def analyze_cookies_and_storage(target: str) -> Dict[str, Any]:
    """
    Analyze cookies and local storage as potential input vectors.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing cookie and storage analysis results
    """
    try:
        print(f"[INFO] Analyzing cookies and storage for {target}")
        
        cookies_found = {}
        storage_indicators = []
        potential_inputs = []
        
        # Test both HTTP and HTTPS
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                # Analyze cookies
                if response.cookies:
                    for cookie in response.cookies:
                        cookies_found[cookie.name] = {
                            "value": cookie.value,
                            "domain": cookie.domain,
                            "path": cookie.path,
                            "secure": cookie.secure,
                            "httponly": cookie.has_nonstandard_attr('HttpOnly')
                        }
                        
                        # Check if cookie might contain user data
                        if any(indicator in cookie.name.lower() for indicator in ["user", "id", "role", "token", "session", "auth"]):
                            potential_inputs.append({
                                "type": "cookie",
                                "name": cookie.name,
                                "value": cookie.value,
                                "sensitive": True
                            })
                
                # Check for local storage indicators in JavaScript
                response_text = response.text.lower()
                storage_keywords = [
                    "localstorage", "sessionstorage", "setitem", "getitem",
                    "localstorage.setitem", "sessionstorage.setitem"
                ]
                
                for keyword in storage_keywords:
                    if keyword in response_text:
                        storage_indicators.append(keyword)
                
                # Look for JSON Web Tokens or other tokens in cookies
                jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
                for cookie_name, cookie_info in cookies_found.items():
                    if re.search(jwt_pattern, cookie_info["value"]):
                        potential_inputs.append({
                            "type": "jwt_cookie",
                            "name": cookie_name,
                            "value": cookie_info["value"][:50] + "...",
                            "sensitive": True
                        })
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "cookies_found": cookies_found,
            "storage_indicators": storage_indicators,
            "potential_inputs": potential_inputs,
            "total_cookies": len(cookies_found),
            "total_storage_indicators": len(storage_indicators),
            "total_potential_inputs": len(potential_inputs)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "cookies_found": {},
            "storage_indicators": [],
            "potential_inputs": []
        }

def discover_json_xml_inputs(target: str, endpoints: List[str]) -> Dict[str, Any]:
    """
    Discover JSON and XML input endpoints and analyze their structure.
    
    Args:
        target: Target domain
        endpoints: List of discovered endpoints to test
        
    Returns:
        Dictionary containing JSON/XML input discovery results
    """
    try:
        print(f"[INFO] Discovering JSON/XML inputs for {target}")
        
        json_endpoints = []
        xml_endpoints = []
        api_endpoints = []
        
        # Common API endpoint patterns
        api_patterns = [
            "/api/",
            "/rest/",
            "/graphql",
            "/v1/",
            "/v2/",
            "/v3/",
            "/swagger",
            "/openapi",
            "/docs"
        ]
        
        # Test endpoints for JSON/XML acceptance
        for endpoint in endpoints[:50]:  # Limit to first 50 endpoints
            try:
                # Test JSON acceptance
                json_payload = {"test": "input_vector", "data": "test_value"}
                response = requests.post(endpoint, json=json_payload, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 201, 400, 422]:
                    json_endpoints.append({
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "accepts_json": True
                    })
                
                # Test XML acceptance
                xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<test>
    <input>test_vector</input>
    <data>test_value</data>
</test>"""
                headers = {"Content-Type": "application/xml"}
                response = requests.post(endpoint, data=xml_payload, headers=headers, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 201, 400, 422]:
                    xml_endpoints.append({
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "accepts_xml": True
                    })
                
                # Check for API patterns
                for pattern in api_patterns:
                    if pattern in endpoint:
                        api_endpoints.append({
                            "endpoint": endpoint,
                            "pattern": pattern,
                            "type": "api_endpoint"
                        })
                        break
                        
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "json_endpoints": json_endpoints,
            "xml_endpoints": xml_endpoints,
            "api_endpoints": api_endpoints,
            "total_json_endpoints": len(json_endpoints),
            "total_xml_endpoints": len(xml_endpoints),
            "total_api_endpoints": len(api_endpoints)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "json_endpoints": [],
            "xml_endpoints": [],
            "api_endpoints": []
        }

def discover_file_upload_endpoints(target: str, endpoints: List[str]) -> Dict[str, Any]:
    """
    Discover file upload endpoints and analyze their capabilities.
    
    Args:
        target: Target domain
        endpoints: List of discovered endpoints to test
        
    Returns:
        Dictionary containing file upload discovery results
    """
    try:
        print(f"[INFO] Discovering file upload endpoints for {target}")
        
        upload_endpoints = []
        upload_patterns = [
            "/upload",
            "/file",
            "/attachment",
            "/media",
            "/image",
            "/document",
            "/file-upload",
            "/upload-file",
            "/attach",
            "/import"
        ]
        
        # Test endpoints for file upload capabilities
        for endpoint in endpoints:
            # Check if endpoint matches upload patterns
            for pattern in upload_patterns:
                if pattern in endpoint.lower():
                    upload_endpoints.append({
                        "endpoint": endpoint,
                        "pattern": pattern,
                        "type": "potential_upload"
                    })
                    break
        
        # Test specific endpoints for file upload
        test_endpoints = [
            f"http://{target}/upload",
            f"http://{target}/api/upload",
            f"http://{target}/file/upload",
            f"https://{target}/upload",
            f"https://{target}/api/upload",
            f"https://{target}/file/upload"
        ]
        
        for test_endpoint in test_endpoints:
            try:
                # Test with a simple file upload
                files = {"file": ("test.txt", "test content", "text/plain")}
                response = requests.post(test_endpoint, files=files, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 201, 400, 413]:
                    upload_endpoints.append({
                        "endpoint": test_endpoint,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "type": "confirmed_upload"
                    })
                    
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "upload_endpoints": upload_endpoints,
            "total_upload_endpoints": len(upload_endpoints),
            "confirmed_uploads": len([e for e in upload_endpoints if e["type"] == "confirmed_upload"])
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "upload_endpoints": [],
            "total_upload_endpoints": 0
        }

def analyze_client_side_inputs(target: str) -> Dict[str, Any]:
    """
    Analyze client-side code for input vectors and hidden endpoints.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing client-side analysis results
    """
    try:
        print(f"[INFO] Analyzing client-side inputs for {target}")
        
        client_inputs = []
        hidden_endpoints = []
        form_inputs = []
        
        # Test both HTTP and HTTPS
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                response_text = response.text
                
                # Extract form inputs
                form_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                form_matches = re.findall(form_pattern, response_text, re.IGNORECASE)
                
                for match in form_matches:
                    form_inputs.append({
                        "name": match,
                        "type": "form_input",
                        "source": "html"
                    })
                
                # Extract JavaScript variables that might be inputs
                js_patterns = [
                    r'var\s+(\w+)\s*=\s*["\'][^"\']*["\']',
                    r'let\s+(\w+)\s*=\s*["\'][^"\']*["\']',
                    r'const\s+(\w+)\s*=\s*["\'][^"\']*["\']',
                    r'(\w+)\s*:\s*["\'][^"\']*["\']'
                ]
                
                for pattern in js_patterns:
                    matches = re.findall(pattern, response_text)
                    for match in matches:
                        if any(keyword in match.lower() for keyword in ["input", "param", "data", "value", "token", "key"]):
                            client_inputs.append({
                                "name": match,
                                "type": "javascript_variable",
                                "source": "javascript"
                            })
                
                # Extract hidden endpoints from JavaScript
                endpoint_patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/rest/[^"\']+)["\']',
                    r'["\'](/v[0-9]+/[^"\']+)["\']',
                    r'url\s*:\s*["\']([^"\']+)["\']',
                    r'endpoint\s*:\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in endpoint_patterns:
                    matches = re.findall(pattern, response_text)
                    for match in matches:
                        if match not in hidden_endpoints:
                            hidden_endpoints.append({
                                "endpoint": match,
                                "type": "hidden_endpoint",
                                "source": "javascript"
                            })
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "client_inputs": client_inputs,
            "hidden_endpoints": hidden_endpoints,
            "form_inputs": form_inputs,
            "total_client_inputs": len(client_inputs),
            "total_hidden_endpoints": len(hidden_endpoints),
            "total_form_inputs": len(form_inputs)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "client_inputs": [],
            "hidden_endpoints": [],
            "form_inputs": []
        }

def run_input_vectors_discovery(target: str, endpoints: List[str], raw_output_path: str) -> Dict[str, Any]:
    """
    Run comprehensive input vectors discovery.
    
    Args:
        target: Target domain
        endpoints: List of discovered endpoints
        raw_output_path: Path to save raw output
        
    Returns:
        Dictionary containing comprehensive input vectors discovery results
    """
    print(f"[INFO] Starting input vectors discovery for {target}")
    
    start_time = time.time()
    all_results = {}
    
    # Step 1: HTTP header analysis
    print(f"[INFO] Analyzing HTTP headers as inputs")
    header_results = analyze_http_headers_as_inputs(target)
    all_results["http_headers"] = header_results
    
    # Step 2: Cookie and storage analysis
    print(f"[INFO] Analyzing cookies and storage")
    cookie_results = analyze_cookies_and_storage(target)
    all_results["cookies_storage"] = cookie_results
    
    # Step 3: JSON/XML input discovery
    print(f"[INFO] Discovering JSON/XML inputs")
    json_xml_results = discover_json_xml_inputs(target, endpoints)
    all_results["json_xml_inputs"] = json_xml_results
    
    # Step 4: File upload discovery
    print(f"[INFO] Discovering file upload endpoints")
    upload_results = discover_file_upload_endpoints(target, endpoints)
    all_results["file_uploads"] = upload_results
    
    # Step 5: Client-side analysis
    print(f"[INFO] Analyzing client-side inputs")
    client_results = analyze_client_side_inputs(target)
    all_results["client_side"] = client_results
    
    # Step 6: Generate summary
    execution_time = time.time() - start_time
    
    summary = {
        "target": target,
        "execution_time": execution_time,
        "http_header_inputs": header_results.get("total_potential_inputs", 0),
        "cookie_storage_inputs": cookie_results.get("total_potential_inputs", 0),
        "json_endpoints": json_xml_results.get("total_json_endpoints", 0),
        "xml_endpoints": json_xml_results.get("total_xml_endpoints", 0),
        "api_endpoints": json_xml_results.get("total_api_endpoints", 0),
        "upload_endpoints": upload_results.get("total_upload_endpoints", 0),
        "client_inputs": client_results.get("total_client_inputs", 0),
        "hidden_endpoints": client_results.get("total_hidden_endpoints", 0),
        "form_inputs": client_results.get("total_form_inputs", 0)
    }
    
    # Save raw output
    raw_output = {
        "target": target,
        "timestamp": time.time(),
        "header_results": header_results,
        "cookie_results": cookie_results,
        "json_xml_results": json_xml_results,
        "upload_results": upload_results,
        "client_results": client_results
    }
    
    with open(raw_output_path, 'w') as f:
        json.dump(raw_output, f, indent=2)
    
    return {
        "success": True,
        "summary": summary,
        "results": all_results,
        "files": {
            "raw_output": raw_output_path
        }
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python run_input_vectors_discovery.py <target> <endpoints_file> <raw_output_path>")
        sys.exit(1)
    
    target = sys.argv[1]
    endpoints_file = sys.argv[2]
    raw_output_path = sys.argv[3]
    
    # Load endpoints
    with open(endpoints_file, 'r') as f:
        endpoints = [line.strip() for line in f if line.strip()]
    
    results = run_input_vectors_discovery(target, endpoints, raw_output_path)
    print(json.dumps(results, indent=2)) 