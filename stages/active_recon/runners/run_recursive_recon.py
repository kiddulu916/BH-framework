#!/usr/bin/env python3
"""
Recursive Reconnaissance Runner

This module handles the recursive reconnaissance process where:
1. All unique subdomains from both passive and active recon are gathered
2. A master subdomain list is created
3. Each subdomain is run through passive and active recon as individual subtargets
4. Subtarget profiles are created in the database within the main target profile

Features:
- Subdomain deduplication and validation
- Subtarget creation and management
- Recursive passive and active recon execution
- Progress tracking and reporting
- Error handling and recovery
"""

import os
import json
import subprocess
import requests
import time
import re
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime

def extract_subdomains_from_results(all_results: Dict[str, Any]) -> Set[str]:
    """
    Extract all unique subdomains from active recon results.
    
    Args:
        all_results: Dictionary containing all active recon tool results
        
    Returns:
        Set of unique subdomains found
    """
    subdomains = set()
    
    # Extract from enhanced subdomain enumeration
    if "enhanced_subdomain_enumeration" in all_results:
        result = all_results["enhanced_subdomain_enumeration"]
        if result.get("success"):
            # Add brute-forced subdomains
            for subdomain in result.get("brute_force_results", {}).get("subdomains", []):
                subdomains.add(subdomain)
            
            # Add takeover check subdomains
            for check in result.get("takeover_checks", []):
                subdomains.add(check.get("subdomain", ""))
            
            # Add third-party service subdomains
            for service in result.get("third_party_services", []):
                subdomains.add(service.get("subdomain", ""))
    
    # Extract from WAF/CDN detection
    if "waf_cdn_detection" in all_results:
        result = all_results["waf_cdn_detection"]
        if result.get("success"):
            # Add origin IPs that might be subdomains
            for origin in result.get("origin_ips", []):
                if "." in origin and not re.match(r'^\d+\.\d+\.\d+\.\d+$', origin):
                    subdomains.add(origin)
    
    # Extract from cloud infrastructure
    if "cloud_infrastructure_enumeration" in all_results:
        result = all_results["cloud_infrastructure_enumeration"]
        if result.get("success"):
            # Add cloud-related subdomains
            for bucket in result.get("s3_buckets", []):
                if bucket.get("subdomain"):
                    subdomains.add(bucket["subdomain"])
    
    # Extract from dynamic analysis
    if "dynamic_analysis" in all_results:
        result = all_results["dynamic_analysis"]
        if result.get("success"):
            # Add discovered URLs that might be subdomains
            for url in result.get("playwright_results", {}).get("urls_found", []):
                try:
                    parsed = urlparse(url)
                    if parsed.netloc and "." in parsed.netloc:
                        subdomains.add(parsed.netloc)
                except:
                    pass
    
    # Extract from input vectors discovery
    if "input_vectors_discovery" in all_results:
        result = all_results["input_vectors_discovery"]
        if result.get("success"):
            # Add discovered endpoints that might be subdomains
            for endpoint in result.get("http_header_inputs", []):
                if endpoint.get("subdomain"):
                    subdomains.add(endpoint["subdomain"])
                    
    # Extract from getjs
    if "getjs" in all_results:
        result = all_results["getjs"]
        if result.get("success"):
            # Add discovered endpoints that might be subdomains
            for endpoint in result.get("http_header_inputs", []):
                if endpoint.get("subdomain"):
                    subdomains.add(endpoint["subdomain"])
    
    # Extract from katana
    if "katana" in all_results:
        result = all_results["katana"]
        if result.get("success"):
            # Add discovered endpoints that might be subdomains
            for endpoint in result.get("http_header_inputs", []):
                if endpoint.get("subdomain"):
                    subdomains.add(endpoint["subdomain"])
    
    #Extract from Naabu
    if "naabu" in all_results:
        result = all_results["naabu"]
        if result.get("success"):
            # Add discovered endpoints that might be subdomains
            for endpoint in result.get("http_header_inputs", []):
                if endpoint.get("subdomain"):
                    subdomains.add(endpoint["subdomain"])
                       
    return subdomains

def get_passive_recon_subdomains(target_id: str, api_url: str, jwt_token: str) -> Set[str]:
    """
    Get subdomains from passive recon results via API.
    
    Args:
        target_id: Target ID in the database
        api_url: Backend API URL
        jwt_token: JWT authentication token
        
    Returns:
        Set of subdomains from passive recon
    """
    subdomains = set()
    
    try:
        headers = {'Authorization': f'Bearer {jwt_token}'}
        
        # Get passive recon results
        response = requests.get(f"{api_url}/passive_recon/results/{target_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("data"):
                results = data["data"]
                
                # Extract subdomains from various passive recon tools
                for tool_result in results:
                    tool_name = tool_result.get("tool_name", "")
                    tool_data = tool_result.get("data", {})
                    
                    if tool_name == "amass":
                        for subdomain in tool_data.get("subdomains", []):
                            subdomains.add(subdomain)
                    elif tool_name == "subfinder":
                        for subdomain in tool_data.get("subdomains", []):
                            subdomains.add(subdomain)
                    elif tool_name == "assetfinder":
                        for subdomain in tool_data.get("subdomains", []):
                            subdomains.add(subdomain)
                    elif tool_name == "sublist3r":
                        for subdomain in tool_data.get("subdomains", []):
                            subdomains.add(subdomain)
                    elif tool_name == "gau":
                        for url in tool_data.get("urls", []):
                            try:
                                parsed = urlparse(url)
                                if parsed.netloc and "." in parsed.netloc:
                                    subdomains.add(parsed.netloc)
                            except:
                                pass
                    elif tool_name == "waybackurls":
                        for url in tool_data.get("urls", []):
                            try:
                                parsed = urlparse(url)
                                if parsed.netloc and "." in parsed.netloc:
                                    subdomains.add(parsed.netloc)
                            except:
                                pass
        
        print(f"[INFO] Retrieved {len(subdomains)} subdomains from passive recon")
        
    except Exception as e:
        print(f"[ERROR] Failed to get passive recon subdomains: {e}")
    
    return subdomains

def validate_and_clean_subdomains(subdomains: Set[str], main_target: str) -> Set[str]:
    """
    Validate and clean subdomains, ensuring they are related to the main target.
    
    Args:
        subdomains: Set of subdomains to validate
        main_target: Main target domain
        
    Returns:
        Set of validated and cleaned subdomains
    """
    cleaned_subdomains = set()
    
    for subdomain in subdomains:
        # Skip empty or invalid subdomains
        if not subdomain or not isinstance(subdomain, str):
            continue
        
        # Clean the subdomain
        subdomain = subdomain.strip().lower()
        
        # Skip if it's just the main target
        if subdomain == main_target:
            continue
        
        # Validate it's related to the main target
        if subdomain.endswith(f".{main_target}") or main_target in subdomain:
            cleaned_subdomains.add(subdomain)
        # Also include subdomains that might be discovered through various means
        elif "." in subdomain and not re.match(r'^\d+\.\d+\.\d+\.\d+$', subdomain):
            # Additional validation could be added here
            cleaned_subdomains.add(subdomain)
    
    print(f"[INFO] Validated {len(cleaned_subdomains)} subdomains from {len(subdomains)} total")
    return cleaned_subdomains

def create_subtarget(target_id: str, subdomain: str, api_url: str, jwt_token: str) -> Optional[str]:
    """
    Create a subtarget in the database.
    
    Args:
        target_id: Parent target ID
        subdomain: Subdomain to create as subtarget
        api_url: Backend API URL
        jwt_token: JWT authentication token
        
    Returns:
        Subtarget ID if successful, None otherwise
    """
    try:
        headers = {'Authorization': f'Bearer {jwt_token}'}
        
        payload = {
            "value": subdomain,
            "parent_target_id": target_id,
            "type": "subdomain",
            "description": f"Subdomain discovered during reconnaissance of {target_id}"
        }
        
        response = requests.post(f"{api_url}/targets/", json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("data", {}).get("id"):
                subtarget_id = data["data"]["id"]
                print(f"[INFO] Created subtarget {subdomain} with ID {subtarget_id}")
                return subtarget_id
        
        print(f"[WARNING] Failed to create subtarget {subdomain}")
        return None
        
    except Exception as e:
        print(f"[ERROR] Error creating subtarget {subdomain}: {e}")
        return None

def run_passive_recon_on_subtarget(subtarget_id: str, subdomain: str, api_url: str, jwt_token: str) -> bool:
    """
    Run passive recon on a subtarget.
    
    Args:
        subtarget_id: Subtarget ID in the database
        subdomain: Subdomain to scan
        api_url: Backend API URL
        jwt_token: JWT authentication token
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[INFO] Starting passive recon on subtarget: {subdomain}")
        
        # Run passive recon script
        cmd = [
            "python", "run_passive_recon.py",
            "--target", subdomain,
            "--stage", "passive_recon"
        ]
        
        # Set environment variables
        env = os.environ.copy()
        env["BACKEND_API_URL"] = api_url
        env["BACKEND_JWT_TOKEN"] = jwt_token
        env["TARGET_ID"] = subtarget_id
        
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)
        
        if result.returncode == 0:
            print(f"[SUCCESS] Passive recon completed for {subdomain}")
            return True
        else:
            print(f"[ERROR] Passive recon failed for {subdomain}: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error running passive recon on {subdomain}: {e}")
        return False

def run_active_recon_on_subtarget(subtarget_id: str, subdomain: str, api_url: str, jwt_token: str) -> bool:
    """
    Run active recon on a subtarget.
    
    Args:
        subtarget_id: Subtarget ID in the database
        subdomain: Subdomain to scan
        api_url: Backend API URL
        jwt_token: JWT authentication token
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[INFO] Starting active recon on subtarget: {subdomain}")
        
        # Run active recon script
        cmd = [
            "python", "run_active_recon.py",
            "--target", subdomain,
            "--stage", "active_recon"
        ]
        
        # Set environment variables
        env = os.environ.copy()
        env["BACKEND_API_URL"] = api_url
        env["BACKEND_JWT_TOKEN"] = jwt_token
        env["TARGET_ID"] = subtarget_id
        
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=3600)
        
        if result.returncode == 0:
            print(f"[SUCCESS] Active recon completed for {subdomain}")
            return True
        else:
            print(f"[ERROR] Active recon failed for {subdomain}: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error running active recon on {subdomain}: {e}")
        return False

def run_recursive_reconnaissance(target_id: str, main_target: str, all_results: Dict[str, Any], api_url: str, jwt_token: str, max_concurrent: int = 3) -> Dict[str, Any]:
    """
    Run recursive reconnaissance on all discovered subdomains.
    
    Args:
        target_id: Main target ID in the database
        main_target: Main target domain
        all_results: All active recon results
        api_url: Backend API URL
        jwt_token: JWT authentication token
        max_concurrent: Maximum concurrent subtarget scans
        
    Returns:
        Dictionary containing recursive recon results
    """
    print(f"[INFO] Starting recursive reconnaissance for {main_target}")
    
    # Step 1: Gather all subdomains
    print("[STEP 1] Gathering subdomains from active recon results...")
    active_subdomains = extract_subdomains_from_results(all_results)
    print(f"[INFO] Found {len(active_subdomains)} subdomains in active recon results")
    
    print("[STEP 2] Gathering subdomains from passive recon results...")
    passive_subdomains = get_passive_recon_subdomains(target_id, api_url, jwt_token)
    print(f"[INFO] Found {len(passive_subdomains)} subdomains in passive recon results")
    
    # Step 3: Combine and deduplicate
    print("[STEP 3] Combining and deduplicating subdomains...")
    all_subdomains = active_subdomains.union(passive_subdomains)
    print(f"[INFO] Combined total: {len(all_subdomains)} subdomains")
    
    # Step 4: Validate and clean
    print("[STEP 4] Validating and cleaning subdomains...")
    valid_subdomains = validate_and_clean_subdomains(all_subdomains, main_target)
    print(f"[INFO] Valid subdomains: {len(valid_subdomains)}")
    
    if not valid_subdomains:
        print("[INFO] No valid subdomains found for recursive reconnaissance")
        return {
            "success": True,
            "total_subdomains": 0,
            "subtargets_created": 0,
            "passive_recon_successful": 0,
            "active_recon_successful": 0,
            "subdomains": []
        }
    
    # Step 5: Create subtargets and run reconnaissance
    print("[STEP 5] Creating subtargets and running reconnaissance...")
    
    subtargets_created = 0
    passive_recon_successful = 0
    active_recon_successful = 0
    subtarget_results = []
    
    # Process subdomains with concurrency control
    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        # Create futures for all subdomains
        future_to_subdomain = {}
        
        for subdomain in valid_subdomains:
            # Create subtarget first
            subtarget_id = create_subtarget(target_id, subdomain, api_url, jwt_token)
            if subtarget_id:
                subtargets_created += 1
                
                # Submit passive recon task
                passive_future = executor.submit(run_passive_recon_on_subtarget, subtarget_id, subdomain, api_url, jwt_token)
                future_to_subdomain[passive_future] = ("passive", subdomain, subtarget_id)
                
                # Submit active recon task (after passive recon)
                active_future = executor.submit(run_active_recon_on_subtarget, subtarget_id, subdomain, api_url, jwt_token)
                future_to_subdomain[active_future] = ("active", subdomain, subtarget_id)
        
        # Process completed tasks
        for future in as_completed(future_to_subdomain):
            recon_type, subdomain, subtarget_id = future_to_subdomain[future]
            
            try:
                success = future.result()
                if success:
                    if recon_type == "passive":
                        passive_recon_successful += 1
                    else:
                        active_recon_successful += 1
                
                subtarget_results.append({
                    "subdomain": subdomain,
                    "subtarget_id": subtarget_id,
                    "passive_recon_success": recon_type == "passive" and success,
                    "active_recon_success": recon_type == "active" and success
                })
                
            except Exception as e:
                print(f"[ERROR] Task failed for {subdomain} ({recon_type}): {e}")
                subtarget_results.append({
                    "subdomain": subdomain,
                    "subtarget_id": subtarget_id,
                    "passive_recon_success": False,
                    "active_recon_success": False,
                    "error": str(e)
                })
    
    # Step 6: Generate summary
    print("[STEP 6] Generating recursive reconnaissance summary...")
    
    summary = {
        "success": True,
        "main_target": main_target,
        "target_id": target_id,
        "total_subdomains": len(valid_subdomains),
        "subtargets_created": subtargets_created,
        "passive_recon_successful": passive_recon_successful,
        "active_recon_successful": active_recon_successful,
        "passive_recon_success_rate": (passive_recon_successful / len(valid_subdomains) * 100) if valid_subdomains else 0,
        "active_recon_success_rate": (active_recon_successful / len(valid_subdomains) * 100) if valid_subdomains else 0,
        "subdomains": list(valid_subdomains),
        "subtarget_results": subtarget_results,
        "timestamp": datetime.now().isoformat()
    }
    
    print(f"[SUCCESS] Recursive reconnaissance completed for {main_target}")
    print(f"  - Total subdomains: {len(valid_subdomains)}")
    print(f"  - Subtargets created: {subtargets_created}")
    print(f"  - Passive recon successful: {passive_recon_successful}")
    print(f"  - Active recon successful: {active_recon_successful}")
    
    return summary

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Recursive Reconnaissance Runner")
    parser.add_argument("--target", required=True, help="Main target domain")
    parser.add_argument("--target-id", required=True, help="Main target ID")
    parser.add_argument("--api-url", required=True, help="Backend API URL")
    parser.add_argument("--jwt-token", required=True, help="JWT authentication token")
    parser.add_argument("--max-concurrent", type=int, default=3, help="Maximum concurrent subtarget scans")
    parser.add_argument("--results-file", help="Path to active recon results JSON file")
    
    args = parser.parse_args()
    
    # Load results if provided
    all_results = {}
    if args.results_file and os.path.exists(args.results_file):
        with open(args.results_file, 'r') as f:
            all_results = json.load(f)
    
    # Run recursive reconnaissance
    result = run_recursive_reconnaissance(
        args.target_id,
        args.target,
        all_results,
        args.api_url,
        args.jwt_token,
        args.max_concurrent
    )
    
    # Save results
    output_file = f"recursive_recon_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"[INFO] Results saved to {output_file}") 