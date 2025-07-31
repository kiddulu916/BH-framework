#!/usr/bin/env python3
"""
Cloud Infrastructure Enumeration Runner

This module provides comprehensive cloud infrastructure enumeration capabilities
for discovering cloud services, storage buckets, and misconfigurations.

Features:
- Cloud storage bucket enumeration (AWS S3, Azure Blob, GCP Storage)
- Cloud service discovery and mapping
- Infrastructure misconfiguration detection
- Cloud metadata service testing
- Cloud API key discovery
"""

import os
import json
import subprocess
import requests
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def enumerate_s3_buckets(target: str) -> Dict[str, Any]:
    """
    Enumerate AWS S3 buckets for the target domain.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing S3 bucket enumeration results
    """
    try:
        print(f"[INFO] Enumerating S3 buckets for {target}")
        
        # Generate potential bucket names
        bucket_names = []
        
        # Common bucket naming patterns
        patterns = [
            target,
            f"{target}-backup",
            f"{target}-assets",
            f"{target}-files",
            f"{target}-uploads",
            f"{target}-media",
            f"{target}-static",
            f"{target}-cdn",
            f"{target}-dev",
            f"{target}-staging",
            f"{target}-prod",
            f"{target}-test",
            f"{target}-admin",
            f"{target}-api",
            f"{target}-app",
            f"{target}-web",
            f"{target}-www",
            f"{target}-blog",
            f"{target}-docs",
            f"{target}-support"
        ]
        
        # Add variations
        for pattern in patterns:
            bucket_names.extend([
                pattern,
                pattern.replace('.', '-'),
                pattern.replace('.', ''),
                f"{pattern}-bucket",
                f"{pattern}-storage"
            ])
        
        # Remove duplicates
        bucket_names = list(set(bucket_names))
        
        accessible_buckets = []
        public_buckets = []
        
        for bucket_name in bucket_names:
            try:
                # Test bucket access
                url = f"http://{bucket_name}.s3.amazonaws.com"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    accessible_buckets.append({
                        "bucket": bucket_name,
                        "url": url,
                        "status_code": response.status_code,
                        "public": True
                    })
                    public_buckets.append(bucket_name)
                elif response.status_code == 403:
                    # Bucket exists but is private
                    accessible_buckets.append({
                        "bucket": bucket_name,
                        "url": url,
                        "status_code": response.status_code,
                        "public": False
                    })
                    
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "buckets_tested": len(bucket_names),
            "accessible_buckets": accessible_buckets,
            "public_buckets": public_buckets,
            "total_accessible": len(accessible_buckets),
            "total_public": len(public_buckets)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "buckets_tested": 0,
            "accessible_buckets": [],
            "public_buckets": []
        }

def enumerate_azure_blobs(target: str) -> Dict[str, Any]:
    """
    Enumerate Azure Blob Storage containers for the target domain.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing Azure blob enumeration results
    """
    try:
        print(f"[INFO] Enumerating Azure blobs for {target}")
        
        # Generate potential container names
        container_names = []
        
        patterns = [
            target,
            f"{target}-backup",
            f"{target}-assets",
            f"{target}-files",
            f"{target}-uploads",
            f"{target}-media",
            f"{target}-static",
            f"{target}-cdn",
            f"{target}-dev",
            f"{target}-staging",
            f"{target}-prod",
            f"{target}-test"
        ]
        
        for pattern in patterns:
            container_names.extend([
                pattern,
                pattern.replace('.', '-'),
                pattern.replace('.', ''),
                f"{pattern}-container",
                f"{pattern}-storage"
            ])
        
        container_names = list(set(container_names))
        
        accessible_containers = []
        
        for container_name in container_names:
            try:
                # Test Azure blob access
                url = f"https://{container_name}.blob.core.windows.net"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 403]:
                    accessible_containers.append({
                        "container": container_name,
                        "url": url,
                        "status_code": response.status_code,
                        "public": response.status_code == 200
                    })
                    
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "containers_tested": len(container_names),
            "accessible_containers": accessible_containers,
            "total_accessible": len(accessible_containers),
            "total_public": len([c for c in accessible_containers if c["public"]])
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "containers_tested": 0,
            "accessible_containers": []
        }

def enumerate_gcp_storage(target: str) -> Dict[str, Any]:
    """
    Enumerate Google Cloud Storage buckets for the target domain.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing GCP storage enumeration results
    """
    try:
        print(f"[INFO] Enumerating GCP storage for {target}")
        
        # Generate potential bucket names
        bucket_names = []
        
        patterns = [
            target,
            f"{target}-backup",
            f"{target}-assets",
            f"{target}-files",
            f"{target}-uploads",
            f"{target}-media",
            f"{target}-static",
            f"{target}-cdn",
            f"{target}-dev",
            f"{target}-staging",
            f"{target}-prod",
            f"{target}-test"
        ]
        
        for pattern in patterns:
            bucket_names.extend([
                pattern,
                pattern.replace('.', '-'),
                pattern.replace('.', ''),
                f"{pattern}-bucket",
                f"{pattern}-storage"
            ])
        
        bucket_names = list(set(bucket_names))
        
        accessible_buckets = []
        
        for bucket_name in bucket_names:
            try:
                # Test GCP storage access
                url = f"https://storage.googleapis.com/{bucket_name}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 403]:
                    accessible_buckets.append({
                        "bucket": bucket_name,
                        "url": url,
                        "status_code": response.status_code,
                        "public": response.status_code == 200
                    })
                    
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "buckets_tested": len(bucket_names),
            "accessible_buckets": accessible_buckets,
            "total_accessible": len(accessible_buckets),
            "total_public": len([b for b in accessible_buckets if b["public"]])
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "buckets_tested": 0,
            "accessible_buckets": []
        }

def detect_cloud_services(target: str) -> Dict[str, Any]:
    """
    Detect cloud services and infrastructure for the target domain.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing cloud service detection results
    """
    try:
        print(f"[INFO] Detecting cloud services for {target}")
        
        cloud_services = {
            "aws": {
                "indicators": ["aws", "amazon", "s3", "cloudfront", "elb", "ec2", "lambda"],
                "domains": ["amazonaws.com", "cloudfront.net", "elasticbeanstalk.com"]
            },
            "azure": {
                "indicators": ["azure", "microsoft", "blob", "appservice"],
                "domains": ["azurewebsites.net", "cloudapp.net", "azure.com"]
            },
            "gcp": {
                "indicators": ["google", "gcp", "cloud", "appspot"],
                "domains": ["appspot.com", "run.app", "googleapis.com"]
            },
            "heroku": {
                "indicators": ["heroku"],
                "domains": ["herokuapp.com"]
            },
            "netlify": {
                "indicators": ["netlify"],
                "domains": ["netlify.app"]
            },
            "vercel": {
                "indicators": ["vercel"],
                "domains": ["vercel.app"]
            }
        }
        
        detected_services = {}
        
        # Check for cloud service indicators in DNS and HTTP responses
        for service_name, service_info in cloud_services.items():
            detected_services[service_name] = {
                "detected": False,
                "indicators": [],
                "domains": []
            }
            
            # Check for service domains
            for domain in service_info["domains"]:
                try:
                    cmd = ["dig", "+short", f"*.{target}", "CNAME"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and domain in result.stdout:
                        detected_services[service_name]["detected"] = True
                        detected_services[service_name]["domains"].append(domain)
                        
                except Exception:
                    continue
        
        return {
            "success": True,
            "services_detected": detected_services,
            "total_detected": len([s for s in detected_services.values() if s["detected"]])
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "services_detected": {},
            "total_detected": 0
        }

def test_cloud_metadata_services(target: str) -> Dict[str, Any]:
    """
    Test for cloud metadata service exposure (SSRF opportunities).
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing metadata service test results
    """
    try:
        print(f"[INFO] Testing cloud metadata services for {target}")
        
        metadata_endpoints = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "azure": "http://169.254.169.254/metadata/instance",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/",
            "digitalocean": "http://169.254.169.254/metadata/v1/",
            "linode": "http://139.162.130.33/metadata/v1/",
            "vultr": "http://169.254.169.254/v1.json"
        }
        
        metadata_results = {}
        
        for cloud_provider, endpoint in metadata_endpoints.items():
            metadata_results[cloud_provider] = {
                "endpoint": endpoint,
                "accessible": False,
                "response_preview": ""
            }
            
            # Note: We don't actually test these endpoints as they require SSRF
            # This is just for documentation and awareness
            metadata_results[cloud_provider]["note"] = "Requires SSRF to test"
        
        return {
            "success": True,
            "metadata_endpoints": metadata_results,
            "total_endpoints": len(metadata_endpoints)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "metadata_endpoints": {}
        }

def search_for_cloud_keys(target: str) -> Dict[str, Any]:
    """
    Search for potential cloud API keys in common locations.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing cloud key search results
    """
    try:
        print(f"[INFO] Searching for cloud API keys for {target}")
        
        # Common patterns for cloud API keys
        key_patterns = {
            "aws": [
                r"AKIA[0-9A-Z]{16}",
                r"aws_access_key_id",
                r"aws_secret_access_key"
            ],
            "azure": [
                r"[a-zA-Z0-9]{32}",
                r"azure_storage_account",
                r"azure_storage_key"
            ],
            "gcp": [
                r"AIza[0-9A-Za-z\-_]{35}",
                r"google_api_key",
                r"gcp_service_account"
            ]
        }
        
        # This would typically involve searching through discovered files
        # For now, we'll return a template structure
        return {
            "success": True,
            "key_patterns": key_patterns,
            "keys_found": [],
            "note": "Requires file access to search for keys"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "key_patterns": {},
            "keys_found": []
        }

def run_cloud_infrastructure_enumeration(target: str, raw_output_path: str) -> Dict[str, Any]:
    """
    Run comprehensive cloud infrastructure enumeration.
    
    Args:
        target: Target domain
        raw_output_path: Path to save raw output
        
    Returns:
        Dictionary containing comprehensive cloud enumeration results
    """
    print(f"[INFO] Starting cloud infrastructure enumeration for {target}")
    
    start_time = time.time()
    all_results = {}
    
    # Step 1: S3 bucket enumeration
    print(f"[INFO] Enumerating S3 buckets")
    s3_results = enumerate_s3_buckets(target)
    all_results["s3_enumeration"] = s3_results
    
    # Step 2: Azure blob enumeration
    print(f"[INFO] Enumerating Azure blobs")
    azure_results = enumerate_azure_blobs(target)
    all_results["azure_enumeration"] = azure_results
    
    # Step 3: GCP storage enumeration
    print(f"[INFO] Enumerating GCP storage")
    gcp_results = enumerate_gcp_storage(target)
    all_results["gcp_enumeration"] = gcp_results
    
    # Step 4: Cloud service detection
    print(f"[INFO] Detecting cloud services")
    service_results = detect_cloud_services(target)
    all_results["service_detection"] = service_results
    
    # Step 5: Metadata service testing
    print(f"[INFO] Testing metadata services")
    metadata_results = test_cloud_metadata_services(target)
    all_results["metadata_services"] = metadata_results
    
    # Step 6: Cloud key search
    print(f"[INFO] Searching for cloud keys")
    key_results = search_for_cloud_keys(target)
    all_results["key_search"] = key_results
    
    # Step 7: Generate summary
    execution_time = time.time() - start_time
    
    summary = {
        "target": target,
        "execution_time": execution_time,
        "s3_buckets_found": s3_results.get("total_accessible", 0),
        "s3_public_buckets": s3_results.get("total_public", 0),
        "azure_containers_found": azure_results.get("total_accessible", 0),
        "azure_public_containers": azure_results.get("total_public", 0),
        "gcp_buckets_found": gcp_results.get("total_accessible", 0),
        "gcp_public_buckets": gcp_results.get("total_public", 0),
        "cloud_services_detected": service_results.get("total_detected", 0),
        "metadata_endpoints": metadata_results.get("total_endpoints", 0)
    }
    
    # Save raw output
    raw_output = {
        "target": target,
        "timestamp": time.time(),
        "s3_results": s3_results,
        "azure_results": azure_results,
        "gcp_results": gcp_results,
        "service_results": service_results,
        "metadata_results": metadata_results,
        "key_results": key_results
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
    if len(sys.argv) != 3:
        print("Usage: python run_cloud_infrastructure.py <target> <raw_output_path>")
        sys.exit(1)
    
    target = sys.argv[1]
    raw_output_path = sys.argv[2]
    
    results = run_cloud_infrastructure_enumeration(target, raw_output_path)
    print(json.dumps(results, indent=2)) 