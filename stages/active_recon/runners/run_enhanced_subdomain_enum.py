#!/usr/bin/env python3
"""
Enhanced Subdomain Enumeration Runner

This module provides enhanced subdomain enumeration capabilities that build upon
passive recon results and add additional active discovery techniques.

Features:
- Leverages passive recon results as baseline
- Performs additional DNS brute-forcing with enhanced wordlists
- Checks for subdomain takeover opportunities
- Enumerates third-party services and integrations
- Maps IP address spaces and CIDR ranges
"""

import os
import json
import subprocess
import requests
import time
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def run_dns_brute_force(target: str, wordlist_path: str = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt") -> Dict[str, Any]:
    """
    Perform DNS brute-forcing with enhanced wordlists.
    
    Args:
        target: Target domain
        wordlist_path: Path to wordlist file
        
    Returns:
        Dictionary containing brute-force results
    """
    try:
        print(f"[INFO] Starting DNS brute-force for {target}")
        
        # Use gobuster for DNS brute-forcing
        cmd = [
            "gobuster", "dns",
            "-d", target,
            "-w", wordlist_path,
            "-r", "8.8.8.8,8.8.4.4,1.1.1.1",
            "-t", "50",
            "--wildcard"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        subdomains = []
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if target in line and 'Found:' in line:
                    subdomain = line.split('Found: ')[1].strip()
                    if subdomain.endswith(f'.{target}'):
                        subdomains.append(subdomain)
        
        return {
            "success": True,
            "subdomains": subdomains,
            "total_found": len(subdomains),
            "wordlist_used": wordlist_path
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "subdomains": [],
            "total_found": 0
        }

def check_subdomain_takeover(subdomain: str) -> Dict[str, Any]:
    """
    Check for subdomain takeover opportunities.
    
    Args:
        subdomain: Subdomain to check
        
    Returns:
        Dictionary containing takeover check results
    """
    try:
        # Check if subdomain resolves
        cmd = ["nslookup", subdomain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {
                "subdomain": subdomain,
                "takeover_possible": False,
                "reason": "Does not resolve"
            }
        
        # Check for common takeover indicators
        takeover_indicators = [
            "No such bucket",
            "NoSuchBucket",
            "The specified bucket does not exist",
            "Repository not found",
            "404 Not Found",
            "No such host",
            "NXDOMAIN"
        ]
        
        # Try to access the subdomain
        try:
            response = requests.get(f"http://{subdomain}", timeout=10, allow_redirects=False)
            response_text = response.text.lower()
            
            for indicator in takeover_indicators:
                if indicator.lower() in response_text:
                    return {
                        "subdomain": subdomain,
                        "takeover_possible": True,
                        "indicator": indicator,
                        "status_code": response.status_code,
                        "response_preview": response.text[:200]
                    }
            
            return {
                "subdomain": subdomain,
                "takeover_possible": False,
                "reason": "Active subdomain",
                "status_code": response.status_code
            }
            
        except requests.exceptions.RequestException:
            return {
                "subdomain": subdomain,
                "takeover_possible": False,
                "reason": "Connection failed"
            }
            
    except Exception as e:
        return {
            "subdomain": subdomain,
            "takeover_possible": False,
            "error": str(e)
        }

def enumerate_third_party_services(subdomains: List[str]) -> Dict[str, Any]:
    """
    Enumerate third-party services and integrations.
    
    Args:
        subdomains: List of subdomains to check
        
    Returns:
        Dictionary containing third-party service enumeration results
    """
    third_party_services = {
        "github": ["github.io", "githubusercontent.com"],
        "heroku": ["herokuapp.com"],
        "netlify": ["netlify.app"],
        "vercel": ["vercel.app"],
        "aws": ["s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com"],
        "azure": ["azurewebsites.net", "cloudapp.net"],
        "gcp": ["appspot.com", "run.app"],
        "shopify": ["myshopify.com"],
        "wordpress": ["wordpress.com"],
        "squarespace": ["squarespace.com"]
    }
    
    found_services = {}
    
    for subdomain in subdomains:
        for service, domains in third_party_services.items():
            for domain in domains:
                if domain in subdomain:
                    if service not in found_services:
                        found_services[service] = []
                    found_services[service].append(subdomain)
    
    return {
        "success": True,
        "services_found": found_services,
        "total_services": len(found_services),
        "total_subdomains_with_services": sum(len(subs) for subs in found_services.values())
    }

def map_ip_address_space(subdomains: List[str]) -> Dict[str, Any]:
    """
    Map IP address spaces and identify CIDR ranges.
    
    Args:
        subdomains: List of subdomains to resolve
        
    Returns:
        Dictionary containing IP mapping results
    """
    try:
        ips = set()
        
        # Resolve IPs for subdomains
        for subdomain in subdomains:
            try:
                cmd = ["nslookup", subdomain]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Address:' in line and not line.strip().startswith('#'):
                            ip = line.split('Address:')[1].strip()
                            if ip and ip != '127.0.0.1':
                                ips.add(ip)
            except Exception:
                continue
        
        # Convert to list and sort
        ip_list = sorted(list(ips), key=lambda x: ipaddress.IPv4Address(x))
        
        # Find CIDR ranges
        cidr_ranges = []
        if ip_list:
            try:
                # Use ipcalc to find CIDR ranges
                cmd = ["ipcalc", "--network", "--broadcast", "--minaddr", "--maxaddr"] + ip_list
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    # Parse ipcalc output to extract CIDR ranges
                    # This is a simplified approach - in practice, you'd want more sophisticated CIDR calculation
                    for ip in ip_list:
                        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                        cidr_ranges.append(str(network))
            except Exception:
                # Fallback: create /24 networks for each IP
                for ip in ip_list:
                    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    cidr_ranges.append(str(network))
        
        # Remove duplicates
        cidr_ranges = list(set(cidr_ranges))
        
        return {
            "success": True,
            "unique_ips": ip_list,
            "total_ips": len(ip_list),
            "cidr_ranges": cidr_ranges,
            "total_cidr_ranges": len(cidr_ranges)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "unique_ips": [],
            "total_ips": 0,
            "cidr_ranges": [],
            "total_cidr_ranges": 0
        }

def run_enhanced_subdomain_enumeration(target: str, passive_results: List[str], raw_output_path: str) -> Dict[str, Any]:
    """
    Run enhanced subdomain enumeration combining multiple techniques.
    
    Args:
        target: Target domain
        passive_results: List of subdomains from passive recon
        raw_output_path: Path to save raw output
        
    Returns:
        Dictionary containing comprehensive enumeration results
    """
    print(f"[INFO] Starting enhanced subdomain enumeration for {target}")
    
    start_time = time.time()
    all_results = {}
    
    # Step 1: Use passive recon results as baseline
    baseline_subdomains = passive_results.copy()
    all_results["baseline"] = {
        "subdomains": baseline_subdomains,
        "count": len(baseline_subdomains)
    }
    
    # Step 2: Perform DNS brute-forcing
    print(f"[INFO] Performing DNS brute-forcing for {target}")
    brute_force_results = run_dns_brute_force(target)
    all_results["brute_force"] = brute_force_results
    
    # Step 3: Combine and deduplicate subdomains
    all_subdomains = set(baseline_subdomains)
    if brute_force_results.get("success"):
        all_subdomains.update(brute_force_results.get("subdomains", []))
    
    unique_subdomains = sorted(list(all_subdomains))
    
    # Step 4: Check for subdomain takeover opportunities
    print(f"[INFO] Checking {len(unique_subdomains)} subdomains for takeover opportunities")
    takeover_results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain_takeover, subdomain): subdomain 
            for subdomain in unique_subdomains
        }
        
        for future in as_completed(future_to_subdomain):
            result = future.result()
            takeover_results.append(result)
    
    all_results["takeover_checks"] = {
        "results": takeover_results,
        "vulnerable_count": len([r for r in takeover_results if r.get("takeover_possible")])
    }
    
    # Step 5: Enumerate third-party services
    print(f"[INFO] Enumerating third-party services")
    third_party_results = enumerate_third_party_services(unique_subdomains)
    all_results["third_party_services"] = third_party_results
    
    # Step 6: Map IP address spaces
    print(f"[INFO] Mapping IP address spaces")
    ip_mapping_results = map_ip_address_space(unique_subdomains)
    all_results["ip_mapping"] = ip_mapping_results
    
    # Step 7: Generate summary
    execution_time = time.time() - start_time
    
    summary = {
        "target": target,
        "execution_time": execution_time,
        "baseline_subdomains": len(baseline_subdomains),
        "brute_force_subdomains": brute_force_results.get("total_found", 0),
        "total_unique_subdomains": len(unique_subdomains),
        "takeover_vulnerabilities": all_results["takeover_checks"]["vulnerable_count"],
        "third_party_services": third_party_results.get("total_services", 0),
        "unique_ips": ip_mapping_results.get("total_ips", 0),
        "cidr_ranges": ip_mapping_results.get("total_cidr_ranges", 0)
    }
    
    # Save raw output
    raw_output = {
        "target": target,
        "timestamp": time.time(),
        "all_subdomains": unique_subdomains,
        "takeover_results": takeover_results,
        "third_party_services": third_party_results.get("services_found", {}),
        "ip_mapping": ip_mapping_results
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
        print("Usage: python run_enhanced_subdomain_enum.py <target> <passive_results_file> <raw_output_path>")
        sys.exit(1)
    
    target = sys.argv[1]
    passive_results_file = sys.argv[2]
    raw_output_path = sys.argv[3]
    
    # Load passive results
    with open(passive_results_file, 'r') as f:
        passive_results = [line.strip() for line in f if line.strip()]
    
    results = run_enhanced_subdomain_enumeration(target, passive_results, raw_output_path)
    print(json.dumps(results, indent=2)) 