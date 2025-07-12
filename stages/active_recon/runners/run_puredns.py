#!/usr/bin/env python3
"""
PureDNS Runner for Active Reconnaissance

This module uses PureDNS to detect live servers from a list of subdomains
and perform reverse WHOIS lookups for IP/CIDR mapping.
"""

import os
import json
import subprocess
import socket
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_puredns(subdomains: List[str], output_dir: str, wordlist_path: str = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt") -> Dict[str, Any]:
    """
    Run PureDNS to detect live servers from subdomain list.
    
    Args:
        subdomains: List of subdomains to check
        output_dir: Directory to save results
        wordlist_path: Path to DNS wordlist for additional enumeration
    
    Returns:
        Dictionary containing live servers and their details
    """
    try:
        logger.info(f"Starting PureDNS live server detection for {len(subdomains)} subdomains")
        
        # Create output files
        subdomains_file = os.path.join(output_dir, "subdomains_list.txt")
        live_servers_file = os.path.join(output_dir, "live_servers.txt")
        results_file = os.path.join(output_dir, "puredns_results.json")
        
        # Write subdomains to file
        with open(subdomains_file, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        
        logger.info(f"Wrote {len(subdomains)} subdomains to {subdomains_file}")
        
        # Run PureDNS with wildcard detection
        cmd = [
            "puredns", "resolve", subdomains_file,
            "--write", live_servers_file,
            "--write-wildcards", os.path.join(output_dir, "wildcards.txt"),
            "--skip-wildcard-filter",
            "--skip-validation",
            "--rate-limit", "1000"
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            logger.error(f"PureDNS failed: {result.stderr}")
            return {
                "success": False,
                "error": f"PureDNS command failed: {result.stderr}",
                "subdomains_checked": len(subdomains),
                "live_servers": []
            }
        
        # Read live servers
        live_servers = []
        if os.path.exists(live_servers_file):
            with open(live_servers_file, 'r') as f:
                live_servers = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Found {len(live_servers)} live servers")
        
        # Perform reverse WHOIS lookup for each live server
        server_details = []
        for server in live_servers:
            try:
                # Get IP address
                ip_address = socket.gethostbyname(server)
                
                # Get additional DNS information
                try:
                    socket.gethostbyaddr(ip_address)
                    reverse_dns = socket.gethostbyaddr(ip_address)[0]
                except:
                    reverse_dns = None
                
                server_detail = {
                    "subdomain": server,
                    "ip_address": ip_address,
                    "reverse_dns": reverse_dns,
                    "status": "live"
                }
                
                server_details.append(server_detail)
                logger.info(f"Resolved {server} -> {ip_address}")
                
            except Exception as e:
                logger.warning(f"Failed to resolve {server}: {e}")
                server_details.append({
                    "subdomain": server,
                    "ip_address": None,
                    "reverse_dns": None,
                    "status": "unresolved",
                    "error": str(e)
                })
        
        # Group by IP addresses to identify CIDR ranges
        ip_groups = {}
        for detail in server_details:
            if detail["ip_address"]:
                ip = detail["ip_address"]
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(detail)
        
        # Create CIDR-like grouping (simplified)
        cidr_groups = {}
        for ip, servers in ip_groups.items():
            # Extract network portion (first 3 octets)
            network = '.'.join(ip.split('.')[:3]) + '.0/24'
            if network not in cidr_groups:
                cidr_groups[network] = []
            cidr_groups[network].extend(servers)
        
        # Prepare results
        results = {
            "success": True,
            "target": subdomains[0].split('.')[-2] + '.' + subdomains[0].split('.')[-1] if len(subdomains) > 0 else "unknown",
            "subdomains_checked": len(subdomains),
            "live_servers_count": len(live_servers),
            "live_servers": live_servers,
            "server_details": server_details,
            "ip_groups": ip_groups,
            "cidr_groups": cidr_groups,
            "files": {
                "subdomains_file": subdomains_file,
                "live_servers_file": live_servers_file,
                "results_file": results_file
            },
            "summary": {
                "total_subdomains": len(subdomains),
                "live_servers": len(live_servers),
                "unique_ips": len(ip_groups),
                "cidr_ranges": len(cidr_groups)
            }
        }
        
        # Save results to JSON
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"PureDNS completed successfully")
        logger.info(f"  - Subdomains checked: {len(subdomains)}")
        logger.info(f"  - Live servers found: {len(live_servers)}")
        logger.info(f"  - Unique IPs: {len(ip_groups)}")
        logger.info(f"  - CIDR ranges: {len(cidr_groups)}")
        
        return results
        
    except subprocess.TimeoutExpired:
        logger.error("PureDNS command timed out")
        return {
            "success": False,
            "error": "PureDNS command timed out",
            "subdomains_checked": len(subdomains),
            "live_servers": []
        }
    except Exception as e:
        logger.error(f"Error in PureDNS runner: {e}")
        return {
            "success": False,
            "error": str(e),
            "subdomains_checked": len(subdomains),
            "live_servers": []
        }

def perform_reverse_whois_lookup(ip_address: str) -> Dict[str, Any]:
    """
    Perform reverse WHOIS lookup for an IP address.
    
    Args:
        ip_address: IP address to lookup
    
    Returns:
        Dictionary containing WHOIS information
    """
    try:
        # This is a simplified implementation
        # In a real scenario, you might use external APIs or services
        # like IPinfo, MaxMind, or other WHOIS services
        
        whois_info = {
            "ip": ip_address,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "org": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown"
        }
        
        # Try to get basic information using socket
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            whois_info["hostname"] = hostname
        except:
            whois_info["hostname"] = None
        
        return whois_info
        
    except Exception as e:
        logger.error(f"Error in reverse WHOIS lookup for {ip_address}: {e}")
        return {
            "ip": ip_address,
            "error": str(e)
        }

def create_master_subdomain_list(passive_results: List[Dict[str, Any]], target_domain: str) -> List[str]:
    """
    Create a master subdomain list from passive recon results.
    
    Args:
        passive_results: Results from passive recon stage
        target_domain: Target domain name
    
    Returns:
        List of unique subdomains
    """
    try:
        all_subdomains = set()
        
        # Extract subdomains from passive recon results
        for result in passive_results:
            if isinstance(result, dict):
                # Handle different result formats
                if "subdomains" in result:
                    all_subdomains.update(result["subdomains"])
                elif "raw_output" in result and "subdomains" in result["raw_output"]:
                    all_subdomains.update(result["raw_output"]["subdomains"])
                elif "data" in result and isinstance(result["data"], list):
                    for item in result["data"]:
                        if isinstance(item, dict) and "subdomain" in item:
                            all_subdomains.add(item["subdomain"])
                        elif isinstance(item, str):
                            all_subdomains.add(item)
        
        # Add the main target domain if not present
        all_subdomains.add(target_domain)
        
        # Convert to list and sort
        master_list = sorted(list(all_subdomains))
        
        logger.info(f"Created master subdomain list with {len(master_list)} unique subdomains")
        return master_list
        
    except Exception as e:
        logger.error(f"Error creating master subdomain list: {e}")
        return [target_domain]

def main():
    """Main function for testing the PureDNS runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PureDNS Runner")
    parser.add_argument("--subdomains", required=True, help="Comma-separated list of subdomains")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--wordlist", help="Path to DNS wordlist")
    
    args = parser.parse_args()
    
    subdomains = [s.strip() for s in args.subdomains.split(",")]
    
    results = run_puredns(subdomains, args.output_dir, args.wordlist)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 