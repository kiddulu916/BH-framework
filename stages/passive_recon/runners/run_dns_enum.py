#!/usr/bin/env python3
"""
Enhanced DNS enumeration runner for bug hunting reconnaissance.
"""

import os
import json
import subprocess
import re
import socket
import dns.resolver
import dns.reversename
from typing import List, Dict, Any

def run_dns_enum(target: str, output_dir: str) -> Dict[str, Any]:
    """
    Run enhanced DNS enumeration for bug hunting reconnaissance.
    
    Args:
        target: Target domain to enumerate
        output_dir: Directory to save output files
        
    Returns:
        Dictionary containing DNS enumeration results
    """
    print(f"[INFO] Running enhanced DNS enumeration for {target}...")
    
    # Create output file path
    output_file = os.path.join(output_dir, f"dns_enum_{target}.json")
    
    all_results = {
        "target": target,
        "subdomains": [],
        "dns_records": {},
        "reverse_dns": {},
        "dns_servers": [],
        "mail_servers": [],
        "nameservers": [],
        "interesting_findings": [],
        "scan_summary": {}
    }
    
    try:
        # 1. Enhanced Amass DNS enumeration
        print("[INFO] Running enhanced Amass DNS enumeration...")
        amass_results = run_enhanced_amass(target, output_dir)
        all_results.update(amass_results)
        
        # 2. DNS record enumeration
        print("[INFO] Enumerating DNS records...")
        dns_records = enumerate_dns_records(target)
        all_results["dns_records"] = dns_records
        
        # 3. Reverse DNS lookup for discovered IPs
        print("[INFO] Performing reverse DNS lookups...")
        reverse_dns = perform_reverse_dns_lookups(all_results.get("ips", []))
        all_results["reverse_dns"] = reverse_dns
        
        # 4. DNS server enumeration
        print("[INFO] Enumerating DNS servers...")
        dns_servers = enumerate_dns_servers(target)
        all_results["dns_servers"] = dns_servers
        
        # 5. Mail server enumeration
        print("[INFO] Enumerating mail servers...")
        mail_servers = enumerate_mail_servers(target)
        all_results["mail_servers"] = mail_servers
        
        # 6. Nameserver enumeration
        print("[INFO] Enumerating nameservers...")
        nameservers = enumerate_nameservers(target)
        all_results["nameservers"] = nameservers
        
        # 7. Zone transfer attempts
        print("[INFO] Attempting zone transfers...")
        zone_transfer_results = attempt_zone_transfers(target, nameservers)
        all_results["zone_transfer"] = zone_transfer_results
        
        # 8. DNS wildcard detection
        print("[INFO] Detecting DNS wildcards...")
        wildcard_results = detect_dns_wildcards(target)
        all_results["wildcard_detection"] = wildcard_results
        
        # 9. DNS cache snooping
        print("[INFO] Performing DNS cache snooping...")
        cache_snooping_results = perform_dns_cache_snooping(target)
        all_results["cache_snooping"] = cache_snooping_results
        
        # 10. Find interesting findings
        all_results["interesting_findings"] = analyze_findings(all_results)
        
        # Create scan summary
        all_results["scan_summary"] = {
            "total_subdomains": len(all_results.get("subdomains", [])),
            "total_ips": len(all_results.get("ips", [])),
            "total_dns_records": sum(len(records) for records in all_results.get("dns_records", {}).values()),
            "dns_servers_found": len(all_results.get("dns_servers", [])),
            "mail_servers_found": len(all_results.get("mail_servers", [])),
            "nameservers_found": len(all_results.get("nameservers", [])),
            "zone_transfers_successful": len([z for z in all_results.get("zone_transfer", {}).values() if z.get("success", False)]),
            "wildcards_detected": len(all_results.get("wildcard_detection", {}).get("wildcards", [])),
            "interesting_findings": len(all_results.get("interesting_findings", []))
        }
        
        # Save results to file
        with open(output_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"[INFO] Enhanced DNS enumeration completed successfully")
        print(f"[INFO] Found {all_results['scan_summary']['total_subdomains']} subdomains and {all_results['scan_summary']['total_ips']} IPs")
        
        return all_results
        
    except Exception as e:
        print(f"[ERROR] Enhanced DNS enumeration failed: {e}")
        return {
            "target": target,
            "error": str(e),
            "scan_summary": {"error": str(e)}
        }

def run_enhanced_amass(target: str, output_dir: str) -> Dict[str, Any]:
    """Run enhanced Amass with multiple techniques."""
    try:
        # Run Amass with multiple techniques
        cmd = [
            "amass", "enum",
            "-d", target,
            "-active",  # Active reconnaissance
            "-brute",   # Brute force subdomains
            "-w", "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "-json", os.path.join(output_dir, f"amass_enhanced_{target}.json")
        ]
        
        print(f"[INFO] Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode == 0:
            # Parse Amass JSON output
            amass_file = os.path.join(output_dir, f"amass_enhanced_{target}.json")
            if os.path.exists(amass_file):
                with open(amass_file, 'r') as f:
                    amass_data = [json.loads(line) for line in f if line.strip()]
                
                subdomains = []
                ips = []
                
                for entry in amass_data:
                    if 'name' in entry:
                        subdomains.append(entry['name'])
                    if 'addresses' in entry:
                        for addr in entry['addresses']:
                            if 'addr' in addr:
                                ips.append(addr['addr'])
                
                return {
                    "subdomains": list(set(subdomains)),
                    "ips": list(set(ips))
                }
        
        return {"subdomains": [], "ips": []}
        
    except Exception as e:
        print(f"[WARNING] Enhanced Amass failed: {e}")
        return {"subdomains": [], "ips": []}

def enumerate_dns_records(target: str) -> Dict[str, List[str]]:
    """Enumerate various DNS record types."""
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA']
    results = {}
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)
            results[record_type] = [str(answer) for answer in answers]
        except Exception as e:
            results[record_type] = []
    
    return results

def perform_reverse_dns_lookups(ips: List[str]) -> Dict[str, str]:
    """Perform reverse DNS lookups for discovered IPs."""
    results = {}
    
    for ip in ips:
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(reverse_name, "PTR")
            results[ip] = str(answers[0])
        except Exception as e:
            results[ip] = "No PTR record"
    
    return results

def enumerate_dns_servers(target: str) -> List[str]:
    """Enumerate DNS servers for the target."""
    try:
        answers = dns.resolver.resolve(target, 'NS')
        return [str(answer) for answer in answers]
    except Exception as e:
        return []

def enumerate_mail_servers(target: str) -> List[str]:
    """Enumerate mail servers for the target."""
    try:
        answers = dns.resolver.resolve(target, 'MX')
        return [str(answer.exchange) for answer in answers]
    except Exception as e:
        return []

def enumerate_nameservers(target: str) -> List[str]:
    """Enumerate nameservers for the target."""
    try:
        answers = dns.resolver.resolve(target, 'NS')
        return [str(answer) for answer in answers]
    except Exception as e:
        return []

def attempt_zone_transfers(target: str, nameservers: List[str]) -> Dict[str, Dict[str, Any]]:
    """Attempt zone transfers against nameservers."""
    results = {}
    
    for ns in nameservers:
        try:
            # Use dig to attempt zone transfer
            cmd = ["dig", "@" + ns, target, "AXFR"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            success = "Transfer failed" not in result.stdout and result.returncode == 0
            results[ns] = {
                "success": success,
                "output": result.stdout if success else "Zone transfer failed",
                "records_found": len(result.stdout.split('\n')) if success else 0
            }
        except Exception as e:
            results[ns] = {
                "success": False,
                "output": str(e),
                "records_found": 0
            }
    
    return results

def detect_dns_wildcards(target: str) -> Dict[str, Any]:
    """Detect DNS wildcards by querying random subdomains."""
    import random
    import string
    
    wildcards = []
    non_wildcards = []
    
    # Generate random subdomains
    for _ in range(10):
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=10))
        test_domain = f"{random_subdomain}.{target}"
        
        try:
            answers = dns.resolver.resolve(test_domain, 'A')
            if answers:
                wildcards.append(test_domain)
        except Exception:
            non_wildcards.append(test_domain)
    
    return {
        "wildcards": wildcards,
        "non_wildcards": non_wildcards,
        "wildcard_detected": len(wildcards) > 0
    }

def perform_dns_cache_snooping(target: str) -> Dict[str, Any]:
    """Perform DNS cache snooping to find recently queried domains."""
    # This is a simplified implementation
    # In practice, you'd need to query multiple DNS servers and analyze responses
    
    results = {
        "cache_hits": [],
        "cache_misses": [],
        "analysis": "DNS cache snooping requires multiple DNS server queries"
    }
    
    return results

def analyze_findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze findings for interesting discoveries."""
    findings = []
    
    # Check for zone transfer vulnerabilities
    zone_transfers = results.get("zone_transfer", {})
    for ns, result in zone_transfers.items():
        if result.get("success", False):
            findings.append({
                "type": "zone_transfer_vulnerability",
                "severity": "high",
                "description": f"Zone transfer successful on {ns}",
                "details": result
            })
    
    # Check for wildcard DNS
    wildcard_detection = results.get("wildcard_detection", {})
    if wildcard_detection.get("wildcard_detected", False):
        findings.append({
            "type": "dns_wildcard",
            "severity": "medium",
            "description": "DNS wildcard detected",
            "details": wildcard_detection
        })
    
    # Check for interesting subdomains
    subdomains = results.get("subdomains", [])
    interesting_patterns = [
        "admin", "api", "dev", "test", "staging", "internal", "vpn", "mail", "ftp", "ssh"
    ]
    
    for subdomain in subdomains:
        for pattern in interesting_patterns:
            if pattern in subdomain.lower():
                findings.append({
                    "type": "interesting_subdomain",
                    "severity": "medium",
                    "description": f"Interesting subdomain found: {subdomain}",
                    "details": {"subdomain": subdomain, "pattern": pattern}
                })
                break
    
    # Check for exposed services
    dns_records = results.get("dns_records", {})
    for record_type, records in dns_records.items():
        if records:
            findings.append({
                "type": "dns_record",
                "severity": "low",
                "description": f"DNS {record_type} records found",
                "details": {"type": record_type, "records": records}
            })
    
    return findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python run_dns_enum.py <target> <output_dir>")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2]
    
    results = run_dns_enum(target, output_dir)
    print(json.dumps(results, indent=2)) 