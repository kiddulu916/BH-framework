#!/usr/bin/env python3
"""
WAF and CDN Detection Runner

This module provides comprehensive WAF (Web Application Firewall) and CDN 
(Content Delivery Network) detection capabilities.

Features:
- WAF detection using multiple techniques
- CDN identification and origin server discovery
- HTTP header analysis for security infrastructure
- Origin IP discovery for CDN-protected sites
- Security header enumeration
"""

import os
import json
import subprocess
import requests
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import socket
import dns.resolver
import ipaddress

def detect_waf_with_wafw00f(target: str) -> Dict[str, Any]:
    """
    Use WAFW00F to detect WAF presence and type.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing WAF detection results
    """
    try:
        print(f"[INFO] Running WAFW00F detection for {target}")
        
        cmd = ["wafw00f", "-v", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        waf_detected = False
        waf_type = None
        waf_details = []
        
        if result.returncode == 0:
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if "The site" in line and "is behind a" in line:
                    waf_detected = True
                    waf_type = line.split("is behind a ")[1].split(" ")[0]
                elif "No WAF detected" in line:
                    waf_detected = False
                elif "WAF/IPS identified:" in line:
                    waf_details.append(line.strip())
        
        return {
            "success": True,
            "waf_detected": waf_detected,
            "waf_type": waf_type,
            "details": waf_details,
            "raw_output": result.stdout
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "waf_detected": False,
            "waf_type": None
        }

def analyze_http_headers(target: str) -> Dict[str, Any]:
    """
    Analyze HTTP headers for WAF/CDN indicators.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing header analysis results
    """
    try:
        print(f"[INFO] Analyzing HTTP headers for {target}")
        
        # Common WAF/CDN headers to check
        waf_headers = [
            "X-WAF",
            "X-CDN",
            "X-Cloudflare",
            "X-Akamai",
            "X-Fastly",
            "X-Edge",
            "X-Cache",
            "CF-Ray",
            "CF-Cache-Status",
            "X-Powered-By-Cloudflare",
            "Server",
            "X-Server",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP"
        ]
        
        # WAF/CDN indicators in header values
        waf_indicators = {
            "cloudflare": ["cloudflare", "cf-ray", "cf-cache"],
            "akamai": ["akamai", "akamaighost"],
            "fastly": ["fastly", "fastly-ssl"],
            "aws": ["aws", "cloudfront", "elb"],
            "azure": ["azure", "azurewebsites"],
            "gcp": ["google", "gcp", "appspot"],
            "imperva": ["incapsula", "imperva"],
            "f5": ["bigip", "f5", "aspen"],
            "barracuda": ["barracuda"],
            "fortinet": ["fortinet", "fortigate"]
        }
        
        headers_found = {}
        indicators_detected = {}
        
        # Test both HTTP and HTTPS
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                for header_name in waf_headers:
                    if header_name in response.headers:
                        header_value = response.headers[header_name]
                        headers_found[header_name] = header_value
                        
                        # Check for WAF/CDN indicators
                        for waf_type, indicators in waf_indicators.items():
                            for indicator in indicators:
                                if indicator.lower() in header_value.lower():
                                    if waf_type not in indicators_detected:
                                        indicators_detected[waf_type] = []
                                    indicators_detected[waf_type].append({
                                        "header": header_name,
                                        "value": header_value,
                                        "indicator": indicator
                                    })
                
                break  # Use the first successful protocol
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "headers_found": headers_found,
            "indicators_detected": indicators_detected,
            "total_headers": len(headers_found),
            "total_indicators": len(indicators_detected)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "headers_found": {},
            "indicators_detected": {}
        }

def detect_cdn_with_cloudfail(target: str) -> Dict[str, Any]:
    """
    Use CloudFail to detect CDN and find origin servers.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing CDN detection results
    """
    try:
        print(f"[INFO] Running CloudFail detection for {target}")
        
        # Check if cloudfail is available
        try:
            subprocess.run(["cloudfail", "--help"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "success": False,
                "error": "CloudFail not available",
                "cdn_detected": False
            }
        
        cmd = ["cloudfail", "--target", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        cdn_detected = False
        origin_ips = []
        cdn_type = None
        
        if result.returncode == 0:
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if "CDN detected:" in line:
                    cdn_detected = True
                    cdn_type = line.split("CDN detected:")[1].strip()
                elif "Origin IP:" in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        origin_ips.append(ip_match.group(1))
        
        return {
            "success": True,
            "cdn_detected": cdn_detected,
            "cdn_type": cdn_type,
            "origin_ips": origin_ips,
            "raw_output": result.stdout
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "cdn_detected": False,
            "origin_ips": []
        }

def find_origin_ips_manual(target: str) -> Dict[str, Any]:
    """
    Manual origin IP discovery using various techniques.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing origin IP discovery results
    """
    try:
        print(f"[INFO] Performing manual origin IP discovery for {target}")
        
        origin_ips = []
        techniques_used = []
        
        # Technique 1: Historical DNS records
        try:
            cmd = ["dig", "+short", target, "A"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                ips = [ip.strip() for ip in result.stdout.split('\n') if ip.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip.strip())]
                if ips:
                    origin_ips.extend(ips)
                    techniques_used.append("current_dns")
        except Exception:
            pass
        
        # Technique 2: Check for common subdomains that might bypass CDN
        bypass_subdomains = [
            f"origin.{target}",
            f"backend.{target}",
            f"api.{target}",
            f"admin.{target}",
            f"internal.{target}",
            f"dev.{target}",
            f"staging.{target}",
            f"test.{target}"
        ]
        
        for subdomain in bypass_subdomains:
            try:
                cmd = ["dig", "+short", subdomain, "A"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ips = [ip.strip() for ip in result.stdout.split('\n') if ip.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip.strip())]
                    if ips:
                        origin_ips.extend(ips)
                        techniques_used.append(f"bypass_subdomain_{subdomain}")
            except Exception:
                continue
        
        # Technique 3: Check for email headers (MX records)
        try:
            cmd = ["dig", "+short", target, "MX"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                mx_records = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                for mx_record in mx_records:
                    if mx_record and not mx_record.startswith(';'):
                        try:
                            mx_domain = mx_record.split()[-1] if ' ' in mx_record else mx_record
                            cmd = ["dig", "+short", mx_domain, "A"]
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                ips = [ip.strip() for ip in result.stdout.split('\n') if ip.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip.strip())]
                                if ips:
                                    origin_ips.extend(ips)
                                    techniques_used.append(f"mx_record_{mx_domain}")
                        except Exception:
                            continue
        except Exception:
            pass
        
        # Remove duplicates and filter private IPs
        unique_ips = []
        for ip in origin_ips:
            if ip not in unique_ips:
                try:
                    # Filter out private IP ranges
                    ip_obj = ipaddress.IPv4Address(ip)
                    if not ip_obj.is_private:
                        unique_ips.append(ip)
                except Exception:
                    continue
        
        return {
            "success": True,
            "origin_ips": unique_ips,
            "techniques_used": techniques_used,
            "total_ips": len(unique_ips)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "origin_ips": [],
            "techniques_used": []
        }

def check_security_headers(target: str) -> Dict[str, Any]:
    """
    Check for security headers that might indicate WAF/CDN presence.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing security header analysis
    """
    try:
        print(f"[INFO] Checking security headers for {target}")
        
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "X-XSS-Protection": "XSS Protection",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy",
            "X-Permitted-Cross-Domain-Policies": "Cross-Domain Policy"
        }
        
        headers_found = {}
        
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                for header_name, description in security_headers.items():
                    if header_name in response.headers:
                        headers_found[header_name] = {
                            "value": response.headers[header_name],
                            "description": description
                        }
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "security_headers": headers_found,
            "total_security_headers": len(headers_found),
            "missing_headers": [h for h in security_headers.keys() if h not in headers_found]
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "security_headers": {},
            "total_security_headers": 0
        }

def run_waf_cdn_detection(target: str, raw_output_path: str) -> Dict[str, Any]:
    """
    Run comprehensive WAF and CDN detection.
    
    Args:
        target: Target domain
        raw_output_path: Path to save raw output
        
    Returns:
        Dictionary containing comprehensive detection results
    """
    print(f"[INFO] Starting WAF and CDN detection for {target}")
    
    start_time = time.time()
    all_results = {}
    
    # Step 1: WAF detection with WAFW00F
    print(f"[INFO] Running WAF detection")
    waf_results = detect_waf_with_wafw00f(target)
    all_results["waf_detection"] = waf_results
    
    # Step 2: HTTP header analysis
    print(f"[INFO] Analyzing HTTP headers")
    header_results = analyze_http_headers(target)
    all_results["header_analysis"] = header_results
    
    # Step 3: CDN detection with CloudFail
    print(f"[INFO] Running CDN detection")
    cdn_results = detect_cdn_with_cloudfail(target)
    all_results["cdn_detection"] = cdn_results
    
    # Step 4: Manual origin IP discovery
    print(f"[INFO] Performing manual origin IP discovery")
    origin_results = find_origin_ips_manual(target)
    all_results["origin_discovery"] = origin_results
    
    # Step 5: Security header analysis
    print(f"[INFO] Checking security headers")
    security_results = check_security_headers(target)
    all_results["security_headers"] = security_results
    
    # Step 6: Generate summary
    execution_time = time.time() - start_time
    
    # Determine overall WAF/CDN status
    waf_detected = (
        waf_results.get("waf_detected", False) or 
        len(header_results.get("indicators_detected", {})) > 0
    )
    
    cdn_detected = (
        cdn_results.get("cdn_detected", False) or
        any("cloud" in indicator.lower() for indicator in header_results.get("indicators_detected", {}))
    )
    
    summary = {
        "target": target,
        "execution_time": execution_time,
        "waf_detected": waf_detected,
        "waf_type": waf_results.get("waf_type"),
        "cdn_detected": cdn_detected,
        "cdn_type": cdn_results.get("cdn_type"),
        "origin_ips_found": len(origin_results.get("origin_ips", [])),
        "security_headers_found": security_results.get("total_security_headers", 0),
        "total_indicators": len(header_results.get("indicators_detected", {}))
    }
    
    # Save raw output
    raw_output = {
        "target": target,
        "timestamp": time.time(),
        "waf_results": waf_results,
        "header_analysis": header_results,
        "cdn_results": cdn_results,
        "origin_discovery": origin_results,
        "security_headers": security_results
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
        print("Usage: python run_waf_cdn_detection.py <target> <raw_output_path>")
        sys.exit(1)
    
    target = sys.argv[1]
    raw_output_path = sys.argv[2]
    
    results = run_waf_cdn_detection(target, raw_output_path)
    print(json.dumps(results, indent=2)) 