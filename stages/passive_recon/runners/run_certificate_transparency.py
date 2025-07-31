import os
import requests
import json
import re
from typing import Dict, List, Optional
from datetime import datetime, timedelta

def run_certificate_transparency(target: str, output_dir: str) -> Dict:
    """
    Query Certificate Transparency logs to discover subdomains and certificates.
    Uses multiple CT log sources for comprehensive coverage.
    """
    output_file = os.path.join(output_dir, f"certificate_transparency_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Query multiple CT log sources
        ct_data = {
            "tool": "certificate_transparency",
            "target": target,
            "raw_output_path": output_file,
            "certificate_logs": [],
            "subdomains": set(),
            "total_certificates": 0,
            "total_subdomains": 0
        }
        
        # Query crt.sh (Certificate Transparency Search)
        crt_sh_results = query_crt_sh(target)
        ct_data["certificate_logs"].extend(crt_sh_results)
        
        # Query Censys (if API key available)
        censys_results = query_censys(target)
        ct_data["certificate_logs"].extend(censys_results)
        
        # Extract unique subdomains from all certificates
        for cert in ct_data["certificate_logs"]:
            if "subject_alt_names" in cert and cert["subject_alt_names"]:
                for san in cert["subject_alt_names"]:
                    if target in san:
                        ct_data["subdomains"].add(san)
        
        ct_data["subdomains"] = list(ct_data["subdomains"])
        ct_data["total_certificates"] = len(ct_data["certificate_logs"])
        ct_data["total_subdomains"] = len(ct_data["subdomains"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(ct_data, f, indent=2, default=str)
        
        return ct_data
        
    except Exception as e:
        print(f"[Certificate Transparency] Error: {e}")
        return {
            "tool": "certificate_transparency",
            "target": target,
            "error": str(e),
            "certificate_logs": [],
            "subdomains": [],
            "total_certificates": 0,
            "total_subdomains": 0
        }

def query_crt_sh(domain: str) -> List[Dict]:
    """
    Query crt.sh for certificate transparency logs.
    """
    certificates = []
    
    try:
        # Query crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        for cert in data:
            cert_info = {
                "domain": domain,
                "certificate_id": str(cert.get("id", "")),
                "issuer": cert.get("issuer_name", ""),
                "subject_alt_names": [],
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
                "serial_number": cert.get("serial_number", ""),
                "fingerprint": cert.get("fingerprint", ""),
                "log_index": str(cert.get("log_index", "")),
                "source": "crt.sh"
            }
            
            # Parse subject alternative names
            if "name_value" in cert:
                sans = cert["name_value"].split("\n")
                cert_info["subject_alt_names"] = [san.strip() for san in sans if san.strip()]
            
            certificates.append(cert_info)
            
    except requests.RequestException as e:
        print(f"[crt.sh] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[crt.sh] JSON decode error: {e}")
    except Exception as e:
        print(f"[crt.sh] Unexpected error: {e}")
    
    return certificates

def query_censys(domain: str) -> List[Dict]:
    """
    Query Censys for certificate transparency logs (requires API key).
    """
    certificates = []
    
    # Check for Censys API credentials
    censys_api_id = os.getenv("CENSYS_API_ID")
    censys_api_secret = os.getenv("CENSYS_API_SECRET")
    
    if not censys_api_id or not censys_api_secret:
        print("[Censys] API credentials not found. Skipping Censys query.")
        return certificates
    
    try:
        # Query Censys certificates index
        url = "https://search.censys.io/api/v2/certificates"
        headers = {
            "Authorization": f"Basic {censys_api_id}:{censys_api_secret}"
        }
        params = {
            "q": f"parsed.names: {domain}",
            "fields": ["parsed.names", "parsed.issuer_dn", "parsed.validity.start", 
                      "parsed.validity.end", "parsed.serial_number", "parsed.fingerprint_sha256"]
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        for result in data.get("result", {}).get("hits", []):
            cert_info = {
                "domain": domain,
                "certificate_id": result.get("_id", ""),
                "issuer": result.get("parsed", {}).get("issuer_dn", ""),
                "subject_alt_names": result.get("parsed", {}).get("names", []),
                "not_before": result.get("parsed", {}).get("validity", {}).get("start", ""),
                "not_after": result.get("parsed", {}).get("validity", {}).get("end", ""),
                "serial_number": result.get("parsed", {}).get("serial_number", ""),
                "fingerprint": result.get("parsed", {}).get("fingerprint_sha256", ""),
                "log_index": "",
                "source": "censys"
            }
            
            certificates.append(cert_info)
            
    except requests.RequestException as e:
        print(f"[Censys] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[Censys] JSON decode error: {e}")
    except Exception as e:
        print(f"[Censys] Unexpected error: {e}")
    
    return certificates

def run_passive_dns(target: str, output_dir: str) -> Dict:
    """
    Query passive DNS databases for historical DNS records.
    """
    output_file = os.path.join(output_dir, f"passive_dns_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        passive_dns_data = {
            "tool": "passive_dns",
            "target": target,
            "raw_output_path": output_file,
            "dns_records": [],
            "total_records": 0
        }
        
        # Query SecurityTrails (if API key available)
        securitytrails_results = query_securitytrails_dns(target)
        passive_dns_data["dns_records"].extend(securitytrails_results)
        
        # Query VirusTotal (if API key available)
        virustotal_results = query_virustotal_dns(target)
        passive_dns_data["dns_records"].extend(virustotal_results)
        
        passive_dns_data["total_records"] = len(passive_dns_data["dns_records"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(passive_dns_data, f, indent=2, default=str)
        
        return passive_dns_data
        
    except Exception as e:
        print(f"[Passive DNS] Error: {e}")
        return {
            "tool": "passive_dns",
            "target": target,
            "error": str(e),
            "dns_records": [],
            "total_records": 0
        }

def query_securitytrails_dns(domain: str) -> List[Dict]:
    """
    Query SecurityTrails for passive DNS records (requires API key).
    """
    records = []
    
    # Check for SecurityTrails API key
    securitytrails_api_key = os.getenv("SECURITYTRAILS_API_KEY")
    
    if not securitytrails_api_key:
        print("[SecurityTrails] API key not found. Skipping SecurityTrails query.")
        return records
    
    try:
        url = f"https://api.securitytrails.com/v1/history/dns/{domain}"
        headers = {
            "APIKEY": securitytrails_api_key
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        for record_type, records_list in data.get("records", {}).items():
            for record in records_list:
                dns_record = {
                    "domain": domain,
                    "record_type": record_type,
                    "value": record.get("value", ""),
                    "first_seen": record.get("first_seen", ""),
                    "last_seen": record.get("last_seen", ""),
                    "source": "securitytrails"
                }
                records.append(dns_record)
                
    except requests.RequestException as e:
        print(f"[SecurityTrails] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[SecurityTrails] JSON decode error: {e}")
    except Exception as e:
        print(f"[SecurityTrails] Unexpected error: {e}")
    
    return records

def query_virustotal_dns(domain: str) -> List[Dict]:
    """
    Query VirusTotal for passive DNS records (requires API key).
    """
    records = []
    
    # Check for VirusTotal API key
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not virustotal_api_key:
        print("[VirusTotal] API key not found. Skipping VirusTotal query.")
        return records
    
    try:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            "apikey": virustotal_api_key,
            "domain": domain
        }
        
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract DNS records
        for record_type, values in data.get("resolutions", {}).items():
            for value in values:
                dns_record = {
                    "domain": domain,
                    "record_type": "A",
                    "value": value.get("ip_address", ""),
                    "first_seen": value.get("last_resolved", ""),
                    "last_seen": value.get("last_resolved", ""),
                    "source": "virustotal"
                }
                records.append(dns_record)
                
    except requests.RequestException as e:
        print(f"[VirusTotal] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[VirusTotal] JSON decode error: {e}")
    except Exception as e:
        print(f"[VirusTotal] Unexpected error: {e}")
    
    return records