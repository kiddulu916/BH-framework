import os
import requests
import json
import hashlib
import re
from typing import Dict, List, Optional
from datetime import datetime

def run_breach_checking(target: str, output_dir: str) -> Dict:
    """
    Check for data breaches and leaked credentials related to the target domain.
    """
    output_file = os.path.join(output_dir, f"breach_checking_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        breach_data = {
            "tool": "breach_checking",
            "target": target,
            "raw_output_path": output_file,
            "breach_records": [],
            "total_records": 0
        }
        
        # Check HaveIBeenPwned
        hibp_results = check_haveibeenpwned(target)
        breach_data["breach_records"].extend(hibp_results)
        
        # Check DeHashed (if API key available)
        dehashed_results = check_dehashed(target)
        breach_data["breach_records"].extend(dehashed_results)
        
        # Check IntelX (if API key available)
        intelx_results = check_intelx(target)
        breach_data["breach_records"].extend(intelx_results)
        
        # Check for domain-specific breaches
        domain_breaches = check_domain_breaches(target)
        breach_data["breach_records"].extend(domain_breaches)
        
        breach_data["total_records"] = len(breach_data["breach_records"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(breach_data, f, indent=2, default=str)
        
        return breach_data
        
    except Exception as e:
        print(f"[Breach Checking] Error: {e}")
        return {
            "tool": "breach_checking",
            "target": target,
            "error": str(e),
            "breach_records": [],
            "total_records": 0
        }

def check_haveibeenpwned(target: str) -> List[Dict]:
    """
    Check HaveIBeenPwned for breached accounts related to the target domain.
    """
    records = []
    
    # Check for HaveIBeenPwned API key
    hibp_api_key = os.getenv("HIBP_API_KEY")
    
    if not hibp_api_key:
        print("[HaveIBeenPwned] API key not found. Skipping HaveIBeenPwned check.")
        return records
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Query HaveIBeenPwned for domain breaches
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        headers = {
            "hibp-api-key": hibp_api_key,
            "user-agent": "BugHuntingFramework/1.0"
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            breaches = response.json()
            
            for breach in breaches:
                # Check if breach is related to the target domain
                if domain.lower() in breach.get("Domain", "").lower():
                    breach_record = {
                        "breach_source": "haveibeenpwned",
                        "breach_type": "domain_breach",
                        "email": None,
                        "username": None,
                        "password_hash": None,
                        "personal_info": {
                            "breach_name": breach.get("Name", ""),
                            "breach_date": breach.get("BreachDate", ""),
                            "pwn_count": breach.get("PwnCount", 0),
                            "description": breach.get("Description", ""),
                            "data_classes": breach.get("DataClasses", []),
                            "is_verified": breach.get("IsVerified", False),
                            "is_fabricated": breach.get("IsFabricated", False),
                            "is_sensitive": breach.get("IsSensitive", False),
                            "is_retired": breach.get("IsRetired", False),
                            "is_spam_list": breach.get("IsSpamList", False)
                        },
                        "breach_date": breach.get("BreachDate", ""),
                        "breach_name": breach.get("Name", ""),
                        "severity": "high" if breach.get("IsSensitive", False) else "medium",
                        "source": "haveibeenpwned"
                    }
                    records.append(breach_record)
                    
        elif response.status_code == 401:
            print("[HaveIBeenPwned] Invalid API key")
        elif response.status_code == 429:
            print("[HaveIBeenPwned] Rate limit exceeded")
        else:
            print(f"[HaveIBeenPwned] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[HaveIBeenPwned] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[HaveIBeenPwned] JSON decode error: {e}")
    except Exception as e:
        print(f"[HaveIBeenPwned] Unexpected error: {e}")
    
    return records

def check_dehashed(target: str) -> List[Dict]:
    """
    Check DeHashed for leaked credentials (requires API key).
    """
    records = []
    
    # Check for DeHashed API credentials
    dehashed_username = os.getenv("DEHASHED_USERNAME")
    dehashed_api_key = os.getenv("DEHASHED_API_KEY")
    
    if not dehashed_username or not dehashed_api_key:
        print("[DeHashed] API credentials not found. Skipping DeHashed check.")
        return records
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Query DeHashed API
        url = "https://api.dehashed.com/search"
        headers = {
            "Authorization": f"Basic {dehashed_username}:{dehashed_api_key}",
            "Accept": "application/json"
        }
        params = {
            "query": f"domain:{domain}",
            "size": 100
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for entry in data.get("entries", []):
                breach_record = {
                    "breach_source": "dehashed",
                    "breach_type": "credential_leak",
                    "email": entry.get("email", ""),
                    "username": entry.get("username", ""),
                    "password_hash": entry.get("password", ""),
                    "personal_info": {
                        "database": entry.get("database_name", ""),
                        "line_number": entry.get("line_number", ""),
                        "hashed": entry.get("hashed", False),
                        "salted": entry.get("salted", False)
                    },
                    "breach_date": entry.get("date", ""),
                    "breach_name": entry.get("database_name", ""),
                    "severity": "high",
                    "source": "dehashed"
                }
                records.append(breach_record)
                
        elif response.status_code == 401:
            print("[DeHashed] Invalid API credentials")
        elif response.status_code == 429:
            print("[DeHashed] Rate limit exceeded")
        else:
            print(f"[DeHashed] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[DeHashed] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[DeHashed] JSON decode error: {e}")
    except Exception as e:
        print(f"[DeHashed] Unexpected error: {e}")
    
    return records

def check_intelx(target: str) -> List[Dict]:
    """
    Check IntelX for leaked data (requires API key).
    """
    records = []
    
    # Check for IntelX API key
    intelx_api_key = os.getenv("INTELX_API_KEY")
    
    if not intelx_api_key:
        print("[IntelX] API key not found. Skipping IntelX check.")
        return records
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Query IntelX API
        url = "https://intelx.io/intel"
        headers = {
            "x-key": intelx_api_key,
            "User-Agent": "BugHuntingFramework/1.0"
        }
        params = {
            "term": domain,
            "maxresults": 100,
            "media": 0,
            "sort": 4,
            "terminate": []
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for result in data.get("results", []):
                breach_record = {
                    "breach_source": "intelx",
                    "breach_type": "data_leak",
                    "email": None,
                    "username": None,
                    "password_hash": None,
                    "personal_info": {
                        "media": result.get("media", ""),
                        "name": result.get("name", ""),
                        "date": result.get("date", ""),
                        "size": result.get("size", ""),
                        "type": result.get("type", ""),
                        "country": result.get("country", ""),
                        "bucket": result.get("bucket", "")
                    },
                    "breach_date": result.get("date", ""),
                    "breach_name": result.get("name", ""),
                    "severity": "medium",
                    "source": "intelx"
                }
                records.append(breach_record)
                
        elif response.status_code == 401:
            print("[IntelX] Invalid API key")
        elif response.status_code == 429:
            print("[IntelX] Rate limit exceeded")
        else:
            print(f"[IntelX] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[IntelX] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[IntelX] JSON decode error: {e}")
    except Exception as e:
        print(f"[IntelX] Unexpected error: {e}")
    
    return records

def check_domain_breaches(target: str) -> List[Dict]:
    """
    Check for domain-specific breaches and leaks.
    """
    records = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common breach databases to check
        breach_sources = [
            "breachdirectory.pwnedpasswords.com",
            "leakcheck.io",
            "snusbase.com"
        ]
        
        for source in breach_sources:
            # This is a placeholder for domain breach checking
            # In a real implementation, you'd use APIs or web scraping
            
            breach_record = {
                "breach_source": source,
                "breach_type": "domain_breach",
                "email": None,
                "username": None,
                "password_hash": None,
                "personal_info": {
                    "source": source,
                    "domain": domain,
                    "note": "Placeholder for domain breach checking"
                },
                "breach_date": None,
                "breach_name": f"{source}_domain_check",
                "severity": "medium",
                "source": source
            }
            records.append(breach_record)
            
    except Exception as e:
        print(f"[Domain Breaches] Error: {e}")
    
    return records

def extract_domain(target: str) -> str:
    """
    Extract domain from target URL or domain.
    """
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        target = target.split('://', 1)[1]
    
    # Remove path and query parameters
    target = target.split('/')[0]
    
    # Remove port if present
    target = target.split(':')[0]
    
    return target

def run_credential_stuffing_check(target: str, output_dir: str) -> Dict:
    """
    Check for potential credential stuffing attacks using breached credentials.
    """
    output_file = os.path.join(output_dir, f"credential_stuffing_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        stuffing_data = {
            "tool": "credential_stuffing_check",
            "target": target,
            "raw_output_path": output_file,
            "breach_records": [],
            "total_records": 0,
            "note": "Credential stuffing check requires specialized tools and APIs"
        }
        
        # This is a placeholder for credential stuffing checking
        # In a real implementation, you'd use specialized tools
        
        # Save placeholder output
        with open(output_file, "w") as f:
            json.dump(stuffing_data, f, indent=2, default=str)
        
        return stuffing_data
        
    except Exception as e:
        print(f"[Credential Stuffing] Error: {e}")
        return {
            "tool": "credential_stuffing_check",
            "target": target,
            "error": str(e),
            "breach_records": [],
            "total_records": 0
        }

def run_password_analysis(target: str, output_dir: str) -> Dict:
    """
    Analyze password patterns and strength from breached data.
    """
    output_file = os.path.join(output_dir, f"password_analysis_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        analysis_data = {
            "tool": "password_analysis",
            "target": target,
            "raw_output_path": output_file,
            "breach_records": [],
            "total_records": 0,
            "password_patterns": [],
            "common_passwords": [],
            "note": "Password analysis requires access to breached password databases"
        }
        
        # This is a placeholder for password analysis
        # In a real implementation, you'd analyze password patterns
        
        # Save placeholder output
        with open(output_file, "w") as f:
            json.dump(analysis_data, f, indent=2, default=str)
        
        return analysis_data
        
    except Exception as e:
        print(f"[Password Analysis] Error: {e}")
        return {
            "tool": "password_analysis",
            "target": target,
            "error": str(e),
            "breach_records": [],
            "total_records": 0
        }