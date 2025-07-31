import os
import requests
import json
import re
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import urljoin, urlparse

def run_archive_mining(target: str, output_dir: str) -> Dict:
    """
    Search archives and historical data for the target domain.
    """
    output_file = os.path.join(output_dir, f"archive_mining_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        archive_data = {
            "tool": "archive_mining",
            "target": target,
            "raw_output_path": output_file,
            "archive_findings": [],
            "total_findings": 0
        }
        
        # Search Wayback Machine
        wayback_results = search_wayback_machine(target)
        archive_data["archive_findings"].extend(wayback_results)
        
        # Search Google Cache
        google_cache_results = search_google_cache(target)
        archive_data["archive_findings"].extend(google_cache_results)
        
        # Search for historical URLs
        historical_url_results = search_historical_urls(target)
        archive_data["archive_findings"].extend(historical_url_results)
        
        # Search for JavaScript secrets
        js_secrets_results = search_javascript_secrets(target)
        archive_data["archive_findings"].extend(js_secrets_results)
        
        # Search for parameter discovery
        parameter_results = search_parameters(target)
        archive_data["archive_findings"].extend(parameter_results)
        
        archive_data["total_findings"] = len(archive_data["archive_findings"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(archive_data, f, indent=2, default=str)
        
        return archive_data
        
    except Exception as e:
        print(f"[Archive Mining] Error: {e}")
        return {
            "tool": "archive_mining",
            "target": target,
            "error": str(e),
            "archive_findings": [],
            "total_findings": 0
        }

def search_wayback_machine(target: str) -> List[Dict]:
    """
    Search Wayback Machine for historical snapshots of the target.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Query Wayback Machine CDX API
        url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": 1000
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Skip header row
            for row in data[1:]:
                if len(row) >= 4:
                    original_url, timestamp, status_code, mime_type = row[:4]
                    
                    # Convert timestamp to readable date
                    archive_date = format_wayback_timestamp(timestamp)
                    
                    # Create archived URL
                    archived_url = f"http://web.archive.org/web/{timestamp}/{original_url}"
                    
                    finding = {
                        "archive_source": "wayback_machine",
                        "finding_type": "historical_snapshot",
                        "original_url": original_url,
                        "archived_url": archived_url,
                        "archive_date": archive_date,
                        "content": f"Status: {status_code}, Type: {mime_type}",
                        "parameters": extract_url_parameters(original_url),
                        "secrets_found": [],
                        "source": "wayback_machine"
                    }
                    findings.append(finding)
                    
        else:
            print(f"[Wayback Machine] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[Wayback Machine] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[Wayback Machine] JSON decode error: {e}")
    except Exception as e:
        print(f"[Wayback Machine] Unexpected error: {e}")
    
    return findings

def search_google_cache(target: str) -> List[Dict]:
    """
    Search Google Cache for cached versions of the target.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Google Cache URLs
        cache_urls = [
            f"https://webcache.googleusercontent.com/search?q=cache:{target}",
            f"https://webcache.googleusercontent.com/search?q=cache:http://{target}",
            f"https://webcache.googleusercontent.com/search?q=cache:https://{target}"
        ]
        
        for cache_url in cache_urls:
            try:
                response = requests.get(cache_url, timeout=30)
                
                if response.status_code == 200:
                    finding = {
                        "archive_source": "google_cache",
                        "finding_type": "cached_page",
                        "original_url": target,
                        "archived_url": cache_url,
                        "archive_date": None,  # Google doesn't provide specific dates
                        "content": f"Cached page available (Status: {response.status_code})",
                        "parameters": extract_url_parameters(target),
                        "secrets_found": extract_secrets_from_content(response.text),
                        "source": "google_cache"
                    }
                    findings.append(finding)
                    
            except requests.RequestException as e:
                print(f"[Google Cache] Request error for {cache_url}: {e}")
                
    except Exception as e:
        print(f"[Google Cache] Unexpected error: {e}")
    
    return findings

def search_historical_urls(target: str) -> List[Dict]:
    """
    Search for historical URLs and endpoints that may no longer be active.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common historical URL patterns
        historical_patterns = [
            f"http://{domain}",
            f"https://{domain}",
            f"http://www.{domain}",
            f"https://www.{domain}",
            f"http://old.{domain}",
            f"https://old.{domain}",
            f"http://legacy.{domain}",
            f"https://legacy.{domain}",
            f"http://archive.{domain}",
            f"https://archive.{domain}",
            f"http://staging.{domain}",
            f"https://staging.{domain}",
            f"http://dev.{domain}",
            f"https://dev.{domain}",
            f"http://test.{domain}",
            f"https://test.{domain}"
        ]
        
        for url in historical_patterns:
            # This is a placeholder for historical URL checking
            # In a real implementation, you'd check if these URLs exist
            
            finding = {
                "archive_source": "historical_urls",
                "finding_type": "historical_endpoint",
                "original_url": url,
                "archived_url": None,
                "archive_date": None,
                "content": f"Historical URL pattern: {url}",
                "parameters": extract_url_parameters(url),
                "secrets_found": [],
                "source": "historical_url_search"
            }
            findings.append(finding)
            
    except Exception as e:
        print(f"[Historical URLs] Error: {e}")
    
    return findings

def search_javascript_secrets(target: str) -> List[Dict]:
    """
    Search for JavaScript files and extract potential secrets.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common JavaScript file patterns
        js_patterns = [
            f"https://{domain}/js/",
            f"https://{domain}/javascript/",
            f"https://{domain}/static/js/",
            f"https://{domain}/assets/js/",
            f"https://{domain}/scripts/",
            f"https://{domain}/app.js",
            f"https://{domain}/main.js",
            f"https://{domain}/bundle.js",
            f"https://{domain}/vendor.js"
        ]
        
        # Common secret patterns in JavaScript
        secret_patterns = [
            (r'api[_-]?key["\s]*[:=]["\s]*["\']([^"\']+)["\']', "api_key"),
            (r'secret["\s]*[:=]["\s]*["\']([^"\']+)["\']', "secret"),
            (r'password["\s]*[:=]["\s]*["\']([^"\']+)["\']', "password"),
            (r'token["\s]*[:=]["\s]*["\']([^"\']+)["\']', "token"),
            (r'aws_access_key_id["\s]*[:=]["\s]*["\']([^"\']+)["\']', "aws_access_key"),
            (r'aws_secret_access_key["\s]*[:=]["\s]*["\']([^"\']+)["\']', "aws_secret_key"),
            (r'private_key["\s]*[:=]["\s]*["\']([^"\']+)["\']', "private_key"),
            (r'-----BEGIN RSA PRIVATE KEY-----', "rsa_private_key"),
            (r'-----BEGIN DSA PRIVATE KEY-----', "dsa_private_key"),
            (r'-----BEGIN EC PRIVATE KEY-----', "ec_private_key"),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', "openssh_private_key")
        ]
        
        for js_url in js_patterns:
            try:
                response = requests.get(js_url, timeout=30)
                
                if response.status_code == 200:
                    content = response.text
                    secrets_found = []
                    
                    for pattern, secret_type in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            secrets_found.append({
                                "type": secret_type,
                                "value": match[:50] + "..." if len(match) > 50 else match,
                                "line": find_line_number(content, match)
                            })
                    
                    if secrets_found:
                        finding = {
                            "archive_source": "javascript_analysis",
                            "finding_type": "javascript_secrets",
                            "original_url": js_url,
                            "archived_url": None,
                            "archive_date": None,
                            "content": f"JavaScript file: {js_url}",
                            "parameters": extract_url_parameters(js_url),
                            "secrets_found": secrets_found,
                            "source": "javascript_secret_search"
                        }
                        findings.append(finding)
                        
            except requests.RequestException as e:
                print(f"[JavaScript Secrets] Request error for {js_url}: {e}")
                
    except Exception as e:
        print(f"[JavaScript Secrets] Error: {e}")
    
    return findings

def search_parameters(target: str) -> List[Dict]:
    """
    Search for URL parameters and query strings in archived data.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common parameter patterns to look for
        parameter_patterns = [
            "id", "user", "username", "email", "password", "token", "key",
            "file", "path", "dir", "directory", "page", "search", "query",
            "sort", "filter", "limit", "offset", "page", "lang", "locale",
            "debug", "test", "admin", "config", "setting", "option"
        ]
        
        # This is a placeholder for parameter discovery
        # In a real implementation, you'd analyze archived URLs for parameters
        
        for param in parameter_patterns:
            finding = {
                "archive_source": "parameter_discovery",
                "finding_type": "url_parameter",
                "original_url": f"https://{domain}/?{param}=value",
                "archived_url": None,
                "archive_date": None,
                "content": f"Potential parameter: {param}",
                "parameters": {param: "value"},
                "secrets_found": [],
                "source": "parameter_search"
            }
            findings.append(finding)
            
    except Exception as e:
        print(f"[Parameters] Error: {e}")
    
    return findings

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

def format_wayback_timestamp(timestamp: str) -> str:
    """
    Convert Wayback Machine timestamp to readable date.
    """
    try:
        # Wayback timestamps are in format: YYYYMMDDHHMMSS
        if len(timestamp) == 14:
            year = timestamp[:4]
            month = timestamp[4:6]
            day = timestamp[6:8]
            hour = timestamp[8:10]
            minute = timestamp[10:12]
            second = timestamp[12:14]
            return f"{year}-{month}-{day} {hour}:{minute}:{second}"
    except Exception:
        pass
    
    return timestamp

def extract_url_parameters(url: str) -> Dict[str, str]:
    """
    Extract URL parameters from a URL.
    """
    params = {}
    try:
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
    except Exception:
        pass
    
    return params

def extract_secrets_from_content(content: str) -> List[Dict]:
    """
    Extract potential secrets from content.
    """
    secrets = []
    
    # Common secret patterns
    secret_patterns = [
        (r'api[_-]?key["\s]*[:=]["\s]*["\']([^"\']+)["\']', "api_key"),
        (r'secret["\s]*[:=]["\s]*["\']([^"\']+)["\']', "secret"),
        (r'password["\s]*[:=]["\s]*["\']([^"\']+)["\']', "password"),
        (r'token["\s]*[:=]["\s]*["\']([^"\']+)["\']', "token"),
        (r'aws_access_key_id["\s]*[:=]["\s]*["\']([^"\']+)["\']', "aws_access_key"),
        (r'aws_secret_access_key["\s]*[:=]["\s]*["\']([^"\']+)["\']', "aws_secret_key")
    ]
    
    for pattern, secret_type in secret_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            secrets.append({
                "type": secret_type,
                "value": match[:50] + "..." if len(match) > 50 else match,
                "line": find_line_number(content, match)
            })
    
    return secrets

def find_line_number(content: str, search_text: str) -> Optional[int]:
    """
    Find the line number of a search text in content.
    """
    try:
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
    except Exception:
        pass
    
    return None

def run_archive_analysis(target: str, output_dir: str) -> Dict:
    """
    Perform comprehensive analysis of archived data.
    """
    output_file = os.path.join(output_dir, f"archive_analysis_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        analysis_data = {
            "tool": "archive_analysis",
            "target": target,
            "raw_output_path": output_file,
            "archive_findings": [],
            "total_findings": 0,
            "note": "Archive analysis requires comprehensive data processing"
        }
        
        # This is a placeholder for archive analysis
        # In a real implementation, you'd analyze patterns in archived data
        
        # Save placeholder output
        with open(output_file, "w") as f:
            json.dump(analysis_data, f, indent=2, default=str)
        
        return analysis_data
        
    except Exception as e:
        print(f"[Archive Analysis] Error: {e}")
        return {
            "tool": "archive_analysis",
            "target": target,
            "error": str(e),
            "archive_findings": [],
            "total_findings": 0
        }