#!/usr/bin/env python3
"""
Feroxbuster Runner for Active Reconnaissance

This module uses feroxbuster to perform directory and file enumeration
from web applications discovered during active reconnaissance.
"""

import os
import json
import subprocess
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_feroxbuster_output(feroxbuster_output: str) -> List[Dict[str, Any]]:
    """
    Parse feroxbuster output and return structured results.
    
    Args:
        feroxbuster_output: Raw feroxbuster output
        
    Returns:
        List of URL information dictionaries
    """
    urls = []
    
    lines = feroxbuster_output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Parse feroxbuster output format: status_code method url
        parts = line.split()
        if len(parts) >= 3:
            try:
                status_code = int(parts[0])
                method = parts[1]
                url = ' '.join(parts[2:])  # URL might contain spaces
                
                # Only accept HTTP/HTTPS URLs
                if url.startswith(('http://', 'https://')):
                    url_info = {
                        "url": url,
                        "method": method,
                        "status": status_code
                    }
                    urls.append(url_info)
            except (ValueError, IndexError):
                # Skip invalid lines
                continue
    
    return urls

def run_feroxbuster(targets: List[str], output_dir: str, wordlist: str = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt", threads: int = 50) -> Dict[str, Any]:
    """
    Run feroxbuster to enumerate directories and files from web applications.
    
    Args:
        targets: List of target URLs to scan
        output_dir: Directory to save results
        wordlist: Path to wordlist file (default: common.txt)
        threads: Number of threads to use (default: 50)
    
    Returns:
        Dictionary containing feroxbuster scan results
    """
    # Initialize cmd variable to avoid UnboundLocalError
    cmd = []
    
    try:
        logger.info(f"Starting feroxbuster directory enumeration for {len(targets)} targets")
        
        # Create output files
        targets_file = os.path.join(output_dir, "feroxbuster_targets.txt")
        results_file = os.path.join(output_dir, "feroxbuster_results.json")
        
        # Write targets to file
        with open(targets_file, 'w') as f:
            for target in targets:
                # Ensure targets have protocol
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                f.write(f"{target}\n")
        
        logger.info(f"Wrote {len(targets)} targets to {targets_file}")
        
        # Run feroxbuster with comprehensive options
        cmd = [
            "feroxbuster",
            "--urls", targets_file,
            "--wordlist", wordlist,
            "--threads", str(threads),
            "--timeout", "10",
            "--rate-limit", "100",
            "--recursion-depth", "3",
            "--extensions", "php,html,js,css,txt,json,xml,conf,config,env,bak,backup,old,tmp,temp,log,logs",
            "--status-codes", "200,204,301,302,307,308,401,403,405,500",
            "--output", results_file.replace('.json', '.txt'),
            "--json"
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 minutes timeout
        
        if result.returncode != 0:
            logger.error(f"Feroxbuster failed: {result.stderr}")
            return {
                "success": False,
                "error": f"Feroxbuster command failed: {result.stderr}",
                "targets_checked": len(targets),
                "urls_found": [],
                "command": cmd,
                "return_code": result.returncode,
                "summary": {
                    "total_targets": len(targets),
                    "total_urls": 0,
                    "unique_endpoints": 0,
                    "interesting_files": 0,
                    "file_types": []
                }
            }
        
        # Parse results from output file
        urls_found = []
        output_file = results_file.replace('.json', '.txt')
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            # Feroxbuster JSON output format
                            url_data = json.loads(line)
                            urls_found.append(url_data)
                        except json.JSONDecodeError:
                            # Handle non-JSON lines (headers, etc.)
                            continue
        
        # Also parse stdout for any additional results
        if result.stdout.strip():
            # Try JSON parsing first
            json_parsed = False
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        url_data = json.loads(line)
                        urls_found.append(url_data)
                        json_parsed = True
                    except json.JSONDecodeError:
                        continue
            
            # If JSON parsing failed, try parsing as plain text output
            if not json_parsed:
                parsed_urls = parse_feroxbuster_output(result.stdout)
                urls_found.extend(parsed_urls)
        
        # Categorize discovered URLs
        categorized_urls = categorize_feroxbuster_urls(urls_found)
        
        # Extract interesting files
        interesting_files = extract_interesting_files_feroxbuster(urls_found)
        
        # Create endpoint mapping
        endpoint_mapping = create_endpoint_mapping_feroxbuster(urls_found)
        
        # Prepare results
        results = {
            "success": True,
            "targets_checked": len(targets),
            "urls_found_count": len(urls_found),
            "urls": urls_found,  # Add 'urls' key for test compatibility
            "urls_found": urls_found,
            "categorized_urls": categorized_urls,
            "interesting_files": interesting_files,
            "endpoint_mapping": endpoint_mapping,
            "command": cmd,
            "return_code": result.returncode,
            "files": {
                "targets_file": targets_file,
                "results_file": results_file,
                "raw_output": output_file
            },
            "summary": {
                "total_targets": len(targets),
                "total_urls": len(urls_found),
                "unique_endpoints": len(endpoint_mapping),
                "interesting_files": len(interesting_files),
                "file_types": list(categorized_urls.get("files", {}).keys())
            }
        }
        
        # Save results to JSON
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Feroxbuster completed successfully")
        logger.info(f"  - Targets checked: {len(targets)}")
        logger.info(f"  - URLs found: {len(urls_found)}")
        logger.info(f"  - Unique endpoints: {len(endpoint_mapping)}")
        logger.info(f"  - Interesting files: {len(interesting_files)}")
        
        return results
        
    except subprocess.TimeoutExpired:
        logger.error("Feroxbuster command timed out")
        return {
            "success": False,
            "error": "timeout: Feroxbuster command timed out",
            "targets_checked": len(targets),
            "urls_found": [],
            "command": cmd,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_urls": 0,
                "unique_endpoints": 0,
                "interesting_files": 0,
                "file_types": [],
                "execution_time_seconds": 300
            }
        }
    except Exception as e:
        logger.error(f"Error in feroxbuster runner: {e}")
        error_msg = str(e)
        if isinstance(e, OSError) and ("No such file or directory" in error_msg or "cannot find the file" in error_msg.lower()):
            error_msg = f"Directory creation failed: {error_msg}"
        return {
            "success": False,
            "error": error_msg,
            "targets_checked": len(targets),
            "urls_found": [],
            "command": cmd,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_urls": 0,
                "unique_endpoints": 0,
                "interesting_files": 0,
                "file_types": []
            }
        }

def categorize_feroxbuster_urls(urls: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Categorize discovered URLs from feroxbuster by type and content.
    
    Args:
        urls: List of URL data from feroxbuster
    
    Returns:
        Dictionary with categorized URLs
    """
    categories = {
        "endpoints": [],
        "files": {},
        "directories": [],
        "admin_panels": [],
        "backup_files": [],
        "config_files": [],
        "log_files": [],
        "api_endpoints": []
    }
    
    interesting_extensions = {
        "php": ["php", "php3", "php4", "php5", "phtml"],
        "html": ["html", "htm", "shtml"],
        "js": ["js", "jsx", "ts", "tsx"],
        "css": ["css", "scss", "sass"],
        "config": ["conf", "config", "ini", "cfg", "env", "properties"],
        "backup": ["bak", "backup", "old", "tmp", "temp", "swp"],
        "logs": ["log", "logs", "txt"],
        "json": ["json", "xml", "yaml", "yml"],
        "images": ["jpg", "jpeg", "png", "gif", "svg", "ico", "bmp"],
        "archives": ["zip", "tar", "gz", "rar", "7z", "bz2"]
    }
    
    for url_data in urls:
        url = url_data.get("url", "")
        if not url:
            continue
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        extension = path.split('.')[-1].lower() if '.' in path else ""
        status_code = url_data.get("status_code", 0)
        
        # Skip 4xx and 5xx status codes for categorization
        if status_code >= 400:
            continue
        
        # Categorize by extension
        categorized = False
        for category, extensions in interesting_extensions.items():
            if extension in extensions:
                if category not in categories["files"]:
                    categories["files"][category] = []
                categories["files"][category].append(url_data)
                categorized = True
                break
        
        # Categorize by path patterns
        if not categorized:
            if path.endswith('/') or not '.' in path:
                categories["directories"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['api', 'rest', 'graphql', 'swagger']):
                categories["api_endpoints"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['admin', 'login', 'dashboard', 'panel', 'manage']):
                categories["admin_panels"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['backup', 'bak', 'old', 'tmp', 'temp']):
                categories["backup_files"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['config', 'conf', 'ini', 'env']):
                categories["config_files"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['log', 'logs', 'debug']):
                categories["log_files"].append(url_data)
            else:
                categories["endpoints"].append(url_data)
    
    return categories

def extract_interesting_files_feroxbuster(urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract interesting files from feroxbuster discovered URLs.
    
    Args:
        urls: List of URL data from feroxbuster
    
    Returns:
        List of interesting file data
    """
    interesting_files = []
    interesting_patterns = [
        'config', 'env', 'backup', 'bak', 'old', 'tmp', 'temp',
        'log', 'logs', 'debug', 'test', 'dev', 'staging',
        'admin', 'login', 'dashboard', 'panel', 'manage',
        'api', 'rest', 'graphql', 'swagger', 'openapi',
        'robots.txt', 'sitemap.xml', '.git', '.svn',
        'phpinfo', 'info.php', 'test.php', 'wp-config',
        'config.php', 'database.php', 'settings.php'
    ]
    
    for url_data in urls:
        url = url_data.get("url", "")
        if not url:
            continue
        
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        status_code = url_data.get("status_code", 0)
        
        # Skip 4xx and 5xx status codes
        if status_code >= 400:
            continue
        
        # Check if URL matches interesting patterns
        is_interesting = any(pattern in path for pattern in interesting_patterns)
        
        if is_interesting:
            file_info = {
                "url": url,
                "path": path,
                "hostname": parsed_url.hostname,
                "port": parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
                "scheme": parsed_url.scheme,
                "extension": path.split('.')[-1] if '.' in path else "",
                "status_code": status_code,
                "content_length": url_data.get("content_length"),
                "method": url_data.get("method", "GET")
            }
            interesting_files.append(file_info)
    
    return interesting_files

def create_endpoint_mapping_feroxbuster(urls: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Create endpoint mapping from feroxbuster results organized by subdomain.
    
    Args:
        urls: List of URL data from feroxbuster
    
    Returns:
        Dictionary mapping subdomains to their endpoints
    """
    endpoint_mapping = {}
    
    for url_data in urls:
        url = url_data.get("url", "")
        if not url:
            continue
        
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        path = parsed_url.path
        status_code = url_data.get("status_code", 0)
        
        # Skip 4xx and 5xx status codes for endpoint mapping
        if status_code >= 400:
            continue
        
        if hostname not in endpoint_mapping:
            endpoint_mapping[hostname] = []
        
        endpoint_info = {
            "url": url,
            "path": path,
            "method": url_data.get("method", "GET"),
            "status_code": status_code,
            "content_length": url_data.get("content_length"),
            "extension": path.split('.')[-1] if '.' in path else ""
        }
        
        endpoint_mapping[hostname].append(endpoint_info)
    
    return endpoint_mapping

def main():
    """Main function for testing the feroxbuster runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Feroxbuster Runner")
    parser.add_argument("--targets", required=True, help="Comma-separated list of targets")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--wordlist", help="Path to wordlist file")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    
    args = parser.parse_args()
    
    targets = [t.strip() for t in args.targets.split(",")]
    
    results = run_feroxbuster(targets, args.output_dir, args.wordlist, args.threads)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 