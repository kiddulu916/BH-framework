#!/usr/bin/env python3
"""
Katana Runner for Active Reconnaissance

This module uses katana to enumerate directories, files, and endpoints
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

def parse_katana_output(katana_output: str) -> List[str]:
    """
    Parse katana output and return list of URLs.
    
    Args:
        katana_output: Raw katana output
        
    Returns:
        List of unique URLs
    """
    urls = set()  # Use set for deduplication
    
    lines = katana_output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Parse katana output format: url
        if line.startswith('http://') or line.startswith('https://'):
            urls.add(line)
    
    return list(urls)  # Convert back to list

def run_katana(targets: List[str], output_dir: str, max_depth: int = 3, max_time: int = 300) -> Dict[str, Any]:
    """
    Run katana to enumerate directories and files from web applications.
    
    Args:
        targets: List of target URLs to crawl
        output_dir: Directory to save results
        max_depth: Maximum crawl depth (default: 3)
        max_time: Maximum crawl time in seconds (default: 300)
    
    Returns:
        Dictionary containing katana crawl results
    """
    # Initialize cmd variable at the start
    cmd = [
        "katana",
        "-list", "targets_file",  # Will be replaced
        "-jc",  # JavaScript crawling
        "-kf", "all",  # Keep all forms
        "-depth", str(max_depth),
        "-timeout", "10",
        "-delay", "1",
        "-concurrency", "10",
        "-rate-limit", "150",
        "-headless",  # Use headless browser
        "-silent",
        "-json"
    ]
    
    try:
        logger.info(f"Starting katana directory enumeration for {len(targets)} targets")
        
        # Create output files
        targets_file = os.path.join(output_dir, "katana_targets.txt")
        results_file = os.path.join(output_dir, "katana_results.json")
        
        # Write targets to file
        with open(targets_file, 'w') as f:
            for target in targets:
                # Ensure targets have protocol
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                f.write(f"{target}\n")
        
        logger.info(f"Wrote {len(targets)} targets to {targets_file}")
        
        # Update command with actual targets file
        cmd[2] = targets_file
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time)
        
        if result.returncode != 0:
            logger.error(f"Katana failed: {result.stderr}")
            return {
                "success": False,
                "error": f"Katana command failed: {result.stderr}",
                "targets_checked": len(targets),
                "urls": [],
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
        
        # Parse output - handle both JSON and plain text
        urls_found = []
        if result.stdout.strip():
            try:
                # Try to parse as JSON first
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        url_data = json.loads(line)
                        if isinstance(url_data, dict):
                            urls_found.append(url_data)
                        else:
                            # If it's a string, treat as URL
                            urls_found.append({"url": url_data})
            except json.JSONDecodeError:
                # If JSON parsing fails, treat as plain text URLs
                urls_found = [{"url": url.strip()} for url in result.stdout.strip().split('\n') if url.strip()]
        
        # Categorize discovered URLs
        categorized_urls = categorize_urls(urls_found)
        
        # Extract interesting files
        interesting_files = extract_interesting_files(urls_found)
        
        # Create endpoint mapping
        endpoint_mapping = create_endpoint_mapping(urls_found)
        
        # Prepare results
        results = {
            "success": True,
            "targets_checked": len(targets),
            "urls_found_count": len(urls_found),
            "urls": urls_found,  # Changed from urls_found to urls
            "urls_found": urls_found,  # Add for test compatibility
            "categorized_urls": categorized_urls,
            "interesting_files": interesting_files,
            "endpoint_mapping": endpoint_mapping,
            "files": {
                "targets_file": targets_file,
                "results_file": results_file
            },
            "command": cmd,
            "return_code": result.returncode,
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
        
        logger.info(f"Katana completed successfully")
        logger.info(f"  - Targets checked: {len(targets)}")
        logger.info(f"  - URLs found: {len(urls_found)}")
        logger.info(f"  - Unique endpoints: {len(endpoint_mapping)}")
        logger.info(f"  - Interesting files: {len(interesting_files)}")
        
        return results
        
    except subprocess.TimeoutExpired:
        logger.error("Katana command timed out")
        return {
            "success": False,
            "error": "timeout: Katana command timed out",
            "targets_checked": len(targets),
            "urls": [],
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
        logger.error(f"Error in katana runner: {e}")
        error_msg = str(e)
        if isinstance(e, OSError) and ("No such file or directory" in error_msg or "cannot find the file" in error_msg.lower()):
            error_msg = f"Directory creation failed: {error_msg}"
        return {
            "success": False,
            "error": error_msg,
            "targets_checked": len(targets),
            "urls": [],
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

def categorize_urls(urls: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Categorize discovered URLs by type and content.
    
    Args:
        urls: List of URL data from katana
    
    Returns:
        Dictionary with categorized URLs
    """
    categories = {
        "endpoints": [],
        "files": {},
        "directories": [],
        "forms": [],
        "javascript": [],
        "api_endpoints": [],
        "admin_panels": [],
        "backup_files": []
    }
    
    interesting_extensions = {
        "js": ["js", "jsx", "ts", "tsx"],
        "json": ["json", "xml", "yaml", "yml"],
        "config": ["conf", "config", "ini", "cfg", "env"],
        "backup": ["bak", "backup", "old", "tmp", "temp"],
        "logs": ["log", "logs"],
        "docs": ["pdf", "doc", "docx", "txt", "md"],
        "images": ["jpg", "jpeg", "png", "gif", "svg", "ico"],
        "archives": ["zip", "tar", "gz", "rar", "7z"]
    }
    
    for url_data in urls:
        url = url_data.get("url", "")
        if not url:
            continue
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        extension = path.split('.')[-1].lower() if '.' in path else ""
        
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
            elif any(keyword in path.lower() for keyword in ['api', 'rest', 'graphql']):
                categories["api_endpoints"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['admin', 'login', 'dashboard']):
                categories["admin_panels"].append(url_data)
            elif any(keyword in path.lower() for keyword in ['backup', 'bak', 'old']):
                categories["backup_files"].append(url_data)
            elif extension == "js":
                categories["javascript"].append(url_data)
            else:
                categories["endpoints"].append(url_data)
        
        # Check for forms
        if url_data.get("forms"):
            categories["forms"].append(url_data)
    
    return categories

def extract_interesting_files(urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract interesting files from discovered URLs.
    
    Args:
        urls: List of URL data from katana
    
    Returns:
        List of interesting file data
    """
    interesting_files = []
    interesting_patterns = [
        'config', 'env', 'backup', 'bak', 'old', 'tmp', 'temp',
        'log', 'logs', 'debug', 'test', 'dev', 'staging',
        'admin', 'login', 'dashboard', 'panel',
        'api', 'rest', 'graphql', 'swagger', 'openapi',
        'robots.txt', 'sitemap.xml', '.git', '.svn',
        'phpinfo', 'info.php', 'test.php'
    ]
    
    for url_data in urls:
        url = url_data.get("url", "")
        if not url:
            continue
        
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
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
                "status_code": url_data.get("status_code"),
                "content_length": url_data.get("content_length"),
                "content_type": url_data.get("content_type"),
                "forms": url_data.get("forms", []),
                "technologies": url_data.get("technologies", [])
            }
            interesting_files.append(file_info)
    
    return interesting_files

def create_endpoint_mapping(urls: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Create endpoint mapping organized by subdomain.
    
    Args:
        urls: List of URL data from katana
    
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
        
        if hostname not in endpoint_mapping:
            endpoint_mapping[hostname] = []
        
        endpoint_info = {
            "url": url,
            "path": path,
            "method": url_data.get("method", "GET"),
            "status_code": url_data.get("status_code"),
            "content_type": url_data.get("content_type"),
            "content_length": url_data.get("content_length"),
            "forms": url_data.get("forms", []),
            "technologies": url_data.get("technologies", [])
        }
        
        endpoint_mapping[hostname].append(endpoint_info)
    
    return endpoint_mapping

def main():
    """Main function for testing the katana runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Katana Runner")
    parser.add_argument("--targets", required=True, help="Comma-separated list of targets")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--max-time", type=int, default=300, help="Maximum crawl time in seconds")
    
    args = parser.parse_args()
    
    targets = [t.strip() for t in args.targets.split(",")]
    
    results = run_katana(targets, args.output_dir, args.max_depth, args.max_time)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 