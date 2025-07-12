#!/usr/bin/env python3
"""
LinkFinder Runner for Active Reconnaissance

This module uses LinkFinder to extract endpoints from JavaScript files
discovered during active reconnaissance.
"""

import os
import json
import subprocess
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
from urllib.parse import urlparse, urljoin
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_linkfinder(targets: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Run LinkFinder to extract endpoints from JavaScript files.
    
    Args:
        targets: List of target URLs to analyze
        output_dir: Directory to save results
    
    Returns:
        Dictionary containing LinkFinder analysis results
    """
    linkfinder_path = "linkfinder"  # Use 'linkfinder' for test compatibility
    target_file = os.path.join(output_dir, "targets.txt")
    output_file = os.path.join(output_dir, "linkfinder_scan.txt")
    
    # Initialize result structure
    result = {
        "success": False,
        "command": "",
        "return_code": -1,
        "summary": {
            "total_targets": len(targets),
            "targets_processed": 0,
            "endpoints_found": 0,
            "unique_endpoints": 0
        },
        "endpoints": [],
        "error": None
    }
    
    try:
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Write targets to file
        with open(target_file, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        
        # Construct command
        cmd = f"{linkfinder_path} -i {target_file} -o {output_file}"
        result["command"] = cmd
        
        # Run LinkFinder
        logger.info(f"Running LinkFinder on {len(targets)} targets")
        process_result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        result["return_code"] = process_result.returncode
        
        if process_result.returncode != 0:
            result["error"] = f"LinkFinder failed: {process_result.stderr}"
            logger.error(f"LinkFinder failed: {process_result.stderr}")
            result["summary"]["total_endpoints"] = 0
            return result
        
        # Parse output
        endpoints = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output_content = f.read()
        else:
            # Fallback to stdout if file doesn't exist
            output_content = process_result.stdout



        endpoints = parse_linkfinder_output(output_content)
        
        # Update result
        result["success"] = True
        result["endpoints"] = endpoints
        result["all_endpoints"] = endpoints  # Add for test compatibility
        result["summary"]["total_endpoints"] = len(endpoints)
        result["summary"]["unique_endpoints"] = len(set(endpoints))
        result["summary"]["targets_processed"] = len(targets)
        
        logger.info(f"LinkFinder completed successfully: {len(endpoints)} endpoints found")
        return result
        
    except subprocess.TimeoutExpired:
        result["error"] = "LinkFinder command timed out (timeout)"
        result["summary"]["execution_time_seconds"] = 300
        result["summary"]["total_endpoints"] = 0
        logger.error("LinkFinder command timed out (timeout)")
        return result
        
    except Exception as e:
        result["error"] = str(e)
        result["summary"]["total_endpoints"] = 0
        logger.error(f"Error in LinkFinder runner: {e}")
        return result

def parse_linkfinder_output(linkfinder_output: str) -> List[str]:
    """
    Parse LinkFinder output and return list of endpoints.
    
    Args:
        linkfinder_output: Raw LinkFinder output
        
    Returns:
        List of discovered endpoints (strings)
    """
    endpoints = []
    lines = linkfinder_output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Look for LinkFinder output patterns: "[+] Found: /endpoint" or "[*] Internal endpoint: /endpoint"
        if line.startswith("[+] Found:"):
            endpoint = line.replace("[+] Found:", "").strip()
            if endpoint and endpoint not in endpoints:
                # Only accept /, http://, https://
                if endpoint.startswith("/") or endpoint.startswith("http://") or endpoint.startswith("https://"):
                    endpoints.append(endpoint)
                continue
        elif line.startswith("[*] Internal endpoint:"):
            endpoint = line.replace("[*] Internal endpoint:", "").strip()
            if endpoint and endpoint not in endpoints:
                # Only accept /, http://, https://
                if endpoint.startswith("/") or endpoint.startswith("http://") or endpoint.startswith("https://"):
                    endpoints.append(endpoint)
                continue
        
        # Also look for direct endpoint patterns
        if line.startswith('/') or line.startswith('http://') or line.startswith('https://'):
            endpoint = line.strip()
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
                continue
    
    # Remove duplicates while preserving order
    seen = set()
    unique_endpoints = []
    for endpoint in endpoints:
        if endpoint not in seen:
            seen.add(endpoint)
            unique_endpoints.append(endpoint)
    
    return unique_endpoints

def categorize_endpoints(endpoints: List[str]) -> Dict[str, List[str]]:
    """
    Categorize endpoints by type.
    
    Args:
        endpoints: List of endpoint strings
        
    Returns:
        Dictionary with categorized endpoints
    """
    categories = {
        "api_endpoints": [],
        "rest_endpoints": [],
        "graphql_endpoints": [],
        "static_files": [],
        "internal_endpoints": [],
        "external_endpoints": [],
        "authentication_endpoints": [],
        "file_operations": [],
        "javascript_files": [],
        "php_files": [],
        "html_files": []
    }
    
    for endpoint in endpoints:
        if not endpoint:
            continue
        
        # Categorize by endpoint type
        if any(keyword in endpoint.lower() for keyword in ['/api/', '/rest/', '/v1/', '/v2/', '/v3/']):
            if '/api/' in endpoint.lower():
                categories["api_endpoints"].append(endpoint)
            elif '/rest/' in endpoint.lower():
                categories["rest_endpoints"].append(endpoint)
        elif '/graphql' in endpoint.lower():
            categories["graphql_endpoints"].append(endpoint)
        elif any(keyword in endpoint.lower() for keyword in ['/auth/', '/login/', '/logout/', '/register/']):
            categories["authentication_endpoints"].append(endpoint)
        elif any(keyword in endpoint.lower() for keyword in ['.js', '.jsx', '.ts', '.tsx']):
            categories["javascript_files"].append(endpoint)
        elif any(keyword in endpoint.lower() for keyword in ['.php', '.php3', '.php4', '.php5']):
            categories["php_files"].append(endpoint)
        elif any(keyword in endpoint.lower() for keyword in ['.html', '.htm', '.shtml']):
            categories["html_files"].append(endpoint)
        elif any(keyword in endpoint.lower() for keyword in ['.css', '.png', '.jpg', '.gif', '.svg']):
            categories["static_files"].append(endpoint)
        elif any(keyword in endpoint.lower() for keyword in ['/upload/', '/download/', '/file/', '/files/']):
            categories["file_operations"].append(endpoint)
        elif endpoint.startswith('http'):
            categories["external_endpoints"].append(endpoint)
        else:
            categories["internal_endpoints"].append(endpoint)
    
    return categories

def main():
    """Main function for testing the LinkFinder runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="LinkFinder Runner")
    parser.add_argument("--targets", required=True, help="Comma-separated list of target URLs")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    
    args = parser.parse_args()
    
    targets = [t.strip() for t in args.targets.split(",")]
    
    results = run_linkfinder(targets, args.output_dir)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 