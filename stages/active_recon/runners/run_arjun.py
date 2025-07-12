#!/usr/bin/env python3
"""
Arjun Runner for Active Reconnaissance

This module uses Arjun to discover API parameters and endpoints
from web applications during active reconnaissance.
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

def run_arjun(targets: List[str], output_dir: str, max_time: int = 900) -> Dict[str, Any]:
    """
    Run Arjun to discover API parameters and endpoints.
    
    Args:
        targets: List of target URLs to scan
        output_dir: Directory to save results
        max_time: Maximum scan time in seconds (default: 900)
    
    Returns:
        Dictionary containing Arjun scan results
    """
    try:
        logger.info(f"Starting Arjun parameter discovery for {len(targets)} targets")
        
        # Create output files
        targets_file = os.path.join(output_dir, "arjun_targets.txt")
        results_file = os.path.join(output_dir, "arjun_results.json")
        
        # Create directories
        os.makedirs(output_dir, exist_ok=True)
        
        # Write targets to file
        with open(targets_file, 'w') as f:
            for target in targets:
                # Ensure targets have protocol
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                f.write(f"{target}\n")
        
        logger.info(f"Wrote {len(targets)} targets to {targets_file}")
        
        # Run Arjun with comprehensive options
        cmd = [
            "arjun",
            "-i", targets_file,
            "-oJ", results_file,
            "-t", "50",  # Threads
            "-T", "10",  # Timeout per request
            "-m", "GET,POST",  # Methods
            "-w", "/usr/share/wordlists/seclists/Discovery/Web-Content/api/api_seen_in_wild.txt",  # Wordlist
            "-v"  # Verbose output
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time)
        
        if result.returncode != 0:
            logger.error(f"Arjun failed: {result.stderr}")
            return {
                "success": False,
                "error": f"Arjun command failed: {result.stderr}",
                "targets_checked": len(targets),
                "endpoints_found": [],
                "command": cmd,
                "return_code": result.returncode
            }
        
        # Parse Arjun results
        endpoints_found = []
        if os.path.exists(results_file):
            try:
                with open(results_file, 'r') as f:
                    arjun_data = json.load(f)
                
                # Process Arjun results
                for endpoint_data in arjun_data:
                    processed_endpoint = process_arjun_endpoint(endpoint_data)
                    if processed_endpoint:
                        endpoints_found.append(processed_endpoint)
                        
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Arjun JSON output: {e}")
                return {
                    "success": False,
                    "error": f"Failed to parse Arjun output: {e}",
                    "targets_checked": len(targets),
                    "endpoints_found": [],
                    "command": cmd,
                    "return_code": result.returncode
                }
        
        # Categorize discovered endpoints
        categorized_endpoints = categorize_arjun_endpoints(endpoints_found)
        
        # Extract interesting parameters
        interesting_parameters = extract_interesting_parameters(endpoints_found)
        
        # Create parameter mapping
        parameter_mapping = create_parameter_mapping(endpoints_found)
        
        # Prepare results
        results = {
            "success": True,
            "targets_checked": len(targets),
            "endpoints_found_count": len(endpoints_found),
            "endpoints_found": endpoints_found,
            "categorized_endpoints": categorized_endpoints,
            "interesting_parameters": interesting_parameters,
            "parameter_mapping": parameter_mapping,
            "files": {
                "targets_file": targets_file,
                "results_file": results_file
            },
            "summary": {
                "total_targets": len(targets),
                "total_endpoints": len(endpoints_found),
                "unique_parameters": len(set([param for ep in endpoints_found for param in ep.get("parameters", [])])),
                "endpoint_categories": list(categorized_endpoints.keys()),
                "interesting_parameters_count": len(interesting_parameters)
            },
            "command": cmd,
            "return_code": result.returncode
        }
        
        # Save processed results to JSON
        processed_results_file = os.path.join(output_dir, "arjun_processed_results.json")
        with open(processed_results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Arjun completed successfully")
        logger.info(f"  - Targets checked: {len(targets)}")
        logger.info(f"  - Endpoints found: {len(endpoints_found)}")
        logger.info(f"  - Unique parameters: {len(set([param for ep in endpoints_found for param in ep.get('parameters', [])]))}")
        logger.info(f"  - Interesting parameters: {len(interesting_parameters)}")
        
        return results
        
    except subprocess.TimeoutExpired:
        logger.error("Arjun command timed out")
        return {
            "success": False,
            "error": "Arjun command timed out",
            "targets_checked": len(targets),
            "endpoints_found": [],
            "command": None,
            "return_code": None
        }
    except Exception as e:
        logger.error(f"Error in Arjun runner: {e}")
        return {
            "success": False,
            "error": str(e),
            "targets_checked": len(targets),
            "endpoints_found": [],
            "command": None,
            "return_code": None
        }

def process_arjun_endpoint(endpoint_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process individual Arjun endpoint data.
    
    Args:
        endpoint_data: Raw endpoint data from Arjun
    
    Returns:
        Processed endpoint information
    """
    try:
        url = endpoint_data.get("url", "")
        if not url:
            return None
        
        parsed_url = urlparse(url)
        
        processed_endpoint = {
            "url": url,
            "hostname": parsed_url.hostname,
            "port": parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
            "scheme": parsed_url.scheme,
            "path": parsed_url.path,
            "method": endpoint_data.get("method", "GET"),
            "parameters": endpoint_data.get("params", []),
            "parameters_count": len(endpoint_data.get("params", [])),
            "status_code": endpoint_data.get("status_code"),
            "content_length": endpoint_data.get("content_length"),
            "content_type": endpoint_data.get("content_type"),
            "response_time": endpoint_data.get("response_time"),
            "raw_data": endpoint_data
        }
        
        return processed_endpoint
        
    except Exception as e:
        logger.warning(f"Failed to process Arjun endpoint: {e}")
        return None

def categorize_arjun_endpoints(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Categorize Arjun endpoints by type and parameters.
    
    Args:
        endpoints: List of endpoint data
    
    Returns:
        Dictionary with categorized endpoints
    """
    categories = {
        "api_endpoints": [],
        "rest_endpoints": [],
        "graphql_endpoints": [],
        "authentication_endpoints": [],
        "file_operations": [],
        "search_endpoints": [],
        "admin_endpoints": [],
        "data_endpoints": [],
        "utility_endpoints": []
    }
    
    for endpoint_data in endpoints:
        url = endpoint_data.get("url", "")
        path = endpoint_data.get("path", "").lower()
        parameters = endpoint_data.get("parameters", [])
        
        # Categorize by path patterns
        if any(keyword in path for keyword in ['/api/', '/rest/', '/v1/', '/v2/', '/v3/']):
            if '/api/' in path:
                categories["api_endpoints"].append(endpoint_data)
            elif '/rest/' in path:
                categories["rest_endpoints"].append(endpoint_data)
        elif '/graphql' in path:
            categories["graphql_endpoints"].append(endpoint_data)
        elif any(keyword in path for keyword in ['/auth/', '/login/', '/logout/', '/register/']):
            categories["authentication_endpoints"].append(endpoint_data)
        elif any(keyword in path for keyword in ['/upload/', '/download/', '/file/', '/files/']):
            categories["file_operations"].append(endpoint_data)
        elif any(keyword in path for keyword in ['/search/', '/query/', '/find/']):
            categories["search_endpoints"].append(endpoint_data)
        elif any(keyword in path for keyword in ['/admin/', '/manage/', '/panel/']):
            categories["admin_endpoints"].append(endpoint_data)
        elif any(keyword in path for keyword in ['/data/', '/json/', '/xml/']):
            categories["data_endpoints"].append(endpoint_data)
        else:
            categories["utility_endpoints"].append(endpoint_data)
    
    return categories

def extract_interesting_parameters(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extract interesting parameters from discovered endpoints.
    
    Args:
        endpoints: List of endpoint data
    
    Returns:
        List of interesting parameter information
    """
    interesting_parameters = []
    interesting_patterns = [
        'id', 'user', 'admin', 'password', 'token', 'key', 'secret',
        'file', 'upload', 'download', 'path', 'dir', 'directory',
        'search', 'query', 'filter', 'sort', 'order', 'limit',
        'email', 'username', 'login', 'auth', 'session',
        'config', 'setting', 'option', 'preference',
        'debug', 'test', 'dev', 'staging', 'prod',
        'sql', 'query', 'database', 'db', 'table',
        'redirect', 'url', 'link', 'href',
        'callback', 'jsonp', 'script'
    ]
    
    for endpoint_data in endpoints:
        url = endpoint_data.get("url", "")
        parameters = endpoint_data.get("parameters", [])
        
        for param in parameters:
            param_lower = param.lower()
            
            # Check if parameter matches interesting patterns
            is_interesting = any(pattern in param_lower for pattern in interesting_patterns)
            
            if is_interesting:
                param_info = {
                    "parameter": param,
                    "endpoint_url": url,
                    "method": endpoint_data.get("method", "GET"),
                    "hostname": endpoint_data.get("hostname"),
                    "path": endpoint_data.get("path"),
                    "status_code": endpoint_data.get("status_code"),
                    "interesting_reason": [pattern for pattern in interesting_patterns if pattern in param_lower]
                }
                interesting_parameters.append(param_info)
    
    return interesting_parameters

def create_parameter_mapping(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Create parameter mapping organized by hostname.
    
    Args:
        endpoints: List of endpoint data
    
    Returns:
        Dictionary mapping hostnames to their parameters
    """
    parameter_mapping = {}
    
    for endpoint_data in endpoints:
        hostname = endpoint_data.get("hostname", "")
        parameters = endpoint_data.get("parameters", [])
        
        if hostname not in parameter_mapping:
            parameter_mapping[hostname] = []
        
        for param in parameters:
            param_info = {
                "parameter": param,
                "endpoint_url": endpoint_data.get("url"),
                "method": endpoint_data.get("method", "GET"),
                "path": endpoint_data.get("path"),
                "status_code": endpoint_data.get("status_code")
            }
            parameter_mapping[hostname].append(param_info)
    
    return parameter_mapping

def main():
    """Main function for testing the Arjun runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Arjun Runner")
    parser.add_argument("--targets", required=True, help="Comma-separated list of targets")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--max-time", type=int, default=900, help="Maximum scan time in seconds")
    
    args = parser.parse_args()
    
    targets = [t.strip() for t in args.targets.split(",")]
    
    results = run_arjun(targets, args.output_dir, args.max_time)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 