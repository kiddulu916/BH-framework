#!/usr/bin/env python3
"""
GetJS Runner for Active Reconnaissance

This module uses getJS to extract JavaScript files and discover endpoints
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

def parse_getjs_output(getjs_output: str) -> List[str]:
    """
    Parse getJS output and return structured results.
    
    Args:
        getjs_output: Raw getJS output
        
    Returns:
        List of unique JavaScript file URLs
    """
    js_files = set()
    
    lines = getjs_output.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Parse getJS output format: url
        if (line.startswith('http://') or line.startswith('https://')) and (line.endswith('.js') or line.endswith('.jsx')):
            js_files.add(line)
    
    return list(js_files)

def run_getjs(targets: List[str], output_dir: str, max_time: int = 600) -> Dict[str, Any]:
    """
    Run getJS to extract JavaScript files and discover endpoints.
    
    Args:
        targets: List of target URLs to scan
        output_dir: Directory to save results
        max_time: Maximum scan time in seconds (default: 600)
    
    Returns:
        Dictionary containing getJS scan results
    """
    # Initialize cmd variable to avoid UnboundLocalError
    cmd = []
    
    try:
        logger.info(f"Starting getJS JavaScript analysis for {len(targets)} targets")
        
        # Create output files
        targets_file = os.path.join(output_dir, "getjs_targets.txt")
        results_file = os.path.join(output_dir, "getjs_results.json")
        js_files_dir = os.path.join(output_dir, "javascript_files")
        
        # Create directories
        os.makedirs(js_files_dir, exist_ok=True)
        
        # Write targets to file
        with open(targets_file, 'w') as f:
            for target in targets:
                # Ensure targets have protocol
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                f.write(f"{target}\n")
        
        logger.info(f"Wrote {len(targets)} targets to {targets_file}")
        
        # Run getJS with comprehensive options
        cmd = [
            "getJS",
            "--input", targets_file,
            "--output", js_files_dir,
            "--threads", "50",  # Threads
            "--timeout", "10",  # Timeout per request
            "--verbose"  # Verbose output
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time)
        
        if result.returncode != 0:
            logger.error(f"GetJS failed: {result.stderr}")
            return {
                "success": False,
                "error": f"GetJS command failed: {result.stderr}",
                "targets_checked": len(targets),
                "js_files_found": [],
                "js_files": [],
                "command": cmd,
                "return_code": result.returncode,
                "summary": {
                    "total_targets": len(targets),
                    "total_js_files": 0,
                    "total_endpoints": 0,
                    "unique_endpoints": 0,
                    "endpoint_categories": []
                }
            }
        
        # Collect discovered JavaScript files
        js_files_found = []
        js_endpoints = []
        js_file_urls = set()
        
        # Scan the output directory for JavaScript files
        for root, dirs, files in os.walk(js_files_dir):
            for file in files:
                if file.endswith('.js') or file.endswith('.jsx'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Extract endpoints from JavaScript content
                        endpoints = extract_endpoints_from_js(content, file)
                        
                        js_file_info = {
                            "filename": file,
                            "file_path": file_path,
                            "size": len(content),
                            "endpoints_found": len(endpoints),
                            "endpoints": endpoints,
                            "source_url": extract_source_url(file_path, targets)
                        }
                        
                        js_files_found.append(js_file_info)
                        js_endpoints.extend(endpoints)
                        # Add to deduplication set
                        js_file_urls.add(js_file_info["file_path"])
                        
                    except Exception as e:
                        logger.warning(f"Failed to process {file}: {e}")
                        continue
        
        # Also parse result.stdout for JS file URLs (for test mocks)
        stdout_js_urls = parse_getjs_output(result.stdout)
        for url in stdout_js_urls:
            if url not in js_file_urls:
                js_file_info = {
                    "filename": url.split('/')[-1] if '/' in url else url,
                    "file_path": url,
                    "size": 0,
                    "endpoints_found": 0,
                    "endpoints": [],
                    "source_url": url
                }
                js_files_found.append(js_file_info)
                js_file_urls.add(url)
        
        # Categorize endpoints
        categorized_endpoints = categorize_js_endpoints(js_endpoints)
        
        # Prepare results
        results = {
            "success": True,
            "targets_checked": len(targets),
            "js_files_found_count": len(js_files_found),
            "js_files_found": js_files_found,
            "js_files": [js["file_path"] for js in js_files_found],
            "total_endpoints_found": len(js_endpoints),
            "js_endpoints": js_endpoints,
            "categorized_endpoints": categorized_endpoints,
            "command": cmd,
            "return_code": result.returncode,
            "files": {
                "targets_file": targets_file,
                "results_file": results_file,
                "js_files_directory": js_files_dir
            },
            "summary": {
                "total_targets": len(targets),
                "total_js_files": len(js_files_found),
                "total_endpoints": len(js_endpoints),
                "unique_endpoints": len(set(js_endpoints)),
                "endpoint_categories": list(categorized_endpoints.keys())
            }
        }
        
        # Save results to JSON
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"GetJS completed successfully")
        logger.info(f"  - Targets checked: {len(targets)}")
        logger.info(f"  - JS files found: {len(js_files_found)}")
        logger.info(f"  - Endpoints found: {len(js_endpoints)}")
        logger.info(f"  - Unique endpoints: {len(set(js_endpoints))}")
        
        return results
        
    except subprocess.TimeoutExpired:
        logger.error("GetJS command timed out")
        return {
            "success": False,
            "error": "timeout: GetJS command timed out",
            "targets_checked": len(targets),
            "js_files_found": [],
            "command": cmd,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_js_files": 0,
                "total_endpoints": 0,
                "unique_endpoints": 0,
                "endpoint_categories": [],
                "execution_time_seconds": 300
            }
        }
    except Exception as e:
        logger.error(f"Error in getJS runner: {e}")
        error_msg = str(e)
        if isinstance(e, OSError) and ("No such file or directory" in error_msg or "cannot find the file" in error_msg.lower()):
            error_msg = f"Directory creation failed: {error_msg}"
        return {
            "success": False,
            "error": error_msg,
            "targets_checked": len(targets),
            "js_files_found": [],
            "command": cmd,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_js_files": 0,
                "total_endpoints": 0,
                "unique_endpoints": 0,
                "endpoint_categories": []
            }
        }

def extract_endpoints_from_js(content: str, filename: str) -> List[Dict[str, Any]]:
    """
    Extract endpoints from JavaScript content using regex patterns.
    
    Args:
        content: JavaScript file content
        filename: Name of the JavaScript file
    
    Returns:
        List of discovered endpoints
    """
    import re
    
    endpoints = []
    
    # Common patterns for API endpoints
    patterns = [
        # Fetch API calls
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*`([^`]+)`',
        
        # AJAX calls
        r'\.ajax\s*\(\s*{\s*url\s*:\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        
        # URL patterns
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\'](/graphql[^"\']*)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        
        # Variable assignments
        r'const\s+\w+\s*=\s*["\']([^"\']+)["\']',
        r'let\s+\w+\s*=\s*["\']([^"\']+)["\']',
        r'var\s+\w+\s*=\s*["\']([^"\']+)["\']',
        
        # Object properties
        r'url\s*:\s*["\']([^"\']+)["\']',
        r'endpoint\s*:\s*["\']([^"\']+)["\']',
        r'path\s*:\s*["\']([^"\']+)["\']',
        
        # Template literals
        r'`([^`]+)`',
        
        # Base URL patterns
        r'baseURL\s*:\s*["\']([^"\']+)["\']',
        r'base_url\s*:\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if match and len(match) > 3:  # Filter out very short matches
                endpoint_info = {
                    "endpoint": match,
                    "pattern": pattern,
                    "filename": filename,
                    "line_number": find_line_number(content, match),
                    "context": extract_context(content, match)
                }
                endpoints.append(endpoint_info)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_endpoints = []
    for endpoint in endpoints:
        endpoint_key = endpoint["endpoint"]
        if endpoint_key not in seen:
            seen.add(endpoint_key)
            unique_endpoints.append(endpoint)
    
    return unique_endpoints

def find_line_number(content: str, search_text: str) -> Optional[int]:
    """
    Find the line number where a text appears in content.
    
    Args:
        content: File content
        search_text: Text to search for
    
    Returns:
        Line number or None if not found
    """
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        if search_text in line:
            return i
    return None

def extract_context(content: str, search_text: str, context_lines: int = 2) -> str:
    """
    Extract context around a search text.
    
    Args:
        content: File content
        search_text: Text to search for
        context_lines: Number of lines before and after
    
    Returns:
        Context string
    """
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if search_text in line:
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            context_lines_list = lines[start:end]
            return '\n'.join(context_lines_list)
    return ""

def extract_source_url(file_path: str, targets: List[str]) -> Optional[str]:
    """
    Try to extract the source URL from the file path.
    
    Args:
        file_path: Path to the JavaScript file
        targets: List of original targets
    
    Returns:
        Source URL or None
    """
    filename = os.path.basename(file_path)
    
    # Try to match filename with target patterns
    for target in targets:
        if target.replace('http://', '').replace('https://', '').replace('.', '_') in filename:
            return target
    
    return None

def categorize_js_endpoints(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Categorize JavaScript endpoints by type.
    
    Args:
        endpoints: List of endpoint data
    
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
        "file_operations": []
    }
    
    for endpoint_data in endpoints:
        endpoint = endpoint_data.get("endpoint", "")
        if not endpoint:
            continue
        
        # Categorize by endpoint type
        if any(keyword in endpoint.lower() for keyword in ['/api/', '/rest/', '/v1/', '/v2/', '/v3/']):
            if '/api/' in endpoint.lower():
                categories["api_endpoints"].append(endpoint_data)
            elif '/rest/' in endpoint.lower():
                categories["rest_endpoints"].append(endpoint_data)
        elif '/graphql' in endpoint.lower():
            categories["graphql_endpoints"].append(endpoint_data)
        elif any(keyword in endpoint.lower() for keyword in ['/auth/', '/login/', '/logout/', '/register/']):
            categories["authentication_endpoints"].append(endpoint_data)
        elif any(keyword in endpoint.lower() for keyword in ['.js', '.css', '.png', '.jpg', '.gif', '.svg']):
            categories["static_files"].append(endpoint_data)
        elif any(keyword in endpoint.lower() for keyword in ['/upload/', '/download/', '/file/', '/files/']):
            categories["file_operations"].append(endpoint_data)
        elif endpoint.startswith('http'):
            categories["external_endpoints"].append(endpoint_data)
        else:
            categories["internal_endpoints"].append(endpoint_data)
    
    return categories

def main():
    """Main function for testing the getJS runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="GetJS Runner")
    parser.add_argument("--targets", required=True, help="Comma-separated list of targets")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--max-time", type=int, default=600, help="Maximum scan time in seconds")
    
    args = parser.parse_args()
    
    targets = [t.strip() for t in args.targets.split(",")]
    
    results = run_getjs(targets, args.output_dir, args.max_time)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 