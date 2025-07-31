#!/usr/bin/env python3
"""
Dynamic Analysis Runner

This module provides dynamic analysis capabilities using headless browser crawling
to discover content that requires JavaScript execution.

Features:
- Headless browser crawling with Playwright
- JavaScript execution and dynamic content discovery
- Single Page Application (SPA) route discovery
- Client-side endpoint extraction
- Dynamic form and input discovery
"""

import os
import json
import subprocess
import requests
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_playwright_crawling(target: str, max_pages: int = 50) -> Dict[str, Any]:
    """
    Run headless browser crawling with Playwright.
    
    Args:
        target: Target domain
        max_pages: Maximum number of pages to crawl
        
    Returns:
        Dictionary containing Playwright crawling results
    """
    try:
        print(f"[INFO] Starting Playwright crawling for {target}")
        
        # Check if playwright is available
        try:
            subprocess.run(["playwright", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "success": False,
                "error": "Playwright not available",
                "pages_crawled": 0,
                "urls_found": []
            }
        
        # Create a Python script for Playwright crawling
        playwright_script = f"""
import asyncio
from playwright.async_api import async_playwright
import json
import sys

async def crawl_site(target):
    urls_found = set()
    pages_crawled = 0
    max_pages = {max_pages}
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        # Set user agent
        await page.set_extra_http_headers({{
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }})
        
        # Navigate to target
        try:
            await page.goto(f'https://{{target}}', wait_until='networkidle', timeout=30000)
            urls_found.add(f'https://{{target}}')
            pages_crawled += 1
            
            # Extract all links
            links = await page.eval_on_selector_all('a[href]', 'elements => elements.map(el => el.href)')
            for link in links:
                if target in link and link not in urls_found:
                    urls_found.add(link)
            
            # Extract JavaScript endpoints
            js_endpoints = await page.evaluate('''
                () => {{
                    const endpoints = new Set();
                    const scripts = document.querySelectorAll('script');
                    scripts.forEach(script => {{
                        if (script.src) {{
                            endpoints.add(script.src);
                        }}
                    }});
                    return Array.from(endpoints);
                }}
            ''')
            
            for endpoint in js_endpoints:
                if target in endpoint:
                    urls_found.add(endpoint)
            
            # Extract API endpoints from network requests
            api_endpoints = await page.evaluate('''
                () => {{
                    const endpoints = new Set();
                    const apiPatterns = ['/api/', '/rest/', '/v1/', '/v2/', '/v3/'];
                    const links = document.querySelectorAll('a[href]');
                    links.forEach(link => {{
                        const href = link.href;
                        if (apiPatterns.some(pattern => href.includes(pattern))) {{
                            endpoints.add(href);
                        }}
                    }});
                    return Array.from(endpoints);
                }}
            ''')
            
            for endpoint in api_endpoints:
                if target in endpoint:
                    urls_found.add(endpoint)
            
        except Exception as e:
            print(f"Error crawling {{target}}: {{e}}")
        
        await browser.close()
        return {{
            'urls_found': list(urls_found),
            'pages_crawled': pages_crawled,
            'js_endpoints': js_endpoints,
            'api_endpoints': api_endpoints
        }}

if __name__ == "__main__":
    target = sys.argv[1]
    result = asyncio.run(crawl_site(target))
    print(json.dumps(result))
"""
        
        # Write script to temporary file
        script_path = f"/tmp/playwright_crawl_{target.replace('.', '_')}.py"
        with open(script_path, 'w') as f:
            f.write(playwright_script)
        
        # Run the script
        result = subprocess.run(["python", script_path, target], capture_output=True, text=True, timeout=300)
        
        # Clean up
        os.remove(script_path)
        
        if result.returncode == 0:
            try:
                crawl_results = json.loads(result.stdout)
                return {
                    "success": True,
                    "urls_found": crawl_results.get("urls_found", []),
                    "pages_crawled": crawl_results.get("pages_crawled", 0),
                    "js_endpoints": crawl_results.get("js_endpoints", []),
                    "api_endpoints": crawl_results.get("api_endpoints", [])
                }
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": "Failed to parse Playwright results",
                    "raw_output": result.stdout
                }
        else:
            return {
                "success": False,
                "error": result.stderr,
                "raw_output": result.stdout
            }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "urls_found": [],
            "pages_crawled": 0
        }

def analyze_javascript_content(target: str, js_files: List[str]) -> Dict[str, Any]:
    """
    Analyze JavaScript files for hidden endpoints and functionality.
    
    Args:
        target: Target domain
        js_files: List of JavaScript file URLs
        
    Returns:
        Dictionary containing JavaScript analysis results
    """
    try:
        print(f"[INFO] Analyzing JavaScript content for {target}")
        
        js_analysis = {
            "endpoints_found": [],
            "api_calls": [],
            "secrets_found": [],
            "domains_found": [],
            "functions_found": []
        }
        
        # Common patterns to look for
        patterns = {
            "endpoints": [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/rest/[^"\']+)["\']',
                r'["\'](/v[0-9]+/[^"\']+)["\']',
                r'url\s*:\s*["\']([^"\']+)["\']',
                r'endpoint\s*:\s*["\']([^"\']+)["\']'
            ],
            "api_calls": [
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\s*\.\s*(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
                r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']'
            ],
            "secrets": [
                r'api[_-]?key["\']?\s*:\s*["\']([^"\']+)["\']',
                r'token["\']?\s*:\s*["\']([^"\']+)["\']',
                r'secret["\']?\s*:\s*["\']([^"\']+)["\']',
                r'password["\']?\s*:\s*["\']([^"\']+)["\']'
            ],
            "domains": [
                r'["\'](https?://[^"\']+)["\']',
                r'["\'](//[^"\']+)["\']'
            ]
        }
        
        for js_file in js_files[:20]:  # Limit to first 20 files
            try:
                response = requests.get(js_file, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    content = response.text
                    
                    # Search for patterns
                    for pattern_type, pattern_list in patterns.items():
                        for pattern in pattern_list:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[0] if match[0] else match[1]
                                
                                if target in match or match.startswith('/'):
                                    if pattern_type == "endpoints":
                                        js_analysis["endpoints_found"].append({
                                            "file": js_file,
                                            "endpoint": match,
                                            "pattern": pattern
                                        })
                                    elif pattern_type == "api_calls":
                                        js_analysis["api_calls"].append({
                                            "file": js_file,
                                            "call": match,
                                            "pattern": pattern
                                        })
                                    elif pattern_type == "secrets":
                                        js_analysis["secrets_found"].append({
                                            "file": js_file,
                                            "secret": match[:20] + "..." if len(match) > 20 else match,
                                            "pattern": pattern
                                        })
                                    elif pattern_type == "domains":
                                        js_analysis["domains_found"].append({
                                            "file": js_file,
                                            "domain": match,
                                            "pattern": pattern
                                        })
                                        
            except requests.exceptions.RequestException:
                continue
        
        # Remove duplicates
        for key in js_analysis:
            if isinstance(js_analysis[key], list):
                seen = set()
                unique_items = []
                for item in js_analysis[key]:
                    if isinstance(item, dict):
                        item_str = json.dumps(item, sort_keys=True)
                    else:
                        item_str = str(item)
                    if item_str not in seen:
                        seen.add(item_str)
                        unique_items.append(item)
                js_analysis[key] = unique_items
        
        return {
            "success": True,
            "analysis": js_analysis,
            "total_endpoints": len(js_analysis["endpoints_found"]),
            "total_api_calls": len(js_analysis["api_calls"]),
            "total_secrets": len(js_analysis["secrets_found"]),
            "total_domains": len(js_analysis["domains_found"])
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "analysis": {},
            "total_endpoints": 0,
            "total_api_calls": 0,
            "total_secrets": 0,
            "total_domains": 0
        }

def discover_spa_routes(target: str) -> Dict[str, Any]:
    """
    Discover Single Page Application routes and navigation.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing SPA route discovery results
    """
    try:
        print(f"[INFO] Discovering SPA routes for {target}")
        
        spa_routes = []
        navigation_patterns = []
        
        # Test both HTTP and HTTPS
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for SPA indicators
                    spa_indicators = [
                        "react", "angular", "vue", "spa", "single page",
                        "router", "navigation", "route", "hashbang",
                        "pushstate", "popstate", "history api"
                    ]
                    
                    for indicator in spa_indicators:
                        if indicator in content:
                            spa_routes.append({
                                "indicator": indicator,
                                "type": "spa_framework",
                                "confidence": "high"
                            })
                    
                    # Look for route patterns
                    route_patterns = [
                        r'["\'](/[a-zA-Z0-9/-]+)["\']',
                        r'route\s*:\s*["\']([^"\']+)["\']',
                        r'path\s*:\s*["\']([^"\']+)["\']',
                        r'href\s*=\s*["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in route_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if match.startswith('/') and len(match) > 1:
                                navigation_patterns.append({
                                    "route": match,
                                    "pattern": pattern,
                                    "type": "navigation_route"
                                })
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "spa_routes": spa_routes,
            "navigation_patterns": navigation_patterns,
            "total_spa_indicators": len(spa_routes),
            "total_navigation_patterns": len(navigation_patterns)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "spa_routes": [],
            "navigation_patterns": []
        }

def extract_dynamic_forms(target: str) -> Dict[str, Any]:
    """
    Extract dynamic forms and input fields from the application.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing dynamic form extraction results
    """
    try:
        print(f"[INFO] Extracting dynamic forms for {target}")
        
        dynamic_forms = []
        input_fields = []
        
        # Test both HTTP and HTTPS
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract form elements
                    form_pattern = r'<form[^>]*>(.*?)</form>'
                    form_matches = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
                    
                    for i, form_content in enumerate(form_matches):
                        form_info = {
                            "form_id": i,
                            "action": "",
                            "method": "",
                            "inputs": []
                        }
                        
                        # Extract form action and method
                        action_match = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_content, re.IGNORECASE)
                        if action_match:
                            form_info["action"] = action_match.group(1)
                        
                        method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_content, re.IGNORECASE)
                        if method_match:
                            form_info["method"] = method_match.group(1)
                        
                        # Extract input fields
                        input_pattern = r'<input[^>]*>'
                        input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
                        
                        for input_match in input_matches:
                            input_info = {}
                            
                            # Extract input attributes
                            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', input_match, re.IGNORECASE)
                            if name_match:
                                input_info["name"] = name_match.group(1)
                            
                            type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', input_match, re.IGNORECASE)
                            if type_match:
                                input_info["type"] = type_match.group(1)
                            
                            if input_info:
                                form_info["inputs"].append(input_info)
                                input_fields.append(input_info)
                        
                        if form_info["inputs"]:
                            dynamic_forms.append(form_info)
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "dynamic_forms": dynamic_forms,
            "input_fields": input_fields,
            "total_forms": len(dynamic_forms),
            "total_inputs": len(input_fields)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "dynamic_forms": [],
            "input_fields": []
        }

def run_dynamic_analysis(target: str, js_files: List[str], raw_output_path: str) -> Dict[str, Any]:
    """
    Run comprehensive dynamic analysis.
    
    Args:
        target: Target domain
        js_files: List of JavaScript files to analyze
        raw_output_path: Path to save raw output
        
    Returns:
        Dictionary containing comprehensive dynamic analysis results
    """
    print(f"[INFO] Starting dynamic analysis for {target}")
    
    start_time = time.time()
    all_results = {}
    
    # Step 1: Playwright crawling
    print(f"[INFO] Running Playwright crawling")
    playwright_results = run_playwright_crawling(target)
    all_results["playwright_crawling"] = playwright_results
    
    # Step 2: JavaScript content analysis
    print(f"[INFO] Analyzing JavaScript content")
    js_analysis_results = analyze_javascript_content(target, js_files)
    all_results["javascript_analysis"] = js_analysis_results
    
    # Step 3: SPA route discovery
    print(f"[INFO] Discovering SPA routes")
    spa_results = discover_spa_routes(target)
    all_results["spa_routes"] = spa_results
    
    # Step 4: Dynamic form extraction
    print(f"[INFO] Extracting dynamic forms")
    form_results = extract_dynamic_forms(target)
    all_results["dynamic_forms"] = form_results
    
    # Step 5: Generate summary
    execution_time = time.time() - start_time
    
    summary = {
        "target": target,
        "execution_time": execution_time,
        "urls_found": len(playwright_results.get("urls_found", [])),
        "js_endpoints": len(playwright_results.get("js_endpoints", [])),
        "api_endpoints": len(playwright_results.get("api_endpoints", [])),
        "js_analysis_endpoints": js_analysis_results.get("total_endpoints", 0),
        "js_analysis_api_calls": js_analysis_results.get("total_api_calls", 0),
        "js_analysis_secrets": js_analysis_results.get("total_secrets", 0),
        "spa_indicators": spa_results.get("total_spa_indicators", 0),
        "navigation_patterns": spa_results.get("total_navigation_patterns", 0),
        "dynamic_forms": form_results.get("total_forms", 0),
        "input_fields": form_results.get("total_inputs", 0)
    }
    
    # Save raw output
    raw_output = {
        "target": target,
        "timestamp": time.time(),
        "playwright_results": playwright_results,
        "js_analysis_results": js_analysis_results,
        "spa_results": spa_results,
        "form_results": form_results
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
    if len(sys.argv) != 4:
        print("Usage: python run_dynamic_analysis.py <target> <js_files_file> <raw_output_path>")
        sys.exit(1)
    
    target = sys.argv[1]
    js_files_file = sys.argv[2]
    raw_output_path = sys.argv[3]
    
    # Load JavaScript files
    with open(js_files_file, 'r') as f:
        js_files = [line.strip() for line in f if line.strip()]
    
    results = run_dynamic_analysis(target, js_files, raw_output_path)
    print(json.dumps(results, indent=2)) 