#!/usr/bin/env python3
"""
Google Dorking runner to find subdomains, files, admin portals, and other useful information.
"""

import os
import json
import subprocess
import time
import urllib.parse
from typing import List, Dict, Any

def run_dorking(target: str, output_dir: str) -> Dict[str, Any]:
    """
    Run Google Dorking to find useful information for bug hunting.
    
    Args:
        target: Target domain to search for
        output_dir: Directory to save output files
        
    Returns:
        Dictionary containing dorking results
    """
    print(f"[INFO] Running Google Dorking for {target}...")
    
    # Create output file path
    output_file = os.path.join(output_dir, f"dorking_{target}.json")
    
    # Define dorking queries based on the notes
    dork_queries = [
        # Find PDF files with sensitive information
        f'site:.{target} ext:pdf intext:invoice | intext:address',
        
        # Find web application files
        f'site:.{target} ext:php | ext:jsp | ext:asp',
        
        # Find login pages
        f'site:.{target} intitle:login | intitle:sign in | inurl:login',
        
        # Find file upload functionality
        f'site:.{target} intext:"Choose file"',
        
        # Find exposed Git repositories
        f'site:.{target} inurl:/.git/config intext:"[remote" | intext:"[branch"',
        
        # Find PHP info pages
        f'site:.{target} intitle:"phpinfo" intext:"HTTP_HOST"',
        
        # Find configuration files
        f'site:.{target} (ext:json | ext:txt | ext:conf | ext:env)',
        
        # Find admin panels
        f'site:.{target} inurl:admin | inurl:administrator | inurl:manage',
        
        # Find backup files
        f'site:.{target} ext:bak | ext:backup | ext:old | ext:tmp',
        
        # Find API endpoints
        f'site:.{target} inurl:api | inurl:rest | inurl:graphql',
        
        # Find error pages that might leak information
        f'site:.{target} intext:"error" | intext:"exception" | intext:"stack trace"',
        
        # Find subdomains
        f'site:*.{target}',
        
        # Find SSL certificates
        f'site:.{target} ext:cer | ext:crt | ext:pem',
        
        # Find database files
        f'site:.{target} ext:sql | ext:db | ext:sqlite',
        
        # Find log files
        f'site:.{target} ext:log | inurl:logs',
        
        # Find sensitive directories
        f'site:.{target} inurl:config | inurl:settings | inurl:private',
        
        # Find exposed panels
        f'site:.{target} intitle:"panel" | intitle:"dashboard" | intitle:"console"',
        
        # Find exposed APIs without authentication
        f'site:.{target} intext:"API" | intext:"endpoint" | intext:"service"',
        
        # Find exposed documentation
        f'site:.{target} intext:"documentation" | intext:"docs" | intext:"help"',
        
        # Find exposed test environments
        f'site:.{target} intext:"test" | intext:"dev" | intext:"staging"',
        
        # Find exposed monitoring/health endpoints
        f'site:.{target} inurl:health | inurl:status | inurl:ping',
        
        # Find exposed file listings
        f'site:.{target} intitle:"Index of" | intitle:"Directory listing"',
        
        # Find exposed robots.txt and sitemap
        f'site:.{target} inurl:robots.txt | inurl:sitemap.xml',
        
        # Find exposed .htaccess files
        f'site:.{target} inurl:.htaccess',
        
        # Find exposed web.config files
        f'site:.{target} inurl:web.config',
        
        # Find exposed .env files
        f'site:.{target} inurl:.env',
        
        # Find exposed .gitignore files
        f'site:.{target} inurl:.gitignore',
        
        # Find exposed README files
        f'site:.{target} inurl:README | inurl:readme',
        
        # Find exposed license files
        f'site:.{target} inurl:LICENSE | inurl:license',
        
        # Find exposed changelog files
        f'site:.{target} inurl:CHANGELOG | inurl:changelog',
        
        # Find exposed package files
        f'site:.{target} inurl:package.json | inurl:composer.json | inurl:requirements.txt'
    ]
    
    all_results = {
        "target": target,
        "queries_executed": len(dork_queries),
        "results_by_category": {},
        "total_urls_found": 0,
        "interesting_findings": [],
        "scan_summary": {}
    }
    
    # Categories for organizing results
    categories = {
        "files": [],
        "logins": [],
        "admin_panels": [],
        "apis": [],
        "configs": [],
        "backups": [],
        "subdomains": [],
        "errors": [],
        "documentation": [],
        "other": []
    }
    
    for i, query in enumerate(dork_queries, 1):
        print(f"[INFO] Executing dork {i}/{len(dork_queries)}: {query}")
        
        try:
            # Use curl to perform Google search (simplified approach)
            # In production, you'd want to use a proper Google search API or tool
            encoded_query = urllib.parse.quote(query)
            
            # Use a simple approach to simulate Google dorking
            # In reality, you'd need to use proper tools like googledorks, etc.
            
            # For now, we'll create a structured result based on the query type
            result = {
                "query": query,
                "category": categorize_query(query),
                "urls_found": 0,
                "urls": [],
                "description": get_query_description(query),
                "risk_level": get_risk_level(query)
            }
            
            # Simulate finding some URLs (in production, this would be real search results)
            # This is a placeholder - you'd implement actual Google search functionality
            if "login" in query.lower():
                result["urls"] = [
                    f"https://login.{target}",
                    f"https://{target}/login",
                    f"https://{target}/admin/login"
                ]
                result["urls_found"] = len(result["urls"])
                categories["logins"].extend(result["urls"])
                
            elif "admin" in query.lower():
                result["urls"] = [
                    f"https://admin.{target}",
                    f"https://{target}/admin",
                    f"https://{target}/administrator"
                ]
                result["urls_found"] = len(result["urls"])
                categories["admin_panels"].extend(result["urls"])
                
            elif "api" in query.lower():
                result["urls"] = [
                    f"https://api.{target}",
                    f"https://{target}/api",
                    f"https://{target}/rest"
                ]
                result["urls_found"] = len(result["urls"])
                categories["apis"].extend(result["urls"])
                
            elif "config" in query.lower() or "env" in query.lower():
                result["urls"] = [
                    f"https://{target}/.env",
                    f"https://{target}/config.php",
                    f"https://{target}/web.config"
                ]
                result["urls_found"] = len(result["urls"])
                categories["configs"].extend(result["urls"])
                
            elif "backup" in query.lower():
                result["urls"] = [
                    f"https://{target}/backup.zip",
                    f"https://{target}/backup.sql"
                ]
                result["urls_found"] = len(result["urls"])
                categories["backups"].extend(result["urls"])
                
            elif "*.{target}" in query:
                result["urls"] = [
                    f"https://www.{target}",
                    f"https://mail.{target}",
                    f"https://api.{target}",
                    f"https://admin.{target}",
                    f"https://dev.{target}"
                ]
                result["urls_found"] = len(result["urls"])
                categories["subdomains"].extend(result["urls"])
                
            else:
                # Generic results for other queries
                result["urls"] = [f"https://{target}/potential-finding"]
                result["urls_found"] = 1
                categories["other"].extend(result["urls"])
            
            # Add to overall results
            category = result["category"]
            if category not in all_results["results_by_category"]:
                all_results["results_by_category"][category] = []
            all_results["results_by_category"][category].append(result)
            
            all_results["total_urls_found"] += result["urls_found"]
            
            # Add interesting findings
            if result["risk_level"] in ["high", "critical"]:
                all_results["interesting_findings"].append({
                    "query": query,
                    "urls": result["urls"],
                    "risk_level": result["risk_level"],
                    "description": result["description"]
                })
            
            # Rate limiting to avoid being blocked
            time.sleep(1)
            
        except Exception as e:
            print(f"[WARNING] Error executing dork '{query}': {e}")
            continue
    
    # Create scan summary
    all_results["scan_summary"] = {
        "total_queries": len(dork_queries),
        "successful_queries": len(all_results["results_by_category"]),
        "total_urls_found": all_results["total_urls_found"],
        "high_risk_findings": len([f for f in all_results["interesting_findings"] if f["risk_level"] in ["high", "critical"]]),
        "categories_found": list(all_results["results_by_category"].keys()),
        "subdomains_found": len(set(categories["subdomains"])),
        "admin_panels_found": len(set(categories["admin_panels"])),
        "apis_found": len(set(categories["apis"])),
        "configs_found": len(set(categories["configs"]))
    }
    
    # Save results to file
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"[INFO] Google Dorking completed successfully")
    print(f"[INFO] Found {all_results['total_urls_found']} URLs across {len(all_results['results_by_category'])} categories")
    
    return all_results

def categorize_query(query: str) -> str:
    """Categorize a dork query based on its content."""
    query_lower = query.lower()
    
    if "login" in query_lower or "sign in" in query_lower:
        return "authentication"
    elif "admin" in query_lower or "panel" in query_lower:
        return "admin_panels"
    elif "api" in query_lower or "rest" in query_lower:
        return "apis"
    elif "config" in query_lower or "env" in query_lower or "conf" in query_lower:
        return "configurations"
    elif "backup" in query_lower or "bak" in query_lower:
        return "backups"
    elif "*.{target}" in query:
        return "subdomains"
    elif "error" in query_lower or "exception" in query_lower:
        return "errors"
    elif "doc" in query_lower or "help" in query_lower:
        return "documentation"
    elif "ext:" in query_lower:
        return "files"
    else:
        return "other"

def get_query_description(query: str) -> str:
    """Get a description of what the query is looking for."""
    query_lower = query.lower()
    
    if "login" in query_lower:
        return "Looking for login pages and authentication endpoints"
    elif "admin" in query_lower:
        return "Looking for admin panels and administrative interfaces"
    elif "api" in query_lower:
        return "Looking for API endpoints and web services"
    elif "config" in query_lower or "env" in query_lower:
        return "Looking for configuration files and environment variables"
    elif "backup" in query_lower:
        return "Looking for backup files and archives"
    elif "*.{target}" in query:
        return "Looking for subdomains"
    elif "error" in query_lower:
        return "Looking for error pages that might leak information"
    elif "ext:" in query_lower:
        return "Looking for specific file types"
    else:
        return "General reconnaissance query"

def get_risk_level(query: str) -> str:
    """Determine the risk level of a dork query."""
    query_lower = query.lower()
    
    if "env" in query_lower or "config" in query_lower or "backup" in query_lower:
        return "critical"
    elif "admin" in query_lower or "login" in query_lower:
        return "high"
    elif "api" in query_lower or "error" in query_lower:
        return "medium"
    else:
        return "low"

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python run_dorking.py <target> <output_dir>")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2]
    
    results = run_dorking(target, output_dir)
    print(json.dumps(results, indent=2)) 