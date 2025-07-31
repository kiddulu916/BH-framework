import argparse
import os
import json
import requests
import time
import threading
import sys
from typing import Optional, Dict, List, Set
from datetime import datetime
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Existing tool runners
from runners.run_amass import run_amass
from runners.run_sublist3r import run_sublist3r
from runners.run_subfinder import run_subfinder
from runners.run_assetfinder import run_assetfinder
from runners.run_gau import run_gau
from runners.run_waybackurls import run_waybackurls
from runners.run_trufflehog import run_trufflehog
from runners.run_dorking import run_dorking
from runners.run_dns_enum import run_dns_enum

# New enhanced OSINT tool runners
from runners.run_whois import run_whois_lookup, run_reverse_whois
from runners.run_certificate_transparency import run_certificate_transparency, run_passive_dns
from runners.run_repository_mining import run_repository_mining
from runners.run_search_dorking import run_search_dorking, run_advanced_dorking
from runners.run_breach_checking import run_breach_checking, run_credential_stuffing_check
from runners.run_infrastructure_exposure import run_infrastructure_exposure, run_vulnerability_scanning
from runners.run_archive_mining import run_archive_mining, run_archive_analysis
from runners.run_social_intelligence import run_social_intelligence

from runners.utils import save_raw_to_db, save_parsed_to_db

class RateLimiter:
    """Rate limiter for API calls to prevent overwhelming external services."""
    
    def __init__(self, calls_per_second: float = 1.0):
        self.calls_per_second = calls_per_second
        self.last_call_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limits."""
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_call_time
            min_interval = 1.0 / self.calls_per_second
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_call_time = time.time()

class ProgressTracker:
    """Track progress of passive recon execution."""
    
    def __init__(self, total_tools: int):
        self.total_tools = total_tools
        self.completed_tools = 0
        self.failed_tools = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def mark_completed(self, tool_name: str, success: bool = True):
        """Mark a tool as completed."""
        with self.lock:
            if success:
                self.completed_tools += 1
                print(f"[PROGRESS] ✅ {tool_name} completed ({self.completed_tools}/{self.total_tools})")
            else:
                self.failed_tools += 1
                print(f"[PROGRESS] ❌ {tool_name} failed ({self.failed_tools} failures)")
    
    def get_progress(self) -> Dict:
        """Get current progress statistics."""
        elapsed_time = time.time() - self.start_time
        success_rate = (self.completed_tools / self.total_tools) * 100 if self.total_tools > 0 else 0
        
        return {
            "completed": self.completed_tools,
            "failed": self.failed_tools,
            "total": self.total_tools,
            "success_rate": success_rate,
            "elapsed_time": elapsed_time
        }

def get_primary_active_target(api_url: str, jwt_token: str) -> Optional[tuple[str, str]]:
    """
    Get the target ID and domain for the primary and active target from the database.
    
    This function queries the targets API to find a target that is both:
    - is_primary = True
    - status = ACTIVE
    
    Returns a tuple of (target_id, domain) if found, None otherwise.
    """
    try:
        # Construct the correct targets URL
        if '/results/passive-recon' in api_url:
            base_url = api_url.split('/results/')[0]
        else:
            base_url = api_url.rstrip('/')
        targets_url = f"{base_url}/targets/"
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {jwt_token}'
        }
        
        # Query for targets with status=ACTIVE
        response = requests.get(f"{targets_url}?status=ACTIVE", headers=headers)

        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('data'):
                # Get targets from response
                targets = data['data'].get('items', [])
                
                # Find the primary target
                for target in targets:
                    if target.get('is_primary', False):
                        target_id = target.get('id')
                        domain = target.get('domain') or target.get('target', '')
                        if target_id and domain:
                            print(f"[INFO] Found primary active target: {domain} (ID: {target_id})")
                            return target_id, domain
                
                # If no primary target found, check if there's only one active target
                if len(targets) == 1:
                    target_id = targets[0].get('id')
                    domain = targets[0].get('domain')
                    if target_id and domain:
                        print(f"[INFO] Found single active target: {domain} (ID: {target_id})")
                        return target_id, domain
                
                # If multiple active targets but none are primary, show warning
                if len(targets) > 1:
                    print(f"[WARNING] Found {len(targets)} active targets but none are marked as primary:")
                    for target in targets:
                        target_domain = target.get('domain') or target.get('target', 'Unknown')
                        print(f"  - {target_domain} (ID: {target.get('id')}, Primary: {target.get('is_primary', False)})")
                elif len(targets) == 0:
                    print("[WARNING] No active targets found in database")
                
        else:
            print(f"[ERROR] Failed to query targets API: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"[ERROR] Failed to get primary active target: {e}")
    
        return None

def get_target_id(domain: str, api_url: str, jwt_token: str) -> Optional[str]:
    """
    Get target ID from backend API by domain name.
    """
    try:
        # Construct the correct targets URL
        if '/results/passive-recon' in api_url:
            base_url = api_url.split('/results/')[0]
        else:
            base_url = api_url.rstrip('/')
        targets_url = f"{base_url}/targets/"
        headers = {
            'Content-Type': 'application/json'
        }
        
        # First try to get target by value
        response = requests.get(f"{targets_url}?value={domain}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('data'):
                # Try different possible keys for targets list
                targets = data['data'].get('targets', []) or data['data'].get('items', [])
                if targets and len(targets) > 0:
                    target_id = targets[0].get('id')
                    if target_id:
                        return target_id
                    
        # If target doesn't exist, try to create it
        print(f"[INFO] Target not found, attempting to create: {domain}")
        return create_target_if_not_exists(domain, api_url, jwt_token)
        
    except Exception as e:
        print(f"[ERROR] Failed to get target ID: {e}")
        return None


def get_target_domain_by_id(target_id: str, api_url: str, jwt_token: str) -> Optional[str]:
    """
    Get the domain for a given target ID from the database.
    
    Args:
        target_id: Target ID
        api_url: Backend API URL
        jwt_token: JWT token for authentication
        
    Returns:
        Domain if found, None otherwise
    """
    try:
        # Construct the correct targets URL
        if '/results/passive-recon' in api_url:
            base_url = api_url.split('/results/')[0]
        else:
            base_url = api_url.rstrip('/')
        targets_url = f"{base_url}/targets/{target_id}/"
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        response = requests.get(targets_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('data'):
                target = data['data']
                return target.get('value')
        return None
    except Exception as e:
        print(f"[ERROR] Failed to get domain for target ID {target_id}: {e}")
        return None

def setup_output_dirs(stage: str, target: str):
    # Create target-specific directory structure
    target_dir = os.path.join("/outputs", target)
    raw_dir = os.path.join(target_dir, "raw")
    parsed_dir = os.path.join(target_dir, "parsed")
    
    # Create directories
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    
    return {"target_dir": target_dir, "raw_dir": raw_dir, "parsed_dir": parsed_dir}

def save_text(data, path):
    """Save data as plain text file."""
    with open(path, "w") as f:
        if isinstance(data, list):
            for item in data:
                f.write(f"{item}\n")
        elif isinstance(data, dict):
            for key, value in data.items():
                f.write(f"{key}: {value}\n")
        else:
            f.write(str(data))
    print(f"[INFO] Saved: {path}")

def run_tool_with_retry(tool_func, tool_name: str, target: str, raw_dir: str, 
                       target_id: str, api_url: str, jwt_token: str, 
                       progress_tracker: ProgressTracker, rate_limiter: RateLimiter,
                       max_retries: int = 3) -> Dict:
    """
    Run a tool with retry logic, rate limiting, and progress tracking.
    """
    for attempt in range(max_retries):
        try:
            # Apply rate limiting
            rate_limiter.wait()
            
            print(f"[INFO] Running {tool_name} (attempt {attempt + 1}/{max_retries})")
            
            # Run the tool
            results = tool_func(target, raw_dir)
            
            # Save results
            raw_path = os.path.join(raw_dir, f"{tool_name}_{target}.json")
            parsed_path = os.path.join(parsed_dir, f"{tool_name}_{target}.txt")
            
            # Save raw results
            with open(raw_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            # Save parsed results
            save_text(results, parsed_path)
            
            # Submit to API
            raw_ok = save_raw_to_db(tool_name, target_id, raw_path, api_url, jwt_token)
            parsed_ok = save_parsed_to_db(tool_name, target_id, target, results, api_url, jwt_token)
            
            # Mark as completed
            progress_tracker.mark_completed(tool_name, True)
            
            return {
                "success": True,
                "results": results,
                "raw_api": raw_ok,
                "parsed_api": parsed_ok
            }
            
        except Exception as e:
            print(f"[ERROR] {tool_name} attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                progress_tracker.mark_completed(tool_name, False)
                return {
                    "success": False,
                    "error": str(e)
                }
            else:
                # Wait before retry
                time.sleep(2 ** attempt)  # Exponential backoff
    
    return {"success": False, "error": "Max retries exceeded"}

def correlate_data(all_results: Dict) -> Dict:
    """
    Correlate data across different tools to identify relationships and patterns.
    """
    correlation_results = {
        "subdomains": set(),
        "ips": set(),
        "technologies": set(),
        "vulnerabilities": set(),
        "secrets": set(),
        "relationships": []
    }
    
    # Extract subdomains from all tools
    for tool_name, results in all_results.items():
        if isinstance(results, dict) and "subdomains" in results:
            correlation_results["subdomains"].update(results["subdomains"])
        elif isinstance(results, list):
            # Handle list of subdomains
            correlation_results["subdomains"].update(results)
    
    # Extract IP addresses
    for tool_name, results in all_results.items():
        if isinstance(results, dict):
            if "ips" in results:
                correlation_results["ips"].update(results["ips"])
            if "infrastructure" in results and "ips" in results["infrastructure"]:
                correlation_results["ips"].update(results["infrastructure"]["ips"])
    
    # Extract technologies
    for tool_name, results in all_results.items():
        if isinstance(results, dict):
            if "technologies" in results:
                correlation_results["technologies"].update(results["technologies"])
            if "tech_stack" in results:
                correlation_results["technologies"].update(results["tech_stack"])
    
    # Extract vulnerabilities
    for tool_name, results in all_results.items():
        if isinstance(results, dict):
            if "vulnerabilities" in results:
                correlation_results["vulnerabilities"].update(results["vulnerabilities"])
            if "security_issues" in results:
                correlation_results["vulnerabilities"].update(results["security_issues"])
    
    # Extract secrets
    for tool_name, results in all_results.items():
        if isinstance(results, dict):
            if "secrets" in results:
                correlation_results["secrets"].update(results["secrets"])
            if "credentials" in results:
                correlation_results["secrets"].update(results["credentials"])
    
    # Convert sets to lists for JSON serialization
    for key in correlation_results:
        if isinstance(correlation_results[key], set):
            correlation_results[key] = list(correlation_results[key])
    
    return correlation_results

def get_target_scan_config(api_url: str, jwt_token: str, target_id: str) -> Dict:
    """
    Get scan configuration from target profile in database.
    
    Returns configuration including rate limiting, in_scope targets, and other settings.
    """
    try:
        # Construct the correct targets URL
        if '/results/passive-recon' in api_url:
            base_url = api_url.split('/results/')[0]
        else:
            base_url = api_url.rstrip('/')
        targets_url = f"{base_url}/targets/{target_id}"
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {jwt_token}'
        }
        
        response = requests.get(targets_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('data'):
                target_data = data['data']
                return {
                    'rate_limit_requests': target_data.get('rate_limit_requests', 10),
                    'rate_limit_seconds': target_data.get('rate_limit_seconds', 60),
                    'in_scope': target_data.get('in_scope', []),
                    'domain': target_data.get('domain', ''),
                    'target': target_data.get('target', ''),
                    'is_primary': target_data.get('is_primary', False),
                    'status': target_data.get('status', 'ACTIVE')
                }
        
        print(f"[WARNING] Failed to get target scan config: {response.status_code}")
        return {
            'rate_limit_requests': 10,
            'rate_limit_seconds': 60,
            'in_scope': [],
            'domain': '',
            'target': '',
            'is_primary': False,
            'status': 'ACTIVE'
        }
        
    except Exception as e:
        print(f"[ERROR] Failed to get target scan config: {e}")
        return {
            'rate_limit_requests': 10,
            'rate_limit_seconds': 60,
            'in_scope': [],
            'domain': '',
            'target': '',
            'is_primary': False,
            'status': 'ACTIVE'
        }

def run_passive_recon_for_target(target_domain: str, target_id: str, api_url: str, jwt_token: str, 
                                scan_config: Dict, parallel: int = 3) -> Dict:
    """
    Run passive reconnaissance for a specific target domain.
    
    Args:
        target_domain: Domain to scan
        target_id: Target ID from database
        api_url: Backend API URL
        jwt_token: JWT token for authentication
        scan_config: Scan configuration from target profile
        parallel: Number of parallel tool executions
        
    Returns:
        Dictionary containing results and discovered subdomains
    """
    print(f"[INFO] Starting Enhanced Passive Reconnaissance for target: {target_domain}")
    print(f"[INFO] Parallel execution: {parallel} tools")
    
    # Calculate rate limit from target configuration
    rate_limit = scan_config.get('rate_limit_requests', 10) / scan_config.get('rate_limit_seconds', 60)
    print(f"[INFO] Rate limit: {rate_limit:.2f} calls/second (from target config)")

    # Setup output directories
    dirs = setup_output_dirs("passive_recon", target_domain)
    target_dir = dirs["target_dir"]
    raw_dir = dirs["raw_dir"]
    parsed_dir = dirs["parsed_dir"]

    # Initialize rate limiter and progress tracker
    rate_limiter = RateLimiter(rate_limit)
    
    # Define all available tools (existing + new enhanced tools)
    all_available_tools = [
        # Existing subdomain enumeration tools
        ("sublist3r", run_sublist3r),
        ("amass", run_amass),
        ("subfinder", run_subfinder),
        ("assetfinder", run_assetfinder),
        ("gau", run_gau),
        ("waybackurls", run_waybackurls),
        ("trufflehog", run_trufflehog),
        ("dorking", run_dorking),
        ("dns_enum", run_dns_enum),
        
        # New enhanced OSINT tools
        ("whois", run_whois_lookup),
        ("certificate_transparency", run_certificate_transparency),
        ("passive_dns", run_passive_dns),
        ("repository_mining", run_repository_mining),
        ("search_dorking", run_search_dorking),
        ("advanced_dorking", run_advanced_dorking),
        ("breach_checking", run_breach_checking),
        ("credential_stuffing", run_credential_stuffing_check),
        ("infrastructure_exposure", run_infrastructure_exposure),
        ("vulnerability_scanning", run_vulnerability_scanning),
        ("archive_mining", run_archive_mining),
        ("archive_analysis", run_archive_analysis),
        ("social_intelligence", run_social_intelligence),
    ]
    
    # Filter tools based on SELECTED_TOOLS environment variable
    selected_tools_str = os.environ.get("SELECTED_TOOLS", "")
    if selected_tools_str:
        selected_tools = [tool.strip().lower() for tool in selected_tools_str.split(",") if tool.strip()]
        print(f"[INFO] Selected tools from environment: {selected_tools}")
        
        # Filter tools_to_run based on selected tools
        tools_to_run = []
        for tool_name, tool_func in all_available_tools:
            if tool_name.lower() in selected_tools:
                tools_to_run.append((tool_name, tool_func))
        
        if not tools_to_run:
            print(f"[WARNING] No valid tools found in selection: {selected_tools}")
            print(f"[INFO] Available tools: {[tool[0] for tool in all_available_tools]}")
            tools_to_run = all_available_tools  # Fall back to all tools
    else:
        # No tools selected, run all tools
        tools_to_run = all_available_tools
        print(f"[INFO] No tools selected, running all {len(tools_to_run)} tools")
    
    progress_tracker = ProgressTracker(len(tools_to_run))
    all_results = {}
    summary = {}
    discovered_subdomains = set()

    print(f"[INFO] Starting execution of {len(tools_to_run)} tools...")
    start_time = time.time()

    # Execute tools with parallel processing
    with ThreadPoolExecutor(max_workers=parallel) as executor:
        # Submit all tasks
        future_to_tool = {}
        for tool_name, tool_func in tools_to_run:
            future = executor.submit(
                run_tool_with_retry,
                tool_func,
                tool_name,
                target_domain,
                raw_dir,
                target_id,
                api_url,
                jwt_token,
                progress_tracker,
                rate_limiter
            )
            future_to_tool[future] = tool_name
        
        # Collect results as they complete
        for future in as_completed(future_to_tool):
            tool_name = future_to_tool[future]
            try:
                result = future.result()
                all_results[tool_name] = result
                summary[tool_name] = result
                
                # Extract subdomains from results
                if result.get("success") and "subdomains" in result.get("results", {}):
                    subdomains = result["results"]["subdomains"]
                    if isinstance(subdomains, list):
                        discovered_subdomains.update(subdomains)
                    elif isinstance(subdomains, set):
                        discovered_subdomains.update(subdomains)
                        
            except Exception as e:
                print(f"[ERROR] Tool {tool_name} failed with exception: {e}")
                all_results[tool_name] = {"success": False, "error": str(e)}
                summary[tool_name] = {"success": False, "error": str(e)}

    # Data correlation and analysis
    print("[INFO] Performing data correlation and analysis...")
    correlation_results = correlate_data(all_results)
    
    # Save correlation results
    correlation_path = os.path.join(parsed_dir, "correlation_analysis.json")
    with open(correlation_path, 'w') as f:
        json.dump(correlation_results, f, indent=2, default=str)
    
    # Save comprehensive summary
    final_summary = {
        "target": target_domain,
        "target_id": target_id,
        "execution_time": time.time() - start_time,
        "progress": progress_tracker.get_progress(),
        "correlation": correlation_results,
        "tool_results": summary,
        "discovered_subdomains": list(discovered_subdomains)
    }
    
    summary_path = os.path.join(parsed_dir, "comprehensive_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(final_summary, f, indent=2, default=str)

    # Print final summary
    print("\n" + "="*60)
    print(f"PASSIVE RECONNAISSANCE COMPLETED FOR: {target_domain}")
    print("="*60)
    
    progress_stats = progress_tracker.get_progress()
    print(f"Target: {target_domain}")
    print(f"Target ID: {target_id}")
    print(f"Execution Time: {progress_stats['elapsed_time']:.2f} seconds")
    print(f"Success Rate: {progress_stats['success_rate']:.1f}%")
    print(f"Tools Completed: {progress_stats['completed']}/{progress_stats['total']}")
    print(f"Tools Failed: {progress_stats['failed']}")
    print(f"Subdomains Discovered: {len(discovered_subdomains)}")
    
    print(f"\nCorrelation Results:")
    print(f"- Unique Subdomains: {len(correlation_results['subdomains'])}")
    print(f"- Unique IPs: {len(correlation_results['ips'])}")
    print(f"- Technologies: {len(correlation_results['technologies'])}")
    print(f"- Vulnerabilities: {len(correlation_results['vulnerabilities'])}")
    print(f"- Secrets Found: {len(correlation_results['secrets'])}")
    
    print(f"\nDetailed Results:")
    for tool_name, result in summary.items():
        status = "✅" if result.get("success", False) else "❌"
        print(f"{status} {tool_name}: {result.get('error', 'Success') if not result.get('success', False) else 'Completed'}")
    
    print(f"\nOutput Files:")
    print(f"- Raw Outputs: {raw_dir}")
    print(f"- Parsed Results: {parsed_dir}")
    print(f"- Correlation Analysis: {correlation_path}")
    print(f"- Comprehensive Summary: {summary_path}")
    
    print("="*60)
    
    return {
        "target_domain": target_domain,
        "target_id": target_id,
        "success": True,
        "discovered_subdomains": list(discovered_subdomains),
        "execution_time": time.time() - start_time,
        "results": final_summary
    }

def main():
    load_dotenv(dotenv_path=".env")
    
    # Get target info from environment variables or database
    api_url = os.environ.get("BACKEND_API_URL", "http://backend:8000/api/results/passive-recon")
    jwt_token = os.environ.get("BACKEND_JWT_TOKEN", "")
    
    # Check if target_id is provided via environment variable (from API)
    target_id = os.environ.get("TARGET_ID")
    target_domain = None
    
    if target_id:
        # Target ID provided via environment variable, get domain from database
        print(f"[INFO] Using target ID from environment: {target_id}")
        target_domain = get_target_domain_by_id(target_id, api_url, jwt_token)
        if not target_domain:
            print(f"[ERROR] Could not get domain for target ID: {target_id}")
            sys.exit(1)
    else:
        # Fall back to getting primary active target from database
        target_info = get_primary_active_target(api_url, jwt_token)
        if not target_info:
            print("[ERROR] Could not get target info from database")
            sys.exit(1)
        target_id, target_domain = target_info
    
    # Get scan configuration from target info
    scan_config = get_target_scan_config(api_url, jwt_token, target_id)
    
    print(f"[INFO] Using primary active target: {target_domain} (ID: {target_id})")
    print(f"[INFO] Rate limiting: {scan_config.get('rate_limit_requests', 10)} requests per {scan_config.get('rate_limit_seconds', 60)} seconds")
    print(f"[INFO] In-scope targets: {len(scan_config.get('in_scope', []))} entries")
    
    # Calculate rate limit for parallel execution
    rate_limit = scan_config.get('rate_limit_requests', 10) / scan_config.get('rate_limit_seconds', 60)
    parallel_tools = max(1, min(5, int(rate_limit * 2)))  # Adjust parallelism based on rate limit
    
    # Collect all targets to scan
    all_targets = set()
    
    # Add main domain
    if scan_config.get('domain'):
        all_targets.add(scan_config['domain'])
    
    # Add in-scope targets
    in_scope_targets = scan_config.get('in_scope', [])
    for scope_target in in_scope_targets:
        if isinstance(scope_target, str):
            all_targets.add(scope_target)
        elif isinstance(scope_target, dict) and 'value' in scope_target:
            all_targets.add(scope_target['value'])
    
    print(f"[INFO] Initial targets to scan: {len(all_targets)}")
    for target in all_targets:
        print(f"  - {target}")
    
    # Track all discovered subdomains across all scans
    all_discovered_subdomains = set()
    scan_results = []
    
    # First pass: Scan all initial targets
    print(f"\n[INFO] Starting first pass: scanning {len(all_targets)} initial targets")
    for target in all_targets:
        try:
            result = run_passive_recon_for_target(target, target_id, api_url, jwt_token, scan_config, parallel_tools)
            scan_results.append(result)
            
            # Collect discovered subdomains
            discovered = result.get('discovered_subdomains', [])
            all_discovered_subdomains.update(discovered)
            
        except Exception as e:
            print(f"[ERROR] Failed to scan target {target}: {e}")
    
    # Second pass: Scan discovered subdomains
    if all_discovered_subdomains:
        print(f"\n[INFO] Starting second pass: scanning {len(all_discovered_subdomains)} discovered subdomains")
        for subdomain in all_discovered_subdomains:
            try:
                result = run_passive_recon_for_target(subdomain, target_id, api_url, jwt_token, scan_config, parallel_tools)
                scan_results.append(result)
                
                # Collect additional subdomains from subdomain scans
                additional_subdomains = result.get('discovered_subdomains', [])
                all_discovered_subdomains.update(additional_subdomains)
                
            except Exception as e:
                print(f"[ERROR] Failed to scan subdomain {subdomain}: {e}")
    
    # Final summary
    print("\n" + "="*80)
    print("COMPREHENSIVE PASSIVE RECONNAISSANCE COMPLETED")
    print("="*80)
    print(f"Primary Target: {target_domain}")
    print(f"Target ID: {target_id}")
    print(f"Initial Targets Scanned: {len(all_targets)}")
    print(f"Total Subdomains Discovered: {len(all_discovered_subdomains)}")
    print(f"Total Scans Completed: {len(scan_results)}")
    
    total_execution_time = sum(result.get('execution_time', 0) for result in scan_results)
    print(f"Total Execution Time: {total_execution_time:.2f} seconds")
    
    successful_scans = sum(1 for result in scan_results if result.get('success', False))
    print(f"Successful Scans: {successful_scans}/{len(scan_results)}")
    
    print(f"\nAll Discovered Subdomains:")
    for subdomain in sorted(all_discovered_subdomains):
        print(f"  - {subdomain}")
    
    print("="*80)

if __name__ == "__main__":
    main()
