import argparse
import os
import json
import subprocess
import requests
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from datetime import datetime
from runners.run_nmap import run_nmap
from runners.run_naabu import run_naabu
from runners.run_proxy_capture import run_proxy_capture
from runners.run_puredns import run_puredns, create_master_subdomain_list
from runners.run_webanalyze import run_webanalyze, enhance_port_scan_results
from runners.run_katana import run_katana
from runners.run_feroxbuster import run_feroxbuster
from runners.run_getjs import run_getjs
from runners.run_linkfinder import run_linkfinder
from runners.run_arjun import run_arjun
from runners.run_eyewitness import run_eyewitness
from runners.run_eyeballer import run_eyeballer

# Enhanced Active Recon Tools
from runners.run_enhanced_subdomain_enum import run_enhanced_subdomain_enumeration
from runners.run_waf_cdn_detection import run_waf_cdn_detection
from runners.run_cloud_infrastructure import run_cloud_infrastructure_enumeration
from runners.run_input_vectors_discovery import run_input_vectors_discovery
from runners.run_dynamic_analysis import run_dynamic_analysis
from runners.run_misconfiguration_detection import run_misconfiguration_detection

# Recursive Reconnaissance
from runners.run_recursive_recon import run_recursive_reconnaissance

from runners.utils import save_raw_to_db, save_parsed_to_db

def setup_output_dirs(stage: str, target: str):
    """Create output directories for the stage with enumeration structure."""
    base_dir = os.path.join("/outputs", stage, target)
    output_dir = os.path.join(base_dir)
    parsed_dir = os.path.join(base_dir, "parsed")
    raw_dir = os.path.join(base_dir, "raw")
    
    # Create base directories
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    
    # Create enumeration directory structure as per notes.txt
    enumeration_dirs = [
        os.path.join(output_dir, "enumeration", "infrastructure"),
        os.path.join(output_dir, "enumeration", "http-requests"),
        os.path.join(output_dir, "enumeration", "http-responses"),
        os.path.join(output_dir, "enumeration", "IPs-and-open-ports"),
        os.path.join(output_dir, "enumeration", "domains"),
        os.path.join(output_dir, "enumeration", "screenshots"),
        os.path.join(output_dir, "enumeration", "live_servers"),
        os.path.join(output_dir, "enumeration", "parameters"),
        os.path.join(output_dir, "enumeration", "findings"),
        os.path.join(output_dir, "enumeration", "js_endpoints"),
        os.path.join(output_dir, "enumeration", "scrapped_files"),
        os.path.join(output_dir, "enumeration", "endpoints"),
        os.path.join(output_dir, "enumeration", "endpoint-json"),
        
        # Enhanced Active Recon Directories
        os.path.join(output_dir, "enumeration", "enhanced_subdomains"),
        os.path.join(output_dir, "enumeration", "waf_cdn"),
        os.path.join(output_dir, "enumeration", "cloud_infrastructure"),
        os.path.join(output_dir, "enumeration", "input_vectors"),
        os.path.join(output_dir, "enumeration", "dynamic_analysis"),
        os.path.join(output_dir, "enumeration", "misconfigurations"),
        os.path.join(output_dir, "enumeration", "takeover_checks"),
        os.path.join(output_dir, "enumeration", "third_party_services"),
        os.path.join(output_dir, "enumeration", "origin_servers"),
        os.path.join(output_dir, "enumeration", "security_headers"),
        os.path.join(output_dir, "enumeration", "tls_analysis"),
        os.path.join(output_dir, "enumeration", "exposed_files"),
        os.path.join(output_dir, "enumeration", "default_credentials"),
        os.path.join(output_dir, "enumeration", "directory_listings"),
        os.path.join(output_dir, "enumeration", "unnecessary_services"),
    ]
    
    for dir_path in enumeration_dirs:
        os.makedirs(dir_path, exist_ok=True)
        print(f"[INFO] Created directory: {dir_path}")
    
    return {"output_dir": output_dir, "parsed": parsed_dir, "raw": raw_dir}

def get_target_id_by_domain(domain: str, targets_api_url: str, jwt_token: str) -> Optional[str]:
    """Get target ID by domain name."""
    try:
        # Targets API doesn't require authentication
        response = requests.get(f"{targets_api_url}?value={domain}")
        response.raise_for_status()
        data = response.json()
        
        if data.get("success") and data.get("data", {}).get("targets"):
            targets = data["data"]["targets"]
            if targets:
                return targets[0]["id"]  # Return the first matching target
        return None
    except Exception as e:
        print(f"[WARNING] Failed to get target ID for domain {domain}: {e}")
        return None


def get_target_domain_by_id(target_id: str, targets_api_url: str, jwt_token: str) -> Optional[str]:
    """
    Get the domain for a given target ID from the database.
    
    Args:
        target_id: Target ID
        targets_api_url: Backend API URL for targets
        jwt_token: JWT token for authentication
        
    Returns:
        Domain if found, None otherwise
    """
    try:
        headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
        response = requests.get(f"{targets_api_url}{target_id}/", headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("success") and data.get("data"):
            target = data["data"]
            return target.get("value")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to get domain for target ID {target_id}: {e}")
        return None

def get_passive_recon_results(target_id: str, api_url: str, jwt_token: str) -> List[str]:
    """Query the backend API to get subdomains from passive recon stage."""
    try:
        headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
        response = requests.get(f"{api_url}/{target_id}", headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("success") and data.get("data"):
            # Extract subdomains from the response
            subdomains = []
            for result in data.get("data", []):
                if "raw_output" in result and "subdomains" in result["raw_output"]:
                    subdomains.extend(result["raw_output"]["subdomains"])
            return list(set(subdomains))  # Remove duplicates
        return []
    except Exception as e:
        print(f"[WARNING] Failed to get passive recon results: {e}")
        return []

def get_targets_from_passive_recon(passive_api_url: str, jwt_token: str) -> List[str]:
    """Get all targets that have passive recon results."""
    try:
        headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
        response = requests.get(f"{passive_api_url}/", headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("success") and data.get("data"):
            targets = []
            for result in data.get("data", []):
                if "target" in result:
                    targets.append(result["target"])
            return list(set(targets))  # Remove duplicates
        return []
    except Exception as e:
        print(f"[WARNING] Failed to get targets from passive recon: {e}")
        return []

def select_target_interactively(targets: List[str]) -> Optional[str]:
    """Provide interactive target selection if multiple targets are found."""
    if not targets:
        print("[ERROR] No targets found from passive recon stage")
        return None
    
    if len(targets) == 1:
        print(f"[INFO] Found single target: {targets[0]}")
        return targets[0]
    
    print(f"[INFO] Found {len(targets)} targets from passive recon stage:")
    for i, target in enumerate(targets, 1):
        print(f"  {i}. {target}")
    
    while True:
        try:
            choice = input(f"\nSelect target (1-{len(targets)}): ").strip()
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(targets):
                selected_target = targets[choice_idx]
                print(f"[INFO] Selected target: {selected_target}")
                return selected_target
            else:
                print(f"Please enter a number between 1 and {len(targets)}")
        except (ValueError, KeyboardInterrupt):
            print("\n[INFO] Using first target as default")
            return targets[0]

def save_json(data, path):
    """Save data as JSON file."""
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] Saved: {path}")

def main():
    load_dotenv(dotenv_path=".env")
    parser = argparse.ArgumentParser(description="Active Recon Main Runner")
    parser.add_argument("--target", required=False, help="Target domain (optional - will be fetched from passive recon if not provided)")
    parser.add_argument("--stage", default="active_recon", help="Stage name (default: active_recon)")
    parser.add_argument("--no-proxy-capture", action="store_true", help="Disable proxy traffic capture (enabled by default)")
    parser.add_argument("--capture-duration", type=int, default=0, help="Proxy capture duration in seconds (default: 0 = never ending)")
    parser.add_argument("--enable-recursive", action="store_true", help="Enable recursive reconnaissance on discovered subdomains")
    parser.add_argument("--max-concurrent-subtargets", type=int, default=3, help="Maximum concurrent subtarget scans (default: 3)")
    args = parser.parse_args()

    # Load API URL and JWT token from environment
    api_url = os.environ.get("BACKEND_API_URL", "http://backend:8000/api/")
    results_api_url = os.environ.get("BACKEND_API_RESULTS_URL", "http://backend:8000/api/results")
    jwt_token = os.environ.get("BACKEND_JWT_TOKEN", "")
    targets_api_url = os.environ.get("TARGETS_API_URL", "http://backend:8000/api/targets/")
    passive_api_url = os.environ.get("PASSIVE_API_URL", "http://backend:8000/api/results/passive-recon")
    active_api_url = os.environ.get("ACTIVE_API_URL", "http://backend:8000/api/results/active-recon")
    
    # Check for target_id from environment variable (from API)
    target_id = os.environ.get("TARGET_ID")
    if target_id:
        print(f"[INFO] Using target ID from environment: {target_id}")
        # Get domain from target ID
        target_domain = get_target_domain_by_id(target_id, targets_api_url, jwt_token)
        if target_domain:
            args.target = target_domain
            print(f"[INFO] Resolved target domain: {args.target}")
        else:
            print(f"[ERROR] Could not get domain for target ID: {target_id}")
            exit(1)
    
    # Check for recursive options from environment variables
    enable_recursive = os.environ.get("OPTION_ENABLE_RECURSIVE", "").lower() == "true"
    max_concurrent_subtargets = int(os.environ.get("OPTION_MAX_CONCURRENT_SUBTARGETS", "3"))
    
    if enable_recursive:
        args.enable_recursive = True
        args.max_concurrent_subtargets = max_concurrent_subtargets
        print(f"[INFO] Recursive recon enabled from environment: max {max_concurrent_subtargets} concurrent subtargets")
    
    # Fix API URLs to use correct endpoints
    raw_api_url = f"{results_api_url}/active-recon/raw"  # For raw file uploads
    parsed_api_url = f"{results_api_url}/active-recon/parsed"    # For parsed active recon results
    
    print(f"[INFO] Using backend API URL: {api_url}")
    if not jwt_token:
        print("[WARNING] No BACKEND_JWT_TOKEN found in environment. API submission will likely fail.")

    # Get target from passive recon if not provided
    if not args.target:
        try:
            print(f"[INFO] Getting target(s) from passive recon stage: {passive_api_url}")
            targets = get_targets_from_passive_recon(passive_api_url, jwt_token)
            if not targets:
                print("[ERROR] No targets found from passive recon stage. Exiting.")
                exit(1)
            
            selected_target = select_target_interactively(targets)
            if not selected_target:
                print("[ERROR] Could not determine target. Exiting.")
                exit(1)
            
            args.target = selected_target  # Update args.target with the selected target
        except Exception as e:
            print(f"[ERROR] Failed to get target(s) from passive recon stage: {e}")
            print("[ERROR] Please provide a target using --target or ensure passive recon has been run.")
            exit(1)
    
    print(f"[INFO] Using target: {args.target}")

    # Setup output directories with enumeration structure
    dirs = setup_output_dirs(args.stage, args.target)
    output_dir = dirs["output_dir"]
    parsed_dir = dirs["parsed"]
    raw_dir = dirs["raw"]

    # Get target ID by domain name
    print(f"[INFO] Getting target ID for domain: {args.target}")
    target_id = get_target_id_by_domain(args.target, targets_api_url, jwt_token)
    
    if not target_id:
        print(f"[WARNING] No target found for domain {args.target}. Using domain as fallback.")
        passive_results = []
        subdomains = [args.target]
    else:
        print(f"[INFO] Found target ID: {target_id}")
        # Get subdomains from passive recon stage
        print(f"[INFO] Querying passive recon results for target ID: {target_id}")
        passive_results = get_passive_recon_results(target_id, passive_api_url, jwt_token)
        
        # Create master subdomain list from passive recon results
        if passive_results:
            print(f"[INFO] Creating master subdomain list from passive recon results")
            # Convert string list to expected format for create_master_subdomain_list
            passive_results_dict = [{"subdomains": passive_results}]
            subdomains = create_master_subdomain_list(passive_results_dict, args.target)
        else:
            print(f"[WARNING] No passive recon results found for {args.target}")
            subdomains = [args.target]
    
    print(f"[INFO] Master subdomain list created with {len(subdomains)} subdomains")
    print(f"[INFO] Sample subdomains: {subdomains[:5]}...")
    
    # Save master subdomain list
    master_list_file = os.path.join(output_dir, "enumeration", "master_subdomain_list.txt")
    with open(master_list_file, 'w') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
    print(f"[INFO] Saved master subdomain list to {master_list_file}")

    all_results = {}
    summary = {}

    # Step 1: Proxy Capture (if enabled and available)
    if args.proxy_capture:
        print(f"[INFO] Starting proxy capture for {args.target})")
        try:
            proxy_raw_path = os.path.join(raw_dir, "proxy_capture.txt")
            proxy_requests_path = os.path.join(output_dir, "enumeration", "http-requests", "proxy_requests.txt")
            proxy_responses_path = os.path.join(output_dir, "enumeration", "http-responses", "proxy_responses.txt")
            proxy_domains_path = os.path.join(output_dir, "enumeration", "domains", "proxy_domains.txt")
            proxy_endpoints_path = os.path.join(output_dir, "enumeration", "endpoints", "proxy_endpoints.txt")
            proxy_summary_path = os.path.join(parsed_dir, "proxy_summary.txt")
            proxy_files_path = os.path.join(output_dir, "enumeration", "scrapped_files", "proxy_files.txt")
            
            proxy_results = run_proxy_capture(args.target, proxy_raw_path)
            proxy_requests = proxy_results.get("requests", [])
            proxy_responses = proxy_results.get("responses", [])
            proxy_domains = proxy_results.get("domains", [])
            proxy_endpoints = proxy_results.get("endpoints", [])
            proxy_summary = proxy_results.get("summary", {})
            proxy_files = proxy_results.get("files", {})
            
            with open(proxy_requests_path, "w") as f:
                for request in proxy_requests:
                    f.write(f"{request}\n")
            with open(proxy_responses_path, "w") as f:
                for response in proxy_responses:
                    f.write(f"{response}\n")
            with open(proxy_domains_path, "w") as f:
                for domain in proxy_domains:
                    f.write(f"{domain}\n")
            with open(proxy_endpoints_path, "w") as f:
                for endpoint in proxy_endpoints:
                    f.write(f"{endpoint}\n")
            with open(proxy_summary_path, "w") as f:
                for key, value in proxy_summary.items():
                    f.write(f"{key}: {value}\n")
            with open(proxy_files_path, "w") as f:
                for file in proxy_files:
                    f.write(f"{file}\n")

            if proxy_results.get("success"):
                save_json(proxy_results, os.path.join(parsed_dir, "proxy_capture_results.json"))
                all_results["proxy_capture"] = proxy_results
                
                # Save infrastructure map to raw directory
                if proxy_results.get("files", {}).get("infrastructure_file"):
                    infrastructure_file = proxy_results["files"]["infrastructure_file"]
                    raw_ok = save_raw_to_db("proxy_capture", args.target, infrastructure_file, raw_api_url, jwt_token)
                    parsed_ok = save_parsed_to_db("proxy_capture", args.target, proxy_results, parsed_api_url, jwt_token)
                    summary["proxy_capture"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                    
                    print(f"[INFO] Proxy capture completed successfully")
                    print(f"  - Requests captured: {proxy_results.get('summary', {}).get('total_requests', 0)}")
                    print(f"  - Responses captured: {proxy_results.get('summary', {}).get('total_responses', 0)}")
                    print(f"  - Unique domains: {proxy_results.get('summary', {}).get('unique_domains', 0)}")
                    print(f"  - Unique endpoints: {proxy_results.get('summary', {}).get('unique_endpoints', 0)}")
                else:
                    summary["proxy_capture"] = {"runner": False, "error": "No infrastructure file generated"}
            else:
                print(f"[ERROR] Proxy capture failed: {proxy_results.get('error', 'Unknown error')}")
                summary["proxy_capture"] = {"runner": False, "error": proxy_results.get('error', 'Unknown error')}
        except Exception as e:
            print(f"[ERROR] Proxy capture runner failed: {e}")
            summary["proxy_capture"] = {"runner": False, "error": str(e)}
    else:
        print("[WARNING] Proxy capture requested but not available (mitmproxy dependency missing)")
        summary["proxy_capture"] = {"runner": False, "error": "Proxy capture not available"}

    # Step 2: PureDNS Live Server Detection
    print(f"[INFO] Starting PureDNS live server detection for {len(subdomains)} subdomains")
    try:
        puredns_raw_path = os.path.join(raw_dir, "puredns_scan.txt")
        puredns_results = run_puredns(subdomains, puredns_raw_path)
        if puredns_results.get("success"):
            save_json(puredns_results, os.path.join(parsed_dir, "puredns_results.json"))
            all_results["puredns"] = puredns_results
            
            # Save live servers list to IPs-and-open-ports directory
            live_servers_file = os.path.join(output_dir, "enumeration", "live_servers", "live_servers.json")
            with open(live_servers_file, 'w') as f:
                json.dump(puredns_results["server_details"], f, indent=2)
            
            # Update subdomains to only include live servers
            live_servers = puredns_results.get("live_servers", [])
            if live_servers:
                subdomains = live_servers
                print(f"[INFO] Updated subdomain list to {len(subdomains)} live servers")
            
            raw_ok = save_raw_to_db("puredns", args.target, puredns_results["files"]["results_file"], raw_api_url, jwt_token)
            parsed_ok = save_parsed_to_db("puredns", args.target, puredns_results, parsed_api_url, jwt_token)
            summary["puredns"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] PureDNS completed successfully")
            print(f"  - Live servers found: {len(live_servers)}")
            print(f"  - Unique IPs: {puredns_results.get('summary', {}).get('unique_ips', 0)}")
            print(f"  - CIDR ranges: {puredns_results.get('summary', {}).get('cidr_ranges', 0)}")
        else:
            print(f"[ERROR] PureDNS failed: {puredns_results.get('error', 'Unknown error')}")
            summary["puredns"] = {"runner": False, "error": puredns_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] PureDNS runner failed: {e}")
        summary["puredns"] = {"runner": False, "error": str(e)}

    # Naabu port scanning
    try:
        naabu_raw_path = os.path.join(raw_dir, "naabu_scan.txt")
        naabu_results = run_naabu(subdomains, naabu_raw_path)
        save_json(naabu_results, os.path.join(parsed_dir, "naabu_results.json"))
        all_results["naabu"] = naabu_results
        raw_ok = save_raw_to_db("naabu", args.target, naabu_raw_path, raw_api_url, jwt_token)
        parsed_ok = save_parsed_to_db("naabu", args.target, naabu_results, parsed_api_url, jwt_token)
        summary["naabu"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Naabu runner failed: {e}")
        summary["naabu"] = {"runner": False, "error": str(e)}

    # Nmap scanning
    try:
        nmap_raw_path = os.path.join(raw_dir, "nmap_scan.xml")
        nmap_results = run_nmap(subdomains, nmap_raw_path)
        save_json(nmap_results, os.path.join(parsed_dir, "nmap_results.json"))
        all_results["nmap"] = nmap_results
        raw_ok = save_raw_to_db("nmap", args.target, nmap_raw_path, raw_api_url, jwt_token)
        parsed_ok = save_parsed_to_db("nmap", args.target, nmap_results, parsed_api_url, jwt_token)
        summary["nmap"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Nmap runner failed: {e}")
        summary["nmap"] = {"runner": False, "error": str(e)}

    # Extract live web servers from port scanning results
    live_servers = []
    if "nmap" in all_results and all_results["nmap"].get("success"):
        for host in all_results["nmap"].get("hosts", []):
            if any(
                isinstance(port, dict) and port.get("service") in [
                    "http", "https", "http-proxy", "https-proxy", "ftp", "ftps", "ssh", "sftp", "smtp", "smtps",
                    "pop3", "pop3s", "imap", "imaps", "telnet", "dns", "ntp", "postgres", "postgresql", "database",
                    "mysql", "mssql", "oracle", "redis", "mongodb", "ldap", "ldaps", "rdp", "vnc", "svn", "git",
                    "svn+ssh", "git+ssh", "nfs", "smb", "webdav", "webdavs", "rtsp", "sip", "xmpp", "irc", "amqp",
                    "mqtt", "coap", "tftp", "snmp", "rsync", "cups", "kafka", "elasticsearch", "solr", "memcached"
                ]
                for port in host.get("ports", [])
            ):
                live_servers.append(host.get("hostname", ""))
    if "naabu" in all_results and all_results["naabu"].get("success"):
        for host in all_results["naabu"].get("hosts", []):
            if any(
                isinstance(port, dict) and port.get("service") in [
                    "http", "https", "http-proxy", "https-proxy", "ftp", "ftps", "ssh", "sftp", "smtp", "smtps",
                    "pop3", "pop3s", "imap", "imaps", "telnet", "dns", "ntp", "postgres", "postgresql", "database",
                    "mysql", "mssql", "oracle", "redis", "mongodb", "ldap", "ldaps", "rdp", "vnc", "svn", "git",
                    "svn+ssh", "git+ssh", "nfs", "smb", "webdav", "webdavs", "rtsp", "sip", "xmpp", "irc", "amqp",
                    "mqtt", "coap", "tftp", "snmp", "rsync", "cups", "kafka", "elasticsearch", "solr", "memcached"
                ]
                for port in host.get("ports", [])
            ):
                if host.get("hostname") not in live_servers:
                    live_servers.append(host.get("hostname", ""))
    
    # Save live servers list
    if live_servers:
        live_servers_file = os.path.join(output_dir, "enumeration", "live_servers", "live_servers.txt")
        with open(live_servers_file, 'w') as f:
            for server in live_servers:
                f.write(f"{server}\n")
        
        print(f"[INFO] Identified {len(live_servers)} live web servers from port scanning")
    else:
        print("[WARNING] No live web servers identified from port scanning")

    # Step 3: WebAnalyze Technology Detection
    print(f"[INFO] Starting webAnalyze technology detection for {len(subdomains)} targets")
    try:
        webanalyze_raw_path = os.path.join(raw_dir, "webanalyze_scan.txt")
        webanalyze_results = run_webanalyze(subdomains, webanalyze_raw_path)
        if webanalyze_results.get("success"):
            save_json(webanalyze_results, os.path.join(parsed_dir, "webanalyze_results.json"))
            all_results["webanalyze"] = webanalyze_results
            
            # Enhance port scan results with technology information
            if "naabu" in all_results:
                enhanced_naabu = enhance_port_scan_results(all_results["naabu"], webanalyze_results)
                all_results["naabu"] = enhanced_naabu
                save_json(enhanced_naabu, os.path.join(parsed_dir, "naabu_enhanced_results.json"))
            
            if "nmap" in all_results:
                enhanced_nmap = enhance_port_scan_results(all_results["nmap"], webanalyze_results)
                all_results["nmap"] = enhanced_nmap
                save_json(enhanced_nmap, os.path.join(parsed_dir, "nmap_enhanced_results.json"))
            
            # Save technology mapping to IPs-and-open-ports directory
            tech_mapping_file = os.path.join(output_dir, "enumeration", "infrastructure", "technology_mapping.json")
            with open(tech_mapping_file, 'w') as f:
                json.dump(webanalyze_results["target_technologies"], f, indent=2)
            
            raw_ok = save_raw_to_db("webanalyze", args.target, webanalyze_results["files"]["results_file"], api_url, jwt_token)
            parsed_ok = save_parsed_to_db("webanalyze", args.target, webanalyze_results, api_url, jwt_token)
            summary["webanalyze"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] webAnalyze completed successfully")
            print(f"  - Technologies found: {webanalyze_results.get('summary', {}).get('total_technologies', 0)}")
            print(f"  - Unique technologies: {webanalyze_results.get('summary', {}).get('unique_technologies', 0)}")
            print(f"  - Technology categories: {webanalyze_results.get('summary', {}).get('categories_found', 0)}")
        else:
            print(f"[ERROR] webAnalyze failed: {webanalyze_results.get('error', 'Unknown error')}")
            summary["webanalyze"] = {"runner": False, "error": webanalyze_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] webAnalyze runner failed: {e}")
        summary["webanalyze"] = {"runner": False, "error": str(e)}

    # Step 4: Directory Enumeration
    print(f"[INFO] Starting directory enumeration for {len(subdomains)} targets")
    
    # Use live servers identified from port scanning for directory enumeration
    web_targets = live_servers.copy()
    
    if not web_targets:
        print("[WARNING] No live web servers found for directory enumeration")
        web_targets = subdomains  # Fallback to all subdomains
    
    print(f"[INFO] Found {len(web_targets)} web targets for directory enumeration")
    
    # Katana directory enumeration
    try:
        katana_raw_path = os.path.join(raw_dir, "katana_scan.txt")
        katana_results = run_katana(web_targets, katana_raw_path)
        if katana_results.get("success"):
            save_json(katana_results, os.path.join(parsed_dir, "katana_results.json"))
            all_results["katana"] = katana_results
            
            # Save interesting files to scrapped_files directory
            if katana_results.get("interesting_files"):
                for file_info in katana_results["interesting_files"]:
                    file_type = file_info.get("extension", "unknown")
                    file_type_dir = os.path.join(output_dir, "enumeration", "scrapped_files", file_type)
                    os.makedirs(file_type_dir, exist_ok=True)
                    
                    # Save file info to type-specific directory
                    file_info_path = os.path.join(file_type_dir, f"{file_info['hostname']}_{file_info['path'].replace('/', '_')}.json")
                    with open(file_info_path, 'w') as f:
                        json.dump(file_info, f, indent=2)
            
            # Save endpoint mapping
            if katana_results.get("endpoint_mapping"):
                for hostname, endpoints in katana_results["endpoint_mapping"].items():
                    endpoint_file = os.path.join(output_dir, "enumeration", "endpoints", f"{hostname}_endpoints.json")
                    with open(endpoint_file, 'w') as f:
                        json.dump(endpoints, f, indent=2)
            
            raw_ok = save_raw_to_db("katana", args.target, katana_results["files"]["results_file"], api_url, jwt_token)
            parsed_ok = save_parsed_to_db("katana", args.target, katana_results, api_url, jwt_token)
            summary["katana"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] Katana completed successfully")
            print(f"  - URLs found: {katana_results.get('summary', {}).get('total_urls', 0)}")
            print(f"  - Unique endpoints: {katana_results.get('summary', {}).get('unique_endpoints', 0)}")
            print(f"  - Interesting files: {katana_results.get('summary', {}).get('interesting_files', 0)}")
        else:
            print(f"[ERROR] Katana failed: {katana_results.get('error', 'Unknown error')}")
            summary["katana"] = {"runner": False, "error": katana_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] Katana runner failed: {e}")
        summary["katana"] = {"runner": False, "error": str(e)}
    
    # Feroxbuster directory enumeration
    try:
        feroxbuster_raw_path = os.path.join(raw_dir, "feroxbuster_scan.txt")
        feroxbuster_results = run_feroxbuster(web_targets, feroxbuster_raw_path)
        if feroxbuster_results.get("success"):
            save_json(feroxbuster_results, os.path.join(parsed_dir, "feroxbuster_results.json"))
            all_results["feroxbuster"] = feroxbuster_results
            
            # Save interesting files to scrapped_files directory
            if feroxbuster_results.get("interesting_files"):
                for file_info in feroxbuster_results["interesting_files"]:
                    file_type = file_info.get("extension", "unknown")
                    file_type_dir = os.path.join(output_dir, "enumeration", "scrapped_files", file_type)
                    os.makedirs(file_type_dir, exist_ok=True)
                    
                    # Save file info to type-specific directory
                    file_info_path = os.path.join(file_type_dir, f"{file_info['hostname']}_{file_info['path'].replace('/', '_')}.json")
                    with open(file_info_path, 'w') as f:
                        json.dump(file_info, f, indent=2)
            
            # Save endpoint mapping
            if feroxbuster_results.get("endpoint_mapping"):
                for hostname, endpoints in feroxbuster_results["endpoint_mapping"].items():
                    endpoint_file = os.path.join(output_dir, "enumeration", "endpoints", f"{hostname}_feroxbuster_endpoints.json")
                    with open(endpoint_file, 'w') as f:
                        json.dump(endpoints, f, indent=2)
            
            raw_ok = save_raw_to_db("feroxbuster", args.target, feroxbuster_results["files"]["results_file"], api_url, jwt_token)
            parsed_ok = save_parsed_to_db("feroxbuster", args.target, feroxbuster_results, api_url, jwt_token)
            summary["feroxbuster"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] Feroxbuster completed successfully")
            print(f"  - URLs found: {feroxbuster_results.get('summary', {}).get('total_urls', 0)}")
            print(f"  - Unique endpoints: {feroxbuster_results.get('summary', {}).get('unique_endpoints', 0)}")
            print(f"  - Interesting files: {feroxbuster_results.get('summary', {}).get('interesting_files', 0)}")
        else:
            print(f"[ERROR] Feroxbuster failed: {feroxbuster_results.get('error', 'Unknown error')}")
            summary["feroxbuster"] = {"runner": False, "error": feroxbuster_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] Feroxbuster runner failed: {e}")
        summary["feroxbuster"] = {"runner": False, "error": str(e)}

    # Step 5: JavaScript Analysis
    print(f"[INFO] Starting JavaScript analysis for discovered web applications")
    
    # Get JavaScript files from getJS
    js_files = []
    try:
        getjs_raw_path = os.path.join(raw_dir, "getjs_scan.txt")
        getjs_results = run_getjs(web_targets, getjs_raw_path)
        if getjs_results.get("success"):
            save_json(getjs_results, os.path.join(parsed_dir, "getjs_results.json"))
            all_results["getjs"] = getjs_results
            
            # Collect JavaScript file paths for LinkFinder analysis
            if getjs_results.get("js_files_found"):
                for js_file_info in getjs_results["js_files_found"]:
                    js_files.append(js_file_info.get("file_path", ""))
            
            raw_ok = save_raw_to_db("getjs", args.target, getjs_results["files"]["results_file"], api_url, jwt_token)
            parsed_ok = save_parsed_to_db("getjs", args.target, getjs_results, api_url, jwt_token)
            summary["getjs"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] GetJS completed successfully")
            print(f"  - JS files found: {getjs_results.get('summary', {}).get('total_js_files', 0)}")
            print(f"  - Endpoints found: {getjs_results.get('summary', {}).get('total_endpoints', 0)}")
            print(f"  - Unique endpoints: {getjs_results.get('summary', {}).get('unique_endpoints', 0)}")
        else:
            print(f"[ERROR] GetJS failed: {getjs_results.get('error', 'Unknown error')}")
            summary["getjs"] = {"runner": False, "error": getjs_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] GetJS runner failed: {e}")
        summary["getjs"] = {"runner": False, "error": str(e)}
    
    # Run LinkFinder on discovered JavaScript files
    if js_files:
        try:
            linkfinder_raw_path = os.path.join(raw_dir, "linkfinder_scan.txt")
            linkfinder_results = run_linkfinder(js_files, linkfinder_raw_path)
            if linkfinder_results.get("success"):
                save_json(linkfinder_results, os.path.join(parsed_dir, "linkfinder_results.json"))
                all_results["linkfinder"] = linkfinder_results
                
                # Save endpoint discoveries
                if linkfinder_results.get("all_endpoints"):
                    endpoints_file = os.path.join(output_dir, "enumeration", "endpoints", "all_endpoints.json")
                    os.makedirs(os.path.dirname(endpoints_file), exist_ok=True)
                    with open(endpoints_file, 'w') as f:
                        json.dump(linkfinder_results["all_endpoints"], f, indent=2)
                
                raw_ok = save_raw_to_db("linkfinder", args.target, linkfinder_results["files"]["results_file"], api_url, jwt_token)
                parsed_ok = save_parsed_to_db("linkfinder", args.target, linkfinder_results, api_url, jwt_token)
                summary["linkfinder"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                
                print(f"[INFO] LinkFinder completed successfully")
                print(f"  - Files processed: {linkfinder_results.get('summary', {}).get('successful_files', 0)}")
                print(f"  - Endpoints found: {linkfinder_results.get('summary', {}).get('total_endpoints', 0)}")
                print(f"  - Unique endpoints: {linkfinder_results.get('summary', {}).get('unique_endpoints', 0)}")
            else:
                print(f"[ERROR] LinkFinder failed: {linkfinder_results.get('error', 'Unknown error')}")
                summary["linkfinder"] = {"runner": False, "error": linkfinder_results.get('error', 'Unknown error')}
        except Exception as e:
            print(f"[ERROR] LinkFinder runner failed: {e}")
            summary["linkfinder"] = {"runner": False, "error": str(e)}
    else:
        print("[WARNING] No JavaScript files found for LinkFinder analysis")
        summary["linkfinder"] = {"runner": False, "error": "No JavaScript files available"}

    # Step 6: Parameter Discovery
    print(f"[INFO] Starting parameter discovery for discovered endpoints")
    
    # Collect all discovered endpoints for parameter discovery
    all_endpoints = []
    
    # Add endpoints from directory enumeration
    if "katana" in all_results and all_results["katana"].get("success"):
        for url_data in all_results["katana"].get("urls_found", []):
            all_endpoints.append(url_data.get("url", ""))
    
    if "feroxbuster" in all_results and all_results["feroxbuster"].get("success"):
        for url_data in all_results["feroxbuster"].get("urls_found", []):
            all_endpoints.append(url_data.get("url", ""))
    
    # Add endpoints from JavaScript analysis
    if "getjs" in all_results and all_results["getjs"].get("success"):
        for endpoint_data in all_results["getjs"].get("js_endpoints", []):
            all_endpoints.append(endpoint_data.get("endpoint", ""))
    
    if "linkfinder" in all_results and all_results["linkfinder"].get("success"):
        for endpoint_data in all_results["linkfinder"].get("all_endpoints", []):
            all_endpoints.append(endpoint_data.get("endpoint", ""))
    
    # Remove duplicates and filter valid URLs
    unique_endpoints = list(set([ep for ep in all_endpoints if ep and (ep.startswith('http') or ep.startswith('/'))]))
    
    if unique_endpoints:
        try:
            arjun_raw_path = os.path.join(raw_dir, "arjun_scan.txt")
            arjun_results = run_arjun(unique_endpoints, arjun_raw_path)
            if arjun_results.get("success"):
                save_json(arjun_results, os.path.join(parsed_dir, "arjun_results.json"))
                all_results["arjun"] = arjun_results
                
                # Save interesting parameters
                if arjun_results.get("interesting_parameters"):
                    interesting_params_file = os.path.join(output_dir, "enumeration", "parameters", "interesting_parameters.json")
                    os.makedirs(os.path.dirname(interesting_params_file), exist_ok=True)
                    with open(interesting_params_file, 'w') as f:
                        json.dump(arjun_results["interesting_parameters"], f, indent=2)
                
                # Save parameter mapping
                if arjun_results.get("parameter_mapping"):
                    for hostname, params in arjun_results["parameter_mapping"].items():
                        param_file = os.path.join(output_dir, "enumeration", "parameters", f"{hostname}_parameters.json")
                        with open(param_file, 'w') as f:
                            json.dump(params, f, indent=2)
                
                raw_ok = save_raw_to_db("arjun", args.target, arjun_results["files"]["results_file"], api_url, jwt_token)
                parsed_ok = save_parsed_to_db("arjun", args.target, arjun_results, api_url, jwt_token)
                summary["arjun"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                
                print(f"[INFO] Arjun completed successfully")
                print(f"  - Endpoints checked: {arjun_results.get('summary', {}).get('total_endpoints', 0)}")
                print(f"  - Unique parameters: {arjun_results.get('summary', {}).get('unique_parameters', 0)}")
                print(f"  - Interesting parameters: {arjun_results.get('summary', {}).get('interesting_parameters_count', 0)}")
            else:
                print(f"[ERROR] Arjun failed: {arjun_results.get('error', 'Unknown error')}")
                summary["arjun"] = {"runner": False, "error": arjun_results.get('error', 'Unknown error')}
        except Exception as e:
            print(f"[ERROR] Arjun runner failed: {e}")
            summary["arjun"] = {"runner": False, "error": str(e)}
    else:
        print("[WARNING] No endpoints found for parameter discovery")
        summary["arjun"] = {"runner": False, "error": "No endpoints available for parameter discovery"}

    # Step 7: Screenshot Capture with EyeWitness
    print(f"[INFO] Starting screenshot capture for discovered web applications")
    
    # Use live servers for screenshot capture
    screenshot_targets = live_servers.copy()
    if not screenshot_targets:
        print("[WARNING] No live servers available for screenshot capture")
        summary["eyewitness"] = {"runner": False, "error": "No live servers available"}
    else:
        try:
            eyewitness_raw_path = os.path.join(raw_dir, "eyewitness_scan.txt")
            eyewitness_output_path = os.path.join(output_dir, "enumeration", "screenshots", f"{args.target}", "eyewitness_screenshots")
            eyewitness_results = run_eyewitness(screenshot_targets, eyewitness_raw_path)
            if eyewitness_results.get("success"):
                save_json(eyewitness_results, os.path.join(parsed_dir, "eyewitness_results.json"))
                all_results["eyewitness"] = eyewitness_results
                
                # Save screenshot report
                if eyewitness_results.get("screenshots"):
                    from runners.run_eyewitness import generate_screenshot_report
                    screenshot_report = generate_screenshot_report(
                        eyewitness_results["screenshots"], 
                        eyewitness_output_path
                    )
                    all_results["eyewitness"]["screenshot_report"] = screenshot_report
                
                raw_ok = save_raw_to_db("eyewitness", args.target, eyewitness_results["files"]["targets_file"], api_url, jwt_token)
                parsed_ok = save_parsed_to_db("eyewitness", args.target, eyewitness_results, api_url, jwt_token)
                summary["eyewitness"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                
                print(f"[INFO] EyeWitness completed successfully")
                print(f"  - Targets processed: {eyewitness_results.get('summary', {}).get('total_targets', 0)}")
                print(f"  - Screenshots captured: {eyewitness_results.get('summary', {}).get('successful_screenshots', 0)}")
                print(f"  - Failed captures: {eyewitness_results.get('summary', {}).get('failed_screenshots', 0)}")
            else:
                print(f"[ERROR] EyeWitness failed: {eyewitness_results.get('error', 'Unknown error')}")
                summary["eyewitness"] = {"runner": False, "error": eyewitness_results.get('error', 'Unknown error')}
        except Exception as e:
            print(f"[ERROR] EyeWitness runner failed: {e}")
            summary["eyewitness"] = {"runner": False, "error": str(e)}

    # Step 8: Screenshot Analysis with EyeBaller
    print(f"[INFO] Starting screenshot analysis with EyeBaller")
    
    # Check if we have screenshots to analyze
    if "eyewitness" in all_results and all_results["eyewitness"].get("success"):
        screenshots_dir = all_results["eyewitness"]["files"]["output_dir"]
        
        try:
            eyeballer_raw_path = os.path.join(raw_dir, "eyeballer_scan.txt")
            eyeballer_output_path = os.path.join(output_dir, "enumeration", "findings", f"{args.target}", "eyeballer_findings")
            eyeballer_results = run_eyeballer(screenshots_dir, eyeballer_raw_path)
            if eyeballer_results.get("success"):
                save_json(eyeballer_results, os.path.join(parsed_dir, "eyeballer_results.json"))
                all_results["eyeballer"] = eyeballer_results
                
                # Save analysis report
                if eyeballer_results.get("interesting_findings"):
                    from runners.run_eyeballer import generate_analysis_report
                    analysis_report = generate_analysis_report(
                        eyeballer_results["interesting_findings"], 
                        eyeballer_output_path
                    )
                    all_results["eyeballer"]["analysis_report"] = analysis_report
                
                raw_ok = save_raw_to_db("eyeballer", args.target, eyeballer_results["files"]["results_file"], api_url, jwt_token)
                parsed_ok = save_parsed_to_db("eyeballer", args.target, eyeballer_results, api_url, jwt_token)
                summary["eyeballer"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                
                print(f"[INFO] EyeBaller completed successfully")
                print(f"  - Screenshots analyzed: {eyeballer_results.get('summary', {}).get('analyzed_screenshots', 0)}")
                print(f"  - Interesting findings: {eyeballer_results.get('summary', {}).get('interesting_findings', 0)}")
            else:
                print(f"[ERROR] EyeBaller failed: {eyeballer_results.get('error', 'Unknown error')}")
                summary["eyeballer"] = {"runner": False, "error": eyeballer_results.get('error', 'Unknown error')}
        except Exception as e:
            print(f"[ERROR] EyeBaller runner failed: {e}")
            summary["eyeballer"] = {"runner": False, "error": str(e)}
    else:
        print("[WARNING] No screenshots available for EyeBaller analysis")
        summary["eyeballer"] = {"runner": False, "error": "No screenshots available"}

    # Enhanced Active Recon Tools Execution
    
    # Step 9: Enhanced Subdomain Enumeration
    print(f"[INFO] Starting enhanced subdomain enumeration")
    try:
        enhanced_subdomain_raw_path = os.path.join(raw_dir, "enhanced_subdomain_enum.txt")
        enhanced_subdomain_results = run_enhanced_subdomain_enumeration(args.target, passive_results, enhanced_subdomain_raw_path)
        if enhanced_subdomain_results.get("success"):
            save_json(enhanced_subdomain_results, os.path.join(parsed_dir, "enhanced_subdomain_results.json"))
            all_results["enhanced_subdomain_enum"] = enhanced_subdomain_results
            
            # Save takeover checks
            if enhanced_subdomain_results.get("results", {}).get("takeover_checks", {}).get("results"):
                takeover_file = os.path.join(output_dir, "enumeration", "takeover_checks", "takeover_checks.json")
                with open(takeover_file, 'w') as f:
                    json.dump(enhanced_subdomain_results["results"]["takeover_checks"]["results"], f, indent=2)
            
            # Save third-party services
            if enhanced_subdomain_results.get("results", {}).get("third_party_services", {}).get("services_found"):
                third_party_file = os.path.join(output_dir, "enumeration", "third_party_services", "third_party_services.json")
                with open(third_party_file, 'w') as f:
                    json.dump(enhanced_subdomain_results["results"]["third_party_services"]["services_found"], f, indent=2)
            
            raw_ok = save_raw_to_db("enhanced_subdomain_enum", args.target, enhanced_subdomain_raw_path, raw_api_url, jwt_token)
            parsed_ok = save_parsed_to_db("enhanced_subdomain_enum", args.target, enhanced_subdomain_results, parsed_api_url, jwt_token)
            summary["enhanced_subdomain_enum"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] Enhanced subdomain enumeration completed successfully")
            print(f"  - Total unique subdomains: {enhanced_subdomain_results.get('summary', {}).get('total_unique_subdomains', 0)}")
            print(f"  - Takeover vulnerabilities: {enhanced_subdomain_results.get('summary', {}).get('takeover_vulnerabilities', 0)}")
            print(f"  - Third-party services: {enhanced_subdomain_results.get('summary', {}).get('third_party_services', 0)}")
        else:
            print(f"[ERROR] Enhanced subdomain enumeration failed: {enhanced_subdomain_results.get('error', 'Unknown error')}")
            summary["enhanced_subdomain_enum"] = {"runner": False, "error": enhanced_subdomain_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] Enhanced subdomain enumeration runner failed: {e}")
        summary["enhanced_subdomain_enum"] = {"runner": False, "error": str(e)}

    # Step 10: WAF and CDN Detection
    print(f"[INFO] Starting WAF and CDN detection")
    try:
        waf_cdn_raw_path = os.path.join(raw_dir, "waf_cdn_detection.txt")
        waf_cdn_results = run_waf_cdn_detection(args.target, waf_cdn_raw_path)
        if waf_cdn_results.get("success"):
            save_json(waf_cdn_results, os.path.join(parsed_dir, "waf_cdn_results.json"))
            all_results["waf_cdn_detection"] = waf_cdn_results
            
            # Save origin servers
            if waf_cdn_results.get("results", {}).get("origin_discovery", {}).get("origin_ips"):
                origin_file = os.path.join(output_dir, "enumeration", "origin_servers", "origin_servers.json")
                with open(origin_file, 'w') as f:
                    json.dump(waf_cdn_results["results"]["origin_discovery"]["origin_ips"], f, indent=2)
            
            # Save security headers
            if waf_cdn_results.get("results", {}).get("security_headers", {}).get("security_headers"):
                headers_file = os.path.join(output_dir, "enumeration", "security_headers", "security_headers.json")
                with open(headers_file, 'w') as f:
                    json.dump(waf_cdn_results["results"]["security_headers"]["security_headers"], f, indent=2)
            
            raw_ok = save_raw_to_db("waf_cdn_detection", args.target, waf_cdn_raw_path, raw_api_url, jwt_token)
            parsed_ok = save_parsed_to_db("waf_cdn_detection", args.target, waf_cdn_results, parsed_api_url, jwt_token)
            summary["waf_cdn_detection"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] WAF and CDN detection completed successfully")
            print(f"  - WAF detected: {waf_cdn_results.get('summary', {}).get('waf_detected', False)}")
            print(f"  - CDN detected: {waf_cdn_results.get('summary', {}).get('cdn_detected', False)}")
            print(f"  - Origin IPs found: {waf_cdn_results.get('summary', {}).get('origin_ips_found', 0)}")
        else:
            print(f"[ERROR] WAF and CDN detection failed: {waf_cdn_results.get('error', 'Unknown error')}")
            summary["waf_cdn_detection"] = {"runner": False, "error": waf_cdn_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] WAF and CDN detection runner failed: {e}")
        summary["waf_cdn_detection"] = {"runner": False, "error": str(e)}

    # Step 11: Cloud Infrastructure Enumeration
    print(f"[INFO] Starting cloud infrastructure enumeration")
    try:
        cloud_raw_path = os.path.join(raw_dir, "cloud_infrastructure.txt")
        cloud_results = run_cloud_infrastructure_enumeration(args.target, cloud_raw_path)
        if cloud_results.get("success"):
            save_json(cloud_results, os.path.join(parsed_dir, "cloud_infrastructure_results.json"))
            all_results["cloud_infrastructure"] = cloud_results
            
            # Save cloud findings
            cloud_file = os.path.join(output_dir, "enumeration", "cloud_infrastructure", "cloud_findings.json")
            with open(cloud_file, 'w') as f:
                json.dump(cloud_results["results"], f, indent=2)
            
            raw_ok = save_raw_to_db("cloud_infrastructure", args.target, cloud_raw_path, raw_api_url, jwt_token)
            parsed_ok = save_parsed_to_db("cloud_infrastructure", args.target, cloud_results, parsed_api_url, jwt_token)
            summary["cloud_infrastructure"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] Cloud infrastructure enumeration completed successfully")
            print(f"  - S3 buckets found: {cloud_results.get('summary', {}).get('s3_buckets_found', 0)}")
            print(f"  - Azure containers found: {cloud_results.get('summary', {}).get('azure_containers_found', 0)}")
            print(f"  - GCP buckets found: {cloud_results.get('summary', {}).get('gcp_buckets_found', 0)}")
        else:
            print(f"[ERROR] Cloud infrastructure enumeration failed: {cloud_results.get('error', 'Unknown error')}")
            summary["cloud_infrastructure"] = {"runner": False, "error": cloud_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] Cloud infrastructure enumeration runner failed: {e}")
        summary["cloud_infrastructure"] = {"runner": False, "error": str(e)}

    # Step 12: Input Vectors Discovery
    print(f"[INFO] Starting input vectors discovery")
    try:
        # Collect all discovered endpoints for input vectors analysis
        all_endpoints = []
        if "katana" in all_results and all_results["katana"].get("success"):
            for url_data in all_results["katana"].get("urls_found", []):
                all_endpoints.append(url_data.get("url", ""))
        if "feroxbuster" in all_results and all_results["feroxbuster"].get("success"):
            for url_data in all_results["feroxbuster"].get("urls_found", []):
                all_endpoints.append(url_data.get("url", ""))
        
        if all_endpoints:
            input_vectors_raw_path = os.path.join(raw_dir, "input_vectors_discovery.txt")
            input_vectors_results = run_input_vectors_discovery(args.target, all_endpoints, input_vectors_raw_path)
            if input_vectors_results.get("success"):
                save_json(input_vectors_results, os.path.join(parsed_dir, "input_vectors_results.json"))
                all_results["input_vectors_discovery"] = input_vectors_results
                
                # Save input vectors findings
                input_vectors_file = os.path.join(output_dir, "enumeration", "input_vectors", "input_vectors.json")
                with open(input_vectors_file, 'w') as f:
                    json.dump(input_vectors_results["results"], f, indent=2)
                
                raw_ok = save_raw_to_db("input_vectors_discovery", args.target, input_vectors_raw_path, raw_api_url, jwt_token)
                parsed_ok = save_parsed_to_db("input_vectors_discovery", args.target, input_vectors_results, parsed_api_url, jwt_token)
                summary["input_vectors_discovery"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                
                print(f"[INFO] Input vectors discovery completed successfully")
                print(f"  - HTTP header inputs: {input_vectors_results.get('summary', {}).get('http_header_inputs', 0)}")
                print(f"  - JSON endpoints: {input_vectors_results.get('summary', {}).get('json_endpoints', 0)}")
                print(f"  - Upload endpoints: {input_vectors_results.get('summary', {}).get('upload_endpoints', 0)}")
            else:
                print(f"[ERROR] Input vectors discovery failed: {input_vectors_results.get('error', 'Unknown error')}")
                summary["input_vectors_discovery"] = {"runner": False, "error": input_vectors_results.get('error', 'Unknown error')}
        else:
            print("[WARNING] No endpoints found for input vectors discovery")
            summary["input_vectors_discovery"] = {"runner": False, "error": "No endpoints available"}
    except Exception as e:
        print(f"[ERROR] Input vectors discovery runner failed: {e}")
        summary["input_vectors_discovery"] = {"runner": False, "error": str(e)}

    # Step 13: Dynamic Analysis
    print(f"[INFO] Starting dynamic analysis")
    try:
        # Collect JavaScript files for dynamic analysis
        js_files = []
        if "getjs" in all_results and all_results["getjs"].get("success"):
            for js_file_info in all_results["getjs"].get("js_files_found", []):
                js_files.append(js_file_info.get("file_path", ""))
        
        if js_files:
            dynamic_raw_path = os.path.join(raw_dir, "dynamic_analysis.txt")
            dynamic_results = run_dynamic_analysis(args.target, js_files, dynamic_raw_path)
            if dynamic_results.get("success"):
                save_json(dynamic_results, os.path.join(parsed_dir, "dynamic_analysis_results.json"))
                all_results["dynamic_analysis"] = dynamic_results
                
                # Save dynamic analysis findings
                dynamic_file = os.path.join(output_dir, "enumeration", "dynamic_analysis", "dynamic_findings.json")
                with open(dynamic_file, 'w') as f:
                    json.dump(dynamic_results["results"], f, indent=2)
                
                raw_ok = save_raw_to_db("dynamic_analysis", args.target, dynamic_raw_path, raw_api_url, jwt_token)
                parsed_ok = save_parsed_to_db("dynamic_analysis", args.target, dynamic_results, parsed_api_url, jwt_token)
                summary["dynamic_analysis"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
                
                print(f"[INFO] Dynamic analysis completed successfully")
                print(f"  - URLs found: {dynamic_results.get('summary', {}).get('urls_found', 0)}")
                print(f"  - SPA indicators: {dynamic_results.get('summary', {}).get('spa_indicators', 0)}")
                print(f"  - Dynamic forms: {dynamic_results.get('summary', {}).get('dynamic_forms', 0)}")
            else:
                print(f"[ERROR] Dynamic analysis failed: {dynamic_results.get('error', 'Unknown error')}")
                summary["dynamic_analysis"] = {"runner": False, "error": dynamic_results.get('error', 'Unknown error')}
        else:
            print("[WARNING] No JavaScript files found for dynamic analysis")
            summary["dynamic_analysis"] = {"runner": False, "error": "No JavaScript files available"}
    except Exception as e:
        print(f"[ERROR] Dynamic analysis runner failed: {e}")
        summary["dynamic_analysis"] = {"runner": False, "error": str(e)}

    # Step 14: Misconfiguration Detection
    print(f"[INFO] Starting misconfiguration detection")
    try:
        misconfig_raw_path = os.path.join(raw_dir, "misconfiguration_detection.txt")
        misconfig_results = run_misconfiguration_detection(args.target, misconfig_raw_path)
        if misconfig_results.get("success"):
            save_json(misconfig_results, os.path.join(parsed_dir, "misconfiguration_results.json"))
            all_results["misconfiguration_detection"] = misconfig_results
            
            # Save misconfiguration findings
            misconfig_file = os.path.join(output_dir, "enumeration", "misconfigurations", "misconfigurations.json")
            with open(misconfig_file, 'w') as f:
                json.dump(misconfig_results["results"], f, indent=2)
            
            # Save specific findings to separate files
            if misconfig_results.get("results", {}).get("exposed_files", {}).get("exposed_files"):
                exposed_files_file = os.path.join(output_dir, "enumeration", "exposed_files", "exposed_files.json")
                with open(exposed_files_file, 'w') as f:
                    json.dump(misconfig_results["results"]["exposed_files"]["exposed_files"], f, indent=2)
            
            if misconfig_results.get("results", {}).get("default_credentials", {}).get("successful_logins"):
                default_creds_file = os.path.join(output_dir, "enumeration", "default_credentials", "default_credentials.json")
                with open(default_creds_file, 'w') as f:
                    json.dump(misconfig_results["results"]["default_credentials"]["successful_logins"], f, indent=2)
            
            if misconfig_results.get("results", {}).get("directory_listings", {}).get("directory_listings"):
                dir_listings_file = os.path.join(output_dir, "enumeration", "directory_listings", "directory_listings.json")
                with open(dir_listings_file, 'w') as f:
                    json.dump(misconfig_results["results"]["directory_listings"]["directory_listings"], f, indent=2)
            
            raw_ok = save_raw_to_db("misconfiguration_detection", args.target, misconfig_raw_path, raw_api_url, jwt_token)
            parsed_ok = save_parsed_to_db("misconfiguration_detection", args.target, misconfig_results, parsed_api_url, jwt_token)
            summary["misconfiguration_detection"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
            
            print(f"[INFO] Misconfiguration detection completed successfully")
            print(f"  - Exposed files: {misconfig_results.get('summary', {}).get('exposed_files', 0)}")
            print(f"  - Default credentials: {misconfig_results.get('summary', {}).get('default_credentials', 0)}")
            print(f"  - Directory listings: {misconfig_results.get('summary', {}).get('directory_listings', 0)}")
        else:
            print(f"[ERROR] Misconfiguration detection failed: {misconfig_results.get('error', 'Unknown error')}")
            summary["misconfiguration_detection"] = {"runner": False, "error": misconfig_results.get('error', 'Unknown error')}
    except Exception as e:
        print(f"[ERROR] Misconfiguration detection runner failed: {e}")
        summary["misconfiguration_detection"] = {"runner": False, "error": str(e)}

    # Final Step: Directory Structure & API Integration
    print(f"[INFO] Organizing outputs and preparing final results")
    
    # Create comprehensive directory structure
    create_directory_structure(output_dir, all_results)
    
    # Generate comprehensive reports
    generate_reports(output_dir, all_results, summary)
    
    # Aggregate results with comprehensive metrics
    total_hosts_scanned = len(subdomains)
    total_ports_found = sum(len(host.get("ports", [])) for host in all_results.get("nmap", {}).get("hosts", []))
    total_services_found = sum(len(host.get("services", [])) for host in all_results.get("nmap", {}).get("hosts", []))
    total_technologies_found = len(all_results.get("webanalyze", {}).get("technologies", []))
    total_urls_found = (
        len(all_results.get("katana", {}).get("urls_found", [])) +
        len(all_results.get("feroxbuster", {}).get("urls_found", []))
    )
    total_js_endpoints = len(all_results.get("getjs", {}).get("js_endpoints", []))
    total_parameters = len(set([param for ep in all_results.get("arjun", {}).get("endpoints_found", []) for param in ep.get("parameters", [])]))
    total_screenshots = len(all_results.get("eyewitness", {}).get("screenshots", []))
    total_interesting_findings = len(all_results.get("eyeballer", {}).get("interesting_findings", []))
    
    # Enhanced Active Recon Metrics
    total_enhanced_subdomains = all_results.get("enhanced_subdomain_enum", {}).get("summary", {}).get("total_unique_subdomains", 0)
    total_takeover_vulnerabilities = all_results.get("enhanced_subdomain_enum", {}).get("summary", {}).get("takeover_vulnerabilities", 0)
    total_third_party_services = all_results.get("enhanced_subdomain_enum", {}).get("summary", {}).get("third_party_services", 0)
    waf_detected = all_results.get("waf_cdn_detection", {}).get("summary", {}).get("waf_detected", False)
    cdn_detected = all_results.get("waf_cdn_detection", {}).get("summary", {}).get("cdn_detected", False)
    total_origin_ips = all_results.get("waf_cdn_detection", {}).get("summary", {}).get("origin_ips_found", 0)
    total_s3_buckets = all_results.get("cloud_infrastructure", {}).get("summary", {}).get("s3_buckets_found", 0)
    total_azure_containers = all_results.get("cloud_infrastructure", {}).get("summary", {}).get("azure_containers_found", 0)
    total_gcp_buckets = all_results.get("cloud_infrastructure", {}).get("summary", {}).get("gcp_buckets_found", 0)
    total_http_header_inputs = all_results.get("input_vectors_discovery", {}).get("summary", {}).get("http_header_inputs", 0)
    total_json_endpoints = all_results.get("input_vectors_discovery", {}).get("summary", {}).get("json_endpoints", 0)
    total_upload_endpoints = all_results.get("input_vectors_discovery", {}).get("summary", {}).get("upload_endpoints", 0)
    total_dynamic_urls = all_results.get("dynamic_analysis", {}).get("summary", {}).get("urls_found", 0)
    total_spa_indicators = all_results.get("dynamic_analysis", {}).get("summary", {}).get("spa_indicators", 0)
    total_dynamic_forms = all_results.get("dynamic_analysis", {}).get("summary", {}).get("dynamic_forms", 0)
    total_exposed_files = all_results.get("misconfiguration_detection", {}).get("summary", {}).get("exposed_files", 0)
    total_default_credentials = all_results.get("misconfiguration_detection", {}).get("summary", {}).get("default_credentials", 0)
    total_directory_listings = all_results.get("misconfiguration_detection", {}).get("summary", {}).get("directory_listings", 0)
    
    # Create final results summary
    final_results = {
        "target": args.target,
        "stage": args.stage,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_hosts_scanned": total_hosts_scanned,
            "total_ports_found": total_ports_found,
            "total_services_found": total_services_found,
            "total_technologies_found": total_technologies_found,
            "total_urls_found": total_urls_found,
            "total_js_endpoints": total_js_endpoints,
            "total_parameters": total_parameters,
            "total_screenshots": total_screenshots,
            "total_interesting_findings": total_interesting_findings,
            
            # Enhanced Active Recon Summary
            "total_enhanced_subdomains": total_enhanced_subdomains,
            "total_takeover_vulnerabilities": total_takeover_vulnerabilities,
            "total_third_party_services": total_third_party_services,
            "waf_detected": waf_detected,
            "cdn_detected": cdn_detected,
            "total_origin_ips": total_origin_ips,
            "total_s3_buckets": total_s3_buckets,
            "total_azure_containers": total_azure_containers,
            "total_gcp_buckets": total_gcp_buckets,
            "total_http_header_inputs": total_http_header_inputs,
            "total_json_endpoints": total_json_endpoints,
            "total_upload_endpoints": total_upload_endpoints,
            "total_dynamic_urls": total_dynamic_urls,
            "total_spa_indicators": total_spa_indicators,
            "total_dynamic_forms": total_dynamic_forms,
            "total_exposed_files": total_exposed_files,
            "total_default_credentials": total_default_credentials,
            "total_directory_listings": total_directory_listings,
            
            "tools_executed": list(all_results.keys()),
            "successful_tools": [tool for tool, result in summary.items() if result.get("runner")],
            "execution_summary": summary
        },
        "results": all_results,
        "tool_summary": summary
    }
    
    # Save final results
    save_json(final_results, os.path.join(parsed_dir, "active_recon_final_results.json"))
    
    # Submit final results to backend API
    try:
        final_raw_ok = save_raw_to_db("active_recon_final", args.target, os.path.join(parsed_dir, "active_recon_final_results.json"), api_url, jwt_token)
        final_parsed_ok = save_parsed_to_db("active_recon_final", args.target, final_results, api_url, jwt_token)
        print(f"[INFO] Final results submitted to API - Raw: {final_raw_ok}, Parsed: {final_parsed_ok}")
    except Exception as e:
        print(f"[ERROR] Failed to submit final results to API: {e}")
    
    # Print comprehensive summary
    print(f"\n[FINAL SUMMARY] Active recon completed for {args.target}")
    print(f"  - Hosts scanned: {total_hosts_scanned}")
    print(f"  - Ports found: {total_ports_found}")
    print(f"  - Services found: {total_services_found}")
    print(f"  - Technologies detected: {total_technologies_found}")
    print(f"  - URLs discovered: {total_urls_found}")
    print(f"  - JS endpoints found: {total_js_endpoints}")
    print(f"  - Parameters discovered: {total_parameters}")
    print(f"  - Screenshots captured: {total_screenshots}")
    print(f"  - Interesting findings: {total_interesting_findings}")
    print(f"  - Proxy capture: {'Enabled' if args.proxy_capture else 'Disabled'}")

    # Print tool execution summary
    print("\n[TOOL EXECUTION SUMMARY]")
    for tool, result in summary.items():
        if result.get("runner"):
            print(f"✅ {tool}: Success")
        else:
            print(f"❌ {tool}: {result.get('error', 'Unknown error')}")

    # Step 7: Recursive Reconnaissance
    if args.enable_recursive:
        print(f"\n[STEP 7] Starting recursive reconnaissance for {args.target}")
        try:
            recursive_results = run_recursive_reconnaissance(
                target_id=target_id,
                main_target=args.target,
                all_results=all_results,
                api_url=api_url,
                jwt_token=jwt_token,
                max_concurrent=args.max_concurrent_subtargets
            )
            
            # Save recursive recon results
            recursive_results_file = os.path.join(parsed_dir, "recursive_recon_results.json")
            save_json(recursive_results, recursive_results_file)
            
            # Submit recursive recon results to API
            recursive_raw_ok = save_raw_to_db("recursive_recon", args.target, recursive_results_file, api_url, jwt_token)
            recursive_parsed_ok = save_parsed_to_db("recursive_recon", args.target, recursive_results, api_url, jwt_token)
            print(f"[INFO] Recursive recon results submitted to API - Raw: {recursive_raw_ok}, Parsed: {recursive_parsed_ok}")
            
            # Print recursive recon summary
            print(f"\n[RECURSIVE RECON SUMMARY]")
            print(f"  - Total subdomains discovered: {recursive_results.get('total_subdomains', 0)}")
            print(f"  - Subtargets created: {recursive_results.get('subtargets_created', 0)}")
            print(f"  - Passive recon successful: {recursive_results.get('passive_recon_successful', 0)}")
            print(f"  - Active recon successful: {recursive_results.get('active_recon_successful', 0)}")
            print(f"  - Passive recon success rate: {recursive_results.get('passive_recon_success_rate', 0):.1f}%")
            print(f"  - Active recon success rate: {recursive_results.get('active_recon_success_rate', 0):.1f}%")
            
            # Update final results with recursive recon data
            final_results["recursive_reconnaissance"] = recursive_results
            
        except Exception as e:
            print(f"[ERROR] Recursive reconnaissance failed: {e}")
            final_results["recursive_reconnaissance"] = {
                "success": False,
                "error": str(e)
            }
    else:
        print(f"\n[STEP 7] Recursive reconnaissance skipped (use --enable-recursive to enable)")
        final_results["recursive_reconnaissance"] = {
            "success": True,
            "enabled": False,
            "message": "Recursive reconnaissance was not enabled"
        }

def create_directory_structure(output_dir: str, all_results: Dict[str, Any]) -> None:
    """
    Create comprehensive directory structure for active recon outputs.
    
    Args:
        output_dir: Base output directory
        all_results: All results from active recon tools
    """
    # Create main directories
    directories = [
        "enumeration",
        "enumeration/endpoints",
        "enumeration/scrapped_files",
        "enumeration/js_endpoints",
        "enumeration/parameters",
        "enumeration/screenshots",
        "enumeration/live_servers",
        "enumeration/findings",
        "enumeration/endpoint-json",
        "enumeration/infrastructure",
        "enumeration/http-requests",
        "enumeration/http-responses",
        "enumeration/IPs-and-open-ports",
        "enumeration/domains",
        "port_scanning",
        "technology_detection",
        "proxy_capture",
        "reports"
    ]
    
    for directory in directories:
        os.makedirs(os.path.join(output_dir, directory), exist_ok=True)
    
    # Create subdirectories for file types
    file_types = ["js", "php", "html", "css", "json", "xml", "config", "backup", "logs"]
    for file_type in file_types:
        os.makedirs(os.path.join(output_dir, "enumeration", "scrapped_files", file_type), exist_ok=True)

def generate_reports(output_dir: str, all_results: Dict[str, Any], summary: Dict[str, Any]) -> None:
    """
    Generate comprehensive reports from active recon results.
    
    Args:
        output_dir: Base output directory
        all_results: All results from active recon tools
        summary: Tool execution summary
    """
    # Generate technology report
    if "webanalyze" in all_results and all_results["webanalyze"].get("success"):
        tech_report = {
            "timestamp": datetime.now().isoformat(),
            "technologies": all_results["webanalyze"].get("technologies", []),
            "technology_mapping": all_results["webanalyze"].get("technology_mapping", {}),
            "summary": {
                "total_technologies": len(all_results["webanalyze"].get("technologies", [])),
                "unique_technologies": len(set([tech.get("name", "") for tech in all_results["webanalyze"].get("technologies", [])]))
            }
        }
        
        tech_report_file = os.path.join(output_dir, "reports", "technology_report.json")
        with open(tech_report_file, 'w') as f:
            json.dump(tech_report, f, indent=2)
    
    # Generate endpoint report
    endpoints_report = {
        "timestamp": datetime.now().isoformat(),
        "katana_endpoints": len(all_results.get("katana", {}).get("urls_found", [])),
        "feroxbuster_endpoints": len(all_results.get("feroxbuster", {}).get("urls_found", [])),
        "js_endpoints": len(all_results.get("getjs", {}).get("js_endpoints", [])),
        "linkfinder_endpoints": len(all_results.get("linkfinder", {}).get("all_endpoints", [])),
        "arjun_parameters": len(set([param for ep in all_results.get("arjun", {}).get("endpoints_found", []) for param in ep.get("parameters", [])]))
    }
    
    endpoints_report_file = os.path.join(output_dir, "reports", "endpoints_report.json")
    with open(endpoints_report_file, 'w') as f:
        json.dump(endpoints_report, f, indent=2)
    
    # Generate execution summary report
    execution_report = {
        "timestamp": datetime.now().isoformat(),
        "tool_summary": summary,
        "successful_tools": [tool for tool, result in summary.items() if result.get("runner")],
        "failed_tools": [tool for tool, result in summary.items() if not result.get("runner")],
        "total_tools": len(summary),
        "success_rate": len([tool for tool, result in summary.items() if result.get("runner")]) / len(summary) * 100 if summary else 0
    }
    
    execution_report_file = os.path.join(output_dir, "reports", "execution_summary.json")
    with open(execution_report_file, 'w') as f:
        json.dump(execution_report, f, indent=2)

if __name__ == "__main__":
    main()
