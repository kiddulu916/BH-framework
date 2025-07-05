import argparse
import os
import json
import subprocess
import requests
from typing import List, Dict, Any
from dotenv import load_dotenv
from runners.run_nmap import run_nmap
from runners.run_naabu import run_naabu
from runners.run_httpx import run_httpx
from runners.utils import save_raw_to_db, save_parsed_to_db

def setup_output_dirs(stage: str, target: str):
    """Create output directories for the stage."""
    base_dir = os.path.join("/outputs", stage, target)
    output_dir = os.path.join(base_dir)
    parsed_dir = os.path.join(base_dir, "parsed")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    return {"output_dir": output_dir, "parsed_dir": parsed_dir}

def get_target_id_by_domain(domain: str, targets_api_url: str, jwt_token: str) -> str:
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

def save_json(data, path):
    """Save data as JSON file."""
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] Saved: {path}")

def main():
    load_dotenv(dotenv_path=".env")
    parser = argparse.ArgumentParser(description="Active Recon Main Runner")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--stage", default="active_recon", help="Stage name (default: active_recon)")
    args = parser.parse_args()

    # Setup output directories
    dirs = setup_output_dirs(args.stage, args.target)
    output_dir = dirs["output_dir"]
    parsed_dir = dirs["parsed_dir"]

    # Load API URL and JWT token from environment
    api_url = os.environ.get("BACKEND_API_URL", "http://backend:8000/api/results/active-recon")
    jwt_token = os.environ.get("BACKEND_JWT_TOKEN", "")
    targets_api_url = os.environ.get("TARGETS_API_URL", "http://backend:8000/api/targets/")
    passive_api_url = os.environ.get("PASSIVE_API_URL", "http://backend:8000/api/results/passive-recon")
    
    print(f"[INFO] Using backend API URL: {api_url}")
    if not jwt_token:
        print("[WARNING] No BACKEND_JWT_TOKEN found in environment. API submission will likely fail.")

    # Get target ID by domain name
    print(f"[INFO] Getting target ID for domain: {args.target}")
    target_id = get_target_id_by_domain(args.target, targets_api_url, jwt_token)
    
    if not target_id:
        print(f"[WARNING] No target found for domain {args.target}. Using domain as fallback.")
        subdomains = [args.target]
    else:
        print(f"[INFO] Found target ID: {target_id}")
        # Get subdomains from passive recon stage
        print(f"[INFO] Querying passive recon results for target ID: {target_id}")
        subdomains = get_passive_recon_results(target_id, passive_api_url, jwt_token)
    
    if not subdomains:
        print(f"[WARNING] No subdomains found from passive recon for {args.target}")
        # Fallback: use the main target domain
        subdomains = [args.target]
    
    print(f"[INFO] Found {len(subdomains)} subdomains to scan: {subdomains[:5]}...")

    all_results = {}
    summary = {}

    # Naabu port scanning
    try:
        naabu_results = run_naabu(subdomains, output_dir)
        naabu_raw_path = os.path.join(output_dir, "naabu_scan.txt")
        save_json(naabu_results, os.path.join(parsed_dir, "naabu_results.json"))
        all_results["naabu"] = naabu_results
        raw_ok = save_raw_to_db("naabu", args.target, naabu_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("naabu", args.target, naabu_results, api_url, jwt_token)
        summary["naabu"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Naabu runner failed: {e}")
        summary["naabu"] = {"runner": False, "error": str(e)}

    # Nmap scanning
    try:
        nmap_results = run_nmap(subdomains, output_dir)
        nmap_raw_path = os.path.join(output_dir, "nmap_scan.xml")
        save_json(nmap_results, os.path.join(parsed_dir, "nmap_results.json"))
        all_results["nmap"] = nmap_results
        raw_ok = save_raw_to_db("nmap", args.target, nmap_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("nmap", args.target, nmap_results, api_url, jwt_token)
        summary["nmap"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Nmap runner failed: {e}")
        summary["nmap"] = {"runner": False, "error": str(e)}

    # HTTPX web server detection
    try:
        httpx_results = run_httpx(subdomains, output_dir)
        httpx_raw_path = os.path.join(output_dir, "httpx_scan.txt")
        save_json(httpx_results, os.path.join(parsed_dir, "httpx_results.json"))
        all_results["httpx"] = httpx_results
        raw_ok = save_raw_to_db("httpx", args.target, httpx_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("httpx", args.target, httpx_results, api_url, jwt_token)
        summary["httpx"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] HTTPX runner failed: {e}")
        summary["httpx"] = {"runner": False, "error": str(e)}

    # Aggregate results
    total_hosts_scanned = len(subdomains)
    total_ports_found = sum(len(result.get("ports", [])) for result in all_results.values() if "ports" in result)
    total_services_found = sum(len(result.get("services", [])) for result in all_results.values() if "services" in result)
    
    aggregated_results = {
        "target": args.target,
        "total_hosts_scanned": total_hosts_scanned,
        "total_ports_found": total_ports_found,
        "total_services_found": total_services_found,
        "results": all_results
    }
    
    save_json(aggregated_results, os.path.join(parsed_dir, "all_active_recon_results.json"))
    print(f"[SUMMARY] Active recon completed for {args.target}")
    print(f"  - Hosts scanned: {total_hosts_scanned}")
    print(f"  - Ports found: {total_ports_found}")
    print(f"  - Services found: {total_services_found}")

    # Print summary of successes and failures
    print("\n[RESULTS SUMMARY]")
    for tool, result in summary.items():
        print(f"{tool}: {result}")

if __name__ == "__main__":
    main()
