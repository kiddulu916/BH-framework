import argparse
import os
import json
import requests
from typing import Optional
from dotenv import load_dotenv
from runners.run_amass import run_amass
from runners.run_sublist3r import run_sublist3r
from runners.run_subfinder import run_subfinder
from runners.run_assetfinder import run_assetfinder
from runners.run_gau import run_gau
from runners.run_waybackurls import run_waybackurls
from runners.run_trufflehog import run_trufflehog
from runners.run_dorking import run_dorking
from runners.run_dns_enum import run_dns_enum
from runners.utils import save_raw_to_db, save_parsed_to_db

def create_target_if_not_exists(domain: str, api_url: str, jwt_token: str) -> Optional[str]:
    """
    Create a target if it doesn't exist and return the target ID.
    """
    try:
        # Construct the correct targets URL
        # Extract base URL from the results API URL
        if '/results/passive-recon' in api_url:
            base_url = api_url.split('/results/')[0]
        else:
            base_url = api_url.rstrip('/')
        targets_url = f"{base_url}/targets/"
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Create target payload
        payload = {
            "name": domain,
            "scope": "DOMAIN",  # Uppercase as required by enum
            "value": domain,
            "description": f"Target created automatically for passive recon: {domain}",
            "is_primary": True
        }
        
        response = requests.post(targets_url, headers=headers, json=payload)

        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('data'):
                target_id = data['data'].get('id')
                if target_id:
                    return target_id
        return None
    except Exception as e:
        print(f"[ERROR] Failed to create target: {e}")
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

def main():
    load_dotenv(dotenv_path=".env")
    parser = argparse.ArgumentParser(description="Passive Recon Main Runner")
    parser.add_argument("--target", required=False, default="127.0.0.1:3333", help="Target domain")
    parser.add_argument("--stage", default="passive_recon", help="Stage name (default: passive_recon)")
    args = parser.parse_args()

    # Setup output directories
    dirs = setup_output_dirs(args.stage, args.target)
    target_dir = dirs["target_dir"]
    raw_dir = dirs["raw_dir"]
    parsed_dir = dirs["parsed_dir"]

    # Load API URL and JWT token from environment
    api_url = os.environ.get("BACKEND_API_URL", "http://backend:8000/api/results/passive-recon")
    jwt_token = os.environ.get("BACKEND_JWT_TOKEN", "")
    print(f"[INFO] Using backend API URL: {api_url}")
    if not jwt_token:
        print("[WARNING] No BACKEND_JWT_TOKEN found in environment. API submission will likely fail.")

    # Get target ID from backend API
    target_id = get_target_id(args.target, api_url, jwt_token)
    if not target_id:
        print(f"[WARNING] Could not get target ID for {args.target}. Using target name as ID.")
        target_id = args.target
    else:
        print(f"[INFO] Got target ID: {target_id}")

    all_results = {}
    all_subdomains = set()
    summary = {}

    # Sublist3r
    try:
        sublist3r_subdomains = run_sublist3r(args.target, raw_dir)
        sublist3r_raw_path = os.path.join(raw_dir, f"sublist3r_{args.target}.txt")
        save_text(sublist3r_subdomains, os.path.join(parsed_dir, "sublist3r_subdomains.txt"))
        all_results["sublist3r"] = {"subdomains": sublist3r_subdomains}
        all_subdomains.update(sublist3r_subdomains)
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(sublist3r_raw_path):
            raw_ok = save_raw_to_db("sublist3r", target_id, sublist3r_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("sublist3r", target_id, args.target, {"subdomains": sublist3r_subdomains}, api_url, jwt_token)
        summary["sublist3r"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Sublist3r runner failed: {e}")
        summary["sublist3r"] = {"runner": False, "error": str(e)}

    # Amass
    try:
        amass_results = run_amass(args.target, raw_dir)
        amass_raw_path = os.path.join(raw_dir, f"amass_{args.target}.txt")
        save_text(amass_results, os.path.join(parsed_dir, "amass_results.txt"))
        all_results["amass"] = amass_results
        all_subdomains.update(amass_results.get("subdomains", []))
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(amass_raw_path):
            raw_ok = save_raw_to_db("amass", target_id, amass_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("amass", target_id, args.target, amass_results, api_url, jwt_token)
        summary["amass"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Amass runner failed: {e}")
        summary["amass"] = {"runner": False, "error": str(e)}

    # Subfinder
    try:
        subfinder_subdomains = run_subfinder(args.target, raw_dir)
        subfinder_raw_path = os.path.join(raw_dir, f"subfinder_{args.target}.json")
        save_text(subfinder_subdomains, os.path.join(parsed_dir, "subfinder_subdomains.txt"))
        all_results["subfinder"] = {"subdomains": subfinder_subdomains}
        all_subdomains.update(subfinder_subdomains)
        # Only try to save raw output if the file exists
        raw_ok = False
        if os.path.exists(subfinder_raw_path):
            raw_ok = save_raw_to_db("subfinder", target_id, subfinder_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("subfinder", target_id, args.target, {"subdomains": subfinder_subdomains}, api_url, jwt_token)
        summary["subfinder"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Subfinder runner failed: {e}")
        summary["subfinder"] = {"runner": False, "error": str(e)}

    # Assetfinder
    try:
        assetfinder_subdomains = run_assetfinder(args.target, raw_dir)
        assetfinder_raw_path = os.path.join(raw_dir, f"assetfinder_{args.target}.txt")
        save_text(assetfinder_subdomains, os.path.join(parsed_dir, "assetfinder_subdomains.txt"))
        all_results["assetfinder"] = {"subdomains": assetfinder_subdomains}
        all_subdomains.update(assetfinder_subdomains)
        # Only try to save raw output if the file exists
        raw_ok = False
        if os.path.exists(assetfinder_raw_path):
            raw_ok = save_raw_to_db("assetfinder", target_id, assetfinder_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("assetfinder", target_id, args.target, {"subdomains": assetfinder_subdomains}, api_url, jwt_token)
        summary["assetfinder"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Assetfinder runner failed: {e}")
        summary["assetfinder"] = {"runner": False, "error": str(e)}

    # Gau
    try:
        gau_subdomains = run_gau(args.target, raw_dir)
        gau_raw_path = os.path.join(raw_dir, f"gau_{args.target}.json")
        save_text(gau_subdomains, os.path.join(parsed_dir, "gau_subdomains.txt"))
        all_results["gau"] = {"subdomains": gau_subdomains}
        all_subdomains.update(gau_subdomains)
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(gau_raw_path):
            raw_ok = save_raw_to_db("gau", target_id, gau_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("gau", target_id, args.target, {"subdomains": gau_subdomains}, api_url, jwt_token)
        summary["gau"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Gau runner failed: {e}")
        summary["gau"] = {"runner": False, "error": str(e)}



    # Waybackurls
    try:
        waybackurls_subdomains = run_waybackurls(args.target, raw_dir)
        waybackurls_raw_path = os.path.join(raw_dir, f"waybackurls_{args.target}.txt")
        save_text(waybackurls_subdomains, os.path.join(parsed_dir, "waybackurls_subdomains.txt"))
        all_results["waybackurls"] = {"subdomains": waybackurls_subdomains}
        all_subdomains.update(waybackurls_subdomains)
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(waybackurls_raw_path):
            raw_ok = save_raw_to_db("waybackurls", target_id, waybackurls_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("waybackurls", target_id, args.target, {"subdomains": waybackurls_subdomains}, api_url, jwt_token)
        summary["waybackurls"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] waybackurls runner failed: {e}")
        summary["waybackurls"] = {"runner": False, "error": str(e)}

    # TruffleHog (GitHub Recon)
    try:
        trufflehog_results = run_trufflehog(args.target, raw_dir)
        trufflehog_raw_path = os.path.join(raw_dir, f"trufflehog_{args.target}.json")
        save_text(trufflehog_results, os.path.join(parsed_dir, "trufflehog_results.txt"))
        all_results["trufflehog"] = trufflehog_results
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(trufflehog_raw_path):
            raw_ok = save_raw_to_db("trufflehog", target_id, trufflehog_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("trufflehog", target_id, args.target, trufflehog_results, api_url, jwt_token)
        summary["trufflehog"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] TruffleHog runner failed: {e}")
        summary["trufflehog"] = {"runner": False, "error": str(e)}

    # Google Dorking
    try:
        dorking_results = run_dorking(args.target, raw_dir)
        dorking_raw_path = os.path.join(raw_dir, f"dorking_{args.target}.json")
        save_text(dorking_results, os.path.join(parsed_dir, "dorking_results.txt"))
        all_results["dorking"] = dorking_results
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(dorking_raw_path):
            raw_ok = save_raw_to_db("dorking", target_id, dorking_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("dorking", target_id, args.target, dorking_results, api_url, jwt_token)
        summary["dorking"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Google Dorking runner failed: {e}")
        summary["dorking"] = {"runner": False, "error": str(e)}

    # Enhanced DNS Enumeration
    try:
        dns_enum_results = run_dns_enum(args.target, raw_dir)
        dns_enum_raw_path = os.path.join(raw_dir, f"dns_enum_{args.target}.json")
        save_text(dns_enum_results, os.path.join(parsed_dir, "dns_enum_results.txt"))
        all_results["dns_enum"] = dns_enum_results
        # Add discovered subdomains from DNS enum to the main list
        if "subdomains" in dns_enum_results:
            all_subdomains.update(dns_enum_results["subdomains"])
        # Check if raw file exists before trying to save it
        raw_ok = False
        if os.path.exists(dns_enum_raw_path):
            raw_ok = save_raw_to_db("dns_enum", target_id, dns_enum_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("dns_enum", target_id, args.target, dns_enum_results, api_url, jwt_token)
        summary["dns_enum"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Enhanced DNS Enumeration runner failed: {e}")
        summary["dns_enum"] = {"runner": False, "error": str(e)}

    # Aggregate all subdomains
    all_subdomains = sorted(all_subdomains)
    save_text(all_subdomains, os.path.join(parsed_dir, "all_subdomains.txt"))
    print(f"[SUMMARY] Total unique subdomains found: {len(all_subdomains)}")
    print(json.dumps({"all_subdomains": all_subdomains}, indent=2))

    # Print summary of successes and failures
    print("\n[RESULTS SUMMARY]")
    for tool, result in summary.items():
        print(f"{tool}: {result}")

if __name__ == "__main__":
    main()
