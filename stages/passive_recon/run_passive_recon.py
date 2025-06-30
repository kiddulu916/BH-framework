import argparse
import os
import json
from dotenv import load_dotenv
from runners.run_amass import run_amass
from runners.run_sublist3r import run_sublist3r
from runners.run_subfinder import run_subfinder
from runners.run_assetfinder import run_assetfinder
from runners.run_gau import run_gau
from runners.run_cero import run_cero
from runners.utils import save_raw_to_db, save_parsed_to_db

def setup_output_dirs(stage: str, target: str):
    base_dir = os.path.join("/outputs", stage, target)
    output_dir = os.path.join(base_dir)
    parsed_dir = os.path.join(base_dir, "parsed")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    return {"output_dir": output_dir, "parsed_dir": parsed_dir}

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] Saved: {path}")

def main():
    load_dotenv(dotenv_path=".env")
    parser = argparse.ArgumentParser(description="Passive Recon Main Runner")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--stage", default="passive_recon", help="Stage name (default: passive_recon)")
    args = parser.parse_args()

    # Setup output directories
    dirs = setup_output_dirs(args.stage, args.target)
    output_dir = dirs["output_dir"]
    parsed_dir = dirs["parsed_dir"]

    # Load API URL and JWT token from environment
    api_url = os.environ.get("BACKEND_API_URL", "http://backend:8000/api/v1/results/passive-recon")
    jwt_token = os.environ.get("BACKEND_JWT_TOKEN", "")
    print(f"[INFO] Using backend API URL: {api_url}")
    if not jwt_token:
        print("[WARNING] No BACKEND_JWT_TOKEN found in environment. API submission will likely fail.")

    all_results = {}
    all_subdomains = set()
    summary = {}

    # Sublist3r
    try:
        sublist3r_subdomains = run_sublist3r(args.target, output_dir)
        sublist3r_raw_path = os.path.join(output_dir, f"sublist3r_{args.target}.txt")
        save_json(sublist3r_subdomains, os.path.join(parsed_dir, "sublist3r_subdomains.json"))
        all_results["sublist3r"] = {"subdomains": sublist3r_subdomains}
        all_subdomains.update(sublist3r_subdomains)
        raw_ok = save_raw_to_db("sublist3r", args.target, sublist3r_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("sublist3r", args.target, {"subdomains": sublist3r_subdomains}, api_url, jwt_token)
        summary["sublist3r"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Sublist3r runner failed: {e}")
        summary["sublist3r"] = {"runner": False, "error": str(e)}

    # Amass
    try:
        amass_results = run_amass(args.target, output_dir)
        amass_raw_path = os.path.join(output_dir, f"amass_{args.target}.txt")
        save_json(amass_results, os.path.join(parsed_dir, "amass_results.json"))
        all_results["amass"] = amass_results
        all_subdomains.update(amass_results.get("subdomains", []))
        raw_ok = save_raw_to_db("amass", args.target, amass_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("amass", args.target, amass_results, api_url, jwt_token)
        summary["amass"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Amass runner failed: {e}")
        summary["amass"] = {"runner": False, "error": str(e)}

    # Subfinder
    try:
        subfinder_subdomains = run_subfinder(args.target, output_dir)
        subfinder_raw_path = os.path.join(output_dir, f"subfinder_{args.target}.json")
        save_json(subfinder_subdomains, os.path.join(parsed_dir, "subfinder_subdomains.json"))
        all_results["subfinder"] = {"subdomains": subfinder_subdomains}
        all_subdomains.update(subfinder_subdomains)
        raw_ok = save_raw_to_db("subfinder", args.target, subfinder_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("subfinder", args.target, {"subdomains": subfinder_subdomains}, api_url, jwt_token)
        summary["subfinder"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Subfinder runner failed: {e}")
        summary["subfinder"] = {"runner": False, "error": str(e)}

    # Assetfinder
    try:
        assetfinder_subdomains = run_assetfinder(args.target, output_dir)
        assetfinder_raw_path = os.path.join(output_dir, f"assetfinder_{args.target}.txt")
        save_json(assetfinder_subdomains, os.path.join(parsed_dir, "assetfinder_subdomains.json"))
        all_results["assetfinder"] = {"subdomains": assetfinder_subdomains}
        all_subdomains.update(assetfinder_subdomains)
        raw_ok = save_raw_to_db("assetfinder", args.target, assetfinder_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("assetfinder", args.target, {"subdomains": assetfinder_subdomains}, api_url, jwt_token)
        summary["assetfinder"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Assetfinder runner failed: {e}")
        summary["assetfinder"] = {"runner": False, "error": str(e)}

    # Gau
    try:
        gau_subdomains = run_gau(args.target, output_dir)
        gau_raw_path = os.path.join(output_dir, f"gau_{args.target}.json")
        save_json(gau_subdomains, os.path.join(parsed_dir, "gau_subdomains.json"))
        all_results["gau"] = {"subdomains": gau_subdomains}
        all_subdomains.update(gau_subdomains)
        raw_ok = save_raw_to_db("gau", args.target, gau_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("gau", args.target, {"subdomains": gau_subdomains}, api_url, jwt_token)
        summary["gau"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Gau runner failed: {e}")
        summary["gau"] = {"runner": False, "error": str(e)}

    # Cero
    try:
        cero_results = run_cero(args.target, output_dir)
        cero_raw_path = os.path.join(output_dir, f"cero_{args.target}.txt")
        save_json(cero_results, os.path.join(parsed_dir, "cero_results.json"))
        all_results["cero"] = cero_results
        all_subdomains.update(cero_results.get("subdomains", []))
        raw_ok = save_raw_to_db("cero", args.target, cero_raw_path, api_url, jwt_token)
        parsed_ok = save_parsed_to_db("cero", args.target, cero_results, api_url, jwt_token)
        summary["cero"] = {"runner": True, "raw_api": raw_ok, "parsed_api": parsed_ok}
    except Exception as e:
        print(f"[ERROR] Cero runner failed: {e}")
        summary["cero"] = {"runner": False, "error": str(e)}

    # Aggregate all subdomains
    all_subdomains = sorted(all_subdomains)
    save_json(all_subdomains, os.path.join(parsed_dir, "all_subdomains.json"))
    print(f"[SUMMARY] Total unique subdomains found: {len(all_subdomains)}")
    print(json.dumps({"all_subdomains": all_subdomains}, indent=2))

    # Print summary of successes and failures
    print("\n[RESULTS SUMMARY]")
    for tool, result in summary.items():
        print(f"{tool}: {result}")

if __name__ == "__main__":
    main()
