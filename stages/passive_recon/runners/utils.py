import os
import json
import requests
from typing import List, Dict, Optional

def setup_output_dirs(stage: str, target: str) -> Dict[str, str]:
    """
    Create and return paths for output and parsed directories for a given stage and target.
    """
    base_dir = f"/outputs/{stage}/{target}"
    output_dir = os.path.join(base_dir)
    parsed_dir = os.path.join(base_dir, "parsed")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    return {"output_dir": output_dir, "parsed_dir": parsed_dir}

def post_to_backend_api(api_url: str, jwt_token: str, payload: dict, files: dict = None) -> dict:
    """
    Post parsed or raw data to the backend API using JWT authentication. Returns the API response as a dict.
    """
    headers = {"Authorization": f"Bearer {jwt_token}"} if jwt_token else {}
    if files:
        response = requests.post(api_url, headers=headers, data=payload, files=files)
    else:
        headers["Content-Type"] = "application/json"
        response = requests.post(api_url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def save_raw_to_db(tool: str, target: str, raw_path: str, api_url: str, jwt_token: str) -> bool:
    """
    Save raw output to backend database via API using JWT authentication. Returns True if successful.
    """
    try:
        with open(raw_path, "rb") as f:
            files = {"file": (os.path.basename(raw_path), f)}
            payload = {"tool": tool, "target": target}
            resp = post_to_backend_api(api_url, jwt_token, payload, files)
            print(f"[DB] Raw output saved: {resp}")
            return True
    except Exception as e:
        print(f"[DB ERROR] Failed to save raw output: {e}")
        return False

def save_parsed_to_db(tool: str, target: str, parsed_data: dict, api_url: str, jwt_token: str) -> bool:
    """
    Save parsed output to backend database via API using JWT authentication. Returns True if successful.
    """
    try:
        payload = {"tool": tool, "target": target, "data": parsed_data}
        resp = post_to_backend_api(api_url, jwt_token, payload)
        print(f"[DB] Parsed output saved: {resp}")
        return True
    except Exception as e:
        print(f"[DB ERROR] Failed to save parsed output: {e}")
        return False

def parse_amass_output(raw_path: str) -> Dict:
    """
    Parse amass output file and return a dict with subdomains and metadata.
    """
    subdomains = []
    if not os.path.exists(raw_path):
        return {"subdomains": [], "error": "File not found"}
    with open(raw_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                subdomains.append(line)
    return {
        "tool": "amass",
        "subdomains": subdomains,
        "total": len(subdomains),
        "raw_output_path": raw_path
    }
