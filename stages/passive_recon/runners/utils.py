import os
import json
import requests
from typing import List, Dict, Optional

def setup_output_dirs(stage: str, target: str) -> Dict[str, str]:
    """
    Create and return paths for output and parsed directories for a given stage and target.
    """
    # Create target-specific directory structure
    target_dir = f"/outputs/{target}"
    raw_dir = os.path.join(target_dir, "raw")
    parsed_dir = os.path.join(target_dir, "parsed")
    
    # Create directories
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(parsed_dir, exist_ok=True)
    
    return {"target_dir": target_dir, "raw_dir": raw_dir, "parsed_dir": parsed_dir}

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

def save_raw_to_db(tool: str, target_id: str, raw_path: str, api_url: str, jwt_token: str) -> bool:
    """
    Save raw output to backend database via API using JWT authentication. Returns True if successful.
    """
    try:
        # Use the correct raw upload endpoint
        raw_api_url = api_url if api_url.endswith('/raw') else api_url.rstrip('/') + '/raw'
        
        with open(raw_path, "rb") as f:
            files = {"file": (os.path.basename(raw_path), f)}
            payload = {"tool": tool, "target": target_id}
            resp = post_to_backend_api(raw_api_url, jwt_token, payload, files)
            print(f"[DB] Raw output saved: {resp}")
            return True
    except Exception as e:
        print(f"[DB ERROR] Failed to save raw output: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"[DEBUG] Raw upload backend response: {e.response.text}")
        return False

def save_parsed_to_db(tool: str, target_id: str, domain: str, parsed_data: dict, api_url: str, jwt_token: str) -> bool:
    """
    Save parsed output to backend database via API using JWT authentication. Returns True if successful.
    """
    try:
        # Generate a simple execution ID for now
        import uuid
        execution_id = str(uuid.uuid4())
        
        # Convert tool name to enum value
        tool_enum_map = {
            "amass": "amass",
            "subfinder": "subfinder", 
            "assetfinder": "assetfinder",
            "sublist3r": "sublist3r",
            "gau": "gau",
            "waybackurls": "waybackurls",
            "trufflehog": "trufflehog",
            "dorking": "dorking",
            "dns_enum": "dns_enum"
        }
        
        tool_enum = tool_enum_map.get(tool.lower(), "amass")
        
        # Extract subdomains from parsed_data
        subdomains = []
        if "subdomains" in parsed_data:
            for subdomain in parsed_data["subdomains"]:
                subdomain_obj = {
                    "target_id": target_id,  # This should be a UUID
                    "subdomain": subdomain,
                    "domain": domain,  # Use the actual domain name
                    "ip_addresses": [],
                    "status": "unknown",
                    "source": tool_enum,
                    "metadata": {}
                }
                subdomains.append(subdomain_obj)
        
        # Format payload according to backend schema
        payload = {
            "target_id": target_id,  # This should be a UUID
            "execution_id": execution_id,
            "tools_used": [tool_enum],
            "subdomains": subdomains,
            "total_subdomains": len(subdomains),
            "execution_time": None,
            "raw_output": parsed_data,
            "metadata": {
                "tool": tool,
                "target": target_id,
                "execution_id": execution_id
            }
        }
        # Debug: print the payload being sent
        print(f"[DEBUG] Parsed payload for {tool}: {json.dumps(payload, indent=2)}")
        
        resp = post_to_backend_api(api_url, jwt_token, payload)
        print(f"[DB] Parsed output saved: {resp}")
        return True
    except Exception as e:
        print(f"[DB ERROR] Failed to save parsed output: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"[DEBUG] Parsed upload backend response: {e.response.text}")
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
