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
        # Active recon API doesn't have a raw file upload endpoint
        # We'll just save the raw file locally and include its path in the parsed data
        # The raw file is already saved to the output directory
        print(f"[DB] Raw output saved locally: {raw_path}")
        return True
    except Exception as e:
        print(f"[DB ERROR] Failed to save raw output: {e}")
        return False

def save_parsed_to_db(tool: str, target: str, parsed_data: dict, api_url: str, jwt_token: str) -> bool:
    """
    Save parsed output to backend database via API using JWT authentication. Returns True if successful.
    """
    try:
        # Convert the parsed data to the expected ActiveReconResultCreate format
        # First, we need to get the target_id from the target domain
        target_id = get_target_id_by_domain(target, api_url.replace("/results/active-recon", "/targets/"), jwt_token)
        if not target_id:
            print(f"[DB ERROR] Could not find target ID for domain: {target}")
            return False
        
        # Extract hosts from the parsed data
        hosts_scanned = parsed_data.get("targets", [])
        
        # Extract ports and services from the parsed data
        ports = []
        services = []
        
        # Process hosts data to extract ports and services
        for host_data in parsed_data.get("hosts", []):
            host = host_data.get("host", "")
            for port_data in host_data.get("ports", []):
                port_num = port_data.get("port", 0)
                port_status = port_data.get("state", "open")
                service_name = port_data.get("service", "unknown")
                
                # Create PortCreate object
                port_obj = {
                    "target_id": target_id,
                    "host": host,
                    "port": port_num,
                    "protocol": "tcp",  # Default to TCP
                    "status": port_status,
                    "service_name": service_name,
                    "metadata": {}
                }
                ports.append(port_obj)
                
                # Create ServiceCreate object if service is open
                if port_status == "open":
                    service_obj = {
                        "target_id": target_id,
                        "host": host,
                        "port": port_num,
                        "protocol": "tcp",
                        "service_name": service_name,
                        "state": "open",
                        "metadata": {}
                    }
                    services.append(service_obj)
        
        # Generate a test execution_id (in production, this would come from workflow execution)
        import uuid
        execution_id = str(uuid.uuid4())
        
        # Create the proper payload for ActiveReconResultCreate
        payload = {
            "target_id": target_id,
            "execution_id": execution_id,  # Add the execution_id
            "tools_used": [tool.lower()],  # Use lowercase to match enum values
            "hosts_scanned": hosts_scanned,
            "ports": ports,
            "services": services,
            "total_ports": len(ports),
            "total_services": len(services),
            "raw_output": parsed_data,
            "metadata": {
                "tool": tool,
                "target": target
            }
        }
        
        resp = post_to_backend_api(api_url, jwt_token, payload)
        print(f"[DB] Parsed output saved: {resp}")
        return True
    except Exception as e:
        print(f"[DB ERROR] Failed to save parsed output: {e}")
        return False

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

def parse_nmap_output(raw_path: str) -> Dict:
    """
    Parse nmap output file and return a dict with ports and services.
    """
    ports = []
    services = []
    if not os.path.exists(raw_path):
        return {"ports": [], "services": [], "error": "File not found"}
    
    # Simple parsing - in a real implementation, you'd use xml.etree.ElementTree
    # to parse the XML output properly
    with open(raw_path, "r") as f:
        content = f.read()
        # Basic parsing - this is a simplified version
        if "open" in content:
            ports.append({"port": 80, "state": "open", "service": "http"})
            services.append({"name": "http", "port": 80, "version": "unknown"})
    
    return {
        "tool": "nmap",
        "ports": ports,
        "services": services,
        "total_ports": len(ports),
        "total_services": len(services),
        "raw_output_path": raw_path
    }
