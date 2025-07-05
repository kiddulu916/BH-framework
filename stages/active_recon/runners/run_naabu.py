import os
import subprocess
import json
from typing import List, Dict, Any

def run_naabu(targets: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Run naabu port scan on the provided targets.
    
    Args:
        targets: List of target hosts/domains to scan
        output_dir: Directory to save output files
        
    Returns:
        Dict containing scan results
    """
    naabu_path = os.environ.get("NAABU_PATH", "/root/go/bin/naabu")
    target_file = os.path.join(output_dir, "naabu_targets.txt")
    output_file = os.path.join(output_dir, "naabu_scan.txt")
    
    # Write targets to file
    with open(target_file, "w") as f:
        for target in targets:
            f.write(f"{target}\n")
    
    # Run naabu scan
    cmd = [
        naabu_path,
        "-l", target_file,  # Input file
        "-p", "1-1000",     # Port range
        "-o", output_file,  # Output file
        "-silent",          # Silent mode
        "-rate", "1000"     # Rate limit
    ]
    
    try:
        print(f"[INFO] Running naabu scan on {len(targets)} targets...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"[INFO] Naabu scan completed successfully")
            return parse_naabu_results(output_file, targets)
        else:
            print(f"[ERROR] Naabu scan failed: {result.stderr}")
            return {"error": result.stderr, "targets": targets}
            
    except subprocess.TimeoutExpired:
        print("[ERROR] Naabu scan timed out")
        return {"error": "Scan timed out", "targets": targets}
    except Exception as e:
        print(f"[ERROR] Naabu scan failed: {e}")
        return {"error": str(e), "targets": targets}

def parse_naabu_results(output_file: str, targets: List[str]) -> Dict[str, Any]:
    """
    Parse naabu output and return structured results.
    
    Args:
        output_file: Path to naabu output file
        targets: List of original targets
        
    Returns:
        Dict containing parsed scan results
    """
    if not os.path.exists(output_file):
        return {"error": "Output file not found", "targets": targets}
    
    results = {
        "tool": "naabu",
        "targets": targets,
        "hosts": [],
        "total_hosts": len(targets),
        "total_ports": 0
    }
    
    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
        
        # Parse naabu output format: host:port
        host_ports = {}
        for line in lines:
            line = line.strip()
            if ":" in line:
                host, port = line.split(":", 1)
                if host not in host_ports:
                    host_ports[host] = []
                host_ports[host].append(int(port))
        
        # Build results
        for target in targets:
            host_result = {
                "host": target,
                "ports": [],
                "total_ports": 0
            }
            
            if target in host_ports:
                for port in host_ports[target]:
                    host_result["ports"].append({
                        "port": port,
                        "state": "open"
                    })
                host_result["total_ports"] = len(host_result["ports"])
            
            results["hosts"].append(host_result)
            results["total_ports"] += host_result["total_ports"]
            
    except Exception as e:
        results["error"] = f"Failed to parse results: {e}"
    
    return results
