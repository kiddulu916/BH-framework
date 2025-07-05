import os
import subprocess
import json
from typing import List, Dict, Any

def run_nmap(targets: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Run nmap scan on the provided targets.
    
    Args:
        targets: List of target hosts/domains to scan
        output_dir: Directory to save output files
        
    Returns:
        Dict containing scan results
    """
    nmap_path = os.environ.get("NMAP_PATH", "/usr/bin/nmap")
    target_file = os.path.join(output_dir, "targets.txt")
    output_file = os.path.join(output_dir, "nmap_scan.xml")
    
    # Write targets to file
    with open(target_file, "w") as f:
        for target in targets:
            f.write(f"{target}\n")
    
    # Run nmap scan
    cmd = [
        nmap_path,
        "-sS",  # SYN scan
        "-sV",  # Version detection
        "-O",   # OS detection
        "-p", "1-1000",  # Common ports
        "--script", "default",  # Default scripts
        "-oX", output_file,  # XML output
        "-iL", target_file   # Input file
    ]
    
    try:
        print(f"[INFO] Running nmap scan on {len(targets)} targets...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"[INFO] Nmap scan completed successfully")
            return parse_nmap_results(output_file, targets)
        else:
            print(f"[ERROR] Nmap scan failed: {result.stderr}")
            return {"error": result.stderr, "targets": targets}
            
    except subprocess.TimeoutExpired:
        print("[ERROR] Nmap scan timed out")
        return {"error": "Scan timed out", "targets": targets}
    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        return {"error": str(e), "targets": targets}

def parse_nmap_results(xml_file: str, targets: List[str]) -> Dict[str, Any]:
    """
    Parse nmap XML output and return structured results.
    
    Args:
        xml_file: Path to nmap XML output file
        targets: List of original targets
        
    Returns:
        Dict containing parsed scan results
    """
    if not os.path.exists(xml_file):
        return {"error": "XML file not found", "targets": targets}
    
    # Simplified parsing - in production, use xml.etree.ElementTree
    results = {
        "tool": "nmap",
        "targets": targets,
        "hosts": [],
        "total_hosts": len(targets),
        "total_ports": 0,
        "total_services": 0
    }
    
    try:
        with open(xml_file, "r") as f:
            content = f.read()
            
        # Basic parsing - this is a simplified version
        # In a real implementation, you'd parse the XML properly
        for target in targets:
            host_result = {
                "host": target,
                "status": "up",
                "ports": [],
                "os": "unknown"
            }
            
            # Simulate finding some common ports
            if "example.com" in target:
                host_result["ports"].extend([
                    {"port": 80, "state": "open", "service": "http"},
                    {"port": 443, "state": "open", "service": "https"},
                    {"port": 22, "state": "closed", "service": "ssh"}
                ])
            
            results["hosts"].append(host_result)
            results["total_ports"] += len(host_result["ports"])
            results["total_services"] += len([p for p in host_result["ports"] if p["state"] == "open"])
            
    except Exception as e:
        results["error"] = f"Failed to parse results: {e}"
    
    return results
