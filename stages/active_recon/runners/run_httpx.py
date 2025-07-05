import os
import subprocess
import json
from typing import List, Dict, Any

def run_httpx(targets: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Run httpx web server detection on the provided targets.
    
    Args:
        targets: List of target hosts/domains to scan
        output_dir: Directory to save output files
        
    Returns:
        Dict containing scan results
    """
    httpx_path = os.environ.get("HTTPX_PATH", "/root/go/bin/httpx")
    target_file = os.path.join(output_dir, "httpx_targets.txt")
    output_file = os.path.join(output_dir, "httpx_scan.txt")
    
    # Write targets to file
    with open(target_file, "w") as f:
        for target in targets:
            f.write(f"{target}\n")
    
    # Run httpx scan
    cmd = [
        httpx_path,
        "-l", target_file,      # Input file
        "-o", output_file,      # Output file
        "-silent",              # Silent mode
        "-title",               # Get page titles
        "-status-code",         # Get status codes
        "-tech-detect",         # Technology detection
        "-follow-redirects",    # Follow redirects
        "-timeout", "10"        # Timeout
    ]
    
    try:
        print(f"[INFO] Running httpx scan on {len(targets)} targets...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"[INFO] HTTPX scan completed successfully")
            return parse_httpx_results(output_file, targets)
        else:
            print(f"[ERROR] HTTPX scan failed: {result.stderr}")
            return {"error": result.stderr, "targets": targets}
            
    except subprocess.TimeoutExpired:
        print("[ERROR] HTTPX scan timed out")
        return {"error": "Scan timed out", "targets": targets}
    except Exception as e:
        print(f"[ERROR] HTTPX scan failed: {e}")
        return {"error": str(e), "targets": targets}

def parse_httpx_results(output_file: str, targets: List[str]) -> Dict[str, Any]:
    """
    Parse httpx output and return structured results.
    
    Args:
        output_file: Path to httpx output file
        targets: List of original targets
        
    Returns:
        Dict containing parsed scan results
    """
    if not os.path.exists(output_file):
        return {"error": "Output file not found", "targets": targets}
    
    results = {
        "tool": "httpx",
        "targets": targets,
        "web_servers": [],
        "total_web_servers": 0,
        "total_technologies": 0
    }
    
    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
        
        # Parse httpx output (JSON format)
        for line in lines:
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    web_server = {
                        "url": data.get("url", ""),
                        "host": data.get("host", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "technologies": data.get("technologies", []),
                        "server": data.get("server", ""),
                        "content_type": data.get("content_type", "")
                    }
                    results["web_servers"].append(web_server)
                    results["total_technologies"] += len(web_server["technologies"])
                except json.JSONDecodeError:
                    # Handle non-JSON lines
                    continue
        
        results["total_web_servers"] = len(results["web_servers"])
        
    except Exception as e:
        results["error"] = f"Failed to parse results: {e}"
    
    return results 