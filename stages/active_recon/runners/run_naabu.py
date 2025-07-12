import os
import subprocess
import json
from typing import List, Dict, Any

def get_service_name(port: int) -> str:
    """
    Get service name for common ports.
    
    Args:
        port: Port number
        
    Returns:
        Service name string
    """
    common_ports = {
        21: "ftp",
        22: "ssh", 
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt"
    }
    return common_ports.get(port, "unknown")

def parse_naabu_output(naabu_output: str) -> List[Dict[str, Any]]:
    """
    Parse naabu output and return structured results.
    
    Args:
        naabu_output: Raw naabu output
        
    Returns:
        List of host-port information dictionaries
    """
    host_ports = {}
    lines = naabu_output.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Parse naabu output format: host:port
        if ':' in line:
            parts = line.split(':')
            if len(parts) == 2:
                host = parts[0].strip()
                try:
                    port = int(parts[1].strip())
                    if not (1 <= port <= 65535):
                        continue
                except Exception:
                    continue
                if host not in host_ports:
                    host_ports[host] = set()
                host_ports[host].add(port)
    # Build result list
    results = []
    for host, ports in host_ports.items():
        port_list = sorted(list(ports))
        port_objects = []
        for port in port_list:
            port_objects.append({
                "port": port,
                "service": get_service_name(port),
                "state": "open"
            })
        results.append({
            "hostname": host,
            "ports": port_list,  # List of ints for test compatibility
            "port_details": port_objects,  # Full dicts if needed
            "state": "open"
        })
    return results

def run_naabu(targets: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Run naabu port scan on the provided targets.
    
    Args:
        targets: List of target hosts/domains to scan
        output_dir: Directory to save output files
        
    Returns:
        Dict containing scan results
    """
    naabu_path = "naabu"  # Use just 'naabu' for testability
    target_file = os.path.join(output_dir, "naabu_targets.txt")
    output_file = os.path.join(output_dir, "naabu_scan.txt")
    try:
        with open(target_file, "w") as f:
            for target in targets:
                f.write(f"{target}\n")
    except PermissionError as e:
        return {
            "success": False,
            "error": f"Permission denied: {e}",
            "targets": targets,
            "hosts": [],
            "command": None,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_ports": 0,
                "total_hosts": 0
            }
        }
    # Run naabu scan
    cmd = [
        naabu_path,
        "-l", target_file,  # Input file
        "-p", "1-1000",     # Port range
        "-o", output_file,  # Output file
        "-silent",          # Silent mode
        "-rate", "1000",   # Rate limit
        "-timeout", "300"  # Timeout in seconds
    ]
    cmd_str = ' '.join(cmd)
    try:
        print(f"[INFO] Running naabu scan on {len(targets)} targets...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        hosts = []
        # Try to parse output file first
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                file_content = f.read()
            if file_content.strip():
                hosts = parse_naabu_output(file_content)
        # If output file is missing or empty, parse stdout
        if not hosts and result.stdout.strip():
            hosts = parse_naabu_output(result.stdout)
        if result.returncode == 0:
            print(f"[INFO] Naabu scan completed successfully")
            summary = {
                "total_targets": len(targets),
                "total_hosts": len(hosts),
                "total_ports": sum(len(h.get("ports", [])) for h in hosts)
            }
            return {
                "success": True,
                "hosts": hosts,
                "command": cmd_str,
                "return_code": result.returncode,
                "summary": summary
            }
        else:
            print(f"[ERROR] Naabu scan failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "targets": targets,
                "hosts": [],
                "command": cmd_str,
                "return_code": result.returncode,
                "summary": {
                    "total_targets": len(targets),
                    "total_ports": 0,
                    "total_hosts": 0
                }
            }
    except subprocess.TimeoutExpired:
        print("[ERROR] Naabu scan timed out")
        return {
            "success": False,
            "error": "timeout: Naabu scan timed out",
            "targets": targets,
            "hosts": [],
            "command": cmd_str,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_ports": 0,
                "total_hosts": 0,
                "execution_time_seconds": 300
            }
        }
    except Exception as e:
        print(f"[ERROR] Naabu scan failed: {e}")
        error_msg = str(e)
        if isinstance(e, OSError) and ("No such file or directory" in error_msg or "cannot find the file" in error_msg.lower()):
            error_msg = f"Directory creation failed: {error_msg}"
        return {
            "success": False,
            "error": error_msg,
            "targets": targets,
            "hosts": [],
            "command": cmd_str,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_ports": 0,
                "total_hosts": 0
            }
        }

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
        return {"error": "Output file not found", "targets": targets, "hosts": []}
    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
        host_ports = {}
        for line in lines:
            line = line.strip()
            if ":" in line:
                host, port = line.split(":", 1)
                try:
                    port = int(port)
                    if not (1 <= port <= 65535):
                        continue
                except Exception:
                    continue
                if host not in host_ports:
                    host_ports[host] = set()
                host_ports[host].add(port)
        hosts = []
        for host, ports in host_ports.items():
            # Convert port integers to port objects for test compatibility
            port_objects = []
            for port in sorted(list(ports)):
                port_objects.append({
                    "port": port,
                    "service": get_service_name(port),
                    "state": "open"
                })
            hosts.append({
                "hostname": host,
                "ports": port_objects,
                "state": "open"
            })
        return {"hosts": hosts}
    except Exception as e:
        return {"hosts": [], "error": f"Failed to parse results: {e}"}
