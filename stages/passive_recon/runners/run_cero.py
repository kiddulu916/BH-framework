import os
import subprocess
import re
from typing import Dict, List

def run_cero(target: str, output_dir: str) -> Dict[str, List[str]]:
    """
    Run cero on the target domain, save raw output, and parse IPv4 addresses, subdomains, protocols, and CIDR ranges.
    """
    cero_path = os.getenv("CERO_PATH", "/root/go/bin/cero")
    output_file = os.path.join(output_dir, f"cero_{target}.txt")
    os.makedirs(output_dir, exist_ok=True)
    try:
        result = subprocess.run([
            cero_path,
            target
        ], capture_output=True, text=True, check=True)
        with open(output_file, "w") as f:
            f.write(result.stdout)
        raw_lines = result.stdout.splitlines()
        ipv4s = set()
        subdomains = set()
        protocols = set()
        cidrs = set()
        for line in raw_lines:
            # Example line: 1.2.3.4:443/tcp example.com [1.2.3.0/24]
            # Extract IPv4
            ipv4s.update(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line))
            # Extract subdomain (full domain name)
            domain_match = re.search(r"\s([a-zA-Z0-9.-]+)\s", line)
            if domain_match:
                subdomains.add(domain_match.group(1))
            # Extract protocol (e.g., tcp, udp)
            proto_match = re.search(r"/(tcp|udp|http|https)", line)
            if proto_match:
                protocols.add(proto_match.group(1))
            # Extract CIDR
            cidr_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+/\d+)\]", line)
            if cidr_match:
                cidrs.add(cidr_match.group(1))
        return {
            "ipv4s": list(ipv4s),
            "subdomains": list(subdomains),
            "protocols": list(protocols),
            "cidrs": list(cidrs)
        }
    except Exception as e:
        print(f"[Cero] Error: {e}")
        return {"ipv4s": [], "subdomains": [], "protocols": [], "cidrs": []} 