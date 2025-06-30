import os
import subprocess
from typing import Dict, List
import re

def run_amass(target: str, output_dir: str) -> Dict[str, List[str]]:
    """
    Run Amass on the target domain, save raw output, parse subdomains, DNS, IPv4s, and ASNs, and return them as a dict.
    """
    amass_path = os.getenv("AMASS_PATH", "/usr/bin/amass")
    output_file = os.path.join(output_dir, f"amass_{target}.txt")
    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run([
            amass_path, "enum",
            "-d", target,
            "-max-depth", "10",
            "-o", output_file
        ], check=True)
        subdomains, ips, asns, dns_records = set(), set(), set(), set()
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                subdomains.add(line)
                # Simple regex for IPv4
                ips.update(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line))
                # ASN pattern (e.g., AS12345)
                asns.update(re.findall(r"AS\d+", line))
                # DNS records (very basic, for demo)
                if "dns" in line.lower():
                    dns_records.add(line)
        return {
            "subdomains": list(subdomains),
            "ips": list(ips),
            "asns": list(asns),
            "dns_records": list(dns_records)
        }
    except Exception as e:
        print(f"[Amass] Error: {e}")
        return {"subdomains": [], "ips": [], "asns": [], "dns_records": []}
