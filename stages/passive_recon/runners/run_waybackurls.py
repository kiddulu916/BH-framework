import os
import subprocess
from typing import List
from urllib.parse import urlparse

def run_waybackurls(target: str, output_dir: str) -> List[str]:
    """
    Run waybackurls on the target domain, save raw output, parse URLs, and return unique subdomains.
    """
    waybackurls_path = os.getenv("WAYBACKURLS_PATH", "/usr/local/bin/waybackurls")
    output_file = os.path.join(output_dir, f"waybackurls_{target}.txt")
    os.makedirs(output_dir, exist_ok=True)
    try:
        with open(output_file, "w") as f:
            subprocess.run([
                waybackurls_path,
                target
            ], stdout=f, check=True)
        subdomains = set()
        with open(output_file, "r") as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        subdomains.add(parsed.hostname)
                except Exception:
                    continue
        return list(subdomains)
    except Exception as e:
        print(f"[waybackurls] Error: {e}")
        return [] 