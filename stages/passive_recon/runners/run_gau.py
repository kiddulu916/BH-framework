import os
import subprocess
import json
from typing import List

def run_gau(target: str, output_dir: str) -> List[str]:
    """
    Run Gau on the target domain, save raw JSON output, parse subdomains, and return them as a list.
    """
    gau_path = os.getenv("GAU_PATH", "/usr/local/bin/gau")
    output_file = os.path.join(output_dir, f"gau_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run([
            gau_path,
            target,
            "--json",
            "--subs",
            "--providers", "wayback,urlscan",
            "--o", output_file
        ], check=True)
        subdomains = set()
        with open(output_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    # Extract subdomain from URL
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    if parsed.hostname:
                        subdomains.add(parsed.hostname)
                except Exception:
                    continue
        return list(subdomains)
    except Exception as e:
        print(f"[Gau] Error: {e}")
        return [] 