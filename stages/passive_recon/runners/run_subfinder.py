import os
import subprocess
import json
from typing import List

def run_subfinder(target: str, output_dir: str) -> List[str]:
    """
    Run Subfinder on the target domain, save raw JSON output, parse subdomains, and return them as a list.
    """
    subfinder_path = os.getenv("SUBFINDER_PATH", "/usr/local/bin/subfinder")
    output_file = os.path.join(output_dir, f"subfinder_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run([
            subfinder_path,
            "-d", target,
            "-recursive",
            "-all",
            "-oJ", output_file
        ], check=True)
        subdomains = []
        with open(output_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if "host" in data:
                        subdomains.append(data["host"])
                except Exception:
                    continue
        return subdomains
    except Exception as e:
        print(f"[Subfinder] Error: {e}")
        return []
