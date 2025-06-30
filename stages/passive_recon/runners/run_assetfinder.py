import os
import subprocess
from typing import List

def run_assetfinder(target: str, output_dir: str) -> List[str]:
    """
    Run Assetfinder on the target domain, save raw output, parse subdomains, and return them as a list.
    """
    assetfinder_path = os.getenv("ASSETFINDER_PATH", "/usr/local/bin/assetfinder")
    output_file = os.path.join(output_dir, f"assetfinder_{target}.txt")
    os.makedirs(output_dir, exist_ok=True)
    try:
        result = subprocess.run([
            assetfinder_path,
            "--subs-only",
            target
        ], capture_output=True, text=True, check=True)
        with open(output_file, "w") as f:
            f.write(result.stdout)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return subdomains
    except Exception as e:
        print(f"[Assetfinder] Error: {e}")
        return [] 