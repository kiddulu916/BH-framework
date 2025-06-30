import os
import subprocess
from typing import List

def run_sublist3r(target: str, output_dir: str) -> List[str]:
    """
    Run Sublist3r on the target domain, save raw output, parse subdomains, and return them as a list.
    """
    sublist3r_path = os.getenv("SUBLIST3R_PATH", os.path.expanduser("~/Sublist3r/sublist3r.py"))
    output_file = os.path.join(output_dir, f"sublist3r_{target}.txt")
    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run([
            "python3", sublist3r_path,
            "-d", target,
            "-o", output_file
        ], check=True)
        with open(output_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        return subdomains
    except Exception as e:
        print(f"[Sublist3r] Error: {e}")
        return [] 