import os
import secrets
import glob

# List all .env files to update
ENV_PATHS = [
    "../.env",
    "../stages/passive_recon/.env",
    "../stages/active_recon/.env",
    "../stages/vuln_scan/.env",
    "../stages/vuln_test/.env",
    "../stages/kill_chain/.env",
    "../stages/report/.env"
]

# Also auto-discover any .env files in stages/*/
for env_file in glob.glob("../stages/*/.env"):
    if env_file not in ENV_PATHS:
        ENV_PATHS.append(env_file)

def update_env_var(env_path, key, value):
    if not os.path.exists(env_path):
        print(f"[WARN] {env_path} does not exist, skipping.")
        return False
    with open(env_path, "r") as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f"{key}={value}\n"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}\n")
    with open(env_path, "w") as f:
        f.writelines(lines)
    return True

if __name__ == "__main__":
    new_secret = secrets.token_hex(64)
    updated = []
    for env_path in ENV_PATHS:
        if update_env_var(env_path, "JWT_SECRET", new_secret):
            updated.append(env_path)
    print(f"[INFO] Rotated JWT_SECRET: {new_secret}")
    print(f"[INFO] Updated JWT_SECRET in the following .env files:")
    for path in updated:
        print(f"  - {path}")
    print("[INFO] Set token expiration to 60 minutes (3600 seconds) by default. Use the universal generate_jwt.py script to generate new tokens for each stage.") 