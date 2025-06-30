import os
import secrets
import re
import argparse
from dotenv import load_dotenv
import jwt
import time

ENV_PATH = "../passive_recon/.env"

# Helper to update a key in .env
def update_env_var(env_path, key, value):
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rotate JWT_SECRET and optionally generate a new JWT token.")
    parser.add_argument("--sub", required=True, help="Subject claim for new JWT (e.g., passive_recon_stage)")
    parser.add_argument("--exp", type=int, default=3600, help="Token expiry in seconds (default: 3600)")
    args = parser.parse_args()

    # Generate new secret
    new_secret = secrets.token_hex(64)
    update_env_var(ENV_PATH, "JWT_SECRET", new_secret)
    print(f"[INFO] Rotated JWT_SECRET: {new_secret}")

    # Reload .env with new secret
    load_dotenv(dotenv_path=ENV_PATH, override=True)
    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    payload = {
        "sub": args.sub,
        "iat": int(time.time()),
        "exp": int(time.time()) + args.exp
    }
    token = jwt.encode(payload, new_secret, algorithm=JWT_ALGORITHM)
    print(f"[INFO] New JWT token: {token}")
    update_env_var(ENV_PATH, "BACKEND_JWT_TOKEN", token)
    print(f"[INFO] Updated BACKEND_JWT_TOKEN in .env.") 