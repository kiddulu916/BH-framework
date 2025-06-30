import os
import time
import jwt
import argparse
from dotenv import load_dotenv

def main():
    parser = argparse.ArgumentParser(description="Universal JWT generator for any stage or backend.")
    parser.add_argument("--sub", required=True, help="Subject claim (e.g., passive_recon_stage or backend)")
    parser.add_argument("--env-path", default="../passive_recon/.env", help="Path to .env file with JWT_SECRET and JWT_ALGORITHM (default: ../passive_recon/.env)")
    parser.add_argument("--exp", type=int, default=3600, help="Token expiry in seconds (default: 3600)")
    args = parser.parse_args()

    load_dotenv(dotenv_path=args.env_path)
    JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
    JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
    payload = {
        "sub": args.sub,
        "iat": int(time.time()),
        "exp": int(time.time()) + args.exp
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    print(token)

if __name__ == "__main__":
    main() 