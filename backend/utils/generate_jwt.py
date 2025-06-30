import os
import time
import jwt
import argparse
from dotenv import load_dotenv

def main():
    parser = argparse.ArgumentParser(description="Generate a JWT for backend use.")
    parser.add_argument("--sub", required=True, help="Subject claim (e.g., backend or admin)")
    parser.add_argument("--exp", type=int, default=3600, help="Token expiry in seconds (default: 3600)")
    args = parser.parse_args()

    load_dotenv(dotenv_path="../.env")
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