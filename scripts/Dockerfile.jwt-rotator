FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy JWT rotation script
COPY backend/utils/rotate_jwt_secret.py /app/rotate_jwt_secret.py

# Install Python dependencies
RUN pip install --no-cache-dir \
    cryptography \
    python-dotenv

# Create a simple JWT rotation service
RUN echo '#!/usr/bin/env python3\n\
import os\n\
import time\n\
import subprocess\n\
from dotenv import load_dotenv\n\
\n\
def rotate_jwt_secret():\n\
    """Rotate JWT secret and update all environment files"""\n\
    try:\n\
        # Load current environment\n\
        load_dotenv("/app/backend.env")\n\
        \n\
        # Run the rotation script\n\
        result = subprocess.run([\n\
            "python", "/app/rotate_jwt_secret.py",\n\
            "--env-file", "/app/backend.env",\n\
            "--stages-dir", "/app/stages"\n\
        ], capture_output=True, text=True)\n\
        \n\
        if result.returncode == 0:\n\
            print("JWT secret rotated successfully")\n\
        else:\n\
            print(f"JWT rotation failed: {result.stderr}")\n\
            \n\
    except Exception as e:\n\
        print(f"Error rotating JWT secret: {e}")\n\
\n\
def main():\n\
    """Main service loop"""\n\
    print("JWT Rotator Service Started")\n\
    \n\
    # Initial rotation\n\
    rotate_jwt_secret()\n\
    \n\
    # Rotate every 24 hours\n\
    while True:\n\
        time.sleep(86400)  # 24 hours\n\
        rotate_jwt_secret()\n\
\n\
if __name__ == "__main__":\n\
    main()\n\
' > /app/jwt_rotator_service.py

# Make the service executable
RUN chmod +x /app/jwt_rotator_service.py

# Set the entry point
CMD ["python", "/app/jwt_rotator_service.py"] 