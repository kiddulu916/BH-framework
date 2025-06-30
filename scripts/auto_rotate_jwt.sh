#!/bin/bash

BACKEND_ROTATE_SCRIPT="/app/rotate_jwt_secret.py"
STAGE_JWT_SCRIPT="/app/generate_jwt.py"
STAGE_ENVS=$(find /app/stages -mindepth 2 -maxdepth 2 -name ".env")

while true; do
  echo "[INFO] Rotating JWT secret and tokens at $(date)"

  python $BACKEND_ROTATE_SCRIPT

  for envfile in $STAGE_ENVS; do
    stage_name=$(basename $(dirname "$envfile"))
    token=$(python $STAGE_JWT_SCRIPT --sub "${stage_name}_stage" --env-path "$envfile" --exp 3600)
    if grep -q "^BACKEND_JWT_TOKEN=" "$envfile"; then
      sed -i "s|^BACKEND_JWT_TOKEN=.*|BACKEND_JWT_TOKEN=$token|" "$envfile"
    else
      echo "BACKEND_JWT_TOKEN=$token" >> "$envfile"
    fi
    echo "[INFO] Updated token for $stage_name"
  done

  echo "[INFO] JWT secret and tokens rotated. Sleeping for 60 minutes..."
  sleep 3600
done 