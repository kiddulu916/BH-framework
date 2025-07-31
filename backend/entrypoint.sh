#!/usr/bin/env bash
# Backend container entry-point
# Runs Alembic migrations automatically, then executes the given CMD.

set -e

echo "⇢ Running Alembic migrations (alembic upgrade head)"
alembic upgrade head

# Start Gunicorn with Uvicorn workers after migrations
export RUN_MAIN=true  # prevent Django autoreloader spawning extra process
echo "⇢ Starting Gunicorn"
exec gunicorn api.asgi:application \
    -k uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --workers ${GUNICORN_WORKERS:-2} \
    --timeout 90 \
    --log-level ${LOG_LEVEL:-info} 