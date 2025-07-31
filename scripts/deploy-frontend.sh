#!/bin/bash

# Bug Hunting Framework - Frontend Deployment Script

set -e

echo "🚀 Starting Bug Hunting Framework Frontend Deployment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose is not installed. Please install docker-compose and try again."
    exit 1
fi

# Build and start the frontend service
echo "📦 Building and starting frontend service..."
docker-compose up -d --build frontend

# Wait for the frontend to be healthy
echo "⏳ Waiting for frontend to be healthy..."
timeout=60
counter=0

while [ $counter -lt $timeout ]; do
    if docker-compose ps frontend | grep -q "healthy"; then
        echo "✅ Frontend is healthy and ready!"
        break
    fi
    
    echo "⏳ Waiting for frontend to be ready... ($counter/$timeout)"
    sleep 5
    counter=$((counter + 5))
done

if [ $counter -ge $timeout ]; then
    echo "❌ Frontend failed to become healthy within $timeout seconds"
    echo "📋 Checking frontend logs..."
    docker-compose logs frontend
    exit 1
fi

# Show service status
echo "📊 Service Status:"
docker-compose ps

echo "🌐 Frontend is available at: http://localhost:3000"
echo "🔍 Health check endpoint: http://localhost:3000/health"

echo "✅ Frontend deployment completed successfully!" 