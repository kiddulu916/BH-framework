# Frontend Deployment Guide

This guide explains how to deploy the Bug Hunting Framework frontend using Docker and Docker Compose.

## Prerequisites

- Docker Desktop installed and running
- Docker Compose installed
- Git repository cloned

## Quick Start

### 1. Deploy Frontend Only

```bash
# Using PowerShell (Windows)
.\scripts\deploy-frontend.ps1

# Using Bash (Linux/Mac)
./scripts/deploy-frontend.sh
```

### 2. Deploy Full Stack

```bash
# Deploy all services (db, backend, frontend)
docker-compose up -d

# Deploy with build
docker-compose up -d --build
```

## Manual Deployment

### 1. Build the Frontend Image

```bash
docker-compose build frontend
```

### 2. Start the Frontend Service

```bash
docker-compose up -d frontend
```

### 3. Check Service Status

```bash
docker-compose ps
```

### 4. View Logs

```bash
# View frontend logs
docker-compose logs frontend

# Follow logs in real-time
docker-compose logs -f frontend
```

## Environment Variables

The frontend service uses the following environment variables (defined in `.env`):

- `NEXT_PUBLIC_API_URL`: Backend API URL (default: http://localhost:8000)
- `NEXT_PUBLIC_WS_URL`: WebSocket URL (default: ws://localhost:8000/ws)
- `NODE_ENV`: Node environment (production)
- `PORT`: Port to run on (3000)
- `HOST`: Host to bind to (0.0.0.0)

## Health Checks

The frontend includes a health check endpoint:

- **URL**: http://localhost:3000/health
- **Method**: GET
- **Response**: 200 OK when healthy

## Docker Configuration

### Multi-stage Build

The Dockerfile uses a multi-stage build process:

1. **Dependencies Stage**: Installs production dependencies
2. **Builder Stage**: Builds the Next.js application
3. **Runner Stage**: Creates optimized production container

### Security Features

- Non-root user (`appuser`)
- Signal handling with `dumb-init`
- Minimal base image
- Health checks

### Resource Limits

- Memory: 512MB limit, 256MB reservation
- CPU: 0.5 cores limit, 0.25 cores reservation

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check what's using port 3000
   netstat -ano | findstr :3000
   
   # Stop the service
   docker-compose down frontend
   ```

2. **Build Failures**
   ```bash
   # Clean build
   docker-compose build --no-cache frontend
   ```

3. **Health Check Failures**
   ```bash
   # Check logs
   docker-compose logs frontend
   
   # Check container status
   docker-compose ps frontend
   ```

### Debug Mode

To run in debug mode with logs:

```bash
# PowerShell
.\scripts\deploy-frontend.ps1 -Logs

# Bash
./scripts/deploy-frontend.sh
```

## Development vs Production

### Development

```bash
# Run in development mode
cd frontend
npm run dev
```

### Production

```bash
# Deploy with Docker
docker-compose up -d frontend
```

## Monitoring

### Service Status

```bash
docker-compose ps
```

### Resource Usage

```bash
docker stats bug-hunting-frontend
```

### Logs

```bash
# Recent logs
docker-compose logs --tail=100 frontend

# Follow logs
docker-compose logs -f frontend
```

## Scaling

To scale the frontend service:

```bash
# Scale to 3 instances
docker-compose up -d --scale frontend=3
```

## Cleanup

### Stop Services

```bash
# Stop frontend only
docker-compose stop frontend

# Stop all services
docker-compose down
```

### Remove Containers and Images

```bash
# Remove containers and networks
docker-compose down

# Remove containers, networks, and images
docker-compose down --rmi all

# Remove everything including volumes
docker-compose down -v --rmi all
```

## Performance Optimization

The frontend is optimized for production with:

- Next.js standalone output
- CSS optimization disabled for Docker
- Telemetry disabled
- Bundle analysis support
- Image optimization
- Security headers

## Security

- Non-root user execution
- Security headers configured
- Content Security Policy
- XSS protection
- Frame options
- Content type options 