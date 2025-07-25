# Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Bug Hunting Framework Frontend in various environments, from local development to production container orchestration.

## Prerequisites

### System Requirements
- **Node.js**: 20.x or higher
- **npm**: 8.x or higher
- **Docker**: 20.x or higher (for containerized deployment)
- **Docker Compose**: 2.x or higher (for multi-service deployment)
- **Git**: For version control

### Network Requirements
- **Port 3000**: Frontend application (configurable)
- **Port 8000**: Backend API (for API communication)
- **Internet Access**: For npm package installation and API calls

## Local Development Deployment

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd bug-hunting-framework/frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your configuration
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

5. **Access the application**
   Open `http://localhost:3000` in your browser

### Environment Configuration

Create a `.env.local` file with the following variables:

```bash
# API Configuration
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws

# Development Configuration
NODE_ENV=development
DOCKER_ENV=false

# Performance Monitoring
NEXT_TELEMETRY_DISABLED=1

# Optional: Bundle Analysis
ANALYZE=false
```

## Docker Container Deployment

### Single Container Deployment

1. **Build the container**
   ```bash
   docker build -t bug-hunting-frontend .
   ```

2. **Run the container**
   ```bash
   docker run -p 3000:3000 \
     -e NODE_ENV=production \
     -e NEXT_PUBLIC_API_URL=http://your-api-url \
     bug-hunting-frontend
   ```

3. **Access the application**
   Open `http://localhost:3000` in your browser

### Multi-Stage Build Optimization

The Dockerfile uses multi-stage builds for optimization:

```dockerfile
# Stage 1: Dependencies
FROM node:20-alpine AS deps
# Install dependencies

# Stage 2: Builder
FROM node:20-alpine AS builder
# Build the application

# Stage 3: Production
FROM node:20-alpine AS runner
# Run the application
```

**Benefits:**
- Smaller final image size (~200MB vs ~500MB)
- Faster builds with layer caching
- Security improvements with non-root user
- Production optimizations

### Container Health Checks

The container includes health checks:

```bash
# Check container health
docker exec <container-name> npm run health

# Health check endpoint
curl http://localhost:3000/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-27T10:00:00.000Z",
  "environment": "production",
  "container_id": "container-123",
  "version": "1.0.0",
  "uptime": 3600,
  "memory": {
    "rss": 123456789,
    "heapTotal": 987654321,
    "heapUsed": 123456789
  }
}
```

## Docker Compose Deployment

### Complete Stack Deployment

1. **Navigate to root directory**
   ```bash
   cd bug-hunting-framework
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Check service status**
   ```bash
   docker-compose ps
   ```

5. **View logs**
   ```bash
   docker-compose logs frontend
   ```

### Docker Compose Configuration

The `docker-compose.yml` includes:

```yaml
frontend:
  build:
    context: ./frontend
    dockerfile: Dockerfile
  container_name: bug-hunting-frontend
  restart: unless-stopped
  depends_on:
    backend:
      condition: service_healthy
  environment:
    - NEXT_PUBLIC_API_URL=http://backend:8000
    - NODE_ENV=production
  ports:
    - "3000:3000"
  volumes:
    - ./frontend:/app
    - /app/node_modules
  networks:
    - bug-hunting-network
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
    interval: 30s
    timeout: 10s
    retries: 5
    start_period: 30s
```

### Service Dependencies

The frontend depends on:
- **Database**: PostgreSQL for data persistence
- **Backend**: Django API for target management
- **Network**: Custom bridge network for service communication

## Production Deployment

### Production Environment Setup

1. **Production environment variables**
   ```bash
   # Production Configuration
   NODE_ENV=production
   DOCKER_ENV=true
   
   # API Configuration
   NEXT_PUBLIC_API_URL=https://api.yourdomain.com
   NEXT_PUBLIC_WS_URL=wss://api.yourdomain.com/ws
   
   # Security
   NEXT_TELEMETRY_DISABLED=1
   
   # Performance
   ANALYZE=false
   ```

2. **SSL/TLS Configuration**
   ```bash
   # For HTTPS in production
   NEXT_PUBLIC_API_URL=https://api.yourdomain.com
   ```

3. **Domain Configuration**
   ```bash
   # Set your domain
   NEXT_PUBLIC_DOMAIN=yourdomain.com
   ```

### Production Build

1. **Build for production**
   ```bash
   npm run build
   ```

2. **Test production build**
   ```bash
   npm run start
   ```

3. **Build production Docker image**
   ```bash
   docker build -t bug-hunting-frontend:prod .
   ```

### Production Container Deployment

1. **Run production container**
   ```bash
   docker run -d \
     --name bug-hunting-frontend-prod \
     -p 3000:3000 \
     -e NODE_ENV=production \
     -e NEXT_PUBLIC_API_URL=https://api.yourdomain.com \
     --restart unless-stopped \
     bug-hunting-frontend:prod
   ```

2. **Set up reverse proxy (Nginx)**
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;
       return 301 https://$server_name$request_uri;
   }
   
   server {
       listen 443 ssl http2;
       server_name yourdomain.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

## Kubernetes Deployment

### Kubernetes Manifests

1. **Deployment**
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: bug-hunting-frontend
     labels:
       app: bug-hunting-frontend
   spec:
     replicas: 3
     selector:
       matchLabels:
         app: bug-hunting-frontend
     template:
       metadata:
         labels:
           app: bug-hunting-frontend
       spec:
         containers:
         - name: frontend
           image: bug-hunting-frontend:latest
           ports:
           - containerPort: 3000
           env:
           - name: NODE_ENV
             value: "production"
           - name: NEXT_PUBLIC_API_URL
             value: "http://backend-service:8000"
           resources:
             requests:
               memory: "256Mi"
               cpu: "250m"
             limits:
               memory: "512Mi"
               cpu: "500m"
           livenessProbe:
             httpGet:
               path: /health
               port: 3000
             initialDelaySeconds: 30
             periodSeconds: 10
           readinessProbe:
             httpGet:
               path: /health
               port: 3000
             initialDelaySeconds: 5
             periodSeconds: 5
   ```

2. **Service**
   ```yaml
   apiVersion: v1
   kind: Service
   metadata:
     name: frontend-service
   spec:
     selector:
       app: bug-hunting-frontend
     ports:
     - protocol: TCP
       port: 80
       targetPort: 3000
     type: ClusterIP
   ```

3. **Ingress**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     name: frontend-ingress
     annotations:
       nginx.ingress.kubernetes.io/rewrite-target: /
   spec:
     rules:
     - host: yourdomain.com
       http:
         paths:
         - path: /
           pathType: Prefix
           backend:
             service:
               name: frontend-service
               port:
                 number: 80
   ```

### Kubernetes Deployment Commands

1. **Apply manifests**
   ```bash
   kubectl apply -f k8s/deployment.yaml
   kubectl apply -f k8s/service.yaml
   kubectl apply -f k8s/ingress.yaml
   ```

2. **Check deployment status**
   ```bash
   kubectl get pods -l app=bug-hunting-frontend
   kubectl get services
   kubectl get ingress
   ```

3. **View logs**
   ```bash
   kubectl logs -l app=bug-hunting-frontend
   ```

## Monitoring and Logging

### Health Monitoring

1. **Health check endpoint**
   ```bash
   curl http://localhost:3000/health
   ```

2. **Container health**
   ```bash
   docker exec <container-name> npm run health
   ```

3. **Kubernetes health**
   ```bash
   kubectl describe pod <pod-name>
   ```

### Performance Monitoring

1. **Bundle analysis**
   ```bash
   npm run analyze
   ```

2. **Performance metrics**
   - Core Web Vitals tracking
   - Custom performance metrics
   - Container resource usage

3. **Error monitoring**
   - Error boundaries
   - Error reporting integration
   - Log aggregation

### Logging

1. **Container logs**
   ```bash
   docker logs <container-name>
   docker-compose logs frontend
   kubectl logs <pod-name>
   ```

2. **Application logs**
   - Console logging in development
   - Structured logging in production
   - Log levels (DEBUG, INFO, WARNING, ERROR)

## Security Considerations

### Container Security

1. **Non-root user**
   ```dockerfile
   RUN addgroup -g 1001 -S nodejs && \
       adduser -S nextjs -u 1001
   USER nextjs
   ```

2. **Security headers**
   ```typescript
   // Configured in next.config.ts
   async headers() {
     return [
       {
         source: '/(.*)',
         headers: [
           { key: 'X-Content-Type-Options', value: 'nosniff' },
           { key: 'X-Frame-Options', value: 'DENY' },
           { key: 'X-XSS-Protection', value: '1; mode=block' },
         ],
       },
     ];
   }
   ```

3. **Environment variables**
   - Never commit secrets to version control
   - Use Kubernetes secrets or Docker secrets
   - Rotate secrets regularly

### Network Security

1. **Firewall configuration**
   ```bash
   # Allow only necessary ports
   ufw allow 3000/tcp  # Frontend
   ufw allow 8000/tcp  # Backend
   ufw allow 5432/tcp  # Database
   ```

2. **Network isolation**
   ```yaml
   # Docker Compose network
   networks:
     bug-hunting-network:
       driver: bridge
       ipam:
         config:
           - subnet: 172.20.0.0/16
   ```

## Backup and Recovery

### Data Backup

1. **Application data**
   ```bash
   # Backup form data (if stored locally)
   docker exec <container-name> tar -czf /tmp/app-data.tar.gz /app/data
   docker cp <container-name>:/tmp/app-data.tar.gz ./backup/
   ```

2. **Configuration backup**
   ```bash
   # Backup environment files
   cp .env ./backup/env-$(date +%Y%m%d).backup
   ```

### Disaster Recovery

1. **Container recovery**
   ```bash
   # Restart failed containers
   docker-compose restart frontend
   
   # Rebuild if necessary
   docker-compose build frontend
   docker-compose up -d frontend
   ```

2. **Kubernetes recovery**
   ```bash
   # Restart deployment
   kubectl rollout restart deployment/bug-hunting-frontend
   
   # Check status
   kubectl rollout status deployment/bug-hunting-frontend
   ```

## Troubleshooting

### Common Issues

1. **Container won't start**
   ```bash
   # Check logs
   docker logs <container-name>
   
   # Check resource usage
   docker stats <container-name>
   
   # Check configuration
   docker exec <container-name> env
   ```

2. **Health check failures**
   ```bash
   # Test health endpoint manually
   curl -v http://localhost:3000/health
   
   # Check container health
   docker inspect <container-name> | grep Health -A 10
   ```

3. **Performance issues**
   ```bash
   # Analyze bundle size
   npm run analyze
   
   # Check memory usage
   docker stats <container-name>
   
   # Monitor Core Web Vitals
   # Use browser DevTools Performance tab
   ```

### Debug Mode

Enable debug logging:

```bash
# Environment variable
DEBUG=true

# Container environment
docker run -e DEBUG=true -e NODE_ENV=development ...
```

### Support

For deployment issues:
- **Documentation**: Check this guide and inline comments
- **Logs**: Review container and application logs
- **Issues**: Create an issue on GitHub with detailed information
- **Discussions**: Use GitHub Discussions for questions and ideas

When reporting deployment issues, please include:
- Deployment method (Docker, Kubernetes, etc.)
- Environment details (OS, versions, etc.)
- Error messages and logs
- Steps to reproduce
- Expected vs actual behavior 