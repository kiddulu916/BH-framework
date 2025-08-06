# Bug Hunting Framework - Production Deployment Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Production Environment Setup](#production-environment-setup)
4. [Security Configuration](#security-configuration)
5. [Monitoring and Alerting Setup](#monitoring-and-alerting-setup)
6. [Database Configuration](#database-configuration)
7. [SSL/TLS Certificate Setup](#ssltls-certificate-setup)
8. [Deployment Process](#deployment-process)
9. [Post-Deployment Verification](#post-deployment-verification)
10. [Maintenance and Updates](#maintenance-and-updates)
11. [Troubleshooting](#troubleshooting)
12. [Emergency Procedures](#emergency-procedures)

## Overview

This guide provides comprehensive instructions for deploying the Bug Hunting Framework in a production environment. The framework is designed as a containerized application with multiple services orchestrated via Docker Compose.

### Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Monitoring    │    │   Application   │
│   (Nginx)       │    │   Stack         │    │   Services      │
│                 │    │                 │    │                 │
│ - SSL/TLS       │    │ - Prometheus    │    │ - Backend       │
│ - Rate Limiting │    │ - Grafana       │    │ - Frontend      │
│ - Security      │    │ - AlertManager  │    │ - Database      │
│   Headers       │    │ - ELK Stack     │    │ - Redis         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Prerequisites

### System Requirements

- **Operating System**: Ubuntu 20.04 LTS or later, CentOS 8+, or RHEL 8+
- **CPU**: Minimum 8 cores (16+ recommended for production)
- **Memory**: Minimum 16GB RAM (32GB+ recommended)
- **Storage**: Minimum 100GB SSD (500GB+ recommended for logs and data)
- **Network**: Stable internet connection for updates and external tool access

### Software Requirements

- **Docker**: Version 20.10+ with Docker Compose
- **Git**: For version control and deployment
- **Make**: For automation scripts
- **Certbot**: For SSL certificate management (optional)

### Security Requirements

- **Firewall**: Configured to allow only necessary ports
- **SSH**: Secure SSH configuration with key-based authentication
- **User Management**: Non-root user with sudo privileges
- **Network Security**: VLAN or network segmentation if applicable

## Production Environment Setup

### 1. System Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y docker.io docker-compose git make curl wget

# Add user to docker group
sudo usermod -aG docker $USER

# Configure Docker daemon for production
sudo tee /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true
}
EOF

# Restart Docker
sudo systemctl restart docker
```

### 2. Directory Structure Setup

```bash
# Create application directory
sudo mkdir -p /opt/bug-hunting-framework
sudo chown $USER:$USER /opt/bug-hunting-framework

# Clone the repository
cd /opt/bug-hunting-framework
git clone <repository-url> .

# Create necessary directories
mkdir -p {data,logs,backups,certs}
```

### 3. Environment Configuration

```bash
# Copy production environment template
cp .env.template .env

# Edit environment variables
nano .env
```

**Key Environment Variables to Configure:**

```bash
# Django Configuration
DJANGO_SECRET_KEY=<generate-secure-key> 

# JWT Configuration
JWT_SECRET_KEY=<generate-secure-jwt-key> # Encode any string with base64 or sha256

# Email Configuration
EMAIL_HOST_USER=<your-email-address> # For security alerts to be sent to

# Monitoring Configuration
GRAFANA_ADMIN_PASSWORD=<secure-password>
```

## Security Configuration

### 1. Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow ssh

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow monitoring ports (internal only)
sudo ufw allow from 127.0.0.1 to any port 3000  # Grafana
sudo ufw allow from 127.0.0.1 to any port 9090  # Prometheus

# Enable firewall
sudo ufw enable
```

### 2. SSL/TLS Certificate Setup

```bash
# Install Certbot
sudo apt install -y certbot

# Obtain SSL certificate
sudo certbot certonly --standalone -d localhost -d www.localhost

# Copy certificates to application directory
sudo cp /etc/letsencrypt/live/localhost/fullchain.pem /opt/bug-hunting-framework/certs/
sudo cp /etc/letsencrypt/live/localhost/privkey.pem /opt/bug-hunting-framework/certs/
sudo chown $USER:$USER /opt/bug-hunting-framework/certs/*
```

### 3. Security Headers and Hardening

The framework includes security headers in the Nginx configuration:

- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy: Comprehensive CSP policy
- Strict-Transport-Security: max-age=31536000; includeSubDomains

## Monitoring and Alerting Setup

### 1. Prometheus Configuration

The production deployment includes Prometheus for metrics collection:

```yaml
# Key metrics collected:
- Application metrics (response times, error rates)
- Infrastructure metrics (CPU, memory, disk)
- Business metrics (user activity, workflow completion)
- Security metrics (failed logins, suspicious activity)
```

### 2. Grafana Dashboards

Access Grafana at `https://localhost:3000`:

- **Main Dashboard**: System health and performance overview
- **Security Dashboard**: Security events and threat monitoring
- **Business Dashboard**: User activity and framework effectiveness

### 3. Alerting Configuration

Alerts are configured to send notifications to `<your-email-address>`:

- **Critical Alerts**: Immediate action required
- **High Alerts**: Attention required within hours
- **Security Alerts**: Immediate investigation required

## Database Configuration

### 1. PostgreSQL Setup

```bash
# Database initialization is handled by Docker Compose
# The database will be created automatically on first run

# Backup configuration
# Automated backups run daily at 2:00 AM
# Backups are encrypted and stored in /opt/bug-hunting-framework/backups/
```

### 2. Database Maintenance

```bash
# Run database maintenance
docker-compose -f docker-compose.yml exec db psql -U $DB_USER -d $DB_NAME -c "VACUUM ANALYZE;"

# Check database size
docker-compose -f docker-compose.yml exec db psql -U $DB_USER -d $DB_NAME -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));"
```

## Deployment Process

### 1. Initial Deployment

```bash
# Navigate to application directory
cd /opt/bug-hunting-framework

# Pull latest changes
git pull origin main

# Build and start services
docker-compose -f docker-compose.yml up -d --build

# Wait for services to be healthy
docker-compose -f docker-compose.yml ps
```

### 2. Database Migration

```bash
# Run database migrations
docker-compose -f docker-compose.yml exec backend alembic upgrade head

# Create superuser (first time only)
docker-compose -f docker-compose.yml exec backend python manage.py createsuperuser
```

### 3. Static Files Collection

```bash
# Collect static files
docker-compose -f docker-compose.yml exec backend python manage.py collectstatic --noinput
```

## Post-Deployment Verification

### 1. Health Checks

```bash
# Check service health
docker-compose -f docker-compose.yml ps

# Check application health
curl -f https://localhost:8000/health/

# Check monitoring endpoints
curl -f https://localhost:3001/api/health  # Grafana
curl -f https://localhost:9090/-/healthy   # Prometheus
```

### 2. Functionality Tests

```bash
# Test API endpoints
curl -X GET https://localhost:8000/api/health/
curl -X GET https://localhost:8000/api/targets/

# Test frontend
curl -X GET https://localhost:3000/
```

### 3. Security Verification

```bash
# Check SSL configuration
curl -I https://localhost:8000/

# Verify security headers
curl -I https://localhost:8000/ | grep -E "(X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Content-Security-Policy|Strict-Transport-Security)"
```

## Maintenance and Updates

### 1. Regular Maintenance Tasks

```bash
# Daily tasks
- Monitor system health and alerts
- Check backup completion
- Review security logs

# Weekly tasks
- Update system packages
- Review performance metrics
- Clean up old logs

# Monthly tasks
- Security audit
- Performance optimization
- Capacity planning
```

### 2. Application Updates

```bash
# Update application
cd /opt/bug-hunting-framework
git pull origin main

# Rebuild and restart services
docker-compose -f docker-compose.yml down
docker-compose -f docker-compose.yml up -d --build

# Run migrations
docker-compose -f docker-compose.yml exec backend alembic upgrade head

# Collect static files
docker-compose -f docker-compose.yml exec backend python manage.py collectstatic --noinput
```

### 3. SSL Certificate Renewal

```bash
# Set up automatic renewal
sudo crontab -e

# Add this line for automatic renewal
0 12 * * * /usr/bin/certbot renew --quiet && cp /etc/letsencrypt/live/localhost/fullchain.pem /opt/bug-hunting-framework/certs/ && cp /etc/letsencrypt/live/localhost/privkey.pem /opt/bug-hunting-framework/certs/ && docker-compose -f /opt/bug-hunting-framework/docker-compose.yml restart nginx
```

## Troubleshooting

### 1. Common Issues

**Service Won't Start:**
```bash
# Check logs
docker-compose -f docker-compose.yml logs <service-name>

# Check resource usage
docker stats

# Check disk space
df -h
```

**Database Connection Issues:**
```bash
# Check database status
docker-compose -f docker-compose.yml exec db pg_isready

# Check database logs
docker-compose -f docker-compose.yml logs db
```

**SSL Certificate Issues:**
```bash
# Check certificate validity
openssl x509 -in certs/fullchain.pem -text -noout

# Test SSL configuration
curl -I https://localhost:8000/
```

### 2. Performance Issues

```bash
# Check resource usage
docker stats

# Check application logs
docker-compose -f docker-compose.yml logs backend

# Check database performance
docker-compose -f docker-compose.yml exec db psql -U $DB_USER -d $DB_NAME -c "SELECT * FROM pg_stat_activity;"
```

## Emergency Procedures

### 1. Service Recovery

```bash
# Restart all services
docker-compose -f docker-compose.yml restart

# Restart specific service
docker-compose -f docker-compose.yml restart <service-name>

# Force recreate containers
docker-compose -f docker-compose.yml up -d --force-recreate
```

### 2. Database Recovery

```bash
# Restore from backup
docker-compose -f docker-compose.yml stop backend
docker-compose -f docker-compose.yml exec db pg_restore -U $DB_USER -d $DB_NAME /backups/latest_backup.sql
docker-compose -f docker-compose.yml start backend
```

### 3. Complete System Recovery

```bash
# Stop all services
docker-compose -f docker-compose.yml down

# Restore from backup
tar -xzf /opt/bug-hunting-framework/backups/system_backup_$(date +%Y%m%d).tar.gz

# Restart services
docker-compose -f docker-compose.yml up -d
```

## Support and Contact

For production support and issues:

- **Email**: dat1kidd916@gmail.com
- **Documentation**: Check the `/docs` directory for additional guides
- **Monitoring**: Use Grafana dashboards for system health monitoring
- **Logs**: Check application logs in `/opt/bug-hunting-framework/logs/`

## Appendix

### A. Useful Commands

```bash
# View all logs
docker-compose -f docker-compose.yml logs -f

# View specific service logs
docker-compose -f docker-compose.yml logs -f backend

# Execute commands in containers
docker-compose -f docker-compose.yml exec backend python manage.py shell
docker-compose -f docker-compose.yml exec db psql -U $DB_USER -d $DB_NAME

# Backup database
docker-compose -f docker-compose.yml exec db pg_dump -U $DB_USER $DB_NAME > backup_$(date +%Y%m%d_%H%M%S).sql
```

### B. Configuration Files

- `docker-compose.yml`: Production service orchestration
- `nginx/nginx.conf`: Nginx main configuration
- `nginx/conf.d/default.conf`: Nginx server blocks
- `monitoring/prometheus.yml`: Prometheus configuration
- `monitoring/alertmanager/alertmanager.yml`: AlertManager configuration

### C. Port Reference

- `80`: HTTP (redirects to HTTPS)
- `443`: HTTPS (main application)
- `3000`: Frontend (React)
- `8000`: Backend (Django)
- `3001`: Grafana (monitoring)
- `9090`: Prometheus (metrics)
- `9200`: Elasticsearch (logs)
- `5601`: Kibana (log visualization)
- `6379`: Redis (cache)
- `3002`: Nginx (load balancer)
- `8001`: PenTest Framework Production (passive_recon)
- `8002`: PenTest Framework Production (active_recon)
- `8003`: PenTest Framework Production (vuln_scan)
- `8004`: PenTest Framework Production (vuln_testing)
- `8005`: PenTest Framework Production (kill_chain)
- `8006`: PenTest Framework Production (reporting)
