# Bug Hunting Framework - Dockerfiles Documentation

## Overview

This document provides comprehensive information about all Dockerfiles in the bug hunting framework stages, including their configurations, dependencies, and usage patterns.

## Stage Dockerfiles

### 1. Passive Reconnaissance (`stages/passive_recon/Dockerfile`)

**Purpose**: Performs passive reconnaissance using various OSINT and enumeration tools.

**Key Features**:
- **Base Image**: python:3.11-slim
- **Tools**: Sublist3r, Amass, Subfinder, Assetfinder, Gau, Waybackurls, Trufflehog
- **Go Tools**: Amass, Subfinder, Assetfinder, Gau, Waybackurls, Httpx, Nuclei, Naabu, Katana, Feroxbuster, Gobuster
- **Additional Tools**: LinkFinder, getJS, EyeWitness, EyeBaller, WhatWeb, FingerprintX, WAFW00F, CloudFail, S3enum
- **Fonts**: Minimal font packages for smaller image size

**Resource Requirements**:
- Memory: 2GB default
- CPU: 0.8 cores default
- Port: 8001

**Environment Variables**:
```bash
BACKEND_API_URL=http://backend:8000/api/results/passive-recon
BACKEND_JWT_TOKEN=your_jwt_token_here
TARGET=example.com
STAGE_NAME=passive_recon
```

### 2. Active Reconnaissance (`stages/active_recon/Dockerfile`)

**Purpose**: Performs active reconnaissance and service enumeration.

**Key Features**:
- **Base Image**: python:3.11-slim
- **Tools**: Nmap, Httpx, Nuclei, Subfinder, Amass, Naabu, Katana, Feroxbuster, Gobuster
- **Go Tools**: Httpx, Nuclei, Subfinder, Amass, Naabu, Katana, Feroxbuster, Gobuster, FingerprintX
- **Additional Tools**: WhatWeb, WAFW00F, EyeWitness, EyeBaller
- **Fonts**: Minimal font packages for smaller image size

**Resource Requirements**:
- Memory: 2GB default
- CPU: 0.8 cores default
- Port: 8002

**Environment Variables**:
```bash
BACKEND_API_URL=http://backend:8000/api/results/active-recon
BACKEND_JWT_TOKEN=your_jwt_token_here
TARGET=example.com
STAGE_NAME=active_recon
```

### 3. Vulnerability Scanning (`stages/vuln_scan/Dockerfile`)

**Purpose**: Performs automated vulnerability scanning using multiple tools.

**Key Features**:
- **Base Image**: python:3.11-slim
- **Tools**: Nmap, Nikto, Wapiti, Arachni, Skipfish, OpenVAS, Nuclei, ZAP
- **Go Tools**: Nuclei, Httpx, Subfinder, Amass, Naabu, Katana, Feroxbuster, Gobuster, FingerprintX
- **Additional Tools**: Dirb, Gobuster, FFuf, Wfuzz, WhatWeb, WAFW00F
- **OWASP ZAP**: Integrated ZAP installation
- **Fonts**: Minimal font packages for smaller image size

**Resource Requirements**:
- Memory: 2GB default (configurable)
- CPU: 0.8 cores default
- Port: 8003

**Environment Variables**:
```bash
BACKEND_API_URL=http://backend:8000/api/results/vuln-scan
BACKEND_JWT_TOKEN=your_jwt_token_here
TARGET=example.com
STAGE_NAME=vuln_scan
STAGE_TIMEOUT_SECONDS=1800
```

### 4. Vulnerability Testing (`stages/vuln_test/Dockerfile`)

**Purpose**: Performs manual verification and testing of discovered vulnerabilities with AI integration.

**Key Features**:
- **Base Image**: python:3.11-slim
- **AI/ML**: TensorFlow, PyTorch, Transformers, Scikit-learn
- **Browser Automation**: Chromium, Firefox, Playwright, Selenium
- **Security Tools**: Nmap, Nikto, SQLMap, Hydra, Dirb, Gobuster, FFuf, Wfuzz, WhatWeb, WAFW00F
- **Go Tools**: Httpx, Nuclei, Subfinder, Amass, Naabu, Katana, Feroxbuster, FingerprintX
- **Evidence Collection**: Screenshots, video recording, evidence compression
- **Fonts**: Minimal font packages for smaller image size

**Resource Requirements**:
- Memory: 4GB default (configurable)
- CPU: 1.0 cores default
- Port: 8004

**Environment Variables**:
```bash
BACKEND_API_URL=http://backend:8000/api/results/vuln-test
BACKEND_JWT_TOKEN=your_jwt_token_here
TARGET=example.com
STAGE_NAME=vuln_test
STAGE_TIMEOUT_SECONDS=2400
AI_CONFIDENCE_THRESHOLD=0.8
ENABLE_AI_ANALYSIS=true
```

### 5. Comprehensive Reporting (`stages/comprehensive_reporting/Dockerfile`)

**Purpose**: Generates comprehensive reports and stakeholder communication materials.

**Key Features**:
- **Base Image**: python:3.11-slim
- **Report Generation**: Pandoc, wkhtmltopdf, ReportLab, WeasyPrint
- **Visualization**: Matplotlib, Seaborn, Plotly, Dash
- **Documentation**: Python-docx, OpenPyXL, XlsxWriter
- **Node.js Tools**: Puppeteer for advanced reporting
- **Fonts**: Minimal font packages for smaller image size

**Resource Requirements**:
- Memory: 4GB default (configurable)
- CPU: 1.0 cores default
- Port: 8007

**Environment Variables**:
```bash
BACKEND_API_URL=http://backend:8000/api/results/comprehensive-reporting
BACKEND_JWT_TOKEN=your_jwt_token_here
TARGET=example.com
STAGE_NAME=comprehensive_reporting
STAGE_TIMEOUT_SECONDS=3600
```

## Common Patterns

### 1. Base Image Selection
All stages use `python:3.11-slim` as the base image for consistency and smaller size.

### 2. Security Best Practices
- **Non-root User**: All containers run as non-root user (`appuser`)
- **Minimal Fonts**: Only essential fonts (Liberation, DejaVu) for smaller image size
- **Health Checks**: Built-in health monitoring for all containers
- **Resource Limits**: Configurable memory and CPU limits

### 3. Tool Installation Patterns
- **System Tools**: Installed via apt-get with cleanup
- **Go Tools**: Installed via Go package manager
- **Python Tools**: Installed via pip with requirements.txt
- **Node.js Tools**: Installed via npm for specific stages

### 4. Environment Configuration
- **Standardized Variables**: Consistent environment variable naming
- **JWT Authentication**: Secure API communication
- **Tool Paths**: Explicit tool path configuration
- **Resource Limits**: Configurable memory and CPU limits

### 5. Volume Management
- **Source Code**: Mounted for development
- **Outputs**: Shared output directory
- **Docker Socket**: For container orchestration

## Docker Compose Integration

### Service Dependencies
```
db → backend → frontend
  ↓
passive_recon → active_recon → vuln_scan → vuln_test → kill_chain → comprehensive_reporting
```

### Resource Allocation
- **Database**: 1GB memory, 0.5 CPU cores
- **Backend**: 512MB memory, 0.5 CPU cores
- **Frontend**: 512MB memory, 0.5 CPU cores
- **Stage Containers**: 2-4GB memory, 0.8-1.0 CPU cores

### Network Configuration
- **Custom Network**: `bug-hunting-network`
- **Bridge Driver**: Isolated communication
- **Service Discovery**: Internal DNS resolution

## Environment File Templates

Each stage includes a `.env.template` file with:
- Backend API configuration
- JWT authentication settings
- Stage-specific configuration
- Tool paths and settings
- Resource limits
- Logging configuration

### Usage
```bash
# Copy template to .env
cp stages/vuln_scan/.env.template stages/vuln_scan/.env

# Update with your values
nano stages/vuln_scan/.env

# Generate JWT token
python stages/utils/generate_jwt.py --sub vuln_scan_stage --env-path stages/vuln_scan/.env
```

## Building and Running

### Build Individual Stage
```bash
# Build vuln_scan stage
docker build -t bug-hunting-vuln-scan stages/vuln_scan/

# Build vuln_test stage
docker build -t bug-hunting-vuln-test stages/vuln_test/
```

### Run with Docker Compose
```bash
# Run all services
docker-compose up -d

# Run specific stage
docker-compose up vuln_scan

# Run with custom target
TARGET=example.com docker-compose up vuln_scan
```

### Development Mode
```bash
# Run with source code mounted
docker-compose up vuln_scan vuln_test

# View logs
docker-compose logs -f vuln_scan
```

## Performance Optimization

### 1. Image Size Reduction
- **Minimal Fonts**: Only essential fonts installed
- **Layer Optimization**: Combined RUN commands where possible
- **Cleanup**: Remove package lists after installation
- **Multi-stage Builds**: Consider for production builds

### 2. Resource Optimization
- **Memory Limits**: Appropriate limits for each stage
- **CPU Limits**: Prevent resource exhaustion
- **Timeout Configuration**: Stage-specific timeouts
- **Concurrent Execution**: Configurable concurrency limits

### 3. Caching Strategy
- **Dependency Caching**: Install dependencies before copying code
- **Layer Caching**: Optimize Docker layer ordering
- **Build Cache**: Use Docker build cache effectively

## Security Considerations

### 1. Container Security
- **Non-root Users**: All containers run as non-root
- **Read-only Filesystems**: Consider for production
- **Secrets Management**: Use environment variables
- **Network Isolation**: Custom network for services

### 2. Tool Security
- **Version Pinning**: Specific tool versions
- **Source Verification**: Verify tool sources
- **Update Strategy**: Regular security updates
- **Vulnerability Scanning**: Scan container images

### 3. Data Security
- **Input Validation**: Validate all inputs
- **Output Sanitization**: Sanitize all outputs
- **Encryption**: Encrypt sensitive data
- **Access Control**: Implement proper access controls

## Troubleshooting

### Common Issues

1. **Build Failures**
   ```bash
   # Check Docker build context
   docker build --no-cache stages/vuln_scan/
   
   # Check available disk space
   df -h
   ```

2. **Memory Issues**
   ```bash
   # Increase memory limit
   docker-compose up vuln_test --memory=8g
   
   # Check memory usage
   docker stats
   ```

3. **Network Issues**
   ```bash
   # Check network connectivity
   docker network ls
   docker network inspect bug-hunting-network
   ```

4. **Permission Issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER stages/
   chmod +x stages/*/run_*.py
   ```

### Debug Mode
```bash
# Run with debug logging
LOG_LEVEL=DEBUG docker-compose up vuln_scan

# Access container shell
docker-compose exec vuln_scan bash
```

## Best Practices

1. **Version Control**: Keep Dockerfiles in version control
2. **Documentation**: Document all changes and configurations
3. **Testing**: Test containers before deployment
4. **Monitoring**: Monitor resource usage and performance
5. **Updates**: Regular updates of base images and tools
6. **Security**: Regular security audits and updates
7. **Backup**: Backup important configurations and data

## Support

For issues and questions:
1. Check the logs in `outputs/{stage}/{target}/logs/`
2. Review the troubleshooting section above
3. Check the main project documentation
4. Review the stage-specific documentation
5. Check Docker and Docker Compose documentation 