# Enhanced Passive Reconnaissance Stage - Complete Documentation

## Overview

The Enhanced Passive Reconnaissance Stage is a comprehensive OSINT (Open Source Intelligence) framework that implements all 10 major passive reconnaissance techniques for bug bounty hunting and security research. This stage provides stealthy, automated reconnaissance capabilities without direct target interaction.

## Architecture

### Core Components

1. **Enhanced Data Models** - 9 new SQLAlchemy models for comprehensive OSINT data
2. **Tool Runners** - 22+ modular tool runners for different reconnaissance techniques
3. **Workflow Orchestration** - Parallel execution with rate limiting and progress tracking
4. **API Integration** - Comprehensive REST API for data submission and retrieval
5. **Continuous Monitoring** - Automated scheduling with discovery alerts
6. **Testing Suite** - Comprehensive test coverage for all components

### Data Flow

```
Target Input → Tool Runners → Data Processing → API Submission → Database Storage
     ↓              ↓              ↓              ↓              ↓
Target ID → Enhanced OSINT → Correlation → Backend API → Framework Integration
```

## Enhanced OSINT Data Models

### 1. WHOISRecord
Stores domain registration information and DNS records.

```python
{
    "target_id": "uuid",
    "domain": "example.com",
    "registrar": "Example Registrar",
    "registrant_name": "John Doe",
    "registrant_email": "john@example.com",
    "creation_date": "2020-01-01T00:00:00Z",
    "expiration_date": "2025-01-01T00:00:00Z",
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "dns_records": {"A": ["192.168.1.1"], "MX": ["mail.example.com"]}
}
```

### 2. CertificateLog
Stores certificate transparency log data.

```python
{
    "target_id": "uuid",
    "domain": "example.com",
    "certificate_id": "cert-123",
    "issuer": "Let's Encrypt",
    "subject": "CN=example.com",
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2024-04-01T00:00:00Z",
    "log_index": 12345,
    "log_url": "https://crt.sh/log/12345"
}
```

### 3. RepositoryFinding
Stores public repository discoveries and secrets.

```python
{
    "target_id": "uuid",
    "repository_url": "https://github.com/company/repo",
    "platform": "GitHub",
    "repository_name": "repo",
    "owner": "company",
    "language": "Python",
    "stars": 100,
    "secrets_found": ["API_KEY", "DATABASE_PASSWORD"],
    "files_analyzed": ["config.py", "secrets.json"]
}
```

### 4. SearchDorkResult
Stores search engine dorking results.

```python
{
    "target_id": "uuid",
    "search_engine": "Google",
    "dork_query": "site:example.com filetype:pdf",
    "results_count": 15,
    "urls_found": ["https://example.com/doc1.pdf"],
    "file_types": ["pdf", "doc", "xls"],
    "parameters": ["id", "token", "api_key"]
}
```

### 5. BreachRecord
Stores data breach and credential leak information.

```python
{
    "target_id": "uuid",
    "breach_name": "Example Breach 2024",
    "breach_date": "2024-01-15T00:00:00Z",
    "data_classes": ["email_addresses", "passwords", "usernames"],
    "records_count": 1000000,
    "source": "HaveIBeenPwned",
    "verification_status": "verified"
}
```

### 6. InfrastructureExposure
Stores infrastructure exposure data from internet scanners.

```python
{
    "target_id": "uuid",
    "ip_address": "192.168.1.1",
    "port": 443,
    "service": "https",
    "banner": "nginx/1.18.0",
    "ssl_info": {"issuer": "Let's Encrypt", "subject": "example.com"},
    "vulnerabilities": ["CVE-2021-1234"],
    "source": "Shodan"
}
```

### 7. ArchiveFinding
Stores archive and historical data discoveries.

```python
{
    "target_id": "uuid",
    "url": "https://example.com/admin",
    "archived_url": "http://web.archive.org/web/20200101/https://example.com/admin",
    "archive_date": "2020-01-01T00:00:00Z",
    "archive_source": "Wayback Machine",
    "content_type": "text/html",
    "status_code": 200,
    "parameters": ["admin", "password"],
    "secrets_found": ["admin:password123"]
}
```

### 8. SocialMediaIntel
Stores social media intelligence data.

```python
{
    "target_id": "uuid",
    "platform": "LinkedIn",
    "username": "john.doe",
    "profile_url": "https://linkedin.com/in/john.doe",
    "display_name": "John Doe",
    "company": "Example Corp",
    "job_title": "Security Engineer",
    "followers_count": 500,
    "last_active": "2024-01-20T00:00:00Z"
}
```

### 9. CloudAsset
Stores cloud asset discoveries.

```python
{
    "target_id": "uuid",
    "asset_type": "S3 Bucket",
    "provider": "AWS",
    "asset_name": "example-bucket",
    "asset_url": "https://example-bucket.s3.amazonaws.com",
    "region": "us-east-1",
    "status": "public",
    "permissions": "public-read",
    "size": 1024000
}
```

## API Integration

### Enhanced Endpoints

#### 1. Submit Comprehensive Results
```bash
POST /api/results/passive-recon
Content-Type: application/json
Authorization: Bearer <JWT_TOKEN>

{
    "target_id": "uuid",
    "execution_id": "exec-123",
    "tools_used": ["amass", "subfinder", "whois", "github"],
    "subdomains": [...],
    "whois_records": [...],
    "certificate_logs": [...],
    "repository_findings": [...],
    "search_dork_results": [...],
    "breach_records": [...],
    "infrastructure_exposures": [...],
    "archive_findings": [...],
    "social_media_intel": [...],
    "cloud_assets": [...],
    "correlation_data": {...}
}
```

#### 2. Individual OSINT Data Endpoints
```bash
# WHOIS Records
POST /api/results/passive-recon/whois

# Certificate Logs
POST /api/results/passive-recon/certificates

# Repository Findings
POST /api/results/passive-recon/repositories

# Search Dork Results
POST /api/results/passive-recon/search-dorks

# Breach Records
POST /api/results/passive-recon/breaches

# Infrastructure Exposures
POST /api/results/passive-recon/infrastructure

# Archive Findings
POST /api/results/passive-recon/archives

# Social Media Intelligence
POST /api/results/passive-recon/social-media

# Cloud Assets
POST /api/results/passive-recon/cloud-assets
```

#### 3. Retrieval Endpoints
```bash
# Get comprehensive results
GET /api/results/{target_id}/passive-recon?category=DOMAIN_WHOIS

# Get specific OSINT data
GET /api/results/{target_id}/passive-recon/whois
GET /api/results/{target_id}/passive-recon/certificates
GET /api/results/{target_id}/passive-recon/repositories
GET /api/results/{target_id}/passive-recon/search-dorks
GET /api/results/{target_id}/passive-recon/breaches
GET /api/results/{target_id}/passive-recon/infrastructure
GET /api/results/{target_id}/passive-recon/archives
GET /api/results/{target_id}/passive-recon/social-media
GET /api/results/{target_id}/passive-recon/cloud-assets

# Get enhanced summary
GET /api/results/{target_id}/summary
```

## Tool Runners

### 1. WHOIS & DNS Profiling
**File**: `runners/run_whois.py`
- WHOIS lookup with comprehensive domain information
- Reverse WHOIS for domain discovery
- DNS record enumeration
- Registrant information analysis

### 2. Certificate Transparency
**File**: `runners/run_certificate_transparency.py`
- Certificate transparency log monitoring
- Passive DNS database queries
- SSL certificate analysis
- Subdomain discovery from certificates

### 3. Repository Mining
**File**: `runners/run_repository_mining.py`
- GitHub, GitLab, Bitbucket scanning
- Secret detection with TruffleHog
- Code analysis for internal references
- Repository metadata extraction

### 4. Search Engine Dorking
**File**: `runners/run_search_dorking.py`
- Google/Bing advanced search operators
- File type discovery
- Directory listing detection
- Error message and debug info discovery

### 5. Data Breach Checking
**File**: `runners/run_breach_checking.py`
- HaveIBeenPwned integration
- DeHashed database queries
- IntelX breach data
- Credential leak detection

### 6. Infrastructure Exposure
**File**: `runners/run_infrastructure_exposure.py`
- Shodan, Censys, BinaryEdge, ZoomEye integration
- Service and port discovery
- Vulnerability indicator detection
- SSL certificate analysis

### 7. Archive Mining
**File**: `runners/run_archive_mining.py`
- Wayback Machine integration
- Google Cache analysis
- Historical URL discovery
- JavaScript analysis for secrets

### 8. Social Intelligence
**File**: `runners/run_social_intelligence.py`
- Employee information gathering
- Tech stack discovery
- Cloud asset enumeration
- Community and news monitoring

## Workflow Orchestration

### Main Runner: `run_passive_recon.py`

#### Features
- **Parallel Execution**: ThreadPoolExecutor for concurrent tool execution
- **Rate Limiting**: Intelligent rate limiting to prevent API service blocking
- **Progress Tracking**: Real-time progress monitoring with success/failure statistics
- **Retry Logic**: Exponential backoff retry mechanism for failed executions
- **Data Correlation**: Cross-tool data correlation and deduplication
- **Comprehensive Reporting**: Detailed progress statistics and correlation analysis

#### Usage
```bash
# Basic usage
python run_passive_recon.py --target example.com

# With parallel execution and rate limiting
python run_passive_recon.py --target example.com --parallel 5 --rate-limit 2.0

# With specific tools
python run_passive_recon.py --target example.com --tools whois,github,shodan

# With custom output directory
python run_passive_recon.py --target example.com --output-dir /custom/output
```

#### Configuration
```python
# Rate limiting configuration
rate_limiter = RateLimiter(calls_per_second=1.0)

# Progress tracking
progress_tracker = ProgressTracker(total_tools=22)

# Parallel execution
max_workers = 5  # Configurable parallelism

# Retry configuration
max_retries = 3
retry_delay = 2  # Exponential backoff
```

## Continuous Monitoring

### Monitor: `monitor_passive_recon.py`

#### Features
- **Scheduled Execution**: Configurable monitoring intervals
- **Discovery Alerts**: Email alerts for new discoveries
- **Performance Tracking**: Comprehensive performance metrics
- **Historical Comparison**: Track changes over time
- **Configurable Thresholds**: Alert on discovery thresholds

#### Usage
```bash
# Run once
python monitor_passive_recon.py --run-once --targets example.com test.com

# Continuous monitoring
python monitor_passive_recon.py --config monitor_config.json

# Custom configuration
python monitor_passive_recon.py --targets example.com --interval 12 --threshold 10
```

#### Configuration: `monitor_config.json`
```json
{
    "targets": ["example.com", "test.example.com"],
    "schedule_interval": 24,
    "alert_threshold": 5,
    "email": {
        "enabled": false,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "your-email@gmail.com",
        "password": "your-app-password",
        "from_email": "your-email@gmail.com",
        "to_email": "alerts@yourdomain.com"
    },
    "performance": {
        "max_parallel_executions": 3,
        "rate_limit_per_second": 1.0,
        "retry_attempts": 3,
        "retry_delay": 5
    }
}
```

## Testing

### Test Suite: `test_enhanced_passive_recon.py`

#### Test Coverage
- **Unit Tests**: Individual tool runners and utility functions
- **Integration Tests**: API integration and data flow
- **Performance Tests**: Rate limiting and progress tracking
- **Error Handling Tests**: Exception scenarios and edge cases
- **Data Validation Tests**: Input validation and data processing

#### Running Tests
```bash
# Run all tests
python -m pytest test_enhanced_passive_recon.py -v

# Run specific test categories
python -m pytest test_enhanced_passive_recon.py::TestToolRunners -v
python -m pytest test_enhanced_passive_recon.py::TestAPIIntegration -v
python -m pytest test_enhanced_passive_recon.py::TestMonitoring -v

# Run with coverage
python -m pytest test_enhanced_passive_recon.py --cov=. --cov-report=html
```

#### Test Categories
1. **TestRateLimiter**: Rate limiting functionality
2. **TestProgressTracker**: Progress tracking and statistics
3. **TestToolRunners**: Individual tool runner functionality
4. **TestDataCorrelation**: Cross-tool data correlation
5. **TestAPIIntegration**: API integration and target management
6. **TestToolRetryLogic**: Retry mechanism and error handling
7. **TestMonitoring**: Continuous monitoring functionality
8. **TestErrorHandling**: Exception scenarios and edge cases
9. **TestPerformance**: Performance and scalability tests
10. **TestDataValidation**: Input validation and data processing
11. **TestIntegration**: End-to-end workflow integration

## Environment Configuration

### Required Environment Variables
```bash
# Backend API Configuration
BACKEND_API_URL=http://backend:8000/api/results/passive-recon
BACKEND_JWT_TOKEN=your-jwt-token

# API Keys for External Services
CENSYS_API_ID=your-censys-api-id
CENSYS_API_SECRET=your-censys-api-secret
SHODAN_API_KEY=your-shodan-api-key
GITHUB_TOKEN=your-github-token
HIBP_API_KEY=your-hibp-api-key
DEHASHED_API_KEY=your-dehashed-api-key
INTELX_API_KEY=your-intelx-api-key
BINARYEDGE_API_KEY=your-binaryedge-api-key
ZOOMEYE_API_KEY=your-zoomeye-api-key

# Tool Paths
WHOIS_PATH=/usr/bin/whois
DIG_PATH=/usr/bin/dig
NSLOOKUP_PATH=/usr/bin/nslookup
```

### Tool Installation
```bash
# Install system dependencies
apt-get update && apt-get install -y \
    whois \
    dnsutils \
    curl \
    wget \
    git \
    python3-pip

# Install Python dependencies
pip install -r requirements.txt

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/amass/v4/...@master
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/trufflesecurity/trufflehog@latest
```

## Security Considerations

### Stealth Operations
- **Rate Limiting**: Prevents detection through API rate limiting
- **User-Agent Rotation**: Rotates user agents to avoid detection
- **Request Delays**: Implements delays between requests
- **Proxy Support**: Supports proxy configuration for anonymity

### Legal Compliance
- **Scope Validation**: Validates targets against authorized scope
- **Terms of Service**: Respects API terms of service and rate limits
- **Data Handling**: Implements proper data handling and privacy protection
- **Audit Logging**: Maintains comprehensive audit logs

### Data Protection
- **Encryption**: All sensitive data encrypted at rest and in transit
- **Access Control**: JWT-based authentication and authorization
- **Data Retention**: Configurable data retention policies
- **Privacy**: PII detection and redaction capabilities

## Performance Optimization

### Parallel Execution
- **Configurable Parallelism**: Adjustable number of concurrent tools
- **Resource Management**: Memory and CPU usage optimization
- **Connection Pooling**: HTTP connection pooling for API requests
- **Caching**: Intelligent caching of API responses

### Rate Limiting
- **Intelligent Rate Limiting**: Prevents API service blocking
- **Service-Specific Limits**: Different limits for different services
- **Backoff Strategies**: Exponential backoff for failed requests
- **Queue Management**: Request queuing and prioritization

### Data Processing
- **Streaming Processing**: Stream processing for large datasets
- **Deduplication**: Efficient deduplication algorithms
- **Compression**: Data compression for storage optimization
- **Indexing**: Database indexing for fast queries

## Troubleshooting

### Common Issues

#### 1. API Rate Limiting
```bash
# Error: Rate limit exceeded
# Solution: Reduce rate limit or increase delays
python run_passive_recon.py --target example.com --rate-limit 0.5
```

#### 2. Tool Execution Failures
```bash
# Error: Tool not found
# Solution: Check tool installation and paths
which whois
which subfinder
which amass
```

#### 3. Database Connection Issues
```bash
# Error: Database connection failed
# Solution: Check database configuration and connectivity
python -c "from core.utils.database import get_db_session; print('DB OK')"
```

#### 4. JWT Authentication Issues
```bash
# Error: JWT authentication failed
# Solution: Check JWT token and expiration
python utils/generate_jwt.py --env .env
```

### Debug Mode
```bash
# Enable debug logging
export DEBUG=1
python run_passive_recon.py --target example.com --debug

# Verbose output
python run_passive_recon.py --target example.com --verbose
```

### Log Analysis
```bash
# View execution logs
tail -f /outputs/example.com/passive_recon.log

# Analyze performance metrics
python -c "import json; print(json.dumps(json.load(open('/outputs/example.com/performance_metrics.json')), indent=2))"
```

## Integration Examples

### 1. Docker Integration
```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    whois dnsutils curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy stage files
COPY . .

# Set entry point
CMD ["python", "run_passive_recon.py"]
```

### 2. CI/CD Integration
```yaml
# GitHub Actions workflow
name: Enhanced Passive Recon
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: python -m pytest test_enhanced_passive_recon.py -v
      - name: Run passive recon
        run: python run_passive_recon.py --target test.example.com --run-once
```

### 3. API Integration Example
```python
import requests
import json

# Submit comprehensive passive recon results
def submit_enhanced_results(target_id, results):
    url = "http://backend:8000/api/results/passive-recon"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {JWT_TOKEN}"
    }
    
    payload = {
        "target_id": target_id,
        "tools_used": ["amass", "subfinder", "whois", "github"],
        "subdomains": results.get("subdomains", []),
        "whois_records": results.get("whois_records", []),
        "certificate_logs": results.get("certificate_logs", []),
        "repository_findings": results.get("repository_findings", []),
        "search_dork_results": results.get("search_dork_results", []),
        "breach_records": results.get("breach_records", []),
        "infrastructure_exposures": results.get("infrastructure_exposures", []),
        "archive_findings": results.get("archive_findings", []),
        "social_media_intel": results.get("social_media_intel", []),
        "cloud_assets": results.get("cloud_assets", []),
        "correlation_data": results.get("correlation_data", {})
    }
    
    response = requests.post(url, json=payload, headers=headers)
    return response.json()

# Retrieve enhanced results
def get_enhanced_results(target_id, category=None):
    url = f"http://backend:8000/api/results/{target_id}/passive-recon"
    params = {"category": category} if category else {}
    headers = {"Authorization": f"Bearer {JWT_TOKEN}"}
    
    response = requests.get(url, params=params, headers=headers)
    return response.json()
```

## Conclusion

The Enhanced Passive Reconnaissance Stage provides a comprehensive, production-ready solution for automated OSINT gathering in bug bounty hunting and security research. With its modular architecture, comprehensive data models, robust API integration, and extensive testing, it offers a complete framework for stealthy reconnaissance operations.

Key features include:
- **22+ Tool Runners**: Covering all major OSINT techniques
- **Enhanced Data Models**: 9 new models for comprehensive data storage
- **Parallel Execution**: High-performance concurrent processing
- **Continuous Monitoring**: Automated scheduling and alerting
- **Comprehensive Testing**: Full test coverage for all components
- **Production Ready**: Robust error handling and performance optimization

This stage serves as the foundation for the entire bug hunting framework, providing the reconnaissance data needed for subsequent stages including active reconnaissance, vulnerability scanning, and kill chain analysis.